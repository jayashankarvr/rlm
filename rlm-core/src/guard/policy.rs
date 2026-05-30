//! Pure policy state machine — the self-healing circuit breaker at the heart of
//! the freeze guard.
//!
//! Contract: [`PolicyEngine::tick`] is pure given `(now_ms, sample, procs)` plus
//! the engine's own internal state. It performs **no** syscalls and reads **no**
//! clock — `now_ms` (monotonic milliseconds) is injected by the caller. That is
//! what makes the whole escalation/recovery ladder unit-testable without root.

use std::collections::HashMap;

use super::types::{Action, Intervention, Level, ProcInfo, Sample};
use common::GuardConfig;

/// PSI `full` avg10 (%) that, on its own, forces at least the High level. Mirrors
/// the design doc's "or `full.avg10 >= 3`" High trigger.
const FULL_HIGH_RISE: f64 = 3.0;
/// Rate-limit window for `Notify` actions (ms): at most one notification a minute.
const NOTIFY_INTERVAL_MS: u64 = 60_000;

/// Self-healing circuit-breaker policy engine.
///
/// On a memory spike it drives the ladder *notify -> freeze (short) -> auto-thaw
/// -> still high? soft-cap -> calm sustained -> lift*, never issuing a kill. All
/// of that lives in [`tick`](Self::tick); the struct just holds the state needed
/// to make decisions stable across ticks (hysteresis + cooldowns).
pub struct PolicyEngine {
    cfg: GuardConfig,
    /// Current pressure level (carried across ticks so hysteresis works).
    level: Level,
    /// Active interventions keyed by pid.
    interventions: HashMap<u32, Intervention>,
    /// Last time each pid was frozen — drives the per-pid freeze cooldown that
    /// decides freeze-vs-cap, and is intentionally kept after a thaw.
    last_freeze_ms: HashMap<u32, u64>,
    /// When the level last became `Calm` (None while not calm). Gates cap lifts.
    calm_since_ms: Option<u64>,
    /// When we last emitted a new freeze/cap — the global escalation gate.
    /// `None` means "never acted", so the gate is open on the first action.
    last_action_ms: Option<u64>,
    /// When we last emitted a `Notify` — drives notification rate-limiting.
    /// `None` means "never notified", so the first eligible notify fires.
    last_notify_ms: Option<u64>,
}

impl PolicyEngine {
    pub fn new(cfg: GuardConfig) -> Self {
        Self {
            cfg,
            level: Level::Calm,
            interventions: HashMap::new(),
            last_freeze_ms: HashMap::new(),
            calm_since_ms: None,
            last_action_ms: None,
            last_notify_ms: None,
        }
    }

    /// Advance the state machine one tick and return the actions to apply.
    pub fn tick(&mut self, now_ms: u64, sample: Sample, procs: &[ProcInfo]) -> Vec<Action> {
        // 1. Disabled guard is inert.
        if !self.cfg.enabled {
            return Vec::new();
        }

        let mut actions = Vec::new();

        // 2. Recompute the level with hysteresis and track how long we've been calm.
        self.level = self.next_level(sample);
        match self.level {
            Level::Calm => {
                // Start the calm clock on the *transition* into calm, then leave it.
                if self.calm_since_ms.is_none() {
                    self.calm_since_ms = Some(now_ms);
                }
            }
            _ => self.calm_since_ms = None,
        }

        // 3. Prune interventions whose process has vanished. LiftCap doubles as
        //    "tear down the guard cgroup", so it's the right cleanup for both
        //    frozen and capped dead pids.
        let alive: std::collections::HashSet<u32> = procs.iter().map(|p| p.pid).collect();
        let dead: Vec<u32> = self
            .interventions
            .keys()
            .copied()
            .filter(|pid| !alive.contains(pid))
            .collect();
        for pid in dead {
            actions.push(Action::LiftCap { pid });
            self.interventions.remove(&pid);
        }

        // 4. Recover: auto-thaw held freezes, and lift caps once calm has held.
        let freeze_hold_ms = self.cfg.timing.freeze_hold_secs * 1000;
        let calm_hold_ms = self.cfg.timing.calm_hold_secs * 1000;
        let mut recovered = Vec::new();
        // Pids thawed on this tick must not be re-targeted by escalation in the
        // same tick — they need a re-measure first.
        let mut thawed_now: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for (&pid, intervention) in &self.interventions {
            match *intervention {
                Intervention::Frozen { since_ms } => {
                    if now_ms.saturating_sub(since_ms) >= freeze_hold_ms {
                        actions.push(Action::Thaw { pid });
                        recovered.push(pid);
                        thawed_now.insert(pid);
                    }
                }
                Intervention::Capped { .. } => {
                    // Only lift a cap when pressure is calm *and* has stayed calm
                    // long enough — prevents re-capping churn. `calm_since_ms` is
                    // the transition timestamp, so this measures *sustained* calm.
                    if self.level == Level::Calm {
                        if let Some(calm_since) = self.calm_since_ms {
                            if now_ms.saturating_sub(calm_since) >= calm_hold_ms {
                                actions.push(Action::LiftCap { pid });
                                recovered.push(pid);
                            }
                        }
                    }
                }
            }
        }
        for pid in recovered {
            // Note: last_freeze_ms is intentionally retained for cooldown logic.
            self.interventions.remove(&pid);
        }

        // 5. Escalate, but only when pressure actually warrants action.
        let mut victim_name: Option<String> = None;
        if matches!(self.level, Level::High | Level::Critical) {
            // Global gate: after acting on one hog, wait a freeze-hold before
            // acting again so we re-measure instead of cascading freezes.
            let gate_open = match self.last_action_ms {
                None => true,
                Some(last) => now_ms.saturating_sub(last) >= freeze_hold_ms,
            };
            if gate_open {
                if let Some(victim) = self.select_victim(procs, &thawed_now) {
                    let cooldown_ms = self.cfg.timing.freeze_cooldown_secs * 1000;
                    let in_cooldown = self
                        .last_freeze_ms
                        .get(&victim.pid)
                        .is_some_and(|&last| now_ms.saturating_sub(last) < cooldown_ms);

                    if in_cooldown {
                        // Recently frozen and still hot -> escalate to a soft cap.
                        actions.push(Action::Cap {
                            pid: victim.pid,
                            name: victim.name.clone(),
                        });
                        self.interventions
                            .insert(victim.pid, Intervention::Capped { since_ms: now_ms });
                    } else {
                        actions.push(Action::Freeze {
                            pid: victim.pid,
                            name: victim.name.clone(),
                        });
                        self.interventions
                            .insert(victim.pid, Intervention::Frozen { since_ms: now_ms });
                        self.last_freeze_ms.insert(victim.pid, now_ms);
                    }
                    self.last_action_ms = Some(now_ms);
                    victim_name = Some(victim.name.clone());
                }
            }
        }

        // 6. Notify (rate-limited) while there's anything to report.
        let notify_due = match self.last_notify_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= NOTIFY_INTERVAL_MS,
        };
        if self.cfg.notify
            && matches!(self.level, Level::Warn | Level::High | Level::Critical)
            && notify_due
        {
            let message = match &victim_name {
                Some(name) => format!(
                    "rlm-guard: memory pressure {:?} — acting on {}",
                    self.level, name
                ),
                None => format!("rlm-guard: memory pressure {:?}", self.level),
            };
            actions.push(Action::Notify { message });
            self.last_notify_ms = Some(now_ms);
        }

        actions
    }

    /// Currently active interventions (pid -> intervention), sorted by pid so
    /// callers get a deterministic order.
    pub fn interventions(&self) -> Vec<(u32, Intervention)> {
        let mut out: Vec<(u32, Intervention)> = self
            .interventions
            .iter()
            .map(|(&pid, &iv)| (pid, iv))
            .collect();
        out.sort_by_key(|(pid, _)| *pid);
        out
    }

    /// Compute the next level from the current level + a fresh sample, applying
    /// rise/fall hysteresis. The fall threshold is half the rise threshold, and
    /// we only ever *step down* when below the fall threshold, so a sample that
    /// sits between fall and rise leaves the level unchanged (no flapping).
    fn next_level(&self, s: Sample) -> Level {
        let t = &self.cfg.trigger;
        let floor = t.mem_available_floor_mb;

        // Rise predicates (cross the upper threshold to enter a level).
        let warn_rise = s.some_avg10 >= t.psi_some_warn;
        let high_rise = s.some_avg10 >= t.psi_some_high || s.full_avg10 >= FULL_HIGH_RISE;
        let crit_rise = s.full_avg10 >= t.psi_full_critical || s.mem_available_mb < floor;

        // Stay predicates (above the lower/fall threshold — keep the level).
        let warn_stay = s.some_avg10 >= t.psi_some_warn / 2.0;
        let high_stay =
            s.some_avg10 >= t.psi_some_high / 2.0 || s.full_avg10 >= FULL_HIGH_RISE / 2.0;
        let crit_stay = s.full_avg10 >= t.psi_full_critical / 2.0 || s.mem_available_mb < floor;

        // Highest level we're allowed to be at, given current level + hysteresis.
        // For each tier: enter if its rise fires; otherwise remain if we're
        // already at/above it and its stay predicate still holds.
        let at_critical = self.level == Level::Critical;
        let at_high = matches!(self.level, Level::High | Level::Critical);
        let at_warn = matches!(self.level, Level::Warn | Level::High | Level::Critical);

        if crit_rise || (at_critical && crit_stay) {
            Level::Critical
        } else if high_rise || (at_high && high_stay) {
            Level::High
        } else if warn_rise || (at_warn && warn_stay) {
            Level::Warn
        } else {
            Level::Calm
        }
    }

    /// Pick the eligible victim: the largest-RSS process that is above the
    /// min-RSS floor and not already under an intervention. Protect-list and
    /// uid filtering happen upstream in the Sampler, so anything here is fair game.
    fn select_victim<'a>(
        &self,
        procs: &'a [ProcInfo],
        thawed_now: &std::collections::HashSet<u32>,
    ) -> Option<&'a ProcInfo> {
        let min_rss_kb = self.cfg.selection.min_rss_mb * 1024;
        procs
            .iter()
            .filter(|p| {
                p.rss_kb >= min_rss_kb
                    && !self.interventions.contains_key(&p.pid)
                    && !thawed_now.contains(&p.pid)
            })
            .max_by_key(|p| p.rss_kb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default config = the documented zero-config defaults.
    fn cfg() -> GuardConfig {
        GuardConfig::default()
    }

    fn sample(some: f64, full: f64, avail_mb: u64) -> Sample {
        Sample {
            some_avg10: some,
            full_avg10: full,
            mem_available_mb: avail_mb,
        }
    }

    fn proc(pid: u32, name: &str, rss_mb: u64) -> ProcInfo {
        ProcInfo {
            pid,
            name: name.to_string(),
            rss_kb: rss_mb * 1024,
        }
    }

    /// A comfortably-calm sample (no pressure, lots of memory).
    fn calm() -> Sample {
        sample(0.0, 0.0, 8000)
    }

    /// A clearly-High sample (well above psi_some_high=30, below critical).
    fn high() -> Sample {
        sample(50.0, 0.0, 8000)
    }

    fn freeze_pids(actions: &[Action]) -> Vec<u32> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Freeze { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect()
    }

    fn has_cap(actions: &[Action], pid: u32) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::Cap { pid: p, .. } if *p == pid))
    }

    fn has_thaw(actions: &[Action], pid: u32) -> bool {
        actions.iter().any(|a| matches!(a, Action::Thaw { pid: p } if *p == pid))
    }

    fn has_liftcap(actions: &[Action], pid: u32) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::LiftCap { pid: p } if *p == pid))
    }

    #[test]
    fn calm_yields_no_actions() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(100, "firefox", 2000)];
        let actions = e.tick(1000, calm(), &procs);
        assert!(actions.is_empty(), "calm produced actions: {actions:?}");
        assert_eq!(e.level, Level::Calm);
    }

    #[test]
    fn full_signal_has_fall_hysteresis() {
        // Enter High purely via PSI `full` (some stays low): full=4.0 >= FULL_HIGH_RISE(3.0).
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(100, "firefox", 4000)];
        e.tick(1_000, sample(0.0, 4.0, 8000), &procs);
        assert_eq!(e.level, Level::High, "full=4.0 should enter High");

        // full drifts to 2.0 — between the fall (1.5) and rise (3.0) thresholds.
        // With hysteresis it must HOLD High, not flap back to Calm.
        e.tick(2_000, sample(0.0, 2.0, 8000), &procs);
        assert_eq!(
            e.level,
            Level::High,
            "full=2.0 (between fall and rise) must hold High, not flap"
        );

        // full drops below the fall threshold (1.0 < 1.5): now it may step down.
        e.tick(3_000, sample(0.0, 1.0, 8000), &procs);
        assert_eq!(e.level, Level::Calm, "full below fall threshold drops to Calm");
    }

    #[test]
    fn disabled_engine_is_inert() {
        let mut c = cfg();
        c.enabled = false;
        let mut e = PolicyEngine::new(c);
        let procs = vec![proc(100, "firefox", 4000)];
        assert!(e.tick(1000, high(), &procs).is_empty());
    }

    #[test]
    fn high_freezes_largest_eligible_process() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![
            proc(1, "small", 300),
            proc(2, "biggest", 4000),
            proc(3, "medium", 1000),
        ];
        let actions = e.tick(1000, high(), &procs);
        // Only the single largest hog is frozen, not the smaller ones.
        assert_eq!(freeze_pids(&actions), vec![2]);
        assert_eq!(e.level, Level::High);
    }

    #[test]
    fn process_below_min_rss_is_never_selected() {
        let mut e = PolicyEngine::new(cfg());
        // Both below the 200 MB default floor.
        let procs = vec![proc(1, "tiny", 50), proc(2, "small", 150)];
        let actions = e.tick(1000, high(), &procs);
        assert!(
            freeze_pids(&actions).is_empty(),
            "froze a sub-min-rss process: {actions:?}"
        );
    }

    #[test]
    fn frozen_process_thaws_after_freeze_hold() {
        let mut e = PolicyEngine::new(cfg()); // freeze_hold = 5s
        let procs = vec![proc(2, "hog", 4000)];

        let a0 = e.tick(0, high(), &procs);
        assert_eq!(freeze_pids(&a0), vec![2]);

        // Before the hold elapses: no thaw yet (and escalation gate keeps it quiet).
        let a1 = e.tick(4_000, high(), &procs);
        assert!(!has_thaw(&a1, 2), "thawed too early: {a1:?}");

        // At/after 5s the freeze auto-thaws.
        let a2 = e.tick(5_000, high(), &procs);
        assert!(has_thaw(&a2, 2), "expected thaw at hold: {a2:?}");
        assert!(e.interventions().is_empty());
    }

    #[test]
    fn still_high_within_cooldown_caps_instead_of_refreezing() {
        let mut e = PolicyEngine::new(cfg()); // hold=5s, cooldown=60s
        let procs = vec![proc(2, "hog", 4000)];

        // Freeze at t=0.
        assert_eq!(freeze_pids(&e.tick(0, high(), &procs)), vec![2]);
        // Auto-thaw at t=5s.
        assert!(has_thaw(&e.tick(5_000, high(), &procs), 2));

        // Still high, and within the 60s freeze cooldown -> Cap, not re-Freeze.
        // t must clear the escalation gate (>= last_action 5000 + 5000 hold).
        let a = e.tick(10_000, high(), &procs);
        assert!(has_cap(&a, 2), "expected cap within cooldown: {a:?}");
        assert!(freeze_pids(&a).is_empty(), "should not re-freeze: {a:?}");
        assert!(matches!(
            e.interventions().as_slice(),
            [(2, Intervention::Capped { .. })]
        ));
    }

    #[test]
    fn hysteresis_holds_level_between_fall_and_rise() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];

        // Rise to High.
        e.tick(0, high(), &procs);
        assert_eq!(e.level, Level::High);

        // some=20 is below rise(30) but above fall(15): stay High, no lift.
        let a = e.tick(20_000, sample(20.0, 0.0, 8000), &procs);
        assert_eq!(e.level, Level::High, "dropped out of High prematurely");
        // A thaw here is expected (the freeze hold elapsed), but the cap must not
        // be lifted while we're still High.
        assert!(!has_liftcap(&a, 2), "should not lift while still High: {a:?}");

        // Drop below the fall threshold (some < 15 and full < 3): fall to Warn.
        e.tick(21_000, sample(12.0, 0.0, 8000), &procs);
        assert_eq!(e.level, Level::Warn);
    }

    #[test]
    fn capped_process_lifted_only_after_sustained_calm() {
        let mut e = PolicyEngine::new(cfg()); // calm_hold = 30s
        let procs = vec![proc(2, "hog", 4000)];

        // Drive a freeze, thaw, then a cap (still hot within cooldown).
        e.tick(0, high(), &procs);
        e.tick(5_000, high(), &procs); // thaw
        let a = e.tick(10_000, high(), &procs); // cap
        assert!(has_cap(&a, 2));

        // Calm starts at t=15s. Before 30s of calm: no lift.
        let a1 = e.tick(15_000, calm(), &procs);
        assert!(!has_liftcap(&a1, 2), "lifted before calm sustained: {a1:?}");
        let a2 = e.tick(44_000, calm(), &procs); // 29s of calm
        assert!(!has_liftcap(&a2, 2), "lifted just before hold: {a2:?}");

        // 30s of sustained calm -> lift the cap.
        let a3 = e.tick(45_000, calm(), &procs);
        assert!(has_liftcap(&a3, 2), "expected lift after calm hold: {a3:?}");
        assert!(e.interventions().is_empty());
    }

    #[test]
    fn cap_lift_resets_if_calm_is_interrupted() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        e.tick(0, high(), &procs);
        e.tick(5_000, high(), &procs);
        assert!(has_cap(&e.tick(10_000, high(), &procs), 2));

        e.tick(15_000, calm(), &procs); // calm clock starts
        e.tick(20_000, high(), &procs); // pressure returns -> calm clock cleared
        // New calm window starts at 25s; at 50s only 25s have passed -> no lift.
        e.tick(25_000, calm(), &procs);
        let a = e.tick(50_000, calm(), &procs);
        assert!(!has_liftcap(&a, 2), "calm clock should have reset: {a:?}");
    }

    #[test]
    fn escalation_gate_limits_to_one_freeze_per_hold_window() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(1, "hog-a", 4000), proc(2, "hog-b", 3000)];

        // First High tick freezes hog-a.
        let a0 = e.tick(0, high(), &procs);
        assert_eq!(freeze_pids(&a0), vec![1]);

        // Second High tick within the 5s hold: gate closed, no new freeze.
        let a1 = e.tick(2_000, high(), &procs);
        assert!(
            freeze_pids(&a1).is_empty(),
            "gate should suppress second freeze: {a1:?}"
        );

        // After the gate reopens, the next hog can be frozen.
        let a2 = e.tick(5_000, high(), &procs);
        assert_eq!(freeze_pids(&a2), vec![2]);
    }

    #[test]
    fn dead_pid_is_pruned_with_liftcap() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];

        // Freeze pid 2.
        assert_eq!(freeze_pids(&e.tick(0, high(), &procs)), vec![2]);
        assert_eq!(e.interventions().len(), 1);

        // Next tick pid 2 has vanished -> LiftCap cleanup, intervention dropped.
        let a = e.tick(1_000, calm(), &[]);
        assert!(has_liftcap(&a, 2), "expected LiftCap for dead pid: {a:?}");
        assert!(e.interventions().is_empty());
    }

    #[test]
    fn interventions_reflect_state_sorted_by_pid() {
        let mut e = PolicyEngine::new(cfg());
        // pid 5 is the larger hog; pid 3 the smaller. We build a Capped pid 5
        // and a Frozen pid 3 that coexist, then check ordering + content.
        let procs = vec![proc(5, "a", 4000), proc(3, "b", 3500)];

        // Walk both pids down the freeze -> thaw -> (still hot) cap ladder so two
        // Capped interventions coexist. Caps persist while High (never auto-thaw),
        // which is what lets two interventions overlap under default timing.
        assert_eq!(freeze_pids(&e.tick(0, high(), &procs)), vec![5]); // freeze pid5
        let a1 = e.tick(5_000, high(), &procs); // thaw pid5, freeze pid3
        assert!(has_thaw(&a1, 5));
        assert_eq!(freeze_pids(&a1), vec![3]);
        let a2 = e.tick(10_000, high(), &procs); // thaw pid3, cap pid5 (in cooldown)
        assert!(has_thaw(&a2, 3));
        assert!(has_cap(&a2, 5));
        let a3 = e.tick(15_000, high(), &procs); // cap pid3 (in cooldown)
        assert!(has_cap(&a3, 3));

        let ivs = e.interventions();
        assert_eq!(ivs.len(), 2, "expected pid3 + pid5 both Capped: {ivs:?}");
        // Sorted ascending by pid.
        assert_eq!(ivs[0].0, 3);
        assert_eq!(ivs[1].0, 5);
        assert!(ivs
            .iter()
            .all(|(_, iv)| matches!(iv, Intervention::Capped { .. })));
    }

    #[test]
    fn critical_via_mem_floor_triggers_action() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        // No PSI pressure, but MemAvailable below the 400 MB floor -> Critical.
        let a = e.tick(0, sample(0.0, 0.0, 100), &procs);
        assert_eq!(e.level, Level::Critical);
        assert_eq!(freeze_pids(&a), vec![2]);
    }

    #[test]
    fn notify_emitted_and_rate_limited() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];

        // Warn level: some>=10 but below high; just notify, no freeze.
        let a0 = e.tick(0, sample(12.0, 0.0, 8000), &procs);
        assert!(
            a0.iter().any(|x| matches!(x, Action::Notify { .. })),
            "expected a notify at Warn: {a0:?}"
        );
        assert!(freeze_pids(&a0).is_empty());

        // Within 60s: no second notify.
        let a1 = e.tick(30_000, sample(12.0, 0.0, 8000), &procs);
        assert!(
            !a1.iter().any(|x| matches!(x, Action::Notify { .. })),
            "notify should be rate-limited: {a1:?}"
        );

        // After 60s: notify again.
        let a2 = e.tick(60_000, sample(12.0, 0.0, 8000), &procs);
        assert!(a2.iter().any(|x| matches!(x, Action::Notify { .. })));
    }

    #[test]
    fn notify_disabled_suppresses_notifications() {
        let mut c = cfg();
        c.notify = false;
        let mut e = PolicyEngine::new(c);
        let procs = vec![proc(2, "hog", 4000)];
        let a = e.tick(0, sample(12.0, 0.0, 8000), &procs);
        assert!(!a.iter().any(|x| matches!(x, Action::Notify { .. })));
    }
}
