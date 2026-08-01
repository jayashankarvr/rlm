//! Pure policy state machine — the self-healing circuit breaker at the heart of
//! the freeze guard.
//!
//! Contract: [`PolicyEngine::tick`] is pure given `(now_ms, sample, procs,
//! live_cgroups)` plus the engine's own internal state. It performs **no**
//! syscalls and reads **no** clock — `now_ms` (monotonic milliseconds) is
//! injected by the caller. That is what makes the whole escalation/recovery
//! ladder unit-testable without root.

use std::collections::HashMap;

use super::resolve::{Coverage, Resolution, Verdict};
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
    /// Active interventions keyed by resolved cgroup path. The [`Resolution`]
    /// is retained alongside the intervention so recovery/prune actions
    /// (`Thaw`/`LiftCap`) can be built without re-resolving.
    interventions: HashMap<String, (Intervention, Resolution)>,
    /// Last time each cgroup was frozen — drives the per-cgroup freeze
    /// cooldown that decides freeze-vs-cap, and is intentionally kept after a
    /// thaw.
    last_freeze_ms: HashMap<String, u64>,
    /// When the level last became `Calm` (None while not calm). Gates cap lifts.
    calm_since_ms: Option<u64>,
    /// When we last emitted a new freeze/cap — the global escalation gate.
    /// `None` means "never acted", so the gate is open on the first action.
    last_action_ms: Option<u64>,
    /// Whether the most recent escalation action acted under
    /// `Coverage::Partial`. When true, the escalation gate is reopened
    /// immediately on the next tick instead of waiting a full freeze-hold —
    /// partial coverage means the intervention didn't fully contain the hog,
    /// so we must be able to re-assess right away.
    last_action_partial: bool,
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
            last_action_partial: false,
            last_notify_ms: None,
        }
    }

    /// Advance the state machine one tick and return the actions to apply.
    ///
    /// `live_cgroups` is the set of cgroups the Sampler currently resolves
    /// for *any* of the user's real processes, with no min-RSS or protect
    /// filtering applied (see `Sampler::live_cgroups`) — it is deliberately
    /// a superset of `procs`' own resolutions. Pruning (step 3) checks
    /// liveness against this set, not against `procs`: a successful `Cap`
    /// sizes off anon+swap but `memory.high` also bounds file-backed pages,
    /// so capping a mapped-file-heavy process can push its `rss_kb` below
    /// the min-RSS floor on the very next tick, dropping it out of `procs`
    /// even though the cgroup is very much still alive. Pruning against
    /// `procs` there would lift the cap while pressure is still Critical and
    /// immediately re-trigger it — a ~5s cap/lift/re-cap oscillation. Victim
    /// *selection* (step 5) deliberately keeps using the filtered `procs`.
    pub fn tick(
        &mut self,
        now_ms: u64,
        sample: Sample,
        procs: &[ProcInfo],
        live_cgroups: &std::collections::HashSet<String>,
    ) -> Vec<Action> {
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

        // 3. Prune interventions whose cgroup is no longer live (see
        //    `live_cgroups` doc above). LiftCap doubles as "tear down the
        //    cap", so it's the right cleanup for both frozen and capped dead
        //    cgroups; the effector's LiftCap tolerates a missing cgroup.
        let dead: Vec<String> = self
            .interventions
            .keys()
            .filter(|cg| !live_cgroups.contains(cg.as_str()))
            .cloned()
            .collect();
        for cg in dead {
            let (_, res) = self.interventions.remove(&cg).expect("just found key");
            actions.push(Action::LiftCap { res });
        }

        // 4. Recover: auto-thaw held freezes, and lift caps once calm has held.
        let freeze_hold_ms = self.cfg.timing.freeze_hold_secs * 1000;
        let calm_hold_ms = self.cfg.timing.calm_hold_secs * 1000;
        let mut recovered = Vec::new();
        // Cgroups thawed on this tick must not be re-targeted by escalation in
        // the same tick — they need a re-measure first.
        let mut thawed_now: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (cg, (intervention, res)) in &self.interventions {
            match *intervention {
                Intervention::Frozen { since_ms } => {
                    if now_ms.saturating_sub(since_ms) >= freeze_hold_ms {
                        actions.push(Action::Thaw { res: res.clone() });
                        recovered.push(cg.clone());
                        thawed_now.insert(cg.clone());
                    }
                }
                Intervention::Capped { .. } => {
                    // Only lift a cap when pressure is calm *and* has stayed calm
                    // long enough — prevents re-capping churn. `calm_since_ms` is
                    // the transition timestamp, so this measures *sustained* calm.
                    if self.level == Level::Calm {
                        if let Some(calm_since) = self.calm_since_ms {
                            if now_ms.saturating_sub(calm_since) >= calm_hold_ms {
                                actions.push(Action::LiftCap { res: res.clone() });
                                recovered.push(cg.clone());
                            }
                        }
                    }
                }
            }
        }
        for cg in recovered {
            // Note: last_freeze_ms is intentionally retained for cooldown logic.
            self.interventions.remove(&cg);
        }

        // 5. Escalate, but only when pressure actually warrants action.
        let mut victim_name: Option<String> = None;
        if matches!(self.level, Level::High | Level::Critical) {
            // Global gate: after acting on one hog, wait a freeze-hold before
            // acting again so we re-measure instead of cascading freezes —
            // *unless* the last action only achieved partial coverage (a
            // protected process shared the cgroup), in which case the gate
            // reopens immediately so we can re-assess right away.
            let gate_ms = if self.last_action_partial {
                0
            } else {
                freeze_hold_ms
            };
            let gate_open = match self.last_action_ms {
                None => true,
                Some(last) => now_ms.saturating_sub(last) >= gate_ms,
            };
            if gate_open {
                if let Some(victim) = self.select_victim(procs, &thawed_now) {
                    let res = victim
                        .resolution
                        .clone()
                        .expect("select_victim only returns resolved procs");

                    if res.verdict == Verdict::CapOnly {
                        // CapOnly verdicts never freeze, regardless of cooldown.
                        actions.push(Action::Cap {
                            res: res.clone(),
                            name: victim.name.clone(),
                        });
                        self.interventions.insert(
                            res.cgroup.clone(),
                            (Intervention::Capped { since_ms: now_ms }, res.clone()),
                        );
                    } else {
                        let cooldown_ms = self.cfg.timing.freeze_cooldown_secs * 1000;
                        let in_cooldown = self
                            .last_freeze_ms
                            .get(&res.cgroup)
                            .is_some_and(|&last| now_ms.saturating_sub(last) < cooldown_ms);

                        if in_cooldown {
                            // Recently frozen and still hot -> escalate to a soft cap.
                            actions.push(Action::Cap {
                                res: res.clone(),
                                name: victim.name.clone(),
                            });
                            self.interventions.insert(
                                res.cgroup.clone(),
                                (Intervention::Capped { since_ms: now_ms }, res.clone()),
                            );
                        } else {
                            actions.push(Action::Freeze {
                                res: res.clone(),
                                name: victim.name.clone(),
                            });
                            self.interventions.insert(
                                res.cgroup.clone(),
                                (Intervention::Frozen { since_ms: now_ms }, res.clone()),
                            );
                            self.last_freeze_ms.insert(res.cgroup.clone(), now_ms);
                        }
                    }
                    self.last_action_ms = Some(now_ms);
                    self.last_action_partial = res.coverage == Coverage::Partial;
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

    /// Currently active interventions (cgroup path -> intervention), sorted by
    /// cgroup path so callers get a deterministic order.
    pub fn interventions(&self) -> Vec<(String, Intervention)> {
        let mut out: Vec<(String, Intervention)> = self
            .interventions
            .iter()
            .map(|(cg, (iv, _res))| (cg.clone(), *iv))
            .collect();
        out.sort_by(|(a, _), (b, _)| a.cmp(b));
        out
    }

    /// Cgroup paths the engine currently holds an intervention on — frozen
    /// *or* capped. Interventions are already keyed by cgroup, so this is
    /// just the key set. For external callers (e.g.
    /// `RulesEnforcer::reconcile`, D1) that must not fight/revert an active
    /// guard action: rewriting `memory.high` on a cgroup the engine just
    /// capped would silently no-op the cap and leave `PolicyEngine` holding
    /// a stale `Capped` intervention that then blocks victim re-selection
    /// for the rest of the pressure episode.
    pub fn intervened_cgroups(&self) -> Vec<String> {
        self.interventions.keys().cloned().collect()
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
    /// min-RSS floor, actionable (resolved to a cgroup), and whose resolved
    /// cgroup is not already under an intervention or just thawed this tick.
    /// Protect-list and uid filtering happen upstream in the Sampler, so
    /// anything resolved here is fair game. Two processes that resolve to the
    /// same cgroup (e.g. a browser main process and its sandboxed children)
    /// are naturally deduplicated: only one victim — and hence one action — is
    /// produced per tick.
    fn select_victim<'a>(
        &self,
        procs: &'a [ProcInfo],
        thawed_now: &std::collections::HashSet<String>,
    ) -> Option<&'a ProcInfo> {
        let min_rss_kb = self.cfg.selection.min_rss_mb * 1024;
        procs
            .iter()
            .filter(|p| {
                let Some(res) = p.resolution.as_ref() else {
                    return false;
                };
                p.rss_kb >= min_rss_kb
                    && !self.interventions.contains_key(&res.cgroup)
                    && !thawed_now.contains(&res.cgroup)
            })
            .max_by_key(|p| p.rss_kb)
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolve::Mechanism;
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

    /// Build a default (unprotected, full-coverage) resolution for `cg`.
    fn res(cg: &str) -> Resolution {
        Resolution {
            cgroup: cg.into(),
            unit: Some(format!("{}.scope", cg.rsplit('/').next().unwrap())),
            verdict: Verdict::Freeze,
            coverage: Coverage::Full,
            mechanism: Mechanism::Unit,
        }
    }

    /// Build a `ProcInfo` resolved to `cg`. Distinct pids should be given
    /// distinct scopes (the convention below is `/app.slice/app-<name>-<pid>.scope`)
    /// so they remain independent victims under the engine's cgroup-keyed state.
    fn proc_at(pid: u32, name: &str, rss_mb: u64, cg: &str) -> ProcInfo {
        ProcInfo {
            pid,
            name: name.into(),
            rss_kb: rss_mb * 1024,
            resolution: Some(res(cg)),
        }
    }

    /// Shorthand: build a resolved `ProcInfo` whose cgroup is derived from
    /// `name`/`pid` (`/app.slice/app-<name>-<pid>.scope`), matching how the
    /// existing (migrated) tests keep one process == one distinct cgroup.
    fn proc(pid: u32, name: &str, rss_mb: u64) -> ProcInfo {
        proc_at(
            pid,
            name,
            rss_mb,
            &format!("/app.slice/app-{name}-{pid}.scope"),
        )
    }

    /// A comfortably-calm sample (no pressure, lots of memory).
    fn calm() -> Sample {
        sample(0.0, 0.0, 8000)
    }

    /// A clearly-High sample (well above psi_some_high=30, below critical).
    fn high() -> Sample {
        sample(50.0, 0.0, 8000)
    }

    fn freeze_targets(actions: &[Action]) -> Vec<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Freeze { res, .. } => Some(res.cgroup.clone()),
                _ => None,
            })
            .collect()
    }

    fn has_cap_target(actions: &[Action], cg: &str) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::Cap { res, .. } if res.cgroup == cg))
    }

    fn has_freeze_target(actions: &[Action], cg: &str) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::Freeze { res, .. } if res.cgroup == cg))
    }

    fn has_thaw_target(actions: &[Action], cg: &str) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::Thaw { res } if res.cgroup == cg))
    }

    fn has_liftcap_target(actions: &[Action], cg: &str) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::LiftCap { res } if res.cgroup == cg))
    }

    /// Default `live_cgroups` for tests that aren't specifically exercising
    /// the D2 liveness-vs-eligibility distinction: derive it straight from
    /// `procs`, which reproduces the old (pre-fix) behavior where liveness
    /// was just cgroup membership in the eligible set.
    fn live_from(procs: &[ProcInfo]) -> std::collections::HashSet<String> {
        procs
            .iter()
            .filter_map(|p| p.resolution.as_ref().map(|r| r.cgroup.clone()))
            .collect()
    }

    #[test]
    fn calm_yields_no_actions() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(100, "firefox", 2000)];
        let actions = e.tick(1000, calm(), &procs, &live_from(&procs));
        assert!(actions.is_empty(), "calm produced actions: {actions:?}");
        assert_eq!(e.level, Level::Calm);
    }

    #[test]
    fn full_signal_has_fall_hysteresis() {
        // Enter High purely via PSI `full` (some stays low): full=4.0 >= FULL_HIGH_RISE(3.0).
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(100, "firefox", 4000)];
        e.tick(1_000, sample(0.0, 4.0, 8000), &procs, &live_from(&procs));
        assert_eq!(e.level, Level::High, "full=4.0 should enter High");

        // full drifts to 2.0 — between the fall (1.5) and rise (3.0) thresholds.
        // With hysteresis it must HOLD High, not flap back to Calm.
        e.tick(2_000, sample(0.0, 2.0, 8000), &procs, &live_from(&procs));
        assert_eq!(
            e.level,
            Level::High,
            "full=2.0 (between fall and rise) must hold High, not flap"
        );

        // full drops below the fall threshold (1.0 < 1.5): now it may step down.
        e.tick(3_000, sample(0.0, 1.0, 8000), &procs, &live_from(&procs));
        assert_eq!(
            e.level,
            Level::Calm,
            "full below fall threshold drops to Calm"
        );
    }

    #[test]
    fn disabled_engine_is_inert() {
        let mut c = cfg();
        c.enabled = false;
        let mut e = PolicyEngine::new(c);
        let procs = vec![proc(100, "firefox", 4000)];
        assert!(e.tick(1000, high(), &procs, &live_from(&procs)).is_empty());
    }

    #[test]
    fn high_freezes_largest_eligible_process() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![
            proc(1, "small", 300),
            proc(2, "biggest", 4000),
            proc(3, "medium", 1000),
        ];
        let actions = e.tick(1000, high(), &procs, &live_from(&procs));
        // Only the single largest hog is frozen, not the smaller ones.
        assert_eq!(
            freeze_targets(&actions),
            vec!["/app.slice/app-biggest-2.scope"]
        );
        assert_eq!(e.level, Level::High);
    }

    #[test]
    fn process_below_min_rss_is_never_selected() {
        let mut e = PolicyEngine::new(cfg());
        // Both below the 200 MB default floor.
        let procs = vec![proc(1, "tiny", 50), proc(2, "small", 150)];
        let actions = e.tick(1000, high(), &procs, &live_from(&procs));
        assert!(
            freeze_targets(&actions).is_empty(),
            "froze a sub-min-rss process: {actions:?}"
        );
    }

    #[test]
    fn frozen_process_thaws_after_freeze_hold() {
        let mut e = PolicyEngine::new(cfg()); // freeze_hold = 5s
        let procs = vec![proc(2, "hog", 4000)];
        let cg = "/app.slice/app-hog-2.scope";

        let a0 = e.tick(0, high(), &procs, &live_from(&procs));
        assert_eq!(freeze_targets(&a0), vec![cg]);

        // Before the hold elapses: no thaw yet (and escalation gate keeps it quiet).
        let a1 = e.tick(4_000, high(), &procs, &live_from(&procs));
        assert!(!has_thaw_target(&a1, cg), "thawed too early: {a1:?}");

        // At/after 5s the freeze auto-thaws.
        let a2 = e.tick(5_000, high(), &procs, &live_from(&procs));
        assert!(has_thaw_target(&a2, cg), "expected thaw at hold: {a2:?}");
        assert!(e.interventions().is_empty());
    }

    #[test]
    fn still_high_within_cooldown_caps_instead_of_refreezing() {
        let mut e = PolicyEngine::new(cfg()); // hold=5s, cooldown=60s
        let procs = vec![proc(2, "hog", 4000)];
        let cg = "/app.slice/app-hog-2.scope";

        // Freeze at t=0.
        assert_eq!(
            freeze_targets(&e.tick(0, high(), &procs, &live_from(&procs))),
            vec![cg]
        );
        // Auto-thaw at t=5s.
        assert!(has_thaw_target(
            &e.tick(5_000, high(), &procs, &live_from(&procs)),
            cg
        ));

        // Still high, and within the 60s freeze cooldown -> Cap, not re-Freeze.
        // t must clear the escalation gate (>= last_action 5000 + 5000 hold).
        let a = e.tick(10_000, high(), &procs, &live_from(&procs));
        assert!(
            has_cap_target(&a, cg),
            "expected cap within cooldown: {a:?}"
        );
        assert!(freeze_targets(&a).is_empty(), "should not re-freeze: {a:?}");
        assert!(matches!(
            e.interventions().as_slice(),
            [(c, Intervention::Capped { .. })] if c == cg
        ));
    }

    #[test]
    fn hysteresis_holds_level_between_fall_and_rise() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        let cg = "/app.slice/app-hog-2.scope";

        // Rise to High.
        e.tick(0, high(), &procs, &live_from(&procs));
        assert_eq!(e.level, Level::High);

        // some=20 is below rise(30) but above fall(15): stay High, no lift.
        let a = e.tick(20_000, sample(20.0, 0.0, 8000), &procs, &live_from(&procs));
        assert_eq!(e.level, Level::High, "dropped out of High prematurely");
        // A thaw here is expected (the freeze hold elapsed), but the cap must not
        // be lifted while we're still High.
        assert!(
            !has_liftcap_target(&a, cg),
            "should not lift while still High: {a:?}"
        );

        // Drop below the fall threshold (some < 15 and full < 3): fall to Warn.
        e.tick(21_000, sample(12.0, 0.0, 8000), &procs, &live_from(&procs));
        assert_eq!(e.level, Level::Warn);
    }

    #[test]
    fn capped_process_lifted_only_after_sustained_calm() {
        let mut e = PolicyEngine::new(cfg()); // calm_hold = 30s
        let procs = vec![proc(2, "hog", 4000)];
        let cg = "/app.slice/app-hog-2.scope";

        // Drive a freeze, thaw, then a cap (still hot within cooldown).
        e.tick(0, high(), &procs, &live_from(&procs));
        e.tick(5_000, high(), &procs, &live_from(&procs)); // thaw
        let a = e.tick(10_000, high(), &procs, &live_from(&procs)); // cap
        assert!(has_cap_target(&a, cg));

        // Calm starts at t=15s. Before 30s of calm: no lift.
        let a1 = e.tick(15_000, calm(), &procs, &live_from(&procs));
        assert!(
            !has_liftcap_target(&a1, cg),
            "lifted before calm sustained: {a1:?}"
        );
        let a2 = e.tick(44_000, calm(), &procs, &live_from(&procs)); // 29s of calm
        assert!(
            !has_liftcap_target(&a2, cg),
            "lifted just before hold: {a2:?}"
        );

        // 30s of sustained calm -> lift the cap.
        let a3 = e.tick(45_000, calm(), &procs, &live_from(&procs));
        assert!(
            has_liftcap_target(&a3, cg),
            "expected lift after calm hold: {a3:?}"
        );
        assert!(e.interventions().is_empty());
    }

    #[test]
    fn cap_lift_resets_if_calm_is_interrupted() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        let cg = "/app.slice/app-hog-2.scope";
        e.tick(0, high(), &procs, &live_from(&procs));
        e.tick(5_000, high(), &procs, &live_from(&procs));
        assert!(has_cap_target(
            &e.tick(10_000, high(), &procs, &live_from(&procs)),
            cg
        ));

        e.tick(15_000, calm(), &procs, &live_from(&procs)); // calm clock starts
        e.tick(20_000, high(), &procs, &live_from(&procs)); // pressure returns -> calm clock cleared
                                                            // New calm window starts at 25s; at 50s only 25s have passed -> no lift.
        e.tick(25_000, calm(), &procs, &live_from(&procs));
        let a = e.tick(50_000, calm(), &procs, &live_from(&procs));
        assert!(
            !has_liftcap_target(&a, cg),
            "calm clock should have reset: {a:?}"
        );
    }

    #[test]
    fn escalation_gate_limits_to_one_freeze_per_hold_window() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(1, "hog-a", 4000), proc(2, "hog-b", 3000)];
        let cg_a = "/app.slice/app-hog-a-1.scope";
        let cg_b = "/app.slice/app-hog-b-2.scope";

        // First High tick freezes hog-a.
        let a0 = e.tick(0, high(), &procs, &live_from(&procs));
        assert_eq!(freeze_targets(&a0), vec![cg_a]);

        // Second High tick within the 5s hold: gate closed, no new freeze.
        let a1 = e.tick(2_000, high(), &procs, &live_from(&procs));
        assert!(
            freeze_targets(&a1).is_empty(),
            "gate should suppress second freeze: {a1:?}"
        );

        // After the gate reopens, the next hog can be frozen.
        let a2 = e.tick(5_000, high(), &procs, &live_from(&procs));
        assert_eq!(freeze_targets(&a2), vec![cg_b]);
    }

    #[test]
    fn dead_pid_is_pruned_with_liftcap() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        let cg = "/app.slice/app-hog-2.scope";

        // Freeze the hog's cgroup.
        assert_eq!(
            freeze_targets(&e.tick(0, high(), &procs, &live_from(&procs))),
            vec![cg]
        );
        assert_eq!(e.interventions().len(), 1);

        // Next tick the process (and its resolution) has vanished -> LiftCap
        // cleanup, intervention dropped.
        let a = e.tick(1_000, calm(), &[], &live_from(&[]));
        assert!(
            has_liftcap_target(&a, cg),
            "expected LiftCap for dead cgroup: {a:?}"
        );
        assert!(e.interventions().is_empty());
    }

    /// D2 regression: a cgroup absent from `procs` (e.g. the cap evicted
    /// enough file pages to drop the process below `min_rss_mb`) but still
    /// present in `live_cgroups` must NOT be pruned — the cgroup is real and
    /// alive, just not currently eligible for (re-)selection. A cgroup
    /// absent from *both* sets must still be pruned with a LiftCap.
    #[test]
    fn intervention_survives_in_live_cgroups_but_absent_from_procs() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        let cg = "/app.slice/app-hog-2.scope";

        // Freeze the hog's cgroup.
        assert_eq!(
            freeze_targets(&e.tick(0, high(), &procs, &live_from(&procs))),
            vec![cg]
        );
        assert_eq!(e.interventions().len(), 1);

        // Next tick: the process no longer appears in `procs` (as if the cap
        // evicted its file pages below the min-RSS floor), but its cgroup is
        // still in `live_cgroups` — must NOT be pruned.
        let live: std::collections::HashSet<String> = [cg.to_string()].into();
        let a1 = e.tick(1_000, calm(), &[], &live);
        assert!(
            !has_liftcap_target(&a1, cg),
            "must not prune a cgroup still present in live_cgroups: {a1:?}"
        );
        assert_eq!(
            e.interventions().len(),
            1,
            "intervention must survive while the cgroup is live"
        );

        // Now the cgroup is gone from both sets entirely -> pruned.
        let a2 = e.tick(2_000, calm(), &[], &std::collections::HashSet::new());
        assert!(
            has_liftcap_target(&a2, cg),
            "expected LiftCap once absent from live_cgroups too: {a2:?}"
        );
        assert!(e.interventions().is_empty());
    }

    #[test]
    fn interventions_reflect_state_sorted_by_cgroup() {
        let mut e = PolicyEngine::new(cfg());
        // pid 5 ("a") is the larger hog; pid 3 ("b") the smaller. We build a
        // Capped "a" and a Frozen->Capped "b" that coexist, then check
        // ordering + content. "/app.slice/app-a-5.scope" sorts before
        // "/app.slice/app-b-3.scope" lexicographically.
        let procs = vec![proc(5, "a", 4000), proc(3, "b", 3500)];
        let cg_a = "/app.slice/app-a-5.scope";
        let cg_b = "/app.slice/app-b-3.scope";

        // Walk both cgroups down the freeze -> thaw -> (still hot) cap ladder
        // so two Capped interventions coexist. Caps persist while High (never
        // auto-thaw), which is what lets two interventions overlap under
        // default timing.
        assert_eq!(
            freeze_targets(&e.tick(0, high(), &procs, &live_from(&procs))),
            vec![cg_a]
        ); // freeze a
        let a1 = e.tick(5_000, high(), &procs, &live_from(&procs)); // thaw a, freeze b
        assert!(has_thaw_target(&a1, cg_a));
        assert_eq!(freeze_targets(&a1), vec![cg_b]);
        let a2 = e.tick(10_000, high(), &procs, &live_from(&procs)); // thaw b, cap a (in cooldown)
        assert!(has_thaw_target(&a2, cg_b));
        assert!(has_cap_target(&a2, cg_a));
        let a3 = e.tick(15_000, high(), &procs, &live_from(&procs)); // cap b (in cooldown)
        assert!(has_cap_target(&a3, cg_b));

        let ivs = e.interventions();
        assert_eq!(ivs.len(), 2, "expected a + b both Capped: {ivs:?}");
        // Sorted ascending by cgroup path.
        assert_eq!(ivs[0].0, cg_a);
        assert_eq!(ivs[1].0, cg_b);
        assert!(ivs
            .iter()
            .all(|(_, iv)| matches!(iv, Intervention::Capped { .. })));
    }

    #[test]
    fn critical_via_mem_floor_triggers_action() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        // No PSI pressure, but MemAvailable below the 400 MB floor -> Critical.
        let a = e.tick(0, sample(0.0, 0.0, 100), &procs, &live_from(&procs));
        assert_eq!(e.level, Level::Critical);
        assert_eq!(freeze_targets(&a), vec!["/app.slice/app-hog-2.scope"]);
    }

    #[test]
    fn notify_emitted_and_rate_limited() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];

        // Warn level: some>=10 but below high; just notify, no freeze.
        let a0 = e.tick(0, sample(12.0, 0.0, 8000), &procs, &live_from(&procs));
        assert!(
            a0.iter().any(|x| matches!(x, Action::Notify { .. })),
            "expected a notify at Warn: {a0:?}"
        );
        assert!(freeze_targets(&a0).is_empty());

        // Within 60s: no second notify.
        let a1 = e.tick(30_000, sample(12.0, 0.0, 8000), &procs, &live_from(&procs));
        assert!(
            !a1.iter().any(|x| matches!(x, Action::Notify { .. })),
            "notify should be rate-limited: {a1:?}"
        );

        // After 60s: notify again.
        let a2 = e.tick(60_000, sample(12.0, 0.0, 8000), &procs, &live_from(&procs));
        assert!(a2.iter().any(|x| matches!(x, Action::Notify { .. })));
    }

    #[test]
    fn notify_disabled_suppresses_notifications() {
        let mut c = cfg();
        c.notify = false;
        let mut e = PolicyEngine::new(c);
        let procs = vec![proc(2, "hog", 4000)];
        let a = e.tick(0, sample(12.0, 0.0, 8000), &procs, &live_from(&procs));
        assert!(!a.iter().any(|x| matches!(x, Action::Notify { .. })));
    }

    // ---- Task 5 new behaviors --------------------------------------------

    #[test]
    fn caponly_verdict_never_freezes() {
        let mut e = PolicyEngine::new(cfg());
        let mut p = proc_at(2, "script", 4000, "/app.slice/app-alacritty-9.scope");
        let r = p.resolution.as_mut().unwrap();
        r.verdict = Verdict::CapOnly;
        r.coverage = Coverage::Partial;
        let procs = [p];
        let a = e.tick(0, high(), &procs, &live_from(&procs));
        assert!(
            freeze_targets(&a).is_empty(),
            "CapOnly must not freeze: {a:?}"
        );
        assert!(has_cap_target(&a, "/app.slice/app-alacritty-9.scope"));
    }

    #[test]
    fn partial_coverage_shortens_escalation_gate() {
        let mut e = PolicyEngine::new(cfg());
        let mut p1 = proc_at(1, "script", 4000, "/app.slice/a.scope");
        {
            let r = p1.resolution.as_mut().unwrap();
            r.verdict = Verdict::CapOnly;
            r.coverage = Coverage::Partial;
        }
        let p2 = proc_at(2, "hog", 3000, "/app.slice/b.scope");
        let procs = [p1.clone(), p2.clone()];
        // Partial action at t=0...
        let a0 = e.tick(0, high(), &procs, &live_from(&procs));
        assert!(has_cap_target(&a0, "/app.slice/a.scope"));
        // ...gate must already be open on the very next tick (1s later, < freeze_hold).
        let a1 = e.tick(1_000, high(), &procs, &live_from(&procs));
        assert!(
            has_freeze_target(&a1, "/app.slice/b.scope"),
            "gate should be open after Partial: {a1:?}"
        );
    }

    #[test]
    fn unresolvable_process_is_never_selected() {
        let mut e = PolicyEngine::new(cfg());
        let p = ProcInfo {
            pid: 1,
            name: "stray".into(),
            rss_kb: 4_000_000,
            resolution: None,
        };
        // `high()` still triggers the (unrelated) pressure Notify — that's
        // covered elsewhere (`notify_emitted_and_rate_limited`). What this test
        // guards is that an unresolvable process is never escalated: no
        // Freeze/Cap is ever produced for it, and no intervention is created.
        let procs = [p];
        let a = e.tick(0, high(), &procs, &live_from(&procs));
        assert!(
            !a.iter()
                .any(|x| matches!(x, Action::Freeze { .. } | Action::Cap { .. })),
            "unresolvable process must never be escalated: {a:?}"
        );
        assert!(e.interventions().is_empty());
    }

    #[test]
    fn two_pids_same_scope_yield_one_intervention() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![
            proc_at(10, "firefox", 4000, "/app.slice/app-firefox-1.scope"),
            proc_at(
                11,
                "Isolated Web Co",
                3000,
                "/app.slice/app-firefox-1.scope",
            ),
        ];
        let a = e.tick(0, high(), &procs, &live_from(&procs));
        assert_eq!(
            freeze_targets(&a).len(),
            1,
            "one freeze for the shared scope: {a:?}"
        );
    }
}
