//! Pure policy state machine: the self-healing circuit breaker at the heart of
//! the freeze guard.
//!
//! Contract: [`PolicyEngine::tick`] is pure given `(now_ms, sample, targets,
//! live_cgroups)` plus the engine's own internal state. It performs **no**
//! syscalls and reads **no** clock; `now_ms` (monotonic milliseconds) is
//! injected by the caller. That is what makes the whole escalation/recovery
//! ladder unit-testable without root.

use std::collections::{BTreeMap, HashMap, HashSet};

use super::resolve::{Coverage, Resolution, Verdict};
use super::types::{Action, Intervention, Level, Sample, Target};
use common::GuardConfig;

/// PSI `full` avg10 (%) that, on its own, forces at least the High level. Mirrors
/// the design doc's "or `full.avg10 >= 3`" High trigger.
const FULL_HIGH_RISE: f64 = 3.0;

/// Escalation gate (ms) after an action that only partly covered its app.
/// PSI avg10 is a 10 s average, so re-measuring after 1 s still sees the old
/// pressure; waiting at least this long stops a partial action from
/// cascading into several more within seconds.
pub const PARTIAL_GATE_MS: u64 = 3_000;
/// Most apps the guard holds (frozen or capped) at the same time.
pub const MAX_HELD_APPS: usize = 3;
/// Growth rate (bytes/s of `memory.current`) an app must reach to be picked
/// as the one causing pressure. Below it, the largest app is picked instead.
pub const MIN_GROWTH_BPS: f64 = 1_048_576.0;
/// Most consecutive ticks victim selection waits for growth data when every
/// eligible cgroup is newly seen. After that the largest app is picked, so a
/// stream of short-lived cgroups cannot keep the guard from acting.
pub const MAX_COLD_DEFER_TICKS: u32 = 3;

/// The level a sample reaches on its own, from the rise thresholds alone
/// (no hysteresis): Critical when PSI `full` reaches `psi_full_critical` or
/// available memory is below `mem_available_floor_mb`, High when `some` reaches
/// `psi_some_high` or `full` reaches [`FULL_HIGH_RISE`], Warn when `some`
/// reaches `psi_some_warn`. The engine enters a level on exactly these rules;
/// callers that only show the pressure (the GUI) use this to agree with it.
pub fn rise_level(s: &Sample, t: &common::GuardTrigger) -> Level {
    if s.full_avg10 >= t.psi_full_critical || s.mem_available_mb < t.mem_available_floor_mb {
        Level::Critical
    } else if s.some_avg10 >= t.psi_some_high || s.full_avg10 >= FULL_HIGH_RISE {
        Level::High
    } else if s.some_avg10 >= t.psi_some_warn {
        Level::Warn
    } else {
        Level::Calm
    }
}

/// True when the host is actually short of memory: below the hard floor, or
/// below `act_below_available_pct` percent of RAM. A stall confined to one
/// cgroup's memory.max leaves MemAvailable high, so it never passes this gate.
pub fn is_scarce(s: &Sample, t: &common::GuardTrigger) -> bool {
    s.mem_available_mb < t.mem_available_floor_mb
        || (s.mem_total_mb > 0
            && s.mem_available_mb.saturating_mul(100)
                < s.mem_total_mb.saturating_mul(t.act_below_available_pct))
}

/// Smoothed `memory.current` growth for one cgroup.
struct Growth {
    last_bytes: u64,
    last_ms: u64,
    /// EWMA of bytes per second (negative while shrinking).
    rate_bps: f64,
    /// True once a second sample has been seen, so `rate_bps` is a measured
    /// rate and not the zero placeholder of a first sighting.
    warm: bool,
}

/// Self-healing circuit-breaker policy engine.
///
/// On a memory spike it drives the ladder *freeze (short), auto-thaw,
/// if still high a soft cap, once calm is sustained a lift*, never issuing a kill. All
/// of that lives in [`tick`](Self::tick); the struct just holds the state needed
/// to make decisions stable across ticks (hysteresis, cooldowns, growth).
///
/// The unit of choice is an app: every cgroup of the chosen app is frozen or
/// capped together as one escalation step.
pub struct PolicyEngine {
    cfg: GuardConfig,
    /// Current pressure level (carried across ticks so hysteresis works).
    level: Level,
    /// Active interventions keyed by resolved cgroup path, with the
    /// [`Resolution`] (so `Thaw`/`LiftCap` can be built without re-resolving)
    /// and the app the cgroup was acted on as.
    interventions: HashMap<String, (Intervention, Resolution, String)>,
    /// Last time each app was frozen. Drives the per-app freeze cooldown that
    /// decides freeze-vs-cap, and is intentionally kept after a thaw.
    last_freeze_ms: HashMap<String, u64>,
    /// Per-cgroup `memory.current` growth estimate.
    growth: HashMap<String, Growth>,
    /// When the level last became `Calm` (None while not calm). Gates cap lifts.
    calm_since_ms: Option<u64>,
    /// When we last emitted a new freeze/cap: the global escalation gate.
    /// `None` means "never acted", so the gate is open on the first action.
    last_action_ms: Option<u64>,
    /// Whether the most recent escalation acted under `Coverage::Partial`.
    /// When true the gate is shortened to [`PARTIAL_GATE_MS`] (capped at the
    /// freeze hold) so the guard can re-assess sooner, but never instantly.
    last_action_partial: bool,
    /// Consecutive ticks on which selection deferred for lack of growth
    /// data. Bounded by [`MAX_COLD_DEFER_TICKS`].
    cold_defer_ticks: u32,
}

impl PolicyEngine {
    pub fn new(cfg: GuardConfig) -> Self {
        Self {
            cfg,
            level: Level::Calm,
            interventions: HashMap::new(),
            last_freeze_ms: HashMap::new(),
            growth: HashMap::new(),
            calm_since_ms: None,
            last_action_ms: None,
            last_action_partial: false,
            cold_defer_ticks: 0,
        }
    }

    /// Advance the state machine one tick and return the actions to apply.
    ///
    /// `targets` are the cgroups eligible for action this tick (already
    /// filtered for uid, protect list and min RSS by the Sampler).
    ///
    /// `live_cgroups` is the subset of the engine's intervened cgroups that
    /// still hold a process (see `sampler::live_cgroups`), with no min-RSS
    /// or protect filtering applied; it is deliberately independent of
    /// `targets`. Pruning checks liveness against
    /// this set, not against `targets`: `memory.high` also bounds
    /// file-backed pages, so capping
    /// a mapped-file-heavy process can push its `rss_kb` below the min-RSS
    /// floor on the very next tick, dropping it out of `targets` even though
    /// the cgroup is very much still alive. Pruning against `targets` there
    /// would lift the cap while pressure is still Critical and immediately
    /// re-trigger it. Victim *selection* deliberately keeps using `targets`.
    pub fn tick(
        &mut self,
        now_ms: u64,
        sample: Sample,
        targets: &[Target],
        live_cgroups: &HashSet<String>,
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
                self.cold_defer_ticks = 0;
            }
            _ => self.calm_since_ms = None,
        }

        // 3. Track memory.current growth per cgroup.
        self.update_growth(now_ms, targets);

        // 4. Prune interventions whose cgroup is no longer live (see
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
            let (_, res, _) = self.interventions.remove(&cg).expect("just found key");
            actions.push(Action::LiftCap { res });
        }

        // 5. Recover: auto-thaw held freezes, and lift caps once calm has held.
        let freeze_hold_ms = self.cfg.timing.freeze_hold_secs.saturating_mul(1000);
        let calm_hold_ms = self.cfg.timing.calm_hold_secs.saturating_mul(1000);
        let mut recovered = Vec::new();
        // Apps thawed on this tick must not be re-targeted by escalation in
        // the same tick; they need a re-measure first.
        let mut thawed_apps: HashSet<String> = HashSet::new();
        for (cg, (intervention, res, app)) in &self.interventions {
            match *intervention {
                Intervention::Frozen { since_ms } => {
                    if now_ms.saturating_sub(since_ms) >= freeze_hold_ms {
                        actions.push(Action::Thaw { res: res.clone() });
                        recovered.push(cg.clone());
                        thawed_apps.insert(app.clone());
                    }
                }
                Intervention::Capped { .. } => {
                    // Only lift a cap when pressure is calm *and* has stayed calm
                    // long enough; this prevents re-capping churn. `calm_since_ms` is
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

        // 6. Escalate, but only when apps feel pressure, memory is actually
        //    short (see `is_scarce`), the gate is open, and fewer than
        //    MAX_HELD_APPS apps are already held.
        if matches!(self.level, Level::High | Level::Critical)
            && is_scarce(&sample, &self.cfg.trigger)
            && self.held_apps().len() < MAX_HELD_APPS
        {
            // Global gate: after acting on one app, wait a freeze-hold before
            // acting again so we re-measure instead of cascading. After a
            // partial action wait a shorter, but never zero, interval.
            let gate_ms = if self.last_action_partial {
                PARTIAL_GATE_MS.min(freeze_hold_ms)
            } else {
                freeze_hold_ms
            };
            let gate_open = match self.last_action_ms {
                None => true,
                Some(last) => now_ms.saturating_sub(last) >= gate_ms,
            };
            if gate_open {
                if let Some((app, members)) = self.select_app(targets, &thawed_apps) {
                    let cap_only = members
                        .iter()
                        .any(|m| m.resolution.verdict == Verdict::CapOnly);
                    let partial = members
                        .iter()
                        .any(|m| m.resolution.coverage == Coverage::Partial);
                    let cooldown_ms = self.cfg.timing.freeze_cooldown_secs.saturating_mul(1000);
                    let in_cooldown = self
                        .last_freeze_ms
                        .get(&app)
                        .is_some_and(|&last| now_ms.saturating_sub(last) < cooldown_ms);
                    // CapOnly never freezes; a recently frozen app that is
                    // still hot escalates to a soft cap.
                    let freeze = !cap_only && !in_cooldown;

                    for m in members {
                        let res = m.resolution.clone();
                        let intervention = if freeze {
                            actions.push(Action::Freeze {
                                res: res.clone(),
                                name: app.clone(),
                            });
                            Intervention::Frozen { since_ms: now_ms }
                        } else {
                            actions.push(Action::Cap {
                                res: res.clone(),
                                name: app.clone(),
                            });
                            Intervention::Capped { since_ms: now_ms }
                        };
                        self.interventions
                            .insert(res.cgroup.clone(), (intervention, res, app.clone()));
                    }
                    if freeze {
                        self.last_freeze_ms.insert(app.clone(), now_ms);
                    }
                    self.last_action_ms = Some(now_ms);
                    self.last_action_partial = partial;
                }
            }
        }

        actions
    }

    /// True when the caller should gather targets for the next tick: the
    /// level would be above Calm, or memory is already scarce. Scanning while
    /// scarce keeps growth rates warm, so a sudden drop below the floor can
    /// pick the app that is growing instead of the largest one. A disabled
    /// engine never wants them.
    pub fn wants_candidates(&self, sample: Sample) -> bool {
        self.cfg.enabled
            && (self.next_level(sample) != Level::Calm || is_scarce(&sample, &self.cfg.trigger))
    }

    /// The pressure level as of the last tick.
    pub fn level(&self) -> Level {
        self.level
    }

    /// Currently active interventions (cgroup path and intervention), sorted by
    /// cgroup path so callers get a deterministic order.
    pub fn interventions(&self) -> Vec<(String, Intervention)> {
        let mut out: Vec<(String, Intervention)> = self
            .interventions
            .iter()
            .map(|(cg, (iv, _, _))| (cg.clone(), *iv))
            .collect();
        out.sort_by(|(a, _), (b, _)| a.cmp(b));
        out
    }

    /// Cgroup paths the engine currently holds an intervention on, frozen
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

    /// Distinct apps with at least one active intervention.
    fn held_apps(&self) -> HashSet<&str> {
        self.interventions
            .values()
            .map(|(_, _, app)| app.as_str())
            .collect()
    }

    /// Compute the next level from the current level + a fresh sample, applying
    /// rise/fall hysteresis. The fall threshold is half the rise threshold, and
    /// we only ever *step down* when below the fall threshold, so a sample that
    /// sits between fall and rise leaves the level unchanged (no flapping).
    fn next_level(&self, s: Sample) -> Level {
        let t = &self.cfg.trigger;
        let floor = t.mem_available_floor_mb;

        // Rise predicates (cross the upper threshold to enter a level).
        let rise = rise_level(&s, t);
        let crit_rise = rise == Level::Critical;
        let high_rise = crit_rise || rise == Level::High;
        let warn_rise = high_rise || rise == Level::Warn;

        // Stay predicates (above the lower/fall threshold: keep the level).
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

    /// Update each target cgroup's `memory.current` growth rate (an EWMA
    /// with weight 0.5 per tick) and forget cgroups no longer present.
    fn update_growth(&mut self, now_ms: u64, targets: &[Target]) {
        let mut seen = HashSet::new();
        for t in targets {
            let Some(cur) = t.current_bytes else {
                continue;
            };
            let cg = &t.resolution.cgroup;
            seen.insert(cg.clone());
            match self.growth.get_mut(cg) {
                Some(g) if now_ms > g.last_ms => {
                    let dt = (now_ms - g.last_ms) as f64 / 1000.0;
                    let inst = (cur as f64 - g.last_bytes as f64) / dt;
                    g.rate_bps = 0.5 * g.rate_bps + 0.5 * inst;
                    g.last_bytes = cur;
                    g.last_ms = now_ms;
                    g.warm = true;
                }
                Some(_) => {}
                None => {
                    self.growth.insert(
                        cg.clone(),
                        Growth {
                            last_bytes: cur,
                            last_ms: now_ms,
                            rate_bps: 0.0,
                            warm: false,
                        },
                    );
                }
            }
        }
        self.growth.retain(|cg, _| seen.contains(cg));
    }

    /// Pick the app to act on and its member targets. Eligible apps are not
    /// held, not thawed this tick (`blocked`), have a member at or above the
    /// min-RSS floor, and have no member cgroup under an intervention. The
    /// app whose cgroups grow fastest wins when that growth is at least
    /// [`MIN_GROWTH_BPS`]; otherwise the largest app. Ties go to the
    /// lexicographically smaller app name, so the choice is deterministic.
    ///
    /// Cold start: when no eligible cgroup has a measured growth rate yet but
    /// at least one was first seen this tick, nothing is picked. The next
    /// tick (one sample interval later) has rates, so an idle large app is
    /// not frozen in place of a smaller one that is growing. The deferral
    /// lasts one tick at most per new cgroup, and at most
    /// [`MAX_COLD_DEFER_TICKS`] ticks in a row; after that the largest app is
    /// picked. If no eligible cgroup reports `memory.current` at all, growth
    /// can never be measured and the largest app is picked at once.
    fn select_app<'a>(
        &mut self,
        targets: &'a [Target],
        blocked: &HashSet<String>,
    ) -> Option<(String, Vec<&'a Target>)> {
        let min_rss_kb = self.cfg.selection.min_rss_mb.saturating_mul(1024);
        let held = self.held_apps();
        let mut groups: BTreeMap<&str, Vec<&Target>> = BTreeMap::new();
        for t in targets {
            groups.entry(t.app.as_str()).or_default().push(t);
        }
        let eligible: Vec<(&str, Vec<&Target>)> = groups
            .into_iter()
            .filter(|(app, ms)| {
                !held.contains(app)
                    && !blocked.contains(*app)
                    && ms.iter().any(|m| m.rss_kb >= min_rss_kb)
                    && ms
                        .iter()
                        .all(|m| !self.interventions.contains_key(&m.resolution.cgroup))
            })
            .collect();
        let any_warm = eligible.iter().any(|(_, ms)| {
            ms.iter().any(|m| {
                self.growth
                    .get(&m.resolution.cgroup)
                    .is_some_and(|g| g.warm)
            })
        });
        let any_cold = eligible.iter().any(|(_, ms)| {
            ms.iter().any(|m| {
                self.growth
                    .get(&m.resolution.cgroup)
                    .is_some_and(|g| !g.warm)
            })
        });
        if !any_warm && any_cold && self.cold_defer_ticks < MAX_COLD_DEFER_TICKS {
            self.cold_defer_ticks += 1;
            return None;
        }
        self.cold_defer_ticks = 0;
        let growth = |ms: &[&Target]| -> f64 {
            ms.iter()
                .map(|m| {
                    self.growth
                        .get(&m.resolution.cgroup)
                        .map_or(0.0, |g| g.rate_bps.max(0.0))
                })
                .sum()
        };
        let size = |ms: &[&Target]| -> u64 {
            ms.iter()
                .map(|m| m.current_bytes.unwrap_or(m.rss_kb.saturating_mul(1024)))
                .sum()
        };
        let pick = eligible
            .iter()
            .filter(|(_, ms)| growth(ms) >= MIN_GROWTH_BPS)
            .max_by(|a, b| {
                growth(&a.1)
                    .total_cmp(&growth(&b.1))
                    .then_with(|| b.0.cmp(a.0))
            })
            .or_else(|| {
                eligible
                    .iter()
                    .max_by(|a, b| size(&a.1).cmp(&size(&b.1)).then_with(|| b.0.cmp(a.0)))
            })?;
        Some((pick.0.to_string(), pick.1.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolve::Mechanism;
    use super::super::types::PsiSource;
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
            mem_total_mb: 16_000,
            source: PsiSource::AppSlice,
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

    const MIB: u64 = 1024 * 1024;

    /// Build a `Target` for app `app` in cgroup `cg`, with `mb` MB resident
    /// and the same amount charged to the cgroup.
    fn target(app: &str, cg: &str, mb: u64) -> Target {
        Target {
            app: app.into(),
            resolution: res(cg),
            rss_kb: mb * 1024,
            current_bytes: Some(mb * MIB),
        }
    }

    /// Shorthand: one app per scope, `/app.slice/app-<name>-<pid>.scope`.
    fn proc(pid: u32, name: &str, rss_mb: u64) -> Target {
        target(name, &format!("/app.slice/app-{name}-{pid}.scope"), rss_mb)
    }

    fn proc_at(_pid: u32, name: &str, rss_mb: u64, cg: &str) -> Target {
        target(name, cg, rss_mb)
    }

    /// A comfortably-calm sample (no pressure, lots of memory).
    fn calm() -> Sample {
        sample(0.0, 0.0, 8000)
    }

    /// High PSI while only 12.5% of RAM is available: a real shortage.
    fn high() -> Sample {
        sample(50.0, 0.0, 2_000)
    }

    #[test]
    fn high_pressure_with_plenty_of_free_memory_never_escalates() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "chrome", 4000)];
        // Half of RAM available: this stall is local to some memory.max, not a shortage.
        let a = e.tick(0, sample(80.0, 20.0, 8_000), &procs, &live_from(&procs));
        assert_eq!(e.level, Level::Critical);
        assert!(
            !a.iter()
                .any(|x| matches!(x, Action::Freeze { .. } | Action::Cap { .. })),
            "escalated without scarcity: {a:?}"
        );
    }

    #[test]
    fn is_scarce_uses_floor_or_percentage() {
        let t = common::GuardTrigger::default(); // floor 400 MB, 20%
        assert!(is_scarce(&sample(0.0, 0.0, 300), &t));
        assert!(is_scarce(&sample(0.0, 0.0, 3_000), &t)); // 18.75%
        assert!(!is_scarce(&sample(0.0, 0.0, 3_300), &t)); // 20.6%
        let unknown = Sample {
            mem_total_mb: 0,
            mem_available_mb: u64::MAX,
            ..sample(0.0, 0.0, 0)
        };
        assert!(
            !is_scarce(&unknown, &t),
            "unreadable meminfo must not enable actions"
        );
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

    /// Give every target a measured (zero) growth rate, as if the engine had
    /// already scanned them on an earlier tick. Tests of the ladder use this
    /// so the cold-start deferral does not shift their first action.
    fn prime(e: &mut PolicyEngine, ts: &[Target]) {
        for t in ts {
            e.growth.insert(
                t.resolution.cgroup.clone(),
                Growth {
                    last_bytes: t.current_bytes.unwrap_or(0),
                    last_ms: 0,
                    rate_bps: 0.0,
                    warm: true,
                },
            );
        }
    }

    /// Default `live_cgroups` for tests that aren't specifically exercising
    /// the liveness-vs-eligibility distinction: every target's cgroup.
    fn live_from(ts: &[Target]) -> std::collections::HashSet<String> {
        ts.iter().map(|t| t.resolution.cgroup.clone()).collect()
    }

    #[test]
    fn rise_level_follows_the_engine_rise_rules() {
        let t = common::GuardTrigger::default();
        assert_eq!(rise_level(&sample(0.0, 0.0, 8000), &t), Level::Calm);
        assert_eq!(rise_level(&sample(12.0, 0.0, 8000), &t), Level::Warn);
        assert_eq!(rise_level(&sample(5.0, 4.0, 2000), &t), Level::High);
        assert_eq!(rise_level(&sample(31.0, 0.0, 8000), &t), Level::High);
        assert_eq!(rise_level(&sample(0.0, 10.0, 8000), &t), Level::Critical);
        // Below the free-memory floor is Critical whatever PSI says.
        assert_eq!(rise_level(&sample(0.0, 0.0, 300), &t), Level::Critical);
        // An unreadable MemAvailable is never below the floor.
        assert_eq!(rise_level(&sample(0.0, 0.0, u64::MAX), &t), Level::Calm);
        // From Calm, one tick lands on the same level.
        for s in [
            sample(5.0, 4.0, 2000),
            sample(0.0, 0.0, 300),
            sample(12.0, 0.0, 8000),
        ] {
            let e = PolicyEngine::new(cfg());
            assert_eq!(e.next_level(s), rise_level(&s, &t), "{s:?}");
        }
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

        // full drifts to 2.0, between the fall (1.5) and rise (3.0) thresholds.
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
        prime(&mut e, &procs);
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
        prime(&mut e, &procs);
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
        prime(&mut e, &procs);
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

        // Still high, and within the 60s freeze cooldown: Cap, not re-Freeze.
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
        prime(&mut e, &procs);
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

        // 30s of sustained calm lifts the cap.
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
        prime(&mut e, &procs);
        let cg = "/app.slice/app-hog-2.scope";
        e.tick(0, high(), &procs, &live_from(&procs));
        e.tick(5_000, high(), &procs, &live_from(&procs));
        assert!(has_cap_target(
            &e.tick(10_000, high(), &procs, &live_from(&procs)),
            cg
        ));

        e.tick(15_000, calm(), &procs, &live_from(&procs)); // calm clock starts
        e.tick(20_000, high(), &procs, &live_from(&procs)); // pressure returns, calm clock cleared
                                                            // New calm window starts at 25s; at 50s only 25s have passed, so no lift.
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
        prime(&mut e, &procs);
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
        prime(&mut e, &procs);
        let cg = "/app.slice/app-hog-2.scope";

        // Freeze the hog's cgroup.
        assert_eq!(
            freeze_targets(&e.tick(0, high(), &procs, &live_from(&procs))),
            vec![cg]
        );
        assert_eq!(e.interventions().len(), 1);

        // Next tick the process (and its resolution) has vanished, so LiftCap
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
    /// present in `live_cgroups` must NOT be pruned: the cgroup is real and
    /// alive, just not currently eligible for (re-)selection. A cgroup
    /// absent from *both* sets must still be pruned with a LiftCap.
    #[test]
    fn intervention_survives_in_live_cgroups_but_absent_from_procs() {
        let mut e = PolicyEngine::new(cfg());
        let procs = vec![proc(2, "hog", 4000)];
        prime(&mut e, &procs);
        let cg = "/app.slice/app-hog-2.scope";

        // Freeze the hog's cgroup.
        assert_eq!(
            freeze_targets(&e.tick(0, high(), &procs, &live_from(&procs))),
            vec![cg]
        );
        assert_eq!(e.interventions().len(), 1);

        // Next tick: the process no longer appears in `procs` (as if the cap
        // evicted its file pages below the min-RSS floor), but its cgroup is
        // still in `live_cgroups`, so it must NOT be pruned.
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

        // Now the cgroup is gone from both sets entirely, so it is pruned.
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
        // Capped "a" and a "b" capped after a freeze, both active, then check
        // ordering + content. "/app.slice/app-a-5.scope" sorts before
        // "/app.slice/app-b-3.scope" lexicographically.
        let procs = vec![proc(5, "a", 4000), proc(3, "b", 3500)];
        prime(&mut e, &procs);
        let cg_a = "/app.slice/app-a-5.scope";
        let cg_b = "/app.slice/app-b-3.scope";

        // Walk both cgroups down the freeze, thaw, (still hot) cap ladder
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
        prime(&mut e, &procs);
        // No PSI pressure, but MemAvailable below the 400 MB floor, so Critical.
        let a = e.tick(0, sample(0.0, 0.0, 100), &procs, &live_from(&procs));
        assert_eq!(e.level, Level::Critical);
        assert_eq!(freeze_targets(&a), vec!["/app.slice/app-hog-2.scope"]);
    }

    // ---- Task 5 new behaviors --------------------------------------------

    #[test]
    fn caponly_verdict_never_freezes() {
        let mut e = PolicyEngine::new(cfg());
        let mut p = proc_at(2, "script", 4000, "/app.slice/app-alacritty-9.scope");
        let r = &mut p.resolution;
        r.verdict = Verdict::CapOnly;
        r.coverage = Coverage::Partial;
        let procs = [p];
        prime(&mut e, &procs);
        let a = e.tick(0, high(), &procs, &live_from(&procs));
        assert!(
            freeze_targets(&a).is_empty(),
            "CapOnly must not freeze: {a:?}"
        );
        assert!(has_cap_target(&a, "/app.slice/app-alacritty-9.scope"));
    }

    #[test]
    fn partial_action_waits_at_least_three_seconds() {
        let mut e = PolicyEngine::new(cfg());
        let mut term = target("python3", "/app.slice/term.scope", 4000);
        term.resolution.verdict = Verdict::CapOnly;
        term.resolution.coverage = Coverage::Partial;
        let ts = vec![term, target("hog", "/app.slice/hog.scope", 3000)];
        prime(&mut e, &ts);
        assert!(has_cap_target(
            &e.tick(0, high(), &ts, &live_from(&ts)),
            "/app.slice/term.scope"
        ));
        assert!(freeze_targets(&e.tick(1_000, high(), &ts, &live_from(&ts))).is_empty());
        assert!(freeze_targets(&e.tick(2_000, high(), &ts, &live_from(&ts))).is_empty());
        assert!(has_freeze_target(
            &e.tick(3_000, high(), &ts, &live_from(&ts)),
            "/app.slice/hog.scope"
        ));
    }

    #[test]
    fn two_scopes_of_one_app_are_acted_on_together() {
        let mut e = PolicyEngine::new(cfg());
        let ts = vec![
            target("chrome", "/app.slice/app-chrome-1.scope", 1500),
            target("chrome", "/app.slice/app-chrome-2.scope", 900),
            target("hog", "/app.slice/app-hog-3.scope", 2000),
        ];
        prime(&mut e, &ts);
        let mut frozen = freeze_targets(&e.tick(0, high(), &ts, &live_from(&ts)));
        frozen.sort();
        assert_eq!(
            frozen,
            vec![
                "/app.slice/app-chrome-1.scope",
                "/app.slice/app-chrome-2.scope"
            ]
        );
        let a1 = e.tick(1_000, high(), &ts, &live_from(&ts));
        assert!(
            freeze_targets(&a1).is_empty(),
            "one app is one escalation step: {a1:?}"
        );
    }

    #[test]
    fn fastest_growing_app_is_chosen_over_largest() {
        let mut e = PolicyEngine::new(cfg());
        let warn = sample(12.0, 0.0, 2_000);
        let t0 = vec![
            target("firefox", "/app.slice/ff.scope", 4000),
            target("script", "/app.slice/sh.scope", 1000),
        ];
        assert!(freeze_targets(&e.tick(0, warn, &t0, &live_from(&t0))).is_empty());
        let t1 = vec![
            target("firefox", "/app.slice/ff.scope", 4000),
            target("script", "/app.slice/sh.scope", 1600),
        ];
        assert_eq!(
            freeze_targets(&e.tick(1_000, high(), &t1, &live_from(&t1))),
            vec!["/app.slice/sh.scope"]
        );
    }

    #[test]
    fn largest_app_is_the_fallback_when_nothing_grows() {
        let mut e = PolicyEngine::new(cfg());
        let ts = vec![
            target("small", "/app.slice/s.scope", 300),
            target("big", "/app.slice/b.scope", 3000),
        ];
        e.tick(0, sample(12.0, 0.0, 2_000), &ts, &live_from(&ts));
        assert_eq!(
            freeze_targets(&e.tick(1_000, high(), &ts, &live_from(&ts))),
            vec!["/app.slice/b.scope"]
        );
    }

    #[test]
    fn at_most_three_apps_are_held_at_once() {
        let mut e = PolicyEngine::new(cfg());
        let ts: Vec<Target> = (0..5u64)
            .map(|i| {
                target(
                    &format!("app{i}"),
                    &format!("/app.slice/a{i}.scope"),
                    1000 + i * 100,
                )
            })
            .collect();
        for step in 0..40u64 {
            e.tick(step * 5_000, high(), &ts, &live_from(&ts));
            assert!(
                e.interventions().len() <= MAX_HELD_APPS,
                "held {:?}",
                e.interventions()
            );
        }
    }

    #[test]
    fn held_limit_counts_apps_not_cgroups() {
        let mut e = PolicyEngine::new(cfg());
        let ts = vec![
            target("a", "/app.slice/a1.scope", 2000),
            target("a", "/app.slice/a2.scope", 2000),
            target("b", "/app.slice/b.scope", 1500),
            target("c", "/app.slice/c.scope", 1200),
            target("d", "/app.slice/d.scope", 1100),
        ];
        for step in 0..40u64 {
            e.tick(step * 5_000, high(), &ts, &live_from(&ts));
        }
        let held: Vec<String> = e.interventions().into_iter().map(|(cg, _)| cg).collect();
        assert_eq!(
            held,
            vec![
                "/app.slice/a1.scope",
                "/app.slice/a2.scope",
                "/app.slice/b.scope",
                "/app.slice/c.scope"
            ],
            "4 cgroups across 3 apps are allowed, a 4th app is refused"
        );
    }

    #[test]
    fn candidates_are_wanted_above_calm_or_when_scarce() {
        let e = PolicyEngine::new(cfg());
        assert!(!e.wants_candidates(calm()));
        assert!(e.wants_candidates(sample(12.0, 0.0, 8_000)));
        // Calm PSI but under 20% of RAM available: scan so growth stays warm.
        assert!(e.wants_candidates(sample(0.0, 0.0, 3_000)));
    }

    /// Regression (final review I1): available memory drops below the floor
    /// in one step with no stall first, so the Critical tick is the first
    /// scan. An idle 6 GB app must not be frozen in place of a 3 GB app
    /// that is growing: the first tick defers, the next picks the grower.
    #[test]
    fn cold_start_defers_then_picks_grower_not_largest() {
        let mut e = PolicyEngine::new(cfg());
        for step in 0..5u64 {
            e.tick(step * 1_000, calm(), &[], &HashSet::new());
        }
        let crit = sample(0.0, 0.0, 300);
        let t0 = vec![
            target("chrome", "/app.slice/chrome.scope", 6000),
            target("hog", "/app.slice/hog.scope", 3000),
        ];
        let a0 = e.tick(5_000, crit, &t0, &live_from(&t0));
        assert_eq!(e.level, Level::Critical);
        assert!(
            freeze_targets(&a0).is_empty(),
            "no growth data yet, must defer: {a0:?}"
        );
        let t1 = vec![
            target("chrome", "/app.slice/chrome.scope", 6000),
            target("hog", "/app.slice/hog.scope", 3200),
        ];
        assert_eq!(
            freeze_targets(&e.tick(6_000, crit, &t1, &live_from(&t1))),
            vec!["/app.slice/hog.scope"]
        );
    }

    /// With scarce-but-calm ticks feeding growth, the grower is picked on
    /// the very first Critical tick.
    #[test]
    fn scarce_calm_ticks_warm_growth_for_first_critical_tick() {
        let mut e = PolicyEngine::new(cfg());
        let scarce_calm = sample(0.0, 0.0, 3_000);
        assert!(e.wants_candidates(scarce_calm));
        let t0 = vec![
            target("chrome", "/app.slice/chrome.scope", 6000),
            target("hog", "/app.slice/hog.scope", 2000),
        ];
        assert!(freeze_targets(&e.tick(0, scarce_calm, &t0, &live_from(&t0))).is_empty());
        let t1 = vec![
            target("chrome", "/app.slice/chrome.scope", 6000),
            target("hog", "/app.slice/hog.scope", 3000),
        ];
        assert_eq!(
            freeze_targets(&e.tick(1_000, sample(0.0, 0.0, 300), &t1, &live_from(&t1))),
            vec!["/app.slice/hog.scope"]
        );
    }

    /// A new cgroup on every tick never gets a measured growth rate. The
    /// deferral is bounded, so the guard still acts by the fourth tick and
    /// falls back to the largest eligible app.
    #[test]
    fn cold_start_deferral_is_bounded_when_cgroups_keep_changing() {
        let mut e = PolicyEngine::new(cfg());
        let crit = sample(0.0, 0.0, 300);
        for tick in 0..4u64 {
            let ts = vec![
                target(
                    &format!("big{tick}"),
                    &format!("/app.slice/b{tick}.scope"),
                    3000,
                ),
                target(
                    &format!("small{tick}"),
                    &format!("/app.slice/s{tick}.scope"),
                    1000,
                ),
            ];
            let frozen = freeze_targets(&e.tick(tick * 1_000, crit, &ts, &live_from(&ts)));
            if tick < u64::from(MAX_COLD_DEFER_TICKS) {
                assert!(frozen.is_empty(), "tick {tick} should defer: {frozen:?}");
            } else {
                assert_eq!(frozen, vec![format!("/app.slice/b{tick}.scope")]);
            }
        }
    }

    /// Without any memory.current reading, growth can never be measured, so
    /// the guard does not wait and falls back to the largest app.
    #[test]
    fn no_current_bytes_does_not_defer() {
        let mut e = PolicyEngine::new(cfg());
        let mut big = target("big", "/app.slice/b.scope", 3000);
        big.current_bytes = None;
        let mut small = target("small", "/app.slice/s.scope", 1000);
        small.current_bytes = None;
        let ts = vec![big, small];
        assert_eq!(
            freeze_targets(&e.tick(0, high(), &ts, &live_from(&ts))),
            vec!["/app.slice/b.scope"]
        );
    }
}
