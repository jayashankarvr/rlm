//! Shared types for the freeze-guard engine. This is the stable contract that
//! the Sampler, PolicyEngine, and Effector all code against.

use super::resolve::Resolution;

/// Which PSI file a [`Sample`]'s pressure numbers came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsiSource {
    /// The user's `app.slice/memory.pressure`: stalls felt by the processes
    /// the guard can act on, excluding rlm's own limited cgroups.
    AppSlice,
    /// System-wide `/proc/pressure/memory`, used only when the app.slice file
    /// is missing or unreadable.
    System,
}

impl std::fmt::Display for PsiSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PsiSource::AppSlice => "app.slice",
            PsiSource::System => "system",
        })
    }
}

/// One memory-pressure sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// PSI `some` avg10, percent in `0.0..=100.0`.
    pub some_avg10: f64,
    /// PSI `full` avg10, percent.
    pub full_avg10: f64,
    /// MemAvailable, in MB. `u64::MAX` when /proc/meminfo is unreadable.
    pub mem_available_mb: u64,
    /// MemTotal, in MB. `0` when /proc/meminfo is unreadable.
    pub mem_total_mb: u64,
    /// Where the PSI numbers came from.
    pub source: PsiSource,
}

/// Pressure level derived from a [`Sample`]. Hysteresis (separate rise/fall
/// thresholds) is applied inside the engine, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Calm,
    Warn,
    High,
    Critical,
}

/// A candidate process the guard may act on. Already filtered for eligibility
/// (own uid, not protected, above the min-RSS threshold) by the Sampler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    /// Resident set size + swap, in KB.
    pub rss_kb: u64,
    /// Where and how the guard may act for this process. `None` = not
    /// actionable (outside permitted roots); `targets_from_procs` drops it.
    pub resolution: Option<Resolution>,
}

/// One cgroup the guard may act on, labelled with the app it belongs to.
/// Several targets can share an `app` (e.g. two systemd scopes of one
/// browser); the engine acts on all of them together as one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Executable basename of the largest process in the cgroup.
    pub app: String,
    /// Where and how the guard may act.
    pub resolution: Resolution,
    /// Resident set size + swap of the largest process in the cgroup, in KB.
    pub rss_kb: u64,
    /// The cgroup's `memory.current` in bytes, `None` when unreadable.
    pub current_bytes: Option<u64>,
}

/// An action the [`PolicyEngine`](crate::guard::PolicyEngine) asks the
/// [`Effector`](crate::guard::Effector) to perform. Actions are keyed by the
/// *resolved cgroup*, not a single pid — freezing/capping acts on every
/// process in that cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Best-effort user notification.
    Notify { message: String },
    /// Pause the resolved cgroup (cgroup.freeze) — the circuit breaker.
    /// `name` is the app the cgroup belongs to.
    Freeze { res: Resolution, name: String },
    /// Resume a previously frozen cgroup.
    Thaw { res: Resolution },
    /// Soft-cap the resolved cgroup via `memory.high` (throttle, never OOM-kill).
    /// `name` is the app the cgroup belongs to.
    Cap { res: Resolution, name: String },
    /// Remove a soft cap on the resolved cgroup.
    LiftCap { res: Resolution },
}

/// An active intervention the engine is tracking, for `guard status` and
/// shutdown undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intervention {
    Frozen { since_ms: u64 },
    Capped { since_ms: u64 },
}
