//! Shared types for the freeze-guard engine. This is the stable contract that
//! the Sampler, PolicyEngine, and Effector all code against.

/// One memory-pressure sample taken from the system.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// PSI `some` avg10, percent in `0.0..=100.0`.
    pub some_avg10: f64,
    /// PSI `full` avg10, percent.
    pub full_avg10: f64,
    /// MemAvailable, in MB.
    pub mem_available_mb: u64,
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
}

/// An action the [`PolicyEngine`](crate::guard::PolicyEngine) asks the
/// [`Effector`](crate::guard::Effector) to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Best-effort user notification.
    Notify { message: String },
    /// Pause the process (cgroup.freeze) — the circuit breaker.
    Freeze { pid: u32, name: String },
    /// Resume a previously frozen process.
    Thaw { pid: u32 },
    /// Soft-cap the process via `memory.high` (throttle, never OOM-kill).
    Cap { pid: u32, name: String },
    /// Remove a soft cap and tear down the guard cgroup.
    LiftCap { pid: u32 },
}

/// An active intervention the engine is tracking, for `guard status` and
/// shutdown undo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intervention {
    Frozen { since_ms: u64 },
    Capped { since_ms: u64 },
}
