//! rlm stall-measurement harness — pure, unit-tested `/proc` parsers plus
//! the `Tick` type shared between the probe binary and later summary tools.
//!
//! This crate deliberately has zero dependency on `rlm-core`, `common`, or
//! any other workspace crate: the harness must be able to measure a machine
//! where rlm is not installed at all, since that is the control arm of
//! every comparison it produces.

pub mod proc_parse;

/// One measurement sample from the probe's sleep loop.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Tick {
    /// Milliseconds since probe start.
    pub t_ms: u64,
    /// `actual_elapsed - intended_interval`, in microseconds. May be negative
    /// (the loop woke early), though a plain `sleep`-based scheduler should
    /// only ever be late.
    pub drift_us: i64,
    /// Cumulative runqueue wait time (ns) at this tick, from
    /// `/proc/self/schedstat`.
    pub wait_ns: u64,
    /// Cumulative major faults at this tick, from `/proc/self/stat`.
    pub majflt: u64,
}
