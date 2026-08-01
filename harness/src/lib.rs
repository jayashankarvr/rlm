//! rlm stall-measurement harness — pure, unit-tested `/proc` parsers plus
//! the `Tick` type shared between the probe binary and later summary tools.
//!
//! This crate deliberately has zero dependency on `rlm-core`, `common`, or
//! any other workspace crate: the harness must be able to measure a machine
//! where rlm is not installed at all, since that is the control arm of
//! every comparison it produces.
//!
//! ## Why the probe runs as a pair, not a single process
//!
//! An mlocked probe can never major-fault — its pages are pinned resident by
//! `mlockall`, so it cannot measure residency pressure at all. An unlocked
//! probe's drift, on the other hand, conflates two different delays: time
//! spent waiting for a runqueue slot (scheduling) and time spent blocked on
//! a major fault (reclaim/refault). No single process can measure both the
//! scheduling-only baseline and the memory-induced component, because
//! locking out faults to measure scheduling cleanly is exactly what removes
//! the thing the treatment arm needs to expose.
//!
//! So the harness always runs a **pair**: [`ProbeMode::Locked`] is the
//! scheduling-only control (never major-faults by construction), and
//! [`ProbeMode::Touch`] is the treatment that actively re-touches its
//! working set and stays eligible for eviction. `touch − locked` isolates
//! the memory-induced component of stall — that difference is the number
//! later phases are judged on.
//!
//! Both modes perform an identical per-tick page walk over the anonymous
//! working set (same function, stride, byte count, order), so that walk's
//! CPU cost is symmetric and cancels in the subtraction — `locked`'s copy
//! of the walk can never fault (its pages are mlocked), so only `touch`'s
//! copy carries real fault behaviour. Only `touch` additionally re-reads a
//! file-backed mapping each tick; that asymmetry is intentional (it's the
//! treatment's actual point), so the residual `touch − locked` is the
//! file-backed-reclaim component plus any anon-reclaim effect — not CPU
//! noise from unequal per-tick work. See `rlm-probe.rs`'s module doc for
//! detail.

pub mod proc_parse;

/// Which half of the probe pair this process instance is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ProbeMode {
    /// Scheduling-only control: working set is pre-faulted then `mlockall`'d
    /// (`MCL_CURRENT | MCL_FUTURE`), so it can never major-fault. Its drift
    /// is scheduling delay only.
    Locked,
    /// Memory-pressure treatment: same working set, not locked, re-touched
    /// (write) every tick, plus a small file-backed mapping re-touched
    /// (read) every tick to keep file pages in play. Its drift conflates
    /// scheduling delay with fault delay; `touch − locked` recovers the
    /// fault-delay component.
    Touch,
}

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
