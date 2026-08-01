//! PSI (Pressure Stall Information) sampling — the system-level counterpart
//! to the per-process drift signal in `Tick`. Parses `/proc/pressure/<res>`
//! (`memory` or `io`) and reduces a run's samples to an exact stall count.
//!
//! ## Why the "integral" is a counter delta, not a trapezoid over `avg10`
//!
//! Each line of `/proc/pressure/<res>` reports `avgN` fields (exponential
//! moving averages of % time stalled, over the last 10/60/300s) and a
//! `total` field (cumulative microseconds stalled, monotonic, since boot —
//! an exact hardware-grade counter maintained by the kernel itself).
//!
//! It is tempting to reconstruct "how much stall happened during this run"
//! by trapezoid-integrating consecutive `avg10` samples over elapsed time.
//! That is wrong: `avg10` is *itself* a decaying average, so at any instant
//! it already reflects stall from earlier in its own window bleeding
//! forward. Integrating it over the sampling interval double-counts that
//! carried-forward stall — and because the decay window is fixed (10s)
//! while the sampling interval is a harness parameter, the amount of
//! double-counting *changes with `--interval-ms`*. The same underlying
//! stall event would integrate to a larger number at a faster sample rate
//! and a smaller number at a slower one, which makes the metric useless for
//! comparing runs, let alone machines.
//!
//! `total`, by contrast, is a plain monotonic counter the kernel increments
//! by the exact number of microseconds spent stalled. `stall_us` is defined
//! as `last.total - first.total`, `saturating_sub` so a counter reset (or a
//! kernel that doesn't guarantee monotonicity across some boundary we don't
//! know about) can never underflow into a huge `u64`. Do not "improve" this
//! into an average-based integral — see above for why that is a regression,
//! not an improvement.

use serde::{Deserialize, Serialize};

/// One PSI sample: both the decaying `avg10` figures (useful for eyeballing
/// a live run) and the exact cumulative `total` counters (what `stall_us`
/// actually uses).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PsiSample {
    /// Milliseconds since the sampler started.
    pub t_ms: u64,
    /// `some avg10=` — % of the last 10s at least one task was stalled.
    pub some_avg10: f64,
    /// `full avg10=` — % of the last 10s all non-idle tasks were stalled.
    pub full_avg10: f64,
    /// `some total=`, cumulative microseconds, monotonic.
    pub some_total_us: u64,
    /// `full total=`, cumulative microseconds, monotonic.
    pub full_total_us: u64,
}

/// Parse one `/proc/pressure/<res>` body into `(some_avg10, full_avg10,
/// some_total, full_total)`. Pure — no I/O. A missing `full` line (e.g. some
/// kernels omit it for `io` under certain configs) defaults both of its
/// fields to zero rather than failing the whole parse; a missing `some`
/// line (unexpected on any real kernel) is treated as unparseable.
pub fn parse_psi(body: &str) -> Option<(f64, f64, u64, u64)> {
    let mut some_avg10 = None;
    let mut some_total = None;
    let mut full_avg10 = 0.0;
    let mut full_total = 0u64;

    for line in body.lines() {
        // Fixed field order per line: "<kind> avg10=.. avg60=.. avg300=.. total=..".
        let mut fields = line.split_whitespace();
        let kind = fields.next()?;
        let avg10: f64 = fields.next()?.strip_prefix("avg10=")?.parse().ok()?;
        fields.next()?; // avg60=..., unused
        fields.next()?; // avg300=..., unused
        let total: u64 = fields.next()?.strip_prefix("total=")?.parse().ok()?;

        match kind {
            "some" => {
                some_avg10 = Some(avg10);
                some_total = Some(total);
            }
            "full" => {
                full_avg10 = avg10;
                full_total = total;
            }
            _ => {}
        }
    }

    Some((some_avg10?, full_avg10, some_total?, full_total))
}

/// The PSI "integral" over a run: the exact delta of the kernel's own
/// `total` counters (microseconds stalled), NOT a trapezoid over `avg10`
/// samples — see the module doc for why an average-based integral would be
/// a sampling-rate-dependent bug, not a refinement. `saturating_sub` so a
/// counter reset between `first` and `last` can never underflow into a
/// huge `u64`; a reset instead reports 0 stall for that (invalid) span.
pub fn stall_us(first: &PsiSample, last: &PsiSample) -> (u64, u64) {
    (
        last.some_total_us.saturating_sub(first.some_total_us),
        last.full_total_us.saturating_sub(first.full_total_us),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psi_parses_some_and_full_with_totals() {
        let b = "some avg10=12.34 avg60=5.00 avg300=1.00 total=999999\n\
                 full avg10=3.21 avg60=2.00 avg300=0.50 total=42424\n";
        assert_eq!(parse_psi(b), Some((12.34, 3.21, 999999, 42424)));
    }

    #[test]
    fn psi_missing_full_defaults_zero() {
        let b = "some avg10=1.00 avg60=0.00 avg300=0.00 total=10\n";
        assert_eq!(parse_psi(b), Some((1.0, 0.0, 10, 0)));
    }

    #[test]
    fn stall_us_is_counter_delta_not_average_integral() {
        let a = PsiSample {
            t_ms: 0,
            some_avg10: 0.0,
            full_avg10: 0.0,
            some_total_us: 1000,
            full_total_us: 100,
        };
        let b = PsiSample {
            t_ms: 60_000,
            some_avg10: 50.0,
            full_avg10: 10.0,
            some_total_us: 31_000,
            full_total_us: 5_100,
        };
        assert_eq!(stall_us(&a, &b), (30_000, 5_000));
    }

    #[test]
    fn stall_us_tolerates_counter_reset() {
        // If the second sample is lower (shouldn't happen, but don't underflow).
        let a = PsiSample {
            t_ms: 0,
            some_avg10: 0.0,
            full_avg10: 0.0,
            some_total_us: 500,
            full_total_us: 50,
        };
        let b = PsiSample {
            t_ms: 1000,
            some_avg10: 0.0,
            full_avg10: 0.0,
            some_total_us: 10,
            full_total_us: 5,
        };
        assert_eq!(stall_us(&a, &b), (0, 0));
    }
}
