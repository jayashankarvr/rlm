//! Formats guard state into the plain-text lines `rlm guard status` and
//! `rlm guard history` print. Pure string formatting only, so the CLI and
//! (later) the GUI can share it instead of duplicating the layout.

use super::history::HistoryEvent;
use super::journal::{JournalAction, JournalEntry};
use super::types::Sample;
use common::GuardTrigger;

/// One line describing a pressure sample: source, PSI averages, and
/// available memory. `available unknown` replaces the MB figures when
/// `/proc/meminfo` couldn't be read (`Sample::mem_available_mb == u64::MAX`
/// or `mem_total_mb == 0`, the sentinels `Sampler::sample` uses); printing
/// the raw sentinels (`18446744073709551615 MB of 0 MB`) would be nonsense.
pub fn pressure_line(s: &Sample) -> String {
    let avail = if s.mem_available_mb == u64::MAX || s.mem_total_mb == 0 {
        "available unknown".to_string()
    } else {
        let pct = s.mem_available_mb.saturating_mul(100) / s.mem_total_mb;
        format!(
            "{} MB of {} MB available ({pct}%)",
            s.mem_available_mb, s.mem_total_mb
        )
    };
    format!(
        "{}: some {:.1}% full {:.1}%, {avail}",
        s.source, s.some_avg10, s.full_avg10
    )
}

/// One line describing when the guard acts, from its configured trigger.
pub fn trigger_line(t: &GuardTrigger) -> String {
    format!(
        "acts when pressure is high and available memory is below {}% or {} MB",
        t.act_below_available_pct, t.mem_available_floor_mb
    )
}

/// One line describing a currently active intervention, from the guard's
/// write-ahead journal.
pub fn intervention_line(e: &JournalEntry) -> String {
    match e.action {
        JournalAction::Freeze => format!("{} frozen", e.cgroup),
        JournalAction::Cap => {
            let bytes = e
                .our_high
                .as_deref()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            format!("{} capped at {}", e.cgroup, common::format_bytes(bytes))
        }
    }
}

/// One line of `rlm guard history`: a right-aligned age, the event kind, the
/// app, and its detail.
pub fn history_line(e: &HistoryEvent, now: u64) -> String {
    let age = super::history::format_age(now, e.ts);
    format!("{age:>9}  {:<6}  {}  {}", e.kind.word(), e.app, e.detail)
}

/// The `Pressure:` line's text when `Sampler::sample` returned `None`:
/// neither PSI source could be read at all (both files missing, or neither
/// parsed). Pulled into its own function so `rlm guard status` and
/// `rlm guard test` show identical, accurate wording (fix round 1, Important
/// #1: the old text named only `/proc/pressure/memory`, but app.slice PSI is
/// checked first and can also be the one that failed).
pub fn pressure_unavailable() -> &'static str {
    "unavailable (neither app.slice nor system PSI could be read)"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::types::PsiSource;

    #[test]
    fn pressure_and_trigger_lines() {
        let s = Sample {
            some_avg10: 1.24,
            full_avg10: 0.0,
            mem_available_mb: 9000,
            mem_total_mb: 16000,
            source: PsiSource::AppSlice,
        };
        assert_eq!(
            pressure_line(&s),
            "app.slice: some 1.2% full 0.0%, 9000 MB of 16000 MB available (56%)"
        );
        assert_eq!(
            trigger_line(&common::GuardTrigger::default()),
            "acts when pressure is high and available memory is below 20% or 400 MB"
        );
    }

    /// Extra item #2 (Task 3 review minor): when `/proc/meminfo` couldn't be
    /// read, `Sampler::sample` reports the sentinels `mem_available_mb =
    /// u64::MAX` / `mem_total_mb = 0`. Printing those raw (`available
    /// 18446744073709551615 MB of 0 MB`) is nonsense; the line must say
    /// plainly that availability is unknown.
    #[test]
    fn unreadable_meminfo_prints_available_unknown() {
        let sentinel = Sample {
            some_avg10: 5.0,
            full_avg10: 1.0,
            mem_available_mb: u64::MAX,
            mem_total_mb: 0,
            source: PsiSource::System,
        };
        assert_eq!(
            pressure_line(&sentinel),
            "system: some 5.0% full 1.0%, available unknown"
        );
    }

    /// Fix round 1, Important #1: pin the exact wording `guard status`/
    /// `guard test` show when `Sampler::sample` returns `None` (no PSI
    /// source readable at all), so it can never regress to blaming a single
    /// file again.
    #[test]
    fn pressure_unavailable_names_both_sources() {
        assert_eq!(
            pressure_unavailable(),
            "unavailable (neither app.slice nor system PSI could be read)"
        );
    }
}
