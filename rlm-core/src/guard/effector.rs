//! Executes [`Action`]s against real cgroups, acting in place on the cgroup a
//! process already lives in (a systemd unit's scope/service, or an existing
//! rlm rule cgroup) rather than moving it into an ephemeral `guard-<pid>`
//! cgroup. Every action is best-effort and logged; a failure must never
//! panic or otherwise crash the daemon loop. `apply` may return `Err` so the
//! caller can log it, but a missing `notify-send` (or any other notification
//! failure) is never treated as an error.
//!
//! # Write-ahead journal
//! Freeze/Cap always `journal.append` (which fsyncs) *before* touching the
//! cgroup, so a crash between the two still leaves a durable record that
//! startup recovery (`sweep_leftovers`) can replay. `Journal` is internally
//! mutex-serialized (see `journal.rs`), and the daemon calls into this
//! `Effector` from a single thread (the tick loop in `rlm-guard`'s `main`),
//! so `Effector` just holds a `&Journal` and relies on the daemon's
//! single-threaded call discipline plus the journal's own internal locking
//! for safety — it adds no locking of its own.
//!
//! # Mechanism: systemd unit vs. raw cgroupfs
//! When a target resolved to a systemd unit (`Mechanism::Unit`), we prefer
//! the D-Bus call (`FreezeUnit`/`ThawUnit`/`SetUnitProperties`) with a hard
//! 2s timeout (`systemd::SystemdUser`'s own enforced deadline); on `Err` (bus
//! unavailable, call failed, or timed out) we fall back to the raw cgroupfs
//! primitives in `cgfs`. Raw-mechanism targets (rlm's own rule cgroups) skip
//! the D-Bus attempt entirely. Thawing is mechanism-independent: we always
//! attempt `ThawUnit` best-effort *and* always perform the raw
//! `cgroup.freeze` write afterward, unconditionally — this guarantees a
//! cgroup is never left frozen just because the D-Bus call "succeeded" on a
//! stale unit, and tolerates a missing cgroup (the raw write simply errors
//! and we move on).
//!
//! # Restoring `memory.high`
//! The kernel truncates `memory.high` writes to page multiples, so the byte
//! count we cap to is page-aligned *before* we journal/write it
//! ([`page_align_down`]); as a second line of defense, [`Effector::cap`]
//! reads `memory.high` back after writing and self-corrects the journal if
//! reality still differs (e.g. a systemd-side reformat via the D-Bus path).
//! Restoring on `LiftCap`/replay always clears systemd's runtime
//! `MemoryHigh` property *before* raw-writing `prev_high` back — the other
//! order lets systemd's own `"max"` write clobber the value we just
//! restored. If more than one journal entry ever coexists for the same
//! cgroup (a leak from an incomplete prior removal), every restore path
//! treats them as one chain: liveness is judged against the newest entry,
//! but the value restored is always the *oldest* entry's `prev_high` — the
//! true pre-intervention value, not an intermediate entry's `prev_high`
//! (which is just our own previous `our_high`). See [`restore_target`].

use super::cgfs;
use super::journal::{should_restore, Journal, JournalAction, JournalEntry};
use super::resolve::{Mechanism, Resolution};
use super::systemd::SystemdUser;
use super::types::Action;
use crate::CgroupManager;
use common::Result;
use std::process::Command;
use std::time::Duration;

/// Fallback/floor soft-cap when a cgroup's anon+swap usage can't be read or
/// is implausibly small. 64 MiB is low enough to apply real pressure yet
/// high enough to avoid pinning a process into a thrash loop.
const MIN_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Hard deadline for every D-Bus call on the freeze-guard's storm path. On
/// `Err` (including a timeout) callers fall back to raw cgroupfs writes.
const DBUS_TIMEOUT: Duration = Duration::from_secs(2);

/// Applies guard [`Action`]s in place on the resolved target cgroup, via the
/// systemd-unit D-Bus path (with raw-cgroup fallback) and a write-ahead
/// [`Journal`] for crash-safe restore.
pub struct Effector<'a> {
    /// Kept only for the legacy `guard-<pid>` sweep during the upgrade path
    /// (see [`Effector::sweep_leftovers`]); acting in place no longer uses it.
    manager: &'a CgroupManager,
    journal: &'a Journal,
    systemd: Option<&'a SystemdUser>,
}

impl<'a> Effector<'a> {
    pub fn new(
        manager: &'a CgroupManager,
        journal: &'a Journal,
        systemd: Option<&'a SystemdUser>,
    ) -> Self {
        Self {
            manager,
            journal,
            systemd,
        }
    }

    /// Apply a single action. Best-effort: returns `Err` only so the caller can
    /// log it (a [`Action::Notify`] always returns `Ok`).
    pub fn apply(&self, action: &Action) -> Result<()> {
        match action {
            Action::Freeze { res, name } => self.freeze(res, name),
            Action::Thaw { res } => self.thaw(res),
            Action::Cap { res, name } => self.cap(res, name),
            Action::LiftCap { res } => self.lift_cap(res),
            Action::Notify { message } => {
                notify(message);
                // Notification is always best-effort and never fails the caller.
                Ok(())
            }
        }
    }

    fn freeze(&self, res: &Resolution, name: &str) -> Result<()> {
        let entry = JournalEntry {
            cgroup: res.cgroup.clone(),
            inode: cgfs::dir_inode(&res.cgroup).unwrap_or(0),
            unit: res.unit.clone(),
            action: JournalAction::Freeze,
            prev_high: None,
            our_high: None,
        };
        // Write-ahead: the entry must be durable (journal.append fsyncs)
        // before we ever touch the cgroup, so a crash between the two still
        // leaves a record startup recovery can act on.
        self.journal.append(&entry)?;

        tracing::info!(cgroup = %res.cgroup, name, "freezing cgroup");
        if res.mechanism == Mechanism::Unit {
            if let (Some(unit), Some(systemd)) = (&res.unit, self.systemd) {
                match systemd.freeze_unit(unit, DBUS_TIMEOUT) {
                    Ok(()) => return Ok(()),
                    Err(e) => tracing::warn!(
                        cgroup = %res.cgroup, unit, error = %e,
                        "FreezeUnit failed; falling back to raw cgroup.freeze"
                    ),
                }
            }
        }
        cgfs::write_freeze(&res.cgroup, true)
    }

    fn thaw(&self, res: &Resolution) -> Result<()> {
        tracing::info!(cgroup = %res.cgroup, "thawing cgroup");
        // Gather any coexisting entries for this cgroup first: a `Thaw`
        // action reverses a Frozen intervention, but if a Cap entry ever
        // leaked alongside it (Important #3, Task 6 review) we must still
        // restore its memory.high before wiping the journal record below,
        // not just drop it silently.
        let entries = self.entries_for(&res.cgroup);
        let result = self.thaw_raw(&res.cgroup, res.unit.as_deref());
        if let Err(e) = &result {
            tracing::debug!(cgroup = %res.cgroup, error = %e, "raw thaw failed (cgroup may already be gone)");
        }
        self.restore_high_if_any(&res.cgroup, &entries);
        self.journal.remove(&res.cgroup)?;
        result
    }

    fn cap(&self, res: &Resolution, name: &str) -> Result<()> {
        let prev_high = cgfs::read_high(&res.cgroup);
        // The kernel truncates `memory.high` writes to page multiples, so we
        // must journal/write the value it will actually store — not the raw
        // 90%-of-anon target — or `should_restore`'s string-equality check
        // can never pass again and the cap becomes permanent (Task 6 review,
        // Critical #1).
        let our_bytes = page_align_down(
            cap_from_anon(cgfs::anon_swap_bytes(&res.cgroup)),
            page_size(),
        );
        // Plain decimal bytes, no separators/whitespace: this must be
        // exactly what a later `cgfs::read_high` (which only trims
        // whitespace off the raw file contents) returns. `u64::to_string()`
        // never inserts separators, so the round trip through `write_high`
        // (writes verbatim) -> `read_high` (trims) is exact once the value
        // is page-aligned. See `our_high_string_is_plain_decimal_no_separators`
        // below, and `reconcile_our_high` for the belt-and-braces check.
        let our_high = our_bytes.to_string();

        let entry = JournalEntry {
            cgroup: res.cgroup.clone(),
            inode: cgfs::dir_inode(&res.cgroup).unwrap_or(0),
            unit: res.unit.clone(),
            action: JournalAction::Cap,
            prev_high,
            our_high: Some(our_high.clone()),
        };
        self.journal.append(&entry)?;

        tracing::info!(cgroup = %res.cgroup, name, our_high = %our_high, "soft-capping cgroup");
        let result = if res.mechanism == Mechanism::Unit {
            match (&res.unit, self.systemd) {
                (Some(unit), Some(systemd)) => {
                    match systemd.set_memory_high(unit, our_bytes, DBUS_TIMEOUT) {
                        Ok(()) => Ok(()),
                        Err(e) => {
                            tracing::warn!(
                                cgroup = %res.cgroup, unit, error = %e,
                                "SetUnitProperties(MemoryHigh) failed; falling back to raw memory.high write"
                            );
                            cgfs::write_high(&res.cgroup, &our_high)
                        }
                    }
                }
                _ => cgfs::write_high(&res.cgroup, &our_high),
            }
        } else {
            cgfs::write_high(&res.cgroup, &our_high)
        };

        if result.is_ok() {
            self.reconcile_our_high(&entry);
        }
        result
    }

    /// After a successful `Cap` write, read `memory.high` back; if what's
    /// actually on disk differs from what we journaled (page truncation we
    /// didn't fully pre-empt, or a systemd-side reformat via the D-Bus
    /// path), correct the journal to match reality — otherwise
    /// `should_restore`'s string-equality check can never pass again and
    /// the cap becomes permanent (Task 6 review, Critical #1). Rebuilds
    /// only this cgroup's entries, preserving any others that might coexist
    /// (Important #3), with `written`'s `our_high` corrected to the
    /// read-back value.
    fn reconcile_our_high(&self, written: &JournalEntry) {
        let cgroup: &str = &written.cgroup;
        let Some(actual) = cgfs::read_high(cgroup) else {
            return;
        };
        if written.our_high.as_deref() == Some(actual.as_str()) {
            return;
        }
        tracing::warn!(
            cgroup = %cgroup, journaled = ?written.our_high, actual = %actual,
            "memory.high on disk differs from what we journaled; correcting journal entry"
        );
        let mut entries = self.journal.entries();
        let Some(pos) = entries.iter().rposition(|e| e == written) else {
            // Already removed/replaced by something else (e.g. a concurrent
            // Thaw/LiftCap) — nothing left to correct.
            return;
        };
        entries[pos].our_high = Some(actual);
        if let Err(e) = self.journal.remove(cgroup) {
            tracing::warn!(cgroup = %cgroup, error = %e, "failed to remove stale journal entry during our_high correction");
            return;
        }
        for e in entries.iter().filter(|e| e.cgroup == cgroup) {
            if let Err(e2) = self.journal.append(e) {
                tracing::warn!(cgroup = %cgroup, error = %e2, "failed to re-append journal entry during our_high correction");
            }
        }
    }

    fn lift_cap(&self, res: &Resolution) -> Result<()> {
        tracing::info!(cgroup = %res.cgroup, "lifting cap");
        let entries = self.entries_for(&res.cgroup);
        // Mechanism-independent thaw always runs, regardless of whether any
        // journal record exists — a dead-cgroup prune (carry-forward
        // finding, Task 5 review) must never leave a target frozen just
        // because we lost the journal entry.
        let _ = self.thaw_raw(&res.cgroup, res.unit.as_deref());
        self.restore_high_if_any(&res.cgroup, &entries);
        self.journal.remove(&res.cgroup)
    }

    /// All journal entries for one cgroup, in the order `Journal::entries()`
    /// returns them — oldest-first, since entries are strictly appended.
    fn entries_for(&self, cgroup: &str) -> Vec<JournalEntry> {
        self.journal
            .entries()
            .into_iter()
            .filter(|e| e.cgroup == cgroup)
            .collect()
    }

    /// Startup recovery: legacy `guard-<pid>` sweep (kept for one release as
    /// an upgrade path from pre-act-in-place rlm), then replay every live
    /// journal entry.
    pub fn sweep_leftovers(&self) -> Result<()> {
        if let Err(e) = self.manager.sweep_guard_leftovers() {
            tracing::warn!(error = %e, "legacy guard-<pid> sweep failed (non-fatal)");
        }
        self.replay_and_clear()
    }

    /// Graceful shutdown: undo every live journal entry, then clear the
    /// journal. Same replay as `sweep_leftovers`, minus the legacy sweep.
    pub fn undo_all(&self) -> Result<()> {
        self.replay_and_clear()
    }

    fn replay_and_clear(&self) -> Result<()> {
        // Group by cgroup first (entries for the same cgroup aren't
        // necessarily contiguous in the file) so each cgroup's chain is
        // replayed as one unit — see `restore_high_if_any` — rather than
        // entry-by-entry, which would mis-restore whenever more than one
        // entry coexists for a cgroup (Important #3, Task 6 review).
        let mut by_cgroup: std::collections::HashMap<String, Vec<JournalEntry>> =
            std::collections::HashMap::new();
        for e in self.journal.entries() {
            by_cgroup.entry(e.cgroup.clone()).or_default().push(e);
        }
        for (cgroup, entries) in &by_cgroup {
            let unit = entries.last().and_then(|e| e.unit.clone());
            let _ = self.thaw_raw(cgroup, unit.as_deref());
            self.restore_high_if_any(cgroup, entries);
        }
        self.journal.clear()
    }

    /// Restore `memory.high` for one cgroup's journal `entries` (oldest-first),
    /// if the chain is still live — called *after* the caller has already
    /// performed the mechanism-independent thaw (see module docs: no path
    /// here ever means "leave frozen"). Liveness is judged against the
    /// *newest* entry via [`restore_step`] (that's the entry whose write
    /// should currently be reflected on disk, if nothing else touched it
    /// since); the value actually restored is always [`restore_target`]'s
    /// oldest-entry `prev_high` — the true pre-intervention value, not any
    /// intermediate entry's `prev_high` (Important #3, Task 6 review).
    /// Clears systemd's runtime `MemoryHigh` property *before* raw-writing
    /// `prev_high` back — the other order lets systemd's own `"max"` write
    /// clobber the value we just restored (Critical #2, Task 6 review).
    fn restore_high_if_any(&self, cgroup: &str, entries: &[JournalEntry]) {
        let Some(newest) = entries.last() else {
            return;
        };
        let inode = cgfs::dir_inode(cgroup);
        let high = cgfs::read_high(cgroup);
        match restore_step(newest, inode, high.as_deref()) {
            RestoreStep::ThawAndRestoreHigh { .. } => {
                let Some(to) = restore_target(entries) else {
                    return;
                };
                if let Some(unit) = newest.unit.as_deref() {
                    if let Some(systemd) = self.systemd {
                        if let Err(err) = systemd.set_memory_high(unit, u64::MAX, DBUS_TIMEOUT) {
                            tracing::debug!(
                                cgroup, unit, error = %err,
                                "clearing systemd MemoryHigh runtime property failed"
                            );
                        }
                    }
                }
                if let Err(err) = cgfs::write_high(cgroup, &to) {
                    tracing::warn!(cgroup, error = %err, "failed to restore memory.high");
                }
            }
            RestoreStep::ThawOnly => {}
            RestoreStep::SkipRemove => {
                tracing::info!(
                    cgroup,
                    "not restoring memory.high (cgroup recreated or value changed since our write)"
                );
            }
        }
    }

    /// Mechanism-independent thaw: best-effort `ThawUnit` first (if we have a
    /// unit and a bus), then an *unconditional* raw `cgroup.freeze` write —
    /// this always runs, regardless of mechanism or whether `ThawUnit`
    /// succeeded, so a cgroup is never left frozen. Tolerates a missing
    /// cgroup: the raw write then simply returns `Err`, which every caller
    /// here treats as non-fatal.
    fn thaw_raw(&self, cgroup: &str, unit: Option<&str>) -> Result<()> {
        if let (Some(unit), Some(systemd)) = (unit, self.systemd) {
            if let Err(e) = systemd.thaw_unit(unit, DBUS_TIMEOUT) {
                tracing::debug!(cgroup, unit, error = %e, "ThawUnit failed; raw thaw still runs");
            }
        }
        cgfs::write_freeze(cgroup, false)
    }
}

/// What to do with one journal entry's `memory.high` at restore time. Never
/// speaks to freeze/thaw — that is unconditional and already handled by the
/// caller (`Effector::thaw_raw`) before `restore_step` is even consulted, so
/// no variant here can ever mean "leave it frozen".
#[derive(Debug, PartialEq, Eq)]
pub enum RestoreStep {
    /// A `Freeze` entry whose guard still holds: nothing to restore, thaw
    /// (already done by the caller) was the whole job.
    ThawOnly,
    /// A `Cap` entry whose guard still holds: restore `memory.high` to `to`
    /// (the entry's `prev_high`, "max" if it was never recorded).
    ThawAndRestoreHigh { to: String },
    /// The guard no longer holds (cgroup recreated, or someone else changed
    /// `memory.high` since our write): don't touch `memory.high`, just let
    /// the caller remove the journal entry.
    SkipRemove,
}

/// Pure: what to do for one journal entry at restore time, delegating the
/// safety check to [`should_restore`].
pub fn restore_step(e: &JournalEntry, inode: Option<u64>, high: Option<&str>) -> RestoreStep {
    if !should_restore(e, inode, high) {
        return RestoreStep::SkipRemove;
    }
    match e.action {
        JournalAction::Freeze => RestoreStep::ThawOnly,
        JournalAction::Cap => RestoreStep::ThawAndRestoreHigh {
            to: e.prev_high.clone().unwrap_or_else(|| "max".into()),
        },
    }
}

/// Pure helper: 90% of a cgroup's anon+swap usage, clamped to a
/// [`MIN_CAP_BYTES`] floor, falling back to the floor entirely when the
/// usage couldn't be read. `anon+swap` is the cgroup-level equivalent of a
/// single process's RSS+swap used by the old pid-based cap; sourcing it from
/// the whole cgroup (not one process) is correct now that we cap in place.
pub fn cap_from_anon(anon_swap: Option<u64>) -> u64 {
    anon_swap
        .map(|b| (b / 10 * 9).max(MIN_CAP_BYTES))
        .unwrap_or(MIN_CAP_BYTES)
}

/// Pure: given all journal entries for one cgroup, oldest-first, select the
/// `memory.high` value to restore, if the chain contains a `Cap` entry. The
/// OLDEST `Cap` entry's `prev_high` is the true pre-intervention value — a
/// later entry's `prev_high` is just our own previous `our_high` from an
/// earlier cap in the same chain, not the original (Task 6 review,
/// Important #3). Returns `None` if there's no `Cap` entry (e.g. a
/// `Freeze`-only chain).
pub fn restore_target(entries: &[JournalEntry]) -> Option<String> {
    entries
        .iter()
        .find(|e| e.action == JournalAction::Cap)
        .map(|e| e.prev_high.clone().unwrap_or_else(|| "max".into()))
}

/// Runtime page size in bytes, via `sysconf(_SC_PAGESIZE)`. Falls back to
/// 4096 (by far the most common value) only if the syscall ever returns
/// something nonsensical — a defensive fallback, not the source of truth,
/// since the whole point is to match whatever the kernel actually enforces.
fn page_size() -> u64 {
    // SAFETY: sysconf(_SC_PAGESIZE) reads a static system parameter; no
    // pointers involved, no side effects.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p > 0 {
        p as u64
    } else {
        4096
    }
}

/// Pure: round `bytes` down to a multiple of `page` (a no-op if `page` is 0).
/// The kernel truncates `memory.high` writes to page multiples (Task 6
/// review, Critical #1), so we must journal/write the value it will
/// actually store, not the pre-truncation target — otherwise
/// `should_restore`'s string-equality check can never pass again and a cap
/// becomes permanent.
fn page_align_down(bytes: u64, page: u64) -> u64 {
    bytes.checked_div(page).map_or(bytes, |q| q * page)
}

/// Best-effort desktop notification via `notify-send`. Silently does nothing if
/// the binary is missing or the spawn fails — notifications must never break the
/// guard.
fn notify(message: &str) {
    match Command::new("notify-send")
        .arg("rlm-guard")
        .arg(message)
        .spawn()
    {
        Ok(mut child) => {
            // Reap asynchronously so we don't block; ignore any wait error.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => {
            tracing::debug!(error = %e, "notify-send unavailable; skipping notification");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::resolve::{Coverage, Verdict};
    use super::*;

    #[test]
    fn cap_from_anon_sizes_and_floors() {
        assert_eq!(cap_from_anon(Some(1_000_000_000)), 900_000_000);
        assert_eq!(cap_from_anon(Some(1_000_000)), MIN_CAP_BYTES);
        assert_eq!(cap_from_anon(None), MIN_CAP_BYTES);
    }

    /// Carry-forward (Task 3 review): `our_high` must be a plain decimal
    /// string with no grouping/whitespace, since `should_restore` compares
    /// it by string equality against `cgfs::read_high` (which only trims).
    #[test]
    fn our_high_string_is_plain_decimal_no_separators() {
        let bytes = cap_from_anon(Some(12_345_678_900));
        let s = bytes.to_string();
        assert!(
            s.chars().all(|c| c.is_ascii_digit()),
            "our_high must be plain digits, got {s:?}"
        );
        assert_eq!(s, format!("{bytes}"), "no formatting beyond plain decimal");
    }

    /// Task 6 review, Critical #1: the kernel truncates `memory.high`
    /// writes to page multiples (the reviewer's own observed example:
    /// writing 900_000_000 with a 4096-byte page reads back 899_997_696).
    #[test]
    fn page_align_down_rounds_to_page_multiple() {
        assert_eq!(page_align_down(900_000_000, 4096), 899_997_696);
        assert_eq!(
            page_align_down(4096, 4096),
            4096,
            "already-aligned is a no-op"
        );
        assert_eq!(page_align_down(100, 0), 100, "page=0 guard is a no-op");
    }

    /// Task 6 review, Important #3: when duplicate/stacked `Cap` entries end
    /// up coexisting for one cgroup (a leak from an incomplete prior
    /// removal), the restore target must be the OLDEST entry's `prev_high`
    /// — the true pre-intervention value. The newer entry's `prev_high` is
    /// deliberately a different-looking value here to prove we don't
    /// chain-follow it.
    #[test]
    fn restore_target_uses_oldest_caps_prev_high() {
        let oldest = entry_cap("/x", 42, "max", "A");
        let newest = entry_cap("/x", 42, "A-prime", "B");
        assert_eq!(
            restore_target(&[oldest, newest]),
            Some("max".into()),
            "must use the oldest entry's prev_high, not the newest's"
        );
    }

    #[test]
    fn restore_target_none_for_freeze_only_chain() {
        assert_eq!(restore_target(&[entry_freeze("/x", 42)]), None);
    }

    fn entry_cap(cg: &str, inode: u64, prev: &str, our: &str) -> JournalEntry {
        JournalEntry {
            cgroup: cg.into(),
            inode,
            unit: None,
            action: JournalAction::Cap,
            prev_high: Some(prev.into()),
            our_high: Some(our.into()),
        }
    }

    fn entry_freeze(cg: &str, inode: u64) -> JournalEntry {
        JournalEntry {
            cgroup: cg.into(),
            inode,
            unit: None,
            action: JournalAction::Freeze,
            prev_high: None,
            our_high: None,
        }
    }

    #[test]
    fn restore_step_matrix() {
        let cap = entry_cap("/x", 42, "max", "1000");
        assert_eq!(
            restore_step(&cap, Some(42), Some("1000")),
            RestoreStep::ThawAndRestoreHigh { to: "max".into() }
        );
        assert_eq!(
            restore_step(&cap, Some(43), Some("1000")),
            RestoreStep::SkipRemove
        );
        assert_eq!(
            restore_step(&cap, Some(42), Some("777")),
            RestoreStep::SkipRemove
        );
        let frz = entry_freeze("/x", 42);
        assert_eq!(
            restore_step(&frz, Some(42), None),
            RestoreStep::ThawOnly,
            "alive freeze entry: nothing to restore beyond the unconditional thaw"
        );
        assert_eq!(
            restore_step(&frz, None, None),
            RestoreStep::SkipRemove,
            "dead cgroup: restore_step only decides memory.high, never freeze — the \
             unconditional thaw in Effector::thaw_raw already ran before this is consulted, \
             so a still-frozen dead cgroup is never left behind (carry-forward: Task 5 review)"
        );
    }

    /// Poll `cgfs::read_frozen` until it matches `want` or `timeout` elapses.
    /// Writing `cgroup.freeze` only *requests* a state change; `cgroup.events`'s
    /// `frozen` field (what `read_frozen` reads) only flips once the kernel has
    /// actually quiesced every task in the cgroup, which can lag the write by a
    /// few milliseconds under load — so a bare immediate read is flaky.
    fn wait_for_frozen(cgroup: &str, want: bool, timeout: Duration) -> Option<bool> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let got = cgfs::read_frozen(cgroup);
            if got == Some(want) || std::time::Instant::now() >= deadline {
                return got;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn test_resolution(cgroup: String) -> Resolution {
        Resolution {
            cgroup,
            unit: None,
            verdict: Verdict::Freeze,
            coverage: Coverage::Full,
            mechanism: Mechanism::Raw,
        }
    }

    /// Integration smoke test: freeze a real `sleep` via its (raw, rlm-created)
    /// cgroup through the journal-backed Effector, confirm it's paused via
    /// `cgroup.freeze` and journaled, then thaw and confirm the journal entry
    /// is gone. Only works under cgroup v2 delegation, so it's `#[ignore]`d.
    #[test]
    #[ignore = "requires cgroup v2 delegation; run manually"]
    fn freeze_thaw_real_process_raw_cgroup() {
        use common::Limit;
        use std::process::Command;

        let manager = CgroupManager::new().expect("create CgroupManager");
        let journal_dir = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(journal_dir.path().join("j.jsonl"), "test-boot".into()).unwrap();
        let effector = Effector::new(&manager, &journal, None);

        let abs_path = manager
            .prepare_cgroup("test-freeze-thaw", &Limit::default())
            .expect("create test cgroup");
        let cgroup = format!(
            "/{}",
            abs_path
                .strip_prefix("/sys/fs/cgroup")
                .expect("cgroup under /sys/fs/cgroup")
                .display()
        );

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        manager
            .add_to_cgroup(&abs_path, pid)
            .expect("add sleep to test cgroup");

        let res = test_resolution(cgroup.clone());

        effector
            .apply(&Action::Freeze {
                res: res.clone(),
                name: "sleep".into(),
            })
            .expect("freeze");

        assert_eq!(
            wait_for_frozen(&cgroup, true, Duration::from_secs(2)),
            Some(true),
            "cgroup should be frozen"
        );
        assert_eq!(journal.entries().len(), 1, "freeze should be journaled");

        effector
            .apply(&Action::Thaw { res: res.clone() })
            .expect("thaw");

        assert_eq!(
            wait_for_frozen(&cgroup, false, Duration::from_secs(2)),
            Some(false),
            "cgroup should be thawed"
        );
        assert!(
            journal.entries().is_empty(),
            "journal entry should be removed after thaw"
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = manager.cleanup_cgroup("test-freeze-thaw");
    }

    /// Act-in-place integration test: freeze/thaw a real transient systemd
    /// `--user --scope` unit through the Unit mechanism (D-Bus, with raw
    /// fallback), confirming the journal-backed round trip end to end.
    /// Requires a session bus and cgroup v2 delegation, so it's `#[ignore]`d.
    #[test]
    #[ignore = "requires a session bus and cgroup v2 delegation; run manually"]
    fn freeze_thaw_real_transient_scope() {
        use std::process::Command;

        let uid_out = Command::new("id").arg("-u").output().expect("id -u");
        let uid: u32 = String::from_utf8_lossy(&uid_out.stdout)
            .trim()
            .parse()
            .expect("parse uid");

        let unit_base = format!("rlm-e2e-{}", std::process::id());
        let unit = format!("{unit_base}.scope");
        let cgroup = format!("/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{unit}");

        let mut child = Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                "--slice=app.slice",
                &format!("--unit={unit_base}"),
                "--",
                "sleep",
                "30",
            ])
            .spawn()
            .expect("spawn systemd-run --scope");

        // Give systemd a moment to register the transient scope's cgroup.
        std::thread::sleep(Duration::from_millis(300));

        let manager = CgroupManager::new().expect("create CgroupManager");
        let journal_dir = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(journal_dir.path().join("j.jsonl"), "test-boot".into()).unwrap();
        let systemd = SystemdUser::connect();
        let effector = Effector::new(&manager, &journal, systemd.as_ref());

        let res = Resolution {
            cgroup: cgroup.clone(),
            unit: Some(unit),
            verdict: Verdict::Freeze,
            coverage: Coverage::Full,
            mechanism: Mechanism::Unit,
        };

        effector
            .apply(&Action::Freeze {
                res: res.clone(),
                name: "sleep".into(),
            })
            .expect("freeze");
        assert_eq!(
            wait_for_frozen(&cgroup, true, Duration::from_secs(2)),
            Some(true),
            "scope cgroup should be frozen"
        );
        assert_eq!(journal.entries().len(), 1, "freeze should be journaled");

        effector.apply(&Action::Thaw { res }).expect("thaw");
        assert_eq!(
            wait_for_frozen(&cgroup, false, Duration::from_secs(2)),
            Some(false),
            "scope cgroup should be thawed"
        );
        assert!(
            journal.entries().is_empty(),
            "journal entry should be removed after thaw"
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &format!("{unit_base}.scope")])
            .status();
    }

    /// Regression test for Task 6 review Critical #1: cap a real cgroup and
    /// assert `cgfs::read_high` matches the journaled `our_high` exactly —
    /// i.e. the value we wrote never got silently page-truncated out from
    /// under the journal. The target process holds a chunk of random anon
    /// memory so 90% of its usage is very unlikely to already sit on a page
    /// boundary (MIN_CAP_BYTES, a round power of two, would pass even
    /// without the fix, which would prove nothing). Requires cgroup v2
    /// delegation, so it's `#[ignore]`d.
    #[test]
    #[ignore = "requires cgroup v2 delegation; run manually"]
    fn cap_page_aligns_and_journal_matches_on_disk_value() {
        use common::Limit;
        use std::process::Command;

        let manager = CgroupManager::new().expect("create CgroupManager");
        let journal_dir = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(journal_dir.path().join("j.jsonl"), "test-boot".into()).unwrap();
        let effector = Effector::new(&manager, &journal, None);

        let abs_path = manager
            .prepare_cgroup("test-cap-align", &Limit::default())
            .expect("create test cgroup");
        let cgroup = format!(
            "/{}",
            abs_path
                .strip_prefix("/sys/fs/cgroup")
                .expect("cgroup under /sys/fs/cgroup")
                .display()
        );

        // Hold ~150MB of anon memory whose 90% is very unlikely to land on
        // a page boundary, then sleep.
        let mut child = Command::new("bash")
            .arg("-c")
            .arg("a=$(head -c 150000000 /dev/urandom | base64 -w0); sleep 30")
            .spawn()
            .expect("spawn memory-holding process");
        let pid = child.id();
        manager
            .add_to_cgroup(&abs_path, pid)
            .expect("add process to test cgroup");
        // Give the shell time to actually build up the anon allocation.
        std::thread::sleep(Duration::from_millis(800));

        let res = test_resolution(cgroup.clone());
        effector
            .apply(&Action::Cap {
                res: res.clone(),
                name: "mem-hog".into(),
            })
            .expect("cap");

        let entries = journal.entries();
        assert_eq!(entries.len(), 1, "cap should be journaled");
        let journaled = entries[0].our_high.clone().expect("our_high recorded");

        let on_disk = cgfs::read_high(&cgroup).expect("read memory.high");
        assert_eq!(
            on_disk, journaled,
            "on-disk memory.high must match the journaled our_high exactly"
        );

        let bytes: u64 = journaled.parse().expect("our_high is a plain decimal");
        assert_eq!(bytes % page_size(), 0, "written value must be page-aligned");

        effector.apply(&Action::LiftCap { res }).expect("lift cap");
        assert!(
            journal.entries().is_empty(),
            "journal entry removed after lift"
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = manager.cleanup_cgroup("test-cap-align");
    }

    /// Regression test for Task 6 review Critical #2: a real systemd unit
    /// with a genuine prior `MemoryHigh` (so `prev_high` isn't already
    /// `"max"`, which would pass either ordering) is capped then
    /// lift-capped through the `Unit` mechanism. Before the fix,
    /// `set_memory_high(unit, u64::MAX)` ran *after* the raw restore write
    /// and clobbered it back to `"max"`; after the fix (clear the systemd
    /// property first, restore second) the original value survives.
    /// Requires a session bus and cgroup v2 delegation, so it's `#[ignore]`d.
    #[test]
    #[ignore = "requires a session bus and cgroup v2 delegation; run manually"]
    fn lift_cap_restores_prev_high_not_clobbered_by_systemd_max() {
        use std::process::Command;

        let uid_out = Command::new("id").arg("-u").output().expect("id -u");
        let uid: u32 = String::from_utf8_lossy(&uid_out.stdout)
            .trim()
            .parse()
            .expect("parse uid");

        let unit_base = format!("rlm-e2e-cap-{}", std::process::id());
        let unit = format!("{unit_base}.scope");
        let cgroup = format!("/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/{unit}");

        let mut child = Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                "--slice=app.slice",
                &format!("--unit={unit_base}"),
                // A genuine prior MemoryHigh, distinct from both "max" and
                // whatever Cap computes, so the restored value is
                // unambiguous.
                "--property=MemoryHigh=1500M",
                "--",
                "sleep",
                "30",
            ])
            .spawn()
            .expect("spawn systemd-run --scope with MemoryHigh set");

        std::thread::sleep(Duration::from_millis(300));

        let manager = CgroupManager::new().expect("create CgroupManager");
        let journal_dir = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(journal_dir.path().join("j.jsonl"), "test-boot".into()).unwrap();
        let systemd = SystemdUser::connect();
        let effector = Effector::new(&manager, &journal, systemd.as_ref());

        let original_high =
            cgfs::read_high(&cgroup).expect("systemd-run set an initial memory.high");
        assert_ne!(
            original_high, "max",
            "test needs a concrete prior MemoryHigh to distinguish from systemd's clear-to-max"
        );

        let res = Resolution {
            cgroup: cgroup.clone(),
            unit: Some(unit.clone()),
            verdict: Verdict::CapOnly,
            coverage: Coverage::Full,
            mechanism: Mechanism::Unit,
        };

        effector
            .apply(&Action::Cap {
                res: res.clone(),
                name: "sleep".into(),
            })
            .expect("cap");
        assert_ne!(
            cgfs::read_high(&cgroup),
            Some(original_high.clone()),
            "cap should have changed memory.high"
        );

        effector.apply(&Action::LiftCap { res }).expect("lift cap");
        assert_eq!(
            cgfs::read_high(&cgroup),
            Some(original_high),
            "lift must restore the true prior value, not be clobbered back to \"max\" \
             by a systemd MemoryHigh clear that ran after the raw restore write"
        );
        assert!(
            journal.entries().is_empty(),
            "journal entry removed after lift"
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = Command::new("systemctl")
            .args(["--user", "stop", &unit])
            .status();
    }
}
