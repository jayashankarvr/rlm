//! Executes [`Action`]s against real cgroups, acting in place on the cgroup a
//! process already lives in (a systemd unit's scope/service, or an existing
//! rlm rule cgroup) rather than moving it into an ephemeral `guard-<pid>`
//! cgroup. Every action is best-effort and logged; a failure must never
//! panic or otherwise crash the daemon loop. `apply` may return `Err` so the
//! caller can log it. Desktop notifications are not sent from here: the
//! daemon loop hands each applied action to `guard::notify`.
//!
//! # Write-ahead journal
//! Freeze/Cap always `journal.append` (which fsyncs) *before* touching the
//! cgroup, so a crash between the two still leaves a durable record that
//! startup recovery (`sweep_leftovers`) can replay. `Journal` is internally
//! mutex-serialized (see `journal.rs`), and the daemon calls into this
//! `Effector` from a single thread (the tick loop in `rlm-guard`'s `main`),
//! so `Effector` just holds a `&Journal` and relies on the daemon's
//! single-threaded call discipline plus the journal's own internal locking
//! for safety; it adds no locking of its own.
//!
//! # Mechanism: systemd unit vs. raw cgroupfs
//! When a target resolved to a systemd unit (`Mechanism::Unit`), we prefer
//! the D-Bus call (`FreezeUnit`/`ThawUnit`) with a hard
//! 2s timeout (`systemd::SystemdUser`'s own enforced deadline); on `Err` (bus
//! unavailable, call failed, or timed out) we fall back to the raw cgroupfs
//! primitives in `cgfs`. Raw-mechanism targets (rlm's own rule cgroups) skip
//! the D-Bus attempt entirely. Thawing is mechanism-independent: we always
//! perform the raw `cgroup.freeze` write first, unconditionally, and only
//! then attempt `ThawUnit` best-effort so systemd's view matches. This
//! guarantees a cgroup is never left frozen because of a stale unit or a
//! slow bus, and tolerates a missing cgroup (the raw write simply errors and
//! we move on). On shutdown and startup replay every raw thaw and restore
//! finishes before the first D-Bus call. Caps are the exception: they never
//! go through systemd (see below).
//!
//! # Restoring `memory.high`
//! The kernel truncates `memory.high` writes to page multiples, so the byte
//! count we cap to is page-aligned *before* we journal/write it
//! ([`page_align_down`]); as a second line of defense, [`Effector::cap`]
//! reads `memory.high` back after writing and self-corrects the journal if
//! reality still differs.
//! Caps and restores are raw `memory.high` writes only, never systemd's
//! `SetUnitProperties(MemoryHigh)`: a runtime property leaves a `/run`
//! drop-in that outlives the cap and masks the unit's own configured
//! `MemoryHigh` until reboot, and restoring through systemd wrote `infinity`
//! over it. If systemd later re-applies the unit's value, that only lifts our
//! cap early, and the journal's `our_high` check then skips the restore (the
//! safe direction).
//!
//! If more than one journal entry ever coexists for the same
//! cgroup (a leak from an incomplete prior removal), every restore path
//! treats them as one chain: liveness is judged against the chain's `Cap`
//! entry specifically (only a `Cap` has a `memory.high` to restore; a
//! `Freeze` entry does not, so judging against `entries.last()` when it
//! happens to be a newer `Freeze` would wrongly look like "nothing to
//! restore" and strand `memory.high` at the guard's value forever), and the
//! value restored is always the *oldest* `Cap` entry's `prev_high`, the
//! true pre-intervention value, not an intermediate entry's `prev_high`
//! (which is just our own previous `our_high`). See [`restore_target`].
//! Liveness, however, is judged against the *newest* `Cap` entry, not the
//! oldest: entries are strictly appended, so a later Cap's write always
//! supersedes an earlier one's on disk, and `should_restore`'s string
//! comparison must match what's actually there. See [`restore_decision`].

use super::cgfs;
use super::journal::{should_restore, Journal, JournalAction, JournalEntry};
use super::resolve::{Mechanism, Resolution};
use super::sampler::parse_meminfo;
use super::systemd::SystemdUser;
use super::types::Action;
use crate::CgroupManager;
use common::Result;
use std::time::Duration;

/// Floor for any soft cap. A cap below this is effectively a freeze for a
/// desktop app, so small cgroups are never squeezed further than this.
pub const MIN_CAP_BYTES: u64 = 256 * 1024 * 1024;

/// What a successful [`Effector::apply`] did, beyond "it worked".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// The `memory.high` a `Cap` wrote, in bytes. `None` for other actions.
    pub cap_bytes: Option<u64>,
}

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
    /// log it. On success, [`Applied::cap_bytes`] holds the `memory.high` a
    /// `Cap` wrote.
    pub fn apply(&self, action: &Action) -> Result<Applied> {
        let done = Applied { cap_bytes: None };
        match action {
            Action::Freeze { res, name } => self.freeze(res, name).map(|()| done),
            Action::Thaw { res } => self.thaw(res).map(|()| done),
            Action::Cap { res, name } => self.cap(res, name).map(|bytes| Applied {
                cap_bytes: Some(bytes),
            }),
            Action::LiftCap { res } => self.lift_cap(res).map(|()| done),
        }
    }

    fn freeze(&self, res: &Resolution, name: &str) -> Result<()> {
        // The inode is the guard that lets a later restore tell "this is
        // still the same cgroup" from "this cgroup was torn down and
        // recreated" (`should_restore`). `unwrap_or(0)` used to substitute a
        // poison sentinel here: 0 is never a real inode, so the guard could
        // never match again and the entry became permanently unrestorable,
        // yet it was still journaled-and-acted-on, then later cleared and
        // logged as if it were an intentional skip (Promoted Minor A). Fail
        // closed instead: refuse to freeze at all rather than act with a
        // record we can never safely restore from.
        let Some(inode) = cgfs::dir_inode(&res.cgroup) else {
            tracing::warn!(
                cgroup = %res.cgroup, name,
                "cannot read cgroup inode; refusing to freeze (would be unrestorable)"
            );
            return Err(common::Error::Cgroup(format!(
                "cannot read inode for {}; refusing to freeze",
                res.cgroup
            )));
        };
        let entry = JournalEntry {
            cgroup: res.cgroup.clone(),
            inode,
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

    /// Returns the `memory.high` value written, in bytes.
    fn cap(&self, res: &Resolution, name: &str) -> Result<u64> {
        // See `freeze`'s matching comment (Promoted Minor A): a `0` inode
        // sentinel here would make this Cap permanently unrestorable while
        // looking like a real guard, so fail closed instead of
        // journal-and-act with an unrestorable record.
        let Some(inode) = cgfs::dir_inode(&res.cgroup) else {
            tracing::warn!(
                cgroup = %res.cgroup, name,
                "cannot read cgroup inode; refusing to cap (would be unrestorable)"
            );
            return Err(common::Error::Cgroup(format!(
                "cannot read inode for {}; refusing to cap",
                res.cgroup
            )));
        };
        let prev_high = cgfs::read_high(&res.cgroup);
        // Unknown swap total counts as 0: assuming anon is pinned only makes
        // the cap gentler.
        let swap_total_kb = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|m| parse_meminfo(&m))
            .map_or(0, |m| m.swap_total_kb);
        let anon_ok = cgfs::anon_reclaimable(&res.cgroup, swap_total_kb);
        let Some(target) = cap_target(
            cgfs::current_bytes(&res.cgroup),
            cgfs::file_bytes(&res.cgroup),
            anon_ok,
        ) else {
            tracing::warn!(
                cgroup = %res.cgroup, name,
                "cannot read memory.current; refusing to cap"
            );
            return Err(common::Error::Cgroup(
                "cannot read memory.current; refusing to cap".into(),
            ));
        };
        // The kernel truncates `memory.high` writes to page multiples, so we
        // must journal/write the value it will actually store, not the raw
        // target, or `should_restore`'s string-equality check can never
        // pass again and the cap becomes permanent.
        let our_bytes = page_align_down(target, page_size());
        // Plain decimal bytes, no separators/whitespace: this must be
        // exactly what a later `cgfs::read_high` (which only trims
        // whitespace off the raw file contents) returns. See
        // `our_high_string_is_plain_decimal_no_separators` below, and
        // `reconcile_our_high` for the belt-and-braces check.
        if !cap_tightens(prev_high.as_deref(), our_bytes) {
            tracing::info!(
                cgroup = %res.cgroup, name, prev_high = ?prev_high, our_bytes,
                "existing memory.high already at or below the cap; not capping"
            );
            return Err(common::Error::Cgroup(
                "existing memory.high already at or below the cap; refusing to cap".into(),
            ));
        }
        let our_high = our_bytes.to_string();

        let entry = JournalEntry {
            cgroup: res.cgroup.clone(),
            inode,
            unit: res.unit.clone(),
            action: JournalAction::Cap,
            prev_high,
            our_high: Some(our_high.clone()),
        };
        self.journal.append(&entry)?;

        tracing::info!(
            cgroup = %res.cgroup, name, our_high = %our_high, anon_reclaimable = anon_ok,
            "soft-capping cgroup"
        );
        cgfs::write_high(&res.cgroup, &our_high)?;
        self.reconcile_our_high(&entry);
        Ok(our_bytes)
    }

    /// After a successful `Cap` write, read `memory.high` back; if what's
    /// actually on disk differs from what we journaled (page truncation we
    /// didn't fully pre-empt), correct the journal to match reality. Otherwise
    /// `should_restore`'s string-equality check can never pass again and
    /// the cap becomes permanent (Task 6 review, Critical #1). Rebuilds
    /// only this cgroup's entries, preserving any others that might coexist
    /// (Important #3), with `written`'s `our_high` corrected to the
    /// read-back value. Uses `Journal::replace` (a single atomic rewrite),
    /// not a separate `remove` then `append`: the latter has a window where
    /// the cgroup has no journal record at all, so a crash/SIGKILL/append
    /// failure right there would leave a permanent, unrecoverable cap,
    /// exactly the invariant the journal exists to prevent (Task 6 review,
    /// fix round 2).
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
        let mut entries = self.entries_for(cgroup);
        let Some(pos) = entries.iter().rposition(|e| e == written) else {
            // Already removed/replaced by something else (e.g. a concurrent
            // Thaw/LiftCap); nothing left to correct.
            return;
        };
        entries[pos].our_high = Some(actual);
        if let Err(e) = self.journal.replace(cgroup, &entries) {
            tracing::warn!(cgroup = %cgroup, error = %e, "failed to correct journal entry (atomic replace)");
        }
    }

    fn lift_cap(&self, res: &Resolution) -> Result<()> {
        tracing::info!(cgroup = %res.cgroup, "lifting cap");
        let entries = self.entries_for(&res.cgroup);
        // Mechanism-independent thaw always runs, regardless of whether any
        // journal record exists: a dead-cgroup prune (carry-forward
        // finding, Task 5 review) must never leave a target frozen just
        // because we lost the journal entry.
        let _ = self.thaw_raw(&res.cgroup, res.unit.as_deref());
        self.restore_high_if_any(&res.cgroup, &entries);
        self.journal.remove(&res.cgroup)
    }

    /// All journal entries for one cgroup, in the order `Journal::entries()`
    /// returns them, oldest-first, since entries are strictly appended.
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
        // replayed as one unit (see `restore_high_if_any`) rather than
        // entry-by-entry, which would mis-restore whenever more than one
        // entry coexists for a cgroup (Important #3, Task 6 review).
        let mut by_cgroup: std::collections::HashMap<String, Vec<JournalEntry>> =
            std::collections::HashMap::new();
        for e in self.journal.entries() {
            by_cgroup.entry(e.cgroup.clone()).or_default().push(e);
        }
        // Pass 1: every raw thaw and memory.high restore, then clear the
        // journal. No D-Bus call happens before this is done, so a slow
        // session bus cannot push the undo past systemd's stop timeout.
        for (cgroup, entries) in &by_cgroup {
            if let Err(e) = cgfs::write_freeze(cgroup, false) {
                tracing::debug!(cgroup, error = %e, "raw thaw failed (cgroup may already be gone)");
            }
            self.restore_high_if_any(cgroup, entries);
        }
        let cleared = self.journal.clear();
        // Pass 2, best effort: tell systemd so its view of the units
        // matches the kernel's. The processes already run again.
        if let Some(systemd) = self.systemd {
            for (cgroup, entries) in &by_cgroup {
                if let Some(unit) = entries.last().and_then(|e| e.unit.as_deref()) {
                    if let Err(e) = systemd.thaw_unit(unit, DBUS_TIMEOUT) {
                        tracing::debug!(cgroup, unit, error = %e, "ThawUnit failed after raw thaw");
                    }
                }
            }
        }
        cleared
    }

    /// Restore `memory.high` for one cgroup's journal `entries` (oldest-first),
    /// if the chain is still live. Called *after* the caller has already
    /// performed the mechanism-independent thaw (see module docs: no path
    /// here ever means "leave frozen"). All the decision logic is delegated
    /// to the pure [`restore_decision`]: liveness is judged against the
    /// *newest* `Cap` entry (whose write is what's actually on disk right
    /// now), while the value restored is [`restore_target`]'s *oldest*-entry
    /// `prev_high` (the true pre-intervention value). Judging liveness
    /// against the oldest Cap instead (NEW-1 regression) leaves a stacked
    /// `[Cap, Cap]` chain's on-disk value permanently un-restorable, since
    /// the oldest entry's `our_high` never matches what a later Cap actually
    /// wrote. Judging liveness against `entries.last()` has the same failure
    /// for a `[Cap, Freeze]` chain (Promoted Minor B): the newest entry is
    /// the `Freeze`, which has no `memory.high` of its own. The restore is a
    /// raw `memory.high` write only; systemd's `MemoryHigh` property is never
    /// touched (see module docs).
    fn restore_high_if_any(&self, cgroup: &str, entries: &[JournalEntry]) {
        let inode = cgfs::dir_inode(cgroup);
        let high = cgfs::read_high(cgroup);
        match restore_decision(entries, inode, high.as_deref()) {
            RestoreStep::ThawAndRestoreHigh { to } => {
                if let Err(err) = cgfs::write_high(cgroup, &to) {
                    tracing::warn!(cgroup, error = %err, "failed to restore memory.high");
                }
            }
            // No Cap entry anywhere in the chain (a Freeze-only chain,
            // possibly with leaked duplicates): there is no memory.high to
            // restore. The unconditional thaw already ran in the caller, so
            // there's nothing left to do here.
            RestoreStep::ThawOnly => {}
            RestoreStep::SkipRemove => {
                tracing::warn!(
                    cgroup,
                    "not restoring memory.high (cgroup recreated or value changed since our write)"
                );
            }
        }
    }

    /// Mechanism-independent thaw: an *unconditional* raw `cgroup.freeze`
    /// write first, so a cgroup is never left frozen and a slow bus cannot
    /// delay it, then a best-effort `ThawUnit` (if we have a unit and a bus)
    /// so systemd's view of the unit matches. Tolerates a missing cgroup:
    /// the raw write then simply returns `Err`, which every caller here
    /// treats as non-fatal.
    fn thaw_raw(&self, cgroup: &str, unit: Option<&str>) -> Result<()> {
        let result = cgfs::write_freeze(cgroup, false);
        if let (Some(unit), Some(systemd)) = (unit, self.systemd) {
            if let Err(e) = systemd.thaw_unit(unit, DBUS_TIMEOUT) {
                tracing::debug!(cgroup, unit, error = %e, "ThawUnit failed after raw thaw");
            }
        }
        result
    }
}

/// What to do with one journal entry's `memory.high` at restore time. Never
/// speaks to freeze/thaw; that is unconditional and already handled by the
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

/// Size a soft cap that slows an app down without stalling it.
///
/// memory.high applies to everything charged to the cgroup, page cache
/// included, so the cap is sized from memory.current: it never asks the
/// kernel to reclaim more than 10% of it. When anon memory cannot go to swap,
/// only file pages can be reclaimed, so the cap never asks for more than 80%
/// of them. Returns `None` when memory.current is unreadable: no cap is safer
/// than a guessed one.
pub fn cap_target(current: Option<u64>, file: Option<u64>, anon_reclaimable: bool) -> Option<u64> {
    let current = current?;
    let mut target = current / 10 * 9;
    if !anon_reclaimable {
        let file_floor = current.saturating_sub(file.unwrap_or(0).saturating_mul(8) / 10);
        target = target.max(file_floor);
    }
    Some(target.max(MIN_CAP_BYTES))
}

/// Pure: whether writing `target` would tighten the existing `memory.high`.
/// A numeric `prev_high` at or below `target` means the cap would loosen (or
/// not change) the limit already in place, so the caller must not write it.
/// `"max"`, or anything else that is not a byte count, is no limit at all.
pub fn cap_tightens(prev_high: Option<&str>, target: u64) -> bool {
    match prev_high.and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(prev) => prev > target,
        None => true,
    }
}

/// Pure: the full restore decision for one cgroup's journal `entries`
/// (oldest-first), given the cgroup's current inode and on-disk
/// `memory.high` (both already read by the caller, no IO here). Answers two
/// orthogonal questions with two different entries on purpose:
///
/// - **Liveness** (is the guard we wrote still intact?) is judged against
///   the *newest* `Cap` entry in the chain. Entries are strictly appended,
///   so a later Cap's write always supersedes an earlier one's on disk, so
///   `should_restore`'s string-equality check must compare against the
///   entry whose `our_high` is what's actually there right now.
/// - **Value** (what do we restore to?) is [`restore_target`]'s *oldest*
///   `Cap` entry's `prev_high`, the true pre-intervention value, not an
///   intermediate entry's `prev_high` (which is just our own previous
///   `our_high` from an earlier cap in the same chain).
///
/// Judging both against the oldest Cap (NEW-1 regression) makes a stacked
/// `[Cap, Cap]` chain's liveness check compare a stale `our_high` against
/// the newer write on disk, so it never matches and the chain is treated as
/// dead, stranding `memory.high` at the guard's value forever. Judging
/// liveness against `entries.last()` fails the same way for `[Cap, Freeze]`
/// (Promoted Minor B): the newest entry is the `Freeze`, which has no
/// `memory.high` of its own. Returns [`RestoreStep::ThawOnly`] when there's
/// no `Cap` entry anywhere in the chain (a `Freeze`-only chain): nothing to
/// restore beyond the caller's unconditional thaw.
pub fn restore_decision(
    entries: &[JournalEntry],
    inode: Option<u64>,
    high: Option<&str>,
) -> RestoreStep {
    let Some(newest_cap) = entries
        .iter()
        .rev()
        .find(|e| e.action == JournalAction::Cap)
    else {
        return RestoreStep::ThawOnly;
    };
    match restore_step(newest_cap, inode, high) {
        RestoreStep::ThawAndRestoreHigh { .. } => match restore_target(entries) {
            Some(to) => RestoreStep::ThawAndRestoreHigh { to },
            // Unreachable: `newest_cap` being a Cap guarantees `restore_target`
            // (which only needs *any* Cap entry) also finds one.
            None => RestoreStep::ThawOnly,
        },
        other => other,
    }
}

/// Pure: given all journal entries for one cgroup, oldest-first, select the
/// `memory.high` value to restore, if the chain contains a `Cap` entry. The
/// OLDEST `Cap` entry's `prev_high` is the true pre-intervention value; a
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
/// something nonsensical, a defensive fallback, not the source of truth,
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
/// actually store, not the pre-truncation target; otherwise
/// `should_restore`'s string-equality check can never pass again and a cap
/// becomes permanent.
fn page_align_down(bytes: u64, page: u64) -> u64 {
    bytes.checked_div(page).map_or(bytes, |q| q * page)
}

#[cfg(test)]
mod tests {
    use super::super::resolve::{Coverage, Verdict};
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;

    #[test]
    fn cap_never_demands_more_than_ten_percent_of_current() {
        // Incident: Chrome scope with 1.5 GiB charged, mostly page cache, ~150 MiB anon.
        let current = GIB * 3 / 2;
        let cap = cap_target(Some(current), Some(GIB * 135 / 100), true).unwrap();
        assert!(
            cap >= current / 10 * 9,
            "cap {cap} is below 90% of {current}"
        );
    }

    #[test]
    fn swapless_cap_only_asks_for_reclaimable_file_pages() {
        assert_eq!(
            cap_target(Some(GIB), Some(0), false),
            Some(GIB),
            "nothing reclaimable: demand nothing"
        );
        assert_eq!(
            cap_target(Some(GIB), Some(512 * MIB), false),
            Some(GIB / 10 * 9)
        );
        assert_eq!(
            cap_target(Some(GIB), None, false),
            Some(GIB),
            "unknown file size: demand nothing"
        );
    }

    #[test]
    fn cap_has_a_256_mib_floor() {
        assert_eq!(
            cap_target(Some(100 * MIB), Some(0), true),
            Some(MIN_CAP_BYTES)
        );
    }

    #[test]
    fn cap_never_loosens_an_existing_memory_high() {
        let floor = cap_target(Some(100 * MIB), Some(0), true).unwrap();
        assert_eq!(floor, MIN_CAP_BYTES);
        let prev = (200 * MIB).to_string();
        assert!(
            !cap_tightens(Some(&prev), floor),
            "200 MiB unit limit must not be raised to the 256 MiB floor"
        );
        assert!(
            !cap_tightens(Some(&floor.to_string()), floor),
            "equal: no-op"
        );
        assert!(cap_tightens(Some("max"), floor));
        assert!(cap_tightens(None, floor));
        let prev = (2 * GIB).to_string();
        assert!(cap_tightens(Some(&prev), GIB));
    }

    #[test]
    fn unreadable_current_refuses_to_cap() {
        assert_eq!(cap_target(None, Some(1), true), None);
    }

    /// Carry-forward (Task 3 review): `our_high` must be a plain decimal
    /// string with no grouping/whitespace, since `should_restore` compares
    /// it by string equality against `cgfs::read_high` (which only trims).
    #[test]
    fn our_high_string_is_plain_decimal_no_separators() {
        let bytes = cap_target(Some(12_345_678_900), None, true).unwrap();
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
    /// (the true pre-intervention value). The newer entry's `prev_high` is
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

    /// Regression test for NEW-1: `restore_decision`'s liveness check must be
    /// judged against the NEWEST `Cap` entry (whose `our_high` is what's
    /// actually on disk), while the value restored stays the OLDEST `Cap`
    /// entry's `prev_high`. A stacked `[Cap(prev="max", our="A"),
    /// Cap(prev="A", our="B")]` chain with disk `memory.high == "B"` must
    /// restore to `"max"`, not `SkipRemove`, which the old
    /// `entries.iter().find()` (oldest-Cap-for-everything) produced: it
    /// compared the oldest entry's `our_high` ("A") against disk ("B"),
    /// never matched, and permanently stranded `memory.high`. Also covers
    /// `[Cap, Freeze]` (Promoted Minor B's shape) and a bare `[Cap]` chain in
    /// the same test so a future re-swap of either selection can't slip by.
    #[test]
    fn restore_decision_liveness_uses_newest_cap_value_uses_oldest() {
        // [Cap, Cap]: disk holds the NEWEST Cap's our_high ("B"). Liveness
        // must be checked against "B", not the oldest entry's "A".
        let oldest = entry_cap("/x", 42, "max", "A");
        let newest = entry_cap("/x", 42, "A", "B");
        assert_eq!(
            restore_decision(&[oldest.clone(), newest.clone()], Some(42), Some("B")),
            RestoreStep::ThawAndRestoreHigh { to: "max".into() },
            "must judge liveness against the newest Cap's our_high (matches disk \"B\"), \
             but restore the oldest Cap's prev_high (\"max\")"
        );
        // Sanity: the stale intermediate value "A" is no longer live on disk,
        // so checking against it (the old bug) would report SkipRemove.
        assert_eq!(
            restore_step(&oldest, Some(42), Some("B")),
            RestoreStep::SkipRemove,
            "confirms the bug this guards against: judging liveness against the oldest \
             entry's our_high against the newer on-disk value mismatches"
        );

        // [Cap, Freeze]: newest entry has no memory.high of its own; must
        // still fall through to the Cap for both liveness and value.
        let cap = entry_cap("/x", 42, "max", "1000");
        let frz = entry_freeze("/x", 42);
        assert_eq!(
            restore_decision(&[cap, frz], Some(42), Some("1000")),
            RestoreStep::ThawAndRestoreHigh { to: "max".into() }
        );

        // [Cap] alone: baseline single-entry behavior is unchanged.
        let cap_only = entry_cap("/x", 42, "max", "1000");
        assert_eq!(
            restore_decision(&[cap_only], Some(42), Some("1000")),
            RestoreStep::ThawAndRestoreHigh { to: "max".into() }
        );

        // Freeze-only chain: nothing to restore.
        assert_eq!(
            restore_decision(&[entry_freeze("/x", 42)], Some(42), None),
            RestoreStep::ThawOnly
        );
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
            "dead cgroup: restore_step only decides memory.high, never freeze; the \
             unconditional thaw in Effector::thaw_raw already ran before this is consulted, \
             so a still-frozen dead cgroup is never left behind (carry-forward: Task 5 review)"
        );
    }

    /// Poll `cgfs::read_frozen` until it matches `want` or `timeout` elapses.
    /// Writing `cgroup.freeze` only *requests* a state change; `cgroup.events`'s
    /// `frozen` field (what `read_frozen` reads) only flips once the kernel has
    /// actually quiesced every task in the cgroup, which can lag the write by a
    /// few milliseconds under load, so a bare immediate read is flaky.
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
            .expect("create test cgroup")
            .path;
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
    /// assert `cgfs::read_high` matches the journaled `our_high` exactly,
    /// i.e. the value we wrote never got silently page-truncated out from
    /// under the journal. The target process holds enough random anon
    /// memory (well above the 256 MiB `MIN_CAP_BYTES` floor, a round power
    /// of two that would pass even without the fix and prove nothing) that
    /// the sized cap is very unlikely to already sit on a page boundary. Requires cgroup v2
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
            .expect("create test cgroup")
            .path;
        let cgroup = format!(
            "/{}",
            abs_path
                .strip_prefix("/sys/fs/cgroup")
                .expect("cgroup under /sys/fs/cgroup")
                .display()
        );

        // Hold ~400MB of anon memory (above the 256 MiB floor) whose sized
        // cap is very unlikely to land on a page boundary, then sleep.
        let mut child = Command::new("bash")
            .arg("-c")
            .arg("a=$(head -c 300000000 /dev/urandom | base64 -w0); sleep 30")
            .spawn()
            .expect("spawn memory-holding process");
        let pid = child.id();
        manager
            .add_to_cgroup(&abs_path, pid)
            .expect("add process to test cgroup");
        // Wait until the shell has actually built up the allocation, or the
        // cap would sit on the 256 MiB floor and prove nothing.
        let want = 300 * 1024 * 1024;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let cur = cgfs::current_bytes(&cgroup).unwrap_or(0);
            if cur >= want {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = manager.cleanup_cgroup("test-cap-align");
                panic!("memory.current reached only {cur} bytes, need {want}, after 10s");
            }
            std::thread::sleep(Duration::from_millis(100));
        }

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

    /// Cap and lift go through raw `memory.high` writes only, so the unit's
    /// own `MemoryHigh` property (as systemd reports it) must be the same
    /// before the cap and after the lift, and the raw `memory.high` must be
    /// back at its pre-cap value. A runtime `SetUnitProperties` would leave
    /// a `/run` drop-in behind that changes the reported property.
    /// Requires a session bus and cgroup v2 delegation, so it's `#[ignore]`d.
    #[test]
    #[ignore = "requires a session bus and cgroup v2 delegation; run manually"]
    fn lift_cap_leaves_unit_memory_high_property_untouched() {
        use std::process::Command;

        let unit_memory_high = |unit: &str| -> String {
            let out = Command::new("systemctl")
                .args(["--user", "show", "-p", "MemoryHigh", "--value", unit])
                .output()
                .expect("systemctl --user show");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

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
        let property_before = unit_memory_high(&unit);

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
            unit_memory_high(&unit),
            property_before,
            "cap/lift must not change the unit's MemoryHigh property"
        );
        assert_eq!(
            cgfs::read_high(&cgroup),
            Some(original_high),
            "lift must restore the raw pre-cap memory.high"
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

    /// Regression test for Promoted Minor B: a leaked `[Cap, Freeze]` chain
    /// (Cap journaled first, then the same cgroup frozen later without the
    /// Cap entry ever being cleared) must still restore the Cap's
    /// `prev_high` on thaw. Before the fix, liveness was judged against
    /// `entries.last()` (the Freeze entry, which has no `memory.high` of
    /// its own), so `restore_step` reported "nothing to restore" and
    /// `memory.high` stayed pinned at the guard's Cap value forever once the
    /// whole chain was cleared. Requires cgroup v2 delegation, so it's
    /// `#[ignore]`d.
    #[test]
    #[ignore = "requires cgroup v2 delegation; run manually"]
    fn chain_restores_cap_value_when_newest_entry_is_freeze() {
        use common::Limit;
        use std::process::Command;

        let manager = CgroupManager::new().expect("create CgroupManager");
        let journal_dir = tempfile::tempdir().unwrap();
        let journal =
            Journal::open(journal_dir.path().join("j.jsonl"), "test-boot".into()).unwrap();
        let effector = Effector::new(&manager, &journal, None);

        let abs_path = manager
            .prepare_cgroup("test-chain-restore", &Limit::default())
            .expect("create test cgroup")
            .path;
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

        let original_high = cgfs::read_high(&cgroup).expect("read initial memory.high");
        let res = test_resolution(cgroup.clone());

        // Cap first (oldest entry)...
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

        // ...then freeze the same cgroup without ever clearing the Cap
        // entry. This is the leaked-chain scenario: two coexisting entries,
        // Freeze newest.
        effector
            .apply(&Action::Freeze {
                res: res.clone(),
                name: "sleep".into(),
            })
            .expect("freeze");

        let entries = journal.entries();
        assert_eq!(entries.len(), 2, "both Cap and Freeze entries coexist");
        assert_eq!(entries[0].action, JournalAction::Cap, "Cap is oldest");
        assert_eq!(entries[1].action, JournalAction::Freeze, "Freeze is newest");

        // Thaw (the action that would naturally follow a Freeze) must still
        // restore the Cap's prev_high, not skip restoration just because the
        // newest entry is a Freeze with no memory.high of its own.
        effector.apply(&Action::Thaw { res }).expect("thaw");
        assert_eq!(
            cgfs::read_high(&cgroup),
            Some(original_high),
            "thaw must restore the chain's Cap value even though Freeze is the newest entry"
        );
        assert!(
            journal.entries().is_empty(),
            "both chain entries removed after thaw"
        );

        let _ = child.kill();
        let _ = child.wait();
        let _ = manager.cleanup_cgroup("test-chain-restore");
    }
}
