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
        let result = self.thaw_raw(&res.cgroup, res.unit.as_deref());
        if let Err(e) = &result {
            tracing::debug!(cgroup = %res.cgroup, error = %e, "raw thaw failed (cgroup may already be gone)");
        }
        self.journal.remove(&res.cgroup)?;
        result
    }

    fn cap(&self, res: &Resolution, name: &str) -> Result<()> {
        let prev_high = cgfs::read_high(&res.cgroup);
        let our_bytes = cap_from_anon(cgfs::anon_swap_bytes(&res.cgroup));
        // Plain decimal bytes, no separators/whitespace: this must be
        // exactly what a later `cgfs::read_high` (which only trims
        // whitespace off the raw file contents) returns, since
        // `should_restore`/`restore_step` compare it by string equality.
        // `u64::to_string()` never inserts separators, so the round trip
        // through `write_high` (writes verbatim) -> `read_high` (trims) is
        // exact. See `our_high_string_is_plain_decimal_no_separators` below.
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
        if res.mechanism == Mechanism::Unit {
            if let (Some(unit), Some(systemd)) = (&res.unit, self.systemd) {
                match systemd.set_memory_high(unit, our_bytes, DBUS_TIMEOUT) {
                    Ok(()) => return Ok(()),
                    Err(e) => tracing::warn!(
                        cgroup = %res.cgroup, unit, error = %e,
                        "SetUnitProperties(MemoryHigh) failed; falling back to raw memory.high write"
                    ),
                }
            }
        }
        cgfs::write_high(&res.cgroup, &our_high)
    }

    fn lift_cap(&self, res: &Resolution) -> Result<()> {
        tracing::info!(cgroup = %res.cgroup, "lifting cap");
        match self
            .journal
            .entries()
            .into_iter()
            .find(|e| e.cgroup == res.cgroup)
        {
            Some(entry) => self.replay_entry(&entry),
            None => {
                // No journal record for this cgroup — shouldn't normally
                // happen, since Freeze/Cap always journal first, but stay
                // defensive: a dead-cgroup prune (carry-forward finding)
                // must never leave a target frozen just because we lost the
                // journal entry, so thaw unconditionally regardless.
                let _ = self.thaw_raw(&res.cgroup, res.unit.as_deref());
            }
        }
        self.journal.remove(&res.cgroup)
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
        for entry in self.journal.entries() {
            self.replay_entry(&entry);
        }
        self.journal.clear()
    }

    /// Replay one journal entry at restore time: thaw mechanism-independently
    /// (always, regardless of what follows — see module docs), then restore
    /// `memory.high` only if `restore_step` says to. Used by `LiftCap`,
    /// `sweep_leftovers`, and `undo_all` alike so all three restore paths
    /// agree.
    fn replay_entry(&self, e: &JournalEntry) {
        let _ = self.thaw_raw(&e.cgroup, e.unit.as_deref());

        let inode = cgfs::dir_inode(&e.cgroup);
        let high = cgfs::read_high(&e.cgroup);
        match restore_step(e, inode, high.as_deref()) {
            RestoreStep::ThawAndRestoreHigh { to } => {
                if let Err(err) = cgfs::write_high(&e.cgroup, &to) {
                    tracing::warn!(cgroup = %e.cgroup, error = %err, "failed to restore memory.high");
                }
                if let Some(unit) = &e.unit {
                    if let Some(systemd) = self.systemd {
                        if let Err(err) = systemd.set_memory_high(unit, u64::MAX, DBUS_TIMEOUT) {
                            tracing::debug!(
                                cgroup = %e.cgroup, unit, error = %err,
                                "clearing systemd MemoryHigh runtime property failed"
                            );
                        }
                    }
                }
            }
            RestoreStep::ThawOnly => {}
            RestoreStep::SkipRemove => {
                tracing::info!(
                    cgroup = %e.cgroup,
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
}
