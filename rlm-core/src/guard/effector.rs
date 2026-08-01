//! Executes [`Action`]s against real cgroups. Every action is best-effort and
//! logged; a failure must never panic or otherwise crash the daemon loop.
//! `apply` may return `Err` so the caller can log it, but a missing
//! `notify-send` (or any other notification failure) is never treated as an error.
//!
//! STOPGAP (Task 5): actions are now keyed by [`Resolution`](super::resolve::Resolution)
//! — the *resolved* cgroup (a systemd scope/service, or an existing rlm rule
//! cgroup) — rather than a pid moved into an ephemeral `guard-<pid>` cgroup.
//! This impl acts directly on that path via the raw [`cgfs`](super::cgfs)
//! primitives (`write_freeze`/`write_high`/`anon_swap_bytes`), which is the
//! most direct mapping available and keeps the workspace compiling, but it is
//! a minimal bridge, not the final design: it does not yet prefer the
//! systemd-unit path (`super::systemd`) with raw-cgroup fallback, and
//! `sweep_leftovers`/`undo_all` below still enumerate the old `guard-<pid>`
//! model (a no-op now that nothing creates those cgroups anymore) instead of
//! replaying the write-ahead journal (`super::journal`). Wiring the effector
//! up to systemd + journal-based crash recovery is follow-up work.
use super::cgfs;
use super::types::Action;
use crate::CgroupManager;
use common::Result;
use std::process::Command;

/// Fallback soft-cap when a process's RSS can't be read or is implausibly small.
/// 64 MiB is low enough to apply real pressure yet high enough to avoid pinning
/// a process into a thrash loop.
const MIN_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Fraction of current RSS we cap a process to via `memory.high`. Capping just
/// below the working set forces reclaim/throttle without an OOM-kill.
const CAP_FRACTION_NUM: u64 = 9;
const CAP_FRACTION_DEN: u64 = 10;

/// Applies guard actions using the hardened cgroup primitives on
/// [`CgroupManager`] (`freeze_pid`, `thaw_pid`, `soft_cap_pid`, `lift_cap_pid`,
/// `cleanup_guard`, `list_guard_pids`, `sweep_guard_leftovers`).
pub struct Effector<'a> {
    manager: &'a CgroupManager,
}

impl<'a> Effector<'a> {
    pub fn new(manager: &'a CgroupManager) -> Self {
        Self { manager }
    }

    /// Apply a single action. Best-effort: returns `Err` only so the caller can
    /// log it (a [`Action::Notify`] always returns `Ok`).
    pub fn apply(&self, action: &Action) -> Result<()> {
        match action {
            Action::Freeze { res, name } => {
                tracing::info!(cgroup = %res.cgroup, name = %name, "freezing cgroup");
                cgfs::write_freeze(&res.cgroup, true)
            }
            Action::Thaw { res } => {
                tracing::info!(cgroup = %res.cgroup, "thawing cgroup");
                cgfs::write_freeze(&res.cgroup, false)
            }
            Action::Cap { res, name } => {
                let high_bytes = cap_target_bytes(&res.cgroup);
                tracing::info!(cgroup = %res.cgroup, name = %name, high_bytes, "soft-capping cgroup");
                cgfs::write_high(&res.cgroup, &high_bytes.to_string())
            }
            Action::LiftCap { res } => {
                tracing::info!(cgroup = %res.cgroup, "lifting cap");
                cgfs::write_high(&res.cgroup, "max")
            }
            Action::Notify { message } => {
                notify(message);
                // Notification is always best-effort and never fails the caller.
                Ok(())
            }
        }
    }

    /// Startup recovery: thaw + clean any leftover `guard-*` cgroups from a
    /// prior crash so no process is left frozen.
    pub fn sweep_leftovers(&self) -> Result<()> {
        self.manager.sweep_guard_leftovers()
    }

    /// Graceful shutdown: thaw everything and lift all caps. Each step is
    /// best-effort and logged; one failing pid never aborts the rest.
    pub fn undo_all(&self) -> Result<()> {
        for pid in self.manager.list_guard_pids() {
            if let Err(e) = self.manager.thaw_pid(pid) {
                tracing::warn!(pid, error = %e, "undo_all: thaw failed");
            }
            if let Err(e) = self.manager.lift_cap_pid(pid) {
                tracing::warn!(pid, error = %e, "undo_all: lift_cap failed");
            }
            if let Err(e) = self.manager.cleanup_guard(pid) {
                tracing::warn!(pid, error = %e, "undo_all: cleanup failed");
            }
        }
        // Loudly surface any residue: a guard cgroup still present here means a
        // process may remain throttled/frozen until the next startup sweep.
        let remaining = self.manager.list_guard_pids();
        if !remaining.is_empty() {
            tracing::error!(
                ?remaining,
                "undo_all: guard cgroups could not be fully cleaned; \
                 affected processes may stay constrained until rlm-guard restarts"
            );
        }
        Ok(())
    }
}

/// Read the current anon+swap usage of `cgroup` and derive the `memory.high`
/// soft-cap target. On any read failure we fall back to the minimum cap so the
/// action still applies pressure. `anon+swap` is the cgroup-level equivalent
/// of a single process's RSS+swap used by the old pid-based cap.
fn cap_target_bytes(cgroup: &str) -> u64 {
    match cgfs::anon_swap_bytes(cgroup) {
        Some(bytes) => cap_target_bytes_from_anon_swap(bytes),
        None => {
            tracing::warn!(cgroup, "could not read cgroup memory usage; using min cap");
            MIN_CAP_BYTES
        }
    }
}

/// Pure helper: 90% of `anon_swap_bytes`, clamped to a [`MIN_CAP_BYTES`] floor.
fn cap_target_bytes_from_anon_swap(anon_swap_bytes: u64) -> u64 {
    let target = anon_swap_bytes / CAP_FRACTION_DEN * CAP_FRACTION_NUM;
    target.max(MIN_CAP_BYTES)
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
    use super::super::resolve::{Coverage, Mechanism, Resolution, Verdict};
    use super::*;

    #[test]
    fn cap_target_is_ninety_percent_of_anon_swap() {
        // 1,000,000 kB = 1,024,000,000 bytes; 90% = 921,600,000.
        let got = cap_target_bytes_from_anon_swap(1_000_000 * 1024);
        assert_eq!(got, 1_000_000 * 1024 / 10 * 9);
        assert!(
            got > MIN_CAP_BYTES,
            "a 1GB cgroup should cap above the floor"
        );
    }

    #[test]
    fn tiny_anon_swap_clamps_to_min() {
        // 1 MB → 90% = ~0.9 MB, below the 64 MiB floor → clamped.
        assert_eq!(cap_target_bytes_from_anon_swap(1024 * 1024), MIN_CAP_BYTES);
    }

    #[test]
    fn zero_anon_swap_clamps_to_min() {
        assert_eq!(cap_target_bytes_from_anon_swap(0), MIN_CAP_BYTES);
    }

    #[test]
    fn anon_swap_exactly_at_floor_boundary() {
        // Choose a value whose 90% lands just above the floor to exercise max().
        // floor = 64 MiB = 67,108,864 bytes. Need val*0.9 just above it.
        let bytes = 80_000u64 * 1024;
        let expected = bytes / 10 * 9;
        assert_eq!(cap_target_bytes_from_anon_swap(bytes), expected);
        assert!(expected > MIN_CAP_BYTES);
    }

    #[test]
    fn unreadable_cgroup_falls_back_to_min() {
        assert_eq!(cap_target_bytes("/no/such/cgroup/at/all"), MIN_CAP_BYTES);
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
    /// cgroup, confirm it's paused via `cgroup.freeze`, then thaw and lift.
    /// Only works under cgroup v2 delegation, so it's `#[ignore]`d by default.
    #[test]
    #[ignore = "requires cgroup v2 delegation; run manually"]
    fn freeze_thaw_real_process() {
        use common::Limit;
        use std::process::Command;

        let manager = CgroupManager::new().expect("create CgroupManager");
        let effector = Effector::new(&manager);

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

        let frozen = std::fs::read_to_string(abs_path.join("cgroup.freeze")).unwrap_or_default();
        assert_eq!(frozen.trim(), "1", "cgroup should be frozen");

        effector
            .apply(&Action::Thaw { res: res.clone() })
            .expect("thaw");
        effector.apply(&Action::LiftCap { res }).expect("lift");

        let _ = child.kill();
        let _ = child.wait();
        let _ = manager.cleanup_cgroup("test-freeze-thaw");
    }
}
