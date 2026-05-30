//! Executes [`Action`]s against real cgroups via [`CgroupManager`]. Every action
//! is best-effort and logged; a failure must never panic or otherwise crash the
//! daemon loop. `apply` may return `Err` so the caller can log it, but a missing
//! `notify-send` (or any other notification failure) is never treated as an error.

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
            Action::Freeze { pid, name } => {
                tracing::info!(pid, name = %name, "freezing process");
                self.manager.freeze_pid(*pid)
            }
            Action::Thaw { pid } => {
                tracing::info!(pid, "thawing process");
                self.manager.thaw_pid(*pid)
            }
            Action::Cap { pid, name } => {
                let high_bytes = cap_target_bytes(*pid);
                tracing::info!(pid, name = %name, high_bytes, "soft-capping process");
                self.manager.soft_cap_pid(*pid, high_bytes)
            }
            Action::LiftCap { pid } => {
                tracing::info!(pid, "lifting cap and tearing down guard cgroup");
                // LiftCap doubles as full teardown: lift the cap, then clean up
                // the `guard-<pid>` cgroup. A cleanup failure is non-fatal (the
                // startup sweep will mop up any leftover), so it's only logged.
                let res = self.manager.lift_cap_pid(*pid);
                if let Err(e) = self.manager.cleanup_guard(*pid) {
                    tracing::warn!(pid, error = %e, "guard cleanup after lift_cap failed");
                }
                res
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

/// Read the current RSS of `pid` from `/proc/<pid>/status` and derive the
/// `memory.high` soft-cap target. On any read failure we fall back to the
/// minimum cap so the action still applies pressure.
fn cap_target_bytes(pid: u32) -> u64 {
    match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => cap_target_bytes_from_status(&status),
        Err(e) => {
            tracing::warn!(pid, error = %e, "could not read /proc/<pid>/status; using min cap");
            MIN_CAP_BYTES
        }
    }
}

/// Pure helper: parse the `VmRSS` line (value is in kB) from a
/// `/proc/<pid>/status` body and return 90% of it in bytes, clamped to a
/// [`MIN_CAP_BYTES`] floor. If `VmRSS` is absent or unparseable, return the floor.
fn cap_target_bytes_from_status(status: &str) -> u64 {
    let rss_bytes = status
        .lines()
        .find_map(|line| {
            let rest = line.strip_prefix("VmRSS:")?;
            // Format: "VmRSS:\t   12345 kB". Take the first numeric token.
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            Some(kb * 1024)
        })
        .unwrap_or(0);

    let target = rss_bytes / CAP_FRACTION_DEN * CAP_FRACTION_NUM;
    target.max(MIN_CAP_BYTES)
}

/// Best-effort desktop notification via `notify-send`. Silently does nothing if
/// the binary is missing or the spawn fails — notifications must never break the
/// guard.
fn notify(message: &str) {
    match Command::new("notify-send").arg("rlm-guard").arg(message).spawn() {
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
    use super::*;

    #[test]
    fn cap_target_is_ninety_percent_of_rss() {
        // VmRSS 1,000,000 kB = 1,024,000,000 bytes; 90% = 921,600,000.
        let status = "Name:\tfirefox\nVmHWM:\t  2000000 kB\nVmRSS:\t  1000000 kB\nThreads:\t10\n";
        let got = cap_target_bytes_from_status(status);
        assert_eq!(got, 1_000_000 * 1024 / 10 * 9);
        assert!(got > MIN_CAP_BYTES, "a 1GB process should cap above the floor");
    }

    #[test]
    fn missing_vmrss_falls_back_to_min() {
        let status = "Name:\tsomeproc\nState:\tR (running)\nThreads:\t1\n";
        assert_eq!(cap_target_bytes_from_status(status), MIN_CAP_BYTES);
    }

    #[test]
    fn tiny_rss_clamps_to_min() {
        // 1 MB RSS → 90% = ~0.9 MB, below the 64 MiB floor → clamped.
        let status = "VmRSS:\t     1024 kB\n";
        assert_eq!(cap_target_bytes_from_status(status), MIN_CAP_BYTES);
    }

    #[test]
    fn unparseable_vmrss_falls_back_to_min() {
        let status = "VmRSS:\t   notanumber kB\n";
        assert_eq!(cap_target_bytes_from_status(status), MIN_CAP_BYTES);
    }

    #[test]
    fn vmrss_exactly_at_floor_boundary() {
        // Choose an RSS whose 90% lands just above the floor to exercise max().
        // floor = 64 MiB = 67,108,864 bytes. Need rss*0.9 just above it.
        // rss_kb such that (rss_kb*1024)/10*9 > floor → rss_kb ~ 72843.
        let status = "VmRSS:\t    80000 kB\n";
        let expected = 80_000u64 * 1024 / 10 * 9;
        assert_eq!(cap_target_bytes_from_status(status), expected);
        assert!(expected > MIN_CAP_BYTES);
    }

    /// Integration smoke test: freeze a real `sleep`, confirm it's paused via the
    /// `guard-<pid>` `cgroup.freeze` state, then thaw and tear down. Only works
    /// under cgroup v2 delegation, so it's `#[ignore]`d by default.
    #[test]
    #[ignore = "requires cgroup v2 delegation; run manually"]
    fn freeze_thaw_real_process() {
        use std::process::Command;

        let manager = CgroupManager::new().expect("create CgroupManager");
        let effector = Effector::new(&manager);

        let mut child = Command::new("sleep").arg("30").spawn().expect("spawn sleep");
        let pid = child.id();

        effector
            .apply(&Action::Freeze {
                pid,
                name: "sleep".into(),
            })
            .expect("freeze");

        // The freezer reports state via `guard-<pid>/cgroup.freeze` ("1" frozen).
        let freeze_path = format!("/sys/fs/cgroup/rlm/guard-{pid}/cgroup.freeze");
        let frozen = std::fs::read_to_string(&freeze_path).unwrap_or_default();
        assert_eq!(frozen.trim(), "1", "process should be frozen");

        effector.apply(&Action::Thaw { pid }).expect("thaw");
        effector.apply(&Action::LiftCap { pid }).expect("lift+cleanup");

        let _ = child.kill();
        let _ = child.wait();
    }
}
