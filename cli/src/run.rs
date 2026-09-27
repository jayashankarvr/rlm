//! `rlm run`: launch a command inside a new cgroup with limits.

use common::{Limit, Result};
use rlm_core::CgroupManager;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// How a `rlm run` ended.
pub struct RunOutcome {
    /// Exit code to hand back to the shell (128 + N for a signal death).
    pub exit: u8,
    /// The cgroup the command ran in.
    pub cgroup: String,
    /// Processes the command started that were still in the cgroup when it
    /// exited. The cgroup and its limits are kept while this is non-zero.
    pub left_running: usize,
}

/// Run `command` in a fresh `run-*` cgroup with `limit` and wait for it.
///
/// Many launchers fork the real application and exit at once. When the
/// direct child exits but the cgroup is still populated, the cgroup is left
/// in place so its processes stay limited, and the user is told how to
/// remove it. Only an empty cgroup is removed.
pub fn run_in_cgroup(
    manager: &CgroupManager,
    limit: &Limit,
    command: &[String],
) -> Result<RunOutcome> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| common::Error::InvalidArgs("command is required".into()))?;

    // Generate a collision-resistant cgroup name. Using only the PID risks
    // reusing a stale leaked `run-<pid>` cgroup after PID reuse; the timestamp
    // suffix makes that effectively impossible.
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("run-{}-{}", std::process::id(), uniq);

    // Create cgroup and set limits BEFORE spawning the process
    let prepared = manager.prepare_cgroup(&name, limit)?;
    for w in &prepared.warnings {
        eprintln!("warning: {w}");
    }
    let cgroup_path = prepared.path;

    // Set up signal handler
    let terminated = Arc::new(AtomicBool::new(false));
    let terminated_clone = Arc::clone(&terminated);

    ctrlc::set_handler(move || {
        terminated_clone.store(true, Ordering::SeqCst);
    })
    .ok();

    // Place the child into the cgroup BEFORE it execs, so it is constrained from
    // its first instruction (see CgroupManager::placement_command).
    let mut cmd = manager.placement_command(&cgroup_path, program);
    cmd.args(args);
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            // Nothing was started; don't leave an empty cgroup behind.
            let _ = manager.remove_if_empty(&name);
            return Err(e.into());
        }
    };

    let pid = child.id();

    // Fallback: ensure the process is in the cgroup even if pre-exec placement
    // failed. Idempotent if it's already there.
    if let Err(e) = manager.add_to_cgroup(&cgroup_path, pid) {
        eprintln!("warning: failed to apply limits: {e}");
    }

    // Track if we've sent SIGTERM
    let mut sigterm_sent = false;

    // Wait for process, checking for signals
    let status = loop {
        if terminated.load(Ordering::SeqCst) && !sigterm_sent {
            // Forward signal to child (only once)
            // SAFETY: pid is a valid process ID obtained from child.id() of a process
            // we just spawned. libc::kill with SIGTERM is safe for any PID - worst case
            // the process already exited and kill returns an error (which we ignore).
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            sigterm_sent = true;
        }

        match child.try_wait()? {
            Some(status) => break status,
            None => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    };

    let oom = manager.oom_kills(&name).unwrap_or(0);
    let (exit, messages) = rlm_core::exit::exit_report(
        status.code(),
        status.signal(),
        oom,
        manager.memory_max(&name),
    );
    for m in &messages {
        eprintln!("rlm: {m}");
    }

    // Never move the remaining processes out: they are the application the
    // user asked to limit. Remove the cgroup only once it is empty. A removal
    // error must not mask the command's exit code (cgroup v2 can briefly
    // return EBUSY on rmdir right after the last process exits).
    let left_running = if manager.is_populated(&name) == Some(true) {
        let n = manager.pids_in_cgroup(&name).len();
        eprintln!(
            "rlm: the command exited but {n} process(es) it started are still running in cgroup '{name}'. \
             Their limits stay in place. Remove them with: rlm unlimit --cgroup {name}"
        );
        n
    } else {
        if let Err(e) = manager.remove_if_empty(&name) {
            eprintln!("warning: failed to remove cgroup '{name}': {e}");
        }
        0
    };

    Ok(RunOutcome {
        exit,
        cgroup: name,
        left_running,
    })
}

/// `rlm run`: run the command under limits and return its exit code.
pub fn run_with_limits(
    manager: &CgroupManager,
    limit: &Limit,
    command: &[String],
) -> Result<ExitCode> {
    let outcome = run_in_cgroup(manager, limit, command)?;
    tracing::debug!(
        cgroup = %outcome.cgroup,
        left_running = outcome.left_running,
        exit = outcome.exit,
        "run finished"
    );
    Ok(ExitCode::from(outcome.exit))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a launcher that starts a background child and exits at once, the
    /// way many GUI launchers do. The child must stay limited. Needs cgroup v2
    /// delegation; only processes this test starts are touched.
    #[test]
    #[ignore = "requires cgroup v2 delegation; run manually"]
    fn launcher_that_exits_leaves_limited_children_in_place() {
        let manager = CgroupManager::new().unwrap();
        let limit = common::build_limit(Some("64M"), None, None, None).unwrap();
        let cmd: Vec<String> = ["sh", "-c", "sleep 30 & exit 0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = run_in_cgroup(&manager, &limit, &cmd).unwrap();
        let pids = manager.pids_in_cgroup(&out.cgroup);
        for pid in &pids {
            // SAFETY: these PIDs are the sleep this test started, still inside the test's own cgroup.
            unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = manager.remove_if_empty(&out.cgroup);
        assert_eq!(out.exit, 0);
        assert_eq!(out.left_running, 1, "the background sleep keeps its limits");
    }
}
