//! Reads the `rlm-guard` systemd user service's own active/enabled state, so
//! `rlm guard status` can say whether the daemon is actually running instead
//! of only reporting what it would do.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long we give each `systemctl --user is-active`/`is-enabled` call
/// before giving up on it. Both the CLI (`rlm guard status`) and the GUI's
/// Guard page call [`query`] from a thread that must never hang
/// indefinitely: the CLI would otherwise never return, and the GUI would
/// otherwise freeze its whole main loop if systemd or its D-Bus is wedged.
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(1);

/// How often [`run_with_timeout`] polls a spawned child for completion.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Sentinel `active`/`enabled` value meaning the systemctl call didn't
/// finish within [`SYSTEMCTL_TIMEOUT`] (a wedged systemd or D-Bus),
/// distinct from `"unknown"` (systemctl could not even be spawned: missing
/// binary, no user session). [`describe`] gives each its own wording.
const TIMED_OUT: &str = "timeout";

/// The two independent systemd states relevant to the guard: whether it is
/// currently running (`is-active`) and whether it starts at login
/// (`is-enabled`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    pub active: String,
    pub enabled: String,
}

/// Query `systemctl --user is-active`/`is-enabled` for `rlm-guard`, each
/// bounded by [`SYSTEMCTL_TIMEOUT`]. Both commands print their state word to
/// stdout even when they exit non-zero (e.g. `inactive` exits 3), so their
/// exit status is ignored; only their output matters. If `systemctl` cannot
/// even be spawned (missing binary, no user session), both fields read
/// `"unknown"` rather than the per-field fallback `state_word` would
/// otherwise apply, since neither command ran at all. If either call times
/// out, both fields read [`TIMED_OUT`] instead, so [`describe`] can report
/// the wedge rather than a plain "not available".
pub fn query() -> ServiceState {
    match (
        run_with_timeout(systemctl_command(&["is-active"]), SYSTEMCTL_TIMEOUT),
        run_with_timeout(systemctl_command(&["is-enabled"]), SYSTEMCTL_TIMEOUT),
    ) {
        (RunOutcome::Output(a), RunOutcome::Output(e)) => ServiceState {
            active: state_word(&a, "unknown"),
            enabled: state_word(&e, "not-found"),
        },
        (RunOutcome::TimedOut, _) | (_, RunOutcome::TimedOut) => ServiceState {
            active: TIMED_OUT.to_string(),
            enabled: TIMED_OUT.to_string(),
        },
        _ => ServiceState {
            active: "unknown".to_string(),
            enabled: "unknown".to_string(),
        },
    }
}

/// Build `systemctl --user <verb> rlm-guard`.
fn systemctl_command(verb_args: &[&str]) -> Command {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user");
    cmd.args(verb_args);
    cmd.arg("rlm-guard");
    cmd
}

/// What running a [`Command`] under [`run_with_timeout`] produced.
enum RunOutcome {
    /// The process exited (any status) within the deadline; its stdout.
    Output(String),
    /// The process didn't exit within the deadline. It has already been
    /// killed and reaped.
    TimedOut,
    /// The process could not even be spawned.
    Failed,
}

/// Spawn `cmd` and wait for it to exit, polling [`Child::try_wait`] at
/// [`POLL_INTERVAL`] rather than blocking on `Command::output()` (which has
/// no timeout of its own). If `cmd` hasn't exited by `timeout`, it is killed
/// and reaped so a wedged systemd/D-Bus never leaves a zombie behind on
/// every repeated poll (the GUI calls this via [`query`] on a timer), and
/// [`RunOutcome::TimedOut`] is returned immediately.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> RunOutcome {
    let Ok(mut child) = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else {
        return RunOutcome::Failed;
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return RunOutcome::Output(read_child_stdout(&mut child)),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return RunOutcome::TimedOut;
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return RunOutcome::Failed,
        }
    }
}

/// Read whatever the child already wrote to its (now-closed) stdout pipe.
/// Only called after `try_wait` confirms the child has exited, so this never
/// blocks waiting for more output.
fn read_child_stdout(child: &mut Child) -> String {
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    out
}

/// The first trimmed line of `stdout`, or `fallback` when it's empty.
/// `systemctl --user is-enabled` prints nothing on stdout for a unit that
/// isn't installed at all, hence callers pass `"not-found"` as that fallback.
pub fn state_word(stdout: &str, fallback: &str) -> String {
    match stdout.lines().next().map(str::trim) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => fallback.to_string(),
    }
}

/// A one-line, human-readable summary of a [`ServiceState`] for `rlm guard status`.
pub fn describe(s: &ServiceState) -> String {
    if s.active == TIMED_OUT {
        return "unknown (systemctl did not answer)".to_string();
    }
    if s.active == "unknown" {
        return "unknown (systemctl --user is not available)".to_string();
    }
    if s.active == "failed" {
        return "failed (see: journalctl --user -u rlm-guard -n 20)".to_string();
    }
    if s.enabled == "not-found" {
        return "not installed (run: rlm guard enable)".to_string();
    }
    let running = if s.active == "active" {
        "running"
    } else {
        "stopped"
    };
    let login = if s.enabled == "enabled" {
        "starts at login"
    } else {
        "not started at login"
    };
    format!("{running} ({login})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_words_and_descriptions() {
        assert_eq!(state_word("active\n", "unknown"), "active");
        assert_eq!(state_word("", "not-found"), "not-found");
        let d = |a: &str, e: &str| {
            describe(&ServiceState {
                active: a.into(),
                enabled: e.into(),
            })
        };
        assert_eq!(d("active", "enabled"), "running (starts at login)");
        assert_eq!(d("inactive", "disabled"), "stopped (not started at login)");
        assert_eq!(
            d("inactive", "not-found"),
            "not installed (run: rlm guard enable)"
        );
        assert!(d("failed", "enabled").starts_with("failed (see: journalctl --user -u rlm-guard"));
        assert_eq!(
            d("unknown", "unknown"),
            "unknown (systemctl --user is not available)"
        );
        assert_eq!(
            d(TIMED_OUT, TIMED_OUT),
            "unknown (systemctl did not answer)"
        );
    }

    /// Fix round 1, R19a: a wedged child (standing in for a hung `systemctl`
    /// talking to a wedged systemd/D-Bus) must not be waited on past its
    /// deadline. `sleep 5` run through the same [`run_with_timeout`] helper
    /// `query` uses, with a deadline far shorter than the sleep, must return
    /// promptly (well under the 5s the child would otherwise run for) and
    /// leave no zombie behind.
    #[test]
    fn run_with_timeout_kills_and_reaps_a_hung_child() {
        let mut cmd = Command::new("sleep");
        cmd.arg("5");
        let start = Instant::now();
        let outcome = run_with_timeout(cmd, Duration::from_millis(100));
        assert!(
            matches!(outcome, RunOutcome::TimedOut),
            "expected a timeout, not a completed run"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must not wait anywhere near the full 5s sleep"
        );
    }

    /// A command that finishes well within the deadline returns its stdout
    /// through unchanged.
    #[test]
    fn run_with_timeout_returns_output_when_fast() {
        let mut cmd = Command::new("echo");
        cmd.arg("hello");
        let outcome = run_with_timeout(cmd, Duration::from_secs(1));
        match outcome {
            RunOutcome::Output(s) => assert_eq!(s.trim(), "hello"),
            _ => panic!("expected Output, got a failure or timeout"),
        }
    }
}
