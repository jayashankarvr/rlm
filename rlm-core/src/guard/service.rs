//! Reads the `rlm-guard` systemd user service's own active/enabled state, so
//! `rlm guard status` can say whether the daemon is actually running instead
//! of only reporting what it would do.

use std::process::Command;

/// The two independent systemd states relevant to the guard: whether it is
/// currently running (`is-active`) and whether it starts at login
/// (`is-enabled`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceState {
    pub active: String,
    pub enabled: String,
}

/// Query `systemctl --user is-active`/`is-enabled` for `rlm-guard`. Both
/// commands print their state word to stdout even when they exit non-zero
/// (e.g. `inactive` exits 3), so their exit status is ignored; only their
/// output matters. If `systemctl` cannot even be spawned (missing binary, no
/// user session), both fields read `"unknown"` rather than the per-field
/// fallback `state_word` would otherwise apply, since neither command ran at
/// all.
pub fn query() -> ServiceState {
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "rlm-guard"])
        .output();
    let enabled = Command::new("systemctl")
        .args(["--user", "is-enabled", "rlm-guard"])
        .output();
    match (active, enabled) {
        (Ok(a), Ok(e)) => ServiceState {
            active: state_word(&String::from_utf8_lossy(&a.stdout), "unknown"),
            enabled: state_word(&String::from_utf8_lossy(&e.stdout), "not-found"),
        },
        _ => ServiceState {
            active: "unknown".to_string(),
            enabled: "unknown".to_string(),
        },
    }
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
    }
}
