//! Scripting behavior: no ANSI/log noise on piped stdout, and batch limits
//! refuse to guess when there is no TTY to confirm on.

use std::process::{Command, Stdio};

#[test]
fn piped_output_has_no_ansi_and_no_log_noise() {
    // An empty config dir keeps the maintainer's own config out of the test.
    let cfg = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rlm"))
        .arg("profiles")
        .env_remove("RUST_LOG")
        .env("XDG_CONFIG_HOME", cfg.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Medium"));
    assert!(
        !stdout.contains('\u{1b}') && !out.stderr.contains(&0x1b),
        "no ANSI when piped"
    );
    assert!(
        out.stderr.is_empty(),
        "WARN default: nothing on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn batch_limit_without_tty_or_yes_stops_at_confirmation() {
    // Two processes this test owns; nothing else is ever named.
    let mut a = Command::new("sleep").arg("30").spawn().unwrap();
    let mut b = Command::new("sleep").arg("30").spawn().unwrap();
    let cfg = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rlm"))
        .args([
            "limit",
            "--all-pids",
            &format!("{},{}", a.id(), b.id()),
            "--memory",
            "1G",
        ])
        .env("XDG_CONFIG_HOME", cfg.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = a.kill();
    let _ = b.kill();
    let _ = a.wait();
    let _ = b.wait();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    // Hosts without cgroup v2 fail even earlier, at CgroupManager::new; neither path writes anything.
    assert!(err.contains("--yes") || err.contains("cgroups v2"), "{err}");
}
