//! Integration test for `--psi`/`--mode` exclusivity.
//!
//! `rlm-probe`'s two run modes (the `Tick`-loop probe and the PSI sampler)
//! are mutually exclusive: mixing `--psi` with `--mode` must fail loudly at
//! argument-validation time, not silently run the PSI sampler while
//! discarding `--mode`. This matters because the harness runner builds argv
//! lists programmatically, one flag-set per probe — a stray `--mode` on a
//! PSI invocation should be caught here, not surface later as something
//! trying to parse `Tick` lines out of a PSI stream.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn rlm_probe_binary() -> PathBuf {
    let exe = env!("CARGO_BIN_EXE_rlm-probe");
    PathBuf::from(exe)
}

/// `--psi` combined with `--mode` must be rejected, naming both flags, with
/// a non-zero exit — not silently run the PSI sampler and discard `--mode`.
#[test]
fn test_psi_with_mode_rejected() {
    let probe = rlm_probe_binary();
    let temp_dir = TempDir::new().expect("create temp dir");
    let out_file = temp_dir.path().join("probe.jsonl");

    let output = Command::new(&probe)
        .arg("--psi")
        .arg("--mode")
        .arg("locked")
        .arg("--duration-s")
        .arg("1")
        .arg("--out")
        .arg(&out_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run probe");

    assert!(
        !output.status.success(),
        "probe should fail with --psi and --mode both given"
    );
    assert_eq!(output.status.code(), Some(1), "expected exit code 1");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--psi") && stderr.contains("--mode"),
        "stderr should name both --psi and --mode: {stderr}"
    );

    assert!(
        !out_file.exists() || std::fs::metadata(&out_file).unwrap().len() == 0,
        "no output should be written when validation fails"
    );
}

/// Plain `--psi` (no `--mode`) must still succeed, to confirm the new check
/// doesn't collaterally reject the valid PSI-only invocation.
#[test]
fn test_psi_without_mode_succeeds() {
    let probe = rlm_probe_binary();
    let temp_dir = TempDir::new().expect("create temp dir");
    let out_file = temp_dir.path().join("probe.jsonl");

    let output = Command::new(&probe)
        .arg("--psi")
        .arg("--interval-ms")
        .arg("50")
        .arg("--duration-s")
        .arg("1")
        .arg("--out")
        .arg(&out_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run probe");

    assert!(
        output.status.success(),
        "plain --psi should succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let contents = std::fs::read_to_string(&out_file).expect("read output");
    let first_line = contents.lines().next().expect("at least a header line");
    assert!(
        first_line.contains("\"mode\":\"psi\""),
        "header should carry mode=psi: {first_line}"
    );
}
