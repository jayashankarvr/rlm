//! Integration test for zero-length file handling.
//! This test verifies that:
//! 1. --file-mb 0 is rejected at parse time
//! 2. A zero-length backing file is rejected at mmap time (not via SIGBUS)
//! 3. Scratch files are not left behind on early errors

use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn rlm_probe_binary() -> PathBuf {
    let exe = env!("CARGO_BIN_EXE_rlm-probe");
    PathBuf::from(exe)
}

/// Test that --file-mb 0 is rejected cleanly with exit code 1.
#[test]
fn test_file_mb_zero_rejected() {
    let probe = rlm_probe_binary();
    let temp_dir = TempDir::new().expect("create temp dir");
    let out_file = temp_dir.path().join("probe.jsonl");

    let output = Command::new(&probe)
        .arg("--mode")
        .arg("touch")
        .arg("--duration-s")
        .arg("1")
        .arg("--file-mb")
        .arg("0")
        .arg("--out")
        .arg(&out_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run probe");

    assert!(
        !output.status.success(),
        "probe should fail with --file-mb 0"
    );
    assert_eq!(output.status.code(), Some(1), "expected exit code 1");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--file-mb must be greater than 0"),
        "stderr should contain validation message: {stderr}"
    );

    // Verify no scratch file was created
    let scratch_files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .expect("read temp dir")
        .filter_map(|e| {
            e.ok().and_then(|de| {
                if de
                    .file_name()
                    .to_string_lossy()
                    .contains("rlm-probe-scratch")
                {
                    Some(de.path())
                } else {
                    None
                }
            })
        })
        .collect();
    assert!(
        scratch_files.is_empty(),
        "no scratch files should be created: {scratch_files:?}"
    );
}

/// Test that an empty regular file is rejected cleanly at mmap time.
#[test]
fn test_empty_file_rejected() {
    let probe = rlm_probe_binary();
    let temp_dir = TempDir::new().expect("create temp dir");
    let empty_file = temp_dir.path().join("empty.txt");
    let out_file = temp_dir.path().join("probe.jsonl");

    // Create an empty file
    File::create(&empty_file)
        .expect("create empty file")
        .sync_all()
        .expect("sync empty file");

    let output = Command::new(&probe)
        .arg("--mode")
        .arg("touch")
        .arg("--duration-s")
        .arg("1")
        .arg("--file")
        .arg(&empty_file)
        .arg("--out")
        .arg(&out_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run probe");

    assert!(
        !output.status.success(),
        "probe should fail with empty file"
    );
    // Should exit with code 1, not SIGBUS (signal 7 = exit 128+7=135)
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit code 1, not SIGBUS: {:?}",
        output.status.code()
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("zero-length"),
        "stderr should mention zero-length file: {stderr}"
    );

    // Verify no scratch file was created
    let scratch_files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .expect("read temp dir")
        .filter_map(|e| {
            e.ok().and_then(|de| {
                if de
                    .file_name()
                    .to_string_lossy()
                    .contains("rlm-probe-scratch")
                {
                    Some(de.path())
                } else {
                    None
                }
            })
        })
        .collect();
    assert!(
        scratch_files.is_empty(),
        "no scratch files should be left behind: {scratch_files:?}"
    );
}

/// Test that an error during mmap cleanup doesn't leave the scratch file.
#[test]
fn test_scratch_file_cleanup_on_mmap_error() {
    let probe = rlm_probe_binary();
    let temp_dir = TempDir::new().expect("create temp dir");
    let out_file = temp_dir.path().join("probe.jsonl");

    // Create a normal scratch file; it will fail on warmup if we set it to
    // size 0 but we can't set file-mb to 0 now. Instead, we'll trigger by
    // creating an empty file with --file pointing to it, which causes mmap
    // error during the warmup path.
    let empty_file = temp_dir.path().join("empty.txt");
    File::create(&empty_file)
        .expect("create empty file")
        .sync_all()
        .expect("sync empty file");

    let output = Command::new(&probe)
        .arg("--mode")
        .arg("touch")
        .arg("--duration-s")
        .arg("1")
        .arg("--file")
        .arg(&empty_file)
        .arg("--file-mb")
        .arg("1")
        .arg("--out")
        .arg(&out_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run probe");

    assert!(
        !output.status.success(),
        "probe should fail with empty file"
    );
    assert_eq!(output.status.code(), Some(1), "expected exit code 1");

    // Most important: verify no scratch file was left behind
    let scratch_files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .expect("read temp dir")
        .filter_map(|e| {
            e.ok().and_then(|de| {
                if de
                    .file_name()
                    .to_string_lossy()
                    .contains("rlm-probe-scratch")
                {
                    Some(de.path())
                } else {
                    None
                }
            })
        })
        .collect();
    assert!(
        scratch_files.is_empty(),
        "no scratch files should be left behind on mmap error: {scratch_files:?}"
    );
}
