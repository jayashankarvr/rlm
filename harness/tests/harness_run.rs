//! Integration test for `rlm-harness`'s end-to-end orchestration: place
//! three probes plus a PSI sampler, drive a tiny memory hog, and produce a
//! `report.json` that actually reflects what happened.
//!
//! Requires a systemd `--user` session with cgroup v2 delegation (to place
//! transient units and read PSI), so it's `#[ignore]`d — not run under
//! plain `cargo test -p harness`, only manually or in an environment that
//! has that set up.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn rlm_harness_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rlm-harness"))
}

/// A short, tiny-fraction run: 10s baseline + 20s hog-under-pressure at
/// 0.05 of MemAvailable. Asserts the report parses, all three probes wrote
/// non-empty ticks, and the PSI integral reports a stall.
///
/// Note: whether `stall_some_us > 0` in practice depends on how much spare
/// memory the test machine actually has — a 5% hog on a machine with
/// several GB of headroom may not induce any measurable PSI stall at all.
/// That's exactly why this test is `#[ignore]`d rather than gating the
/// hermetic `cargo test -p harness` run: its outcome is
/// environment/hardware/load-dependent, not just its ability to run at
/// all.
#[test]
#[ignore = "requires a systemd --user session with cgroup v2 delegation and PSI; run manually"]
fn harness_run_produces_report() {
    let harness = rlm_harness_binary();
    let out_dir = tempfile::tempdir().expect("create temp out dir");

    let output = Command::new(&harness)
        .arg("--out-dir")
        .arg(out_dir.path())
        .arg("--baseline-s")
        .arg("10")
        .arg("--duration-s")
        .arg("20")
        .arg("--hog-fraction")
        .arg("0.05")
        .arg("--interval-ms")
        .arg("50")
        .output()
        .expect("run rlm-harness");

    assert!(
        output.status.success(),
        "rlm-harness should succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path = out_dir.path().join("report.json");
    let report_text = std::fs::read_to_string(&report_path).expect("read report.json");
    let report: Value = serde_json::from_str(&report_text).expect("parse report.json");

    assert_eq!(report["schema"], 1);

    let probes = report["probes"].as_array().expect("probes array");
    assert_eq!(probes.len(), 3, "expected 3 probes, got {probes:?}");
    for probe in probes {
        let ticks = probe["ticks"].as_array().expect("ticks array");
        assert!(
            !ticks.is_empty(),
            "probe {:?} should have non-empty ticks",
            probe["label"]
        );
    }

    let stall_some_us = report["psi"]["stall_some_us"]
        .as_u64()
        .expect("stall_some_us present");
    assert!(
        stall_some_us > 0,
        "expected some measurable PSI 'some' stall from the hog; got 0 \
         (see this test's doc comment: this can legitimately happen on a \
         machine with a lot of spare memory)"
    );
}
