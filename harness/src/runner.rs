//! Pure orchestration logic for `rlm-harness`: preflight safety checks,
//! `/proc/meminfo` parsing, argv construction for the probes and hog it
//! spawns, and report assembly from already-collected probe/PSI output.
//!
//! Deliberately kept separate from `rlm-harness.rs` (which owns the actual
//! `systemd-run` invocations, signal handling, and sleeping) so every
//! decision that doesn't require spawning a process is a plain function
//! over strings/structs, testable under plain `cargo test -p harness` with
//! no systemd, no cgroups, and nothing running in the background.

use crate::psi::{stall_us, PsiSample};
use crate::{ProbeMode, Tick};
use serde::Serialize;

/// 12 GiB in kB. The plan's "large-RAM desktop" threshold: past this an
/// operator is plausibly running the harness on their own daily-driver
/// machine (rather than a small CI VM), so a hog sized to actually put a
/// dent in it needs an explicit `--i-know` rather than a bare invocation.
pub const LARGE_RAM_THRESHOLD_KB: u64 = 12 * 1024 * 1024;

/// Everything the preflight decision needs to know. Kept as a plain struct
/// (rather than reading `/proc` itself) so the decision is testable without
/// touching the filesystem.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PreflightInput {
    /// Whether `/proc/pressure/memory` exists on this machine.
    pub psi_memory_exists: bool,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    /// Fraction of `mem_available_kb` the hog will allocate.
    pub hog_fraction: f64,
    /// Whether `--i-know` was passed.
    pub i_know: bool,
}

/// Why a run was refused.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PreflightError {
    /// No `/proc/pressure/memory` on this kernel/cgroup config — the
    /// harness cannot measure or safely bound anything without PSI.
    NoPsiMemory,
    /// `MemTotal` is above the large-RAM-desktop threshold AND the hog, at
    /// the requested fraction, would itself allocate more than that
    /// threshold worth of memory — i.e. this run could put a real dent in
    /// what is plausibly the operator's own daily-driver machine.
    NeedsIKnow {
        mem_total_kb: u64,
        hog_estimated_kb: u64,
    },
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::NoPsiMemory => write!(
                f,
                "/proc/pressure/memory does not exist on this machine (PSI unavailable); \
                 refusing to run without it"
            ),
            PreflightError::NeedsIKnow {
                mem_total_kb,
                hog_estimated_kb,
            } => write!(
                f,
                "MemTotal is {mem_total_kb} kB (> {LARGE_RAM_THRESHOLD_KB} kB) and the \
                 requested --hog-fraction would allocate ~{hog_estimated_kb} kB, which also \
                 exceeds {LARGE_RAM_THRESHOLD_KB} kB. This looks like it could threaten a \
                 real desktop with substantial RAM. Re-run with --i-know to confirm you \
                 intend this."
            ),
        }
    }
}

/// Refuse-to-run decision. Pure: takes already-read facts, returns a
/// decision, does no I/O and spawns nothing.
pub fn preflight_check(input: &PreflightInput) -> Result<(), PreflightError> {
    if !input.psi_memory_exists {
        return Err(PreflightError::NoPsiMemory);
    }

    let hog_estimated_kb = (input.hog_fraction * input.mem_available_kb as f64).round() as u64;
    let threatens_large_ram_desktop =
        input.mem_total_kb > LARGE_RAM_THRESHOLD_KB && hog_estimated_kb > LARGE_RAM_THRESHOLD_KB;

    if threatens_large_ram_desktop && !input.i_know {
        return Err(PreflightError::NeedsIKnow {
            mem_total_kb: input.mem_total_kb,
            hog_estimated_kb,
        });
    }

    Ok(())
}

/// Parse `MemTotal` and `MemAvailable` (both kB) out of `/proc/meminfo`
/// content. Pure. `None` if either field is missing or malformed — both
/// fields are required for the preflight decision above.
pub fn parse_meminfo(content: &str) -> Option<(u64, u64)> {
    let mut mem_total = None;
    let mut mem_available = None;

    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        let Some(value) = fields.next() else {
            continue;
        };
        match key {
            "MemTotal:" => mem_total = value.parse::<u64>().ok(),
            "MemAvailable:" => mem_available = value.parse::<u64>().ok(),
            _ => {}
        }
    }

    Some((mem_total?, mem_available?))
}

/// Whether `name` is present as an executable file directly under one of
/// the `:`-separated directories in `path_var`. Pure with respect to
/// `path_var`'s content (the only non-determinism is the filesystem state
/// of those directories, which tests control via a tempdir), used to detect
/// whether `rlm` is installed without depending on rlm-core or any
/// rlm-specific knowledge of where it lives.
pub fn command_on_path(name: &str, path_var: &str) -> bool {
    path_var
        .split(':')
        .filter(|dir| !dir.is_empty())
        .any(|dir| std::path::Path::new(dir).join(name).is_file())
}

/// Choose the directory for the hog's memory-backing scratch file. Prefers
/// `/dev/shm` (tmpfs — guaranteed RAM-backed) over `out_dir`, since the hog
/// exists to consume real resident memory regardless of where `--out-dir`
/// happens to live: a disk-backed `--out-dir` would make the "hog" mostly
/// reclaimable clean page cache instead of genuine memory pressure (the
/// kernel can drop clean, disk-backed pages near-instantly under pressure,
/// unlike anonymous/tmpfs pages). Falls back to `out_dir` only when
/// `/dev/shm` isn't available at all (`dev_shm_available` is a plain bool
/// so this decision is testable without touching the filesystem; the
/// caller checks `Path::new("/dev/shm").is_dir()`).
pub fn hog_scratch_dir(dev_shm_available: bool, out_dir: &str) -> &str {
    if dev_shm_available {
        "/dev/shm"
    } else {
        out_dir
    }
}

/// Build the `rlm-probe` argv (element 0 is the binary path itself) for one
/// tick-mode probe placement.
#[allow(clippy::too_many_arguments)]
pub fn probe_argv(
    probe_bin: &str,
    label: &str,
    mode: ProbeMode,
    slice_label: &str,
    out_path: &str,
    duration_s: u64,
    interval_ms: u64,
    working_set_mb: u64,
) -> Vec<String> {
    let mode_str = match mode {
        ProbeMode::Locked => "locked",
        ProbeMode::Touch => "touch",
    };
    vec![
        probe_bin.to_string(),
        "--mode".to_string(),
        mode_str.to_string(),
        "--label".to_string(),
        label.to_string(),
        "--slice-label".to_string(),
        slice_label.to_string(),
        "--out".to_string(),
        out_path.to_string(),
        "--duration-s".to_string(),
        duration_s.to_string(),
        "--interval-ms".to_string(),
        interval_ms.to_string(),
        "--working-set-mb".to_string(),
        working_set_mb.to_string(),
    ]
}

/// Build the `rlm-probe --psi` argv (element 0 is the binary path itself).
/// Never includes `--mode` — `--psi` and `--mode` are mutually exclusive and
/// rejected by `rlm-probe` itself (see `rlm-probe.rs`), so a PSI sampler's
/// argv must never carry both.
pub fn psi_probe_argv(
    probe_bin: &str,
    label: &str,
    out_path: &str,
    duration_s: u64,
    interval_ms: u64,
) -> Vec<String> {
    vec![
        probe_bin.to_string(),
        "--psi".to_string(),
        "--label".to_string(),
        label.to_string(),
        "--out".to_string(),
        out_path.to_string(),
        "--duration-s".to_string(),
        duration_s.to_string(),
        "--interval-ms".to_string(),
        interval_ms.to_string(),
    ]
}

/// Wrap `inner_argv` (element 0 = the target binary/interpreter) in a
/// `systemd-run --user` invocation's argv (NOT including the `systemd-run`
/// binary name itself — the caller passes this to `Command::new("systemd-run").args(..)`).
/// `scope: true` places the target directly under a transient scope unit
/// (used for the hog, which the runner needs to `systemctl --user stop` at
/// an arbitrary moment); `scope: false` places it under a transient service
/// unit (used for probes, which run to their own completion and write
/// their output before exiting). `--collect` is always included so systemd
/// unloads the transient unit's state once it goes inactive, rather than
/// accumulating unit records across repeated harness runs.
pub fn systemd_run_argv(
    unit_name: &str,
    slice: Option<&str>,
    scope: bool,
    inner_argv: &[String],
) -> Vec<String> {
    let mut argv = vec!["--user".to_string(), "--collect".to_string()];
    if scope {
        argv.push("--scope".to_string());
    }
    argv.push(format!("--unit={unit_name}"));
    if let Some(s) = slice {
        argv.push(format!("--slice={s}"));
    }
    argv.push("--".to_string());
    argv.extend(inner_argv.iter().cloned());
    argv
}

/// Host facts carried in the report for correlating results across
/// machines/configurations. Detected, never assumed: the harness must be
/// able to measure a machine with rlm not installed at all (the control
/// arm), so these fields describe what was found, not what the harness
/// depends on.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostInfo {
    pub mem_total_kb: u64,
    pub kernel: String,
    pub rlm_installed: bool,
    pub guard_enabled: bool,
}

/// Parameters of this measurement run.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct RunInfo {
    pub duration_s: u64,
    pub baseline_s: u64,
    pub hog_fraction: f64,
    /// Measured harness noise floor, in microseconds — see Task 2's paired
    /// (touch − locked) trial stdev. Carried in the report so downstream
    /// decomposition can mark sub-floor deltas as inconclusive instead of
    /// hardcoding a value that may not match the machine that produced this
    /// particular report.
    pub noise_floor_us: i64,
}

/// One probe placement's collected output.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProbeReport {
    pub label: String,
    pub mode: String,
    pub ticks: Vec<Tick>,
}

/// The PSI sampler's collected output, reduced to the exact stall integral.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PsiReport {
    pub samples: Vec<PsiSample>,
    pub stall_some_us: u64,
    pub stall_full_us: u64,
}

/// The full report written to `report.json`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub schema: u32,
    pub host: HostInfo,
    pub run: RunInfo,
    pub probes: Vec<ProbeReport>,
    pub psi: PsiReport,
}

/// Parse one probe's JSON-lines output (header line, then one `Tick` per
/// line) into a `ProbeReport`. Pure — takes already-read string content, no
/// I/O. Per the probe's contract (see `lib.rs`'s crate doc), line 1 is
/// always a single merged header object and every subsequent line is a
/// `Tick`; there is never a second header. A line that fails to parse as a
/// `Tick` is skipped rather than failing the whole probe's data, so a
/// truncated final line (e.g. the process was killed mid-write, though the
/// probe only writes after its loop ends so this should not happen in
/// practice) can't discard every earlier good tick.
pub fn parse_probe_jsonl(label_fallback: &str, jsonl: &str) -> Result<ProbeReport, String> {
    let mut lines = jsonl.lines();
    let header_line = lines
        .next()
        .ok_or_else(|| "empty probe output (no header line)".to_string())?;
    let header: serde_json::Value = serde_json::from_str(header_line)
        .map_err(|e| format!("failed to parse probe header: {e}"))?;

    let label = header
        .get("label")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(label_fallback)
        .to_string();
    let mode = header
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut ticks = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(tick) = serde_json::from_str::<Tick>(line) {
            ticks.push(tick);
        }
    }

    Ok(ProbeReport { label, mode, ticks })
}

/// Parse the PSI sampler's JSON-lines output (header line, then one
/// `PsiSample` per line) into a `PsiReport`, computing the exact stall
/// integral (`psi::stall_us`) from the first and last sample. Pure — takes
/// already-read string content, no I/O. Fewer than two samples yields
/// `(0, 0)` rather than panicking or erroring — a too-short run has nothing
/// to integrate over, not a malformed run.
pub fn parse_psi_jsonl(jsonl: &str) -> Result<PsiReport, String> {
    let mut lines = jsonl.lines();
    lines
        .next()
        .ok_or_else(|| "empty PSI output (no header line)".to_string())?;

    let mut samples = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(sample) = serde_json::from_str::<PsiSample>(line) {
            samples.push(sample);
        }
    }

    let (stall_some_us, stall_full_us) = match (samples.first(), samples.last()) {
        (Some(first), Some(last)) => stall_us(first, last),
        _ => (0, 0),
    };

    Ok(PsiReport {
        samples,
        stall_some_us,
        stall_full_us,
    })
}

/// Assemble the final report from already-collected pieces. Pure — no I/O,
/// just structuring. `schema` is a fixed constant so a future breaking
/// change to the report shape has somewhere to bump.
pub fn assemble_report(
    host: HostInfo,
    run: RunInfo,
    probes: Vec<ProbeReport>,
    psi: PsiReport,
) -> Report {
    Report {
        schema: 1,
        host,
        run,
        probes,
        psi,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tick(t_ms: u64) -> Tick {
        Tick {
            t_ms,
            drift_us: 5,
            wait_ns: 100,
            majflt: 0,
        }
    }

    // -- preflight_check --

    #[test]
    fn preflight_rejects_missing_psi_memory() {
        let input = PreflightInput {
            psi_memory_exists: false,
            mem_total_kb: 1_000_000,
            mem_available_kb: 500_000,
            hog_fraction: 0.1,
            i_know: false,
        };
        assert_eq!(preflight_check(&input), Err(PreflightError::NoPsiMemory));
    }

    #[test]
    fn preflight_requires_i_know_on_large_ram_with_large_hog() {
        // 16 GiB total, hog fraction would allocate ~13 GiB of the 13 GiB
        // available: both MemTotal and the hog estimate cross the 12 GiB
        // threshold, so this needs an explicit --i-know.
        let mem_total_kb = 16 * 1024 * 1024;
        let mem_available_kb = 13 * 1024 * 1024;
        let input = PreflightInput {
            psi_memory_exists: true,
            mem_total_kb,
            mem_available_kb,
            hog_fraction: 1.0,
            i_know: false,
        };
        let err = preflight_check(&input).expect_err("should require --i-know");
        match err {
            PreflightError::NeedsIKnow {
                mem_total_kb: t,
                hog_estimated_kb: h,
            } => {
                assert_eq!(t, mem_total_kb);
                assert_eq!(h, mem_available_kb);
            }
            other => panic!("expected NeedsIKnow, got {other:?}"),
        }
    }

    #[test]
    fn preflight_i_know_overrides_large_hog_gate() {
        let input = PreflightInput {
            psi_memory_exists: true,
            mem_total_kb: 16 * 1024 * 1024,
            mem_available_kb: 13 * 1024 * 1024,
            hog_fraction: 1.0,
            i_know: true,
        };
        assert_eq!(preflight_check(&input), Ok(()));
    }

    #[test]
    fn preflight_allows_large_ram_with_small_hog() {
        // Large-RAM machine, but the hog itself only takes a small,
        // non-threatening slice of MemAvailable: no gate needed.
        let input = PreflightInput {
            psi_memory_exists: true,
            mem_total_kb: 16 * 1024 * 1024,
            mem_available_kb: 6 * 1024 * 1024,
            hog_fraction: 0.05,
            i_know: false,
        };
        assert_eq!(preflight_check(&input), Ok(()));
    }

    #[test]
    fn preflight_allows_small_ram_machine_even_at_full_hog_fraction() {
        // MemTotal below the large-RAM-desktop threshold: not the scenario
        // this gate protects against (e.g. a small CI VM), regardless of
        // hog fraction.
        let input = PreflightInput {
            psi_memory_exists: true,
            mem_total_kb: 8 * 1024 * 1024,
            mem_available_kb: 6 * 1024 * 1024,
            hog_fraction: 1.0,
            i_know: false,
        };
        assert_eq!(preflight_check(&input), Ok(()));
    }

    // -- parse_meminfo --

    #[test]
    fn parse_meminfo_extracts_total_and_available() {
        let content = "MemTotal:       15522732 kB\n\
                        MemFree:         2511476 kB\n\
                        MemAvailable:    6244240 kB\n\
                        Buffers:          248464 kB\n";
        assert_eq!(parse_meminfo(content), Some((15522732, 6244240)));
    }

    #[test]
    fn parse_meminfo_missing_field_is_none() {
        let content = "MemTotal:       15522732 kB\nMemFree: 2511476 kB\n";
        assert_eq!(parse_meminfo(content), None);
    }

    #[test]
    fn parse_meminfo_malformed_value_is_none() {
        let content = "MemTotal:       not-a-number kB\nMemAvailable:    6244240 kB\n";
        assert_eq!(parse_meminfo(content), None);
    }

    // -- command_on_path --

    #[test]
    fn command_on_path_finds_executable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin_path = dir.path().join("rlm");
        std::fs::write(&bin_path, "#!/bin/sh\n").expect("write fake binary");
        let path_var = format!("/nonexistent:{}", dir.path().display());
        assert!(command_on_path("rlm", &path_var));
    }

    #[test]
    fn command_on_path_absent_is_false() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path_var = format!("/nonexistent:{}", dir.path().display());
        assert!(!command_on_path("rlm", &path_var));
    }

    // -- hog_scratch_dir --

    #[test]
    fn hog_scratch_dir_prefers_dev_shm() {
        assert_eq!(hog_scratch_dir(true, "/home/user/results"), "/dev/shm");
    }

    #[test]
    fn hog_scratch_dir_falls_back_to_out_dir() {
        assert_eq!(
            hog_scratch_dir(false, "/home/user/results"),
            "/home/user/results"
        );
    }

    // -- probe_argv / psi_probe_argv / systemd_run_argv --

    #[test]
    fn probe_argv_never_includes_psi() {
        let argv = probe_argv(
            "/bin/rlm-probe",
            "session-locked",
            ProbeMode::Locked,
            "session.slice",
            "/tmp/out.jsonl",
            60,
            50,
            2,
        );
        assert_eq!(argv[0], "/bin/rlm-probe");
        assert!(argv.contains(&"--mode".to_string()));
        assert!(argv.contains(&"locked".to_string()));
        assert!(!argv.contains(&"--psi".to_string()));
    }

    #[test]
    fn psi_probe_argv_never_includes_mode() {
        // --psi and --mode are mutually exclusive and rejected by
        // rlm-probe itself; the PSI sampler's argv must never carry --mode
        // so a template mistake here would be caught by that guard, not
        // silently produce a mixed invocation.
        let argv = psi_probe_argv("/bin/rlm-probe", "psi", "/tmp/psi.jsonl", 60, 50);
        assert!(argv.contains(&"--psi".to_string()));
        assert!(!argv.contains(&"--mode".to_string()));
    }

    #[test]
    fn systemd_run_argv_scope_for_hog() {
        let inner = vec!["bash".to_string(), "hog.sh".to_string()];
        let argv = systemd_run_argv("rlm-harness-hog", None, true, &inner);
        assert!(argv.contains(&"--scope".to_string()));
        assert!(argv.contains(&"--collect".to_string()));
        assert!(argv.contains(&"--unit=rlm-harness-hog".to_string()));
        assert_eq!(&argv[argv.len() - 2..], ["bash", "hog.sh"]);
    }

    #[test]
    fn systemd_run_argv_service_with_slice_for_probe() {
        let inner = vec!["/bin/rlm-probe".to_string(), "--mode".to_string()];
        let argv = systemd_run_argv("rlm-harness-probe", Some("session.slice"), false, &inner);
        assert!(!argv.contains(&"--scope".to_string()));
        assert!(argv.contains(&"--slice=session.slice".to_string()));
        assert!(argv.contains(&"--unit=rlm-harness-probe".to_string()));
    }

    #[test]
    fn systemd_run_argv_no_slice_when_none() {
        let inner = vec!["/bin/rlm-probe".to_string(), "--psi".to_string()];
        let argv = systemd_run_argv("rlm-harness-psi", None, false, &inner);
        assert!(!argv.iter().any(|a| a.starts_with("--slice=")));
    }

    // -- parse_probe_jsonl / parse_psi_jsonl / assemble_report --

    #[test]
    fn parse_probe_jsonl_parses_header_and_ticks() {
        let jsonl = format!(
            "{{\"label\":\"session-locked\",\"mode\":\"locked\"}}\n{}\n{}\n",
            serde_json::to_string(&sample_tick(0)).unwrap(),
            serde_json::to_string(&sample_tick(50)).unwrap(),
        );
        let report = parse_probe_jsonl("fallback", &jsonl).expect("parse");
        assert_eq!(report.label, "session-locked");
        assert_eq!(report.mode, "locked");
        assert_eq!(report.ticks.len(), 2);
        assert_eq!(report.ticks[1].t_ms, 50);
    }

    #[test]
    fn parse_probe_jsonl_empty_is_err() {
        assert!(parse_probe_jsonl("fallback", "").is_err());
    }

    #[test]
    fn parse_probe_jsonl_falls_back_to_given_label_when_header_lacks_one() {
        let jsonl = "{\"mode\":\"touch\"}\n";
        let report = parse_probe_jsonl("app-touch", jsonl).expect("parse");
        assert_eq!(report.label, "app-touch");
        assert!(report.ticks.is_empty());
    }

    #[test]
    fn parse_probe_jsonl_skips_malformed_trailing_line() {
        let jsonl = format!(
            "{{\"label\":\"x\",\"mode\":\"touch\"}}\n{}\n{{not json",
            serde_json::to_string(&sample_tick(0)).unwrap(),
        );
        let report = parse_probe_jsonl("x", &jsonl).expect("parse");
        assert_eq!(report.ticks.len(), 1, "the one good tick must survive");
    }

    #[test]
    fn parse_psi_jsonl_computes_stall_us_from_first_and_last() {
        let a = PsiSample {
            t_ms: 0,
            some_avg10: 0.0,
            full_avg10: 0.0,
            some_total_us: 1000,
            full_total_us: 100,
        };
        let b = PsiSample {
            t_ms: 60_000,
            some_avg10: 50.0,
            full_avg10: 10.0,
            some_total_us: 31_000,
            full_total_us: 5_100,
        };
        let jsonl = format!(
            "{{\"psi_resource\":\"memory\"}}\n{}\n{}\n",
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
        );
        let report = parse_psi_jsonl(&jsonl).expect("parse");
        assert_eq!(report.samples.len(), 2);
        assert_eq!(report.stall_some_us, 30_000);
        assert_eq!(report.stall_full_us, 5_000);
    }

    #[test]
    fn parse_psi_jsonl_no_samples_is_zero_not_a_panic() {
        let jsonl = "{\"psi_resource\":\"memory\"}\n";
        let report = parse_psi_jsonl(jsonl).expect("parse");
        assert!(report.samples.is_empty());
        assert_eq!((report.stall_some_us, report.stall_full_us), (0, 0));
    }

    #[test]
    fn assemble_report_sets_schema_one() {
        let host = HostInfo {
            mem_total_kb: 1,
            kernel: "6.8.0".to_string(),
            rlm_installed: false,
            guard_enabled: false,
        };
        let run = RunInfo {
            duration_s: 60,
            baseline_s: 10,
            hog_fraction: 0.5,
            noise_floor_us: 40,
        };
        let psi = PsiReport {
            samples: vec![],
            stall_some_us: 0,
            stall_full_us: 0,
        };
        let report = assemble_report(host, run, vec![], psi);
        assert_eq!(report.schema, 1);
    }
}
