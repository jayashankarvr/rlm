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

/// Fraction of `MemAvailable`, at or above which the hog is judged to be
/// consuming enough of what's currently free to threaten a large-RAM
/// desktop, regardless of how much absolute headroom is left afterward.
/// `hog_estimated_kb` can never exceed `mem_available_kb` (it's defined as
/// a fraction of it), so a second *absolute* threshold on it — the
/// original bug — can never fire on a machine whose `MemAvailable` sits
/// below that absolute number, which is the common case (`MemAvailable`
/// is usually well under `MemTotal`). A relative threshold fires
/// regardless of how large `MemTotal` is.
pub const HIGH_HOG_FRACTION_THRESHOLD: f64 = 0.5;

/// Headroom left after the hog runs (`MemAvailable - hog_estimated_kb`),
/// in kB, below which the hog is judged to threaten a large-RAM desktop
/// regardless of what fraction was requested — catches a *low*
/// `--hog-fraction` on a machine that has very little `MemAvailable` to
/// begin with (so even a "small" fraction leaves almost nothing free).
pub const LOW_HEADROOM_THRESHOLD_KB: u64 = 2 * 1024 * 1024; // 2 GiB

/// Hard slack, in seconds, added on top of `baseline_s + duration_s` when
/// computing the hog's `--max-seconds` cap and the transient scope's
/// `RuntimeMaxSec=`. Covers the dbus round trips in `systemctl --user
/// stop`/`reset-failed`, `wait_for_unit_inactive`'s own deadline, and
/// general scheduling jitter — the run's own teardown path should always
/// finish comfortably inside it, so a hog that's still alive past this
/// slack is presumed orphaned, not just slow to tear down.
pub const HOG_MAX_SECONDS_SLACK: u64 = 30;

/// Safety margin applied on top of the hog's estimated size when setting
/// the transient scope's `MemoryMax=`. This bounds how large a *runaway*
/// hog can get (an arithmetic bug overshooting the intended fraction)
/// without clipping a correctly-sized hog due to backend/allocator
/// overhead (stress-ng's own resident footprint, bash, `dd`'s buffers).
pub const HOG_MEMORY_MAX_MARGIN: f64 = 1.25;

/// Dedicated transient slice for the hog's scope. Deliberately NOT
/// `app.slice` (systemd-run's default placement for a `--user` unit given
/// no `--slice`): `app-touch` is placed under `app.slice` on purpose, as
/// the sole probe meant to observe Phase 1's future dynamic cap on it. If
/// the hog shared that slice, any per-slice throttling would hit the hog
/// and the probe it's meant to pressure together, confounding the single
/// number `app-touch` exists to produce. `systemd-run --slice=` auto-vivifies
/// a transient slice by this name if it doesn't already exist.
pub const HOG_SLICE: &str = "rlm-harness-hog.slice";

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
                 requested --hog-fraction would allocate ~{hog_estimated_kb} kB of \
                 MemAvailable, which would consume at least {HIGH_HOG_FRACTION_THRESHOLD} \
                 of what's currently free and/or leave less than \
                 {LOW_HEADROOM_THRESHOLD_KB} kB of headroom behind. This looks like it \
                 could threaten a real desktop with substantial RAM. Re-run with --i-know \
                 to confirm you intend this."
            ),
        }
    }
}

/// The hog's estimated size in kB: `hog_fraction` of `mem_available_kb`,
/// rounded to the nearest kB. Shared by the preflight gate and the report
/// so both agree on the same number (the exact MB the hog allocates,
/// matching `hog.sh`'s own math, is `hog_estimated_mb` below).
pub fn hog_estimated_kb(hog_fraction: f64, mem_available_kb: u64) -> u64 {
    (hog_fraction * mem_available_kb as f64).round() as u64
}

/// Refuse-to-run decision. Pure: takes already-read facts, returns a
/// decision, does no I/O and spawns nothing.
pub fn preflight_check(input: &PreflightInput) -> Result<(), PreflightError> {
    if !input.psi_memory_exists {
        return Err(PreflightError::NoPsiMemory);
    }

    let hog_estimated_kb = hog_estimated_kb(input.hog_fraction, input.mem_available_kb);
    let headroom_after_hog_kb = input.mem_available_kb.saturating_sub(hog_estimated_kb);

    // Relative, not a second absolute threshold (see the constants' doc
    // comments for why the absolute version was the bug): on a large-RAM
    // machine, require --i-know when the hog would either consume a large
    // share of what's currently free, or leave little headroom behind —
    // whichever condition trips first.
    let large_ram_machine = input.mem_total_kb > LARGE_RAM_THRESHOLD_KB;
    let high_fraction = input.hog_fraction >= HIGH_HOG_FRACTION_THRESHOLD;
    let low_headroom = headroom_after_hog_kb < LOW_HEADROOM_THRESHOLD_KB;
    let threatens_large_ram_desktop = large_ram_machine && (high_fraction || low_headroom);

    if threatens_large_ram_desktop && !input.i_know {
        return Err(PreflightError::NeedsIKnow {
            mem_total_kb: input.mem_total_kb,
            hog_estimated_kb,
        });
    }

    Ok(())
}

/// The hog's exact size in MB, matching `hog.sh`'s own `awk` computation
/// byte-for-byte (`(fraction * mem_available_kb) / 1024`, floored, with a
/// 1 MB floor) — so the report's `hog.estimated_mb` and the `MemoryMax=`
/// sizing below describe the same number `hog.sh` actually allocates,
/// not an independently-rounded approximation of it.
pub fn hog_estimated_mb(hog_fraction: f64, mem_available_kb: u64) -> u64 {
    let mb = (hog_fraction * mem_available_kb as f64) / 1024.0;
    let mb = if mb < 1.0 { 1.0 } else { mb };
    mb.trunc() as u64
}

/// The hog's `--max-seconds` cap (and the transient scope's
/// `RuntimeMaxSec=`, set to the same value): long enough to cover the
/// full intended run (`baseline_s + duration_s`) plus `HOG_MAX_SECONDS_SLACK`
/// for teardown, short enough that an orphaned hog (runner SIGKILLed,
/// OOM-killed, terminal closed) self-terminates in bounded time instead of
/// holding memory until reboot.
pub fn hog_max_seconds(baseline_s: u64, duration_s: u64) -> u64 {
    baseline_s + duration_s + HOG_MAX_SECONDS_SLACK
}

/// `MemoryMax=` for the hog's transient scope, in bytes: the hog's exact
/// estimated size (`hog_estimated_mb`), scaled up by `HOG_MEMORY_MAX_MARGIN`.
/// This bounds how large a runaway hog can get — an arithmetic error in the
/// fraction maths cannot outrun the preflight gate — without clipping a
/// correctly-sized hog's own backend overhead.
pub fn hog_memory_max_bytes(hog_estimated_mb: u64) -> u64 {
    ((hog_estimated_mb as f64) * 1024.0 * 1024.0 * HOG_MEMORY_MAX_MARGIN).round() as u64
}

/// Which hog backend `hog.sh` will actually use, given whether `stress-ng`
/// is on `PATH` (the same check `hog.sh` itself makes with
/// `command -v stress-ng`) — recorded in the report because the two
/// backends produce materially different pressure (`stress-ng --vm`
/// touches memory continuously; the `dd`-into-tmpfs fallback just holds a
/// static allocation).
pub fn hog_backend(stress_ng_available: bool) -> &'static str {
    if stress_ng_available {
        "stress-ng"
    } else {
        "dd"
    }
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

/// Parse `SwapTotal` (kB) out of `/proc/meminfo` content. Pure. `None` if
/// the field is missing or malformed. Recorded in the report so a past
/// run's numbers can be interpreted correctly — swap changes how much
/// headroom a hog actually has before triggering real memory pressure.
pub fn parse_swap_total_kb(content: &str) -> Option<u64> {
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        if key == "SwapTotal:" {
            return fields.next()?.parse::<u64>().ok();
        }
    }
    None
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
/// accumulating unit records across repeated harness runs. `properties`
/// are passed through as `--property=<entry>` (e.g. `RuntimeMaxSec=90s`,
/// `MemoryMax=123456`) — used on the hog's scope for the duration/size
/// backstops (see the module doc); empty for the probes/PSI sampler.
pub fn systemd_run_argv(
    unit_name: &str,
    slice: Option<&str>,
    scope: bool,
    properties: &[String],
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
    for p in properties {
        argv.push(format!("--property={p}"));
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
    pub hostname: String,
    /// `SwapTotal` from `/proc/meminfo`, kB. Swap configuration materially
    /// changes how a given `--hog-fraction` translates into real memory
    /// pressure, so it's recorded rather than left to be guessed from
    /// context that may no longer be available later.
    pub swap_total_kb: u64,
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
    /// `MemAvailable` (kB) at run start — `hog_fraction` is a fraction of
    /// *this*, not of `MemTotal`, so without it a past run's absolute hog
    /// size is unrecoverable and two runs with the same fraction are not
    /// comparable.
    pub mem_available_kb: u64,
    pub interval_ms: u64,
    pub working_set_mb: u64,
    /// Unix seconds at run start.
    pub timestamp_unix_s: u64,
}

/// What actually happened with the hog this run — separate from
/// `RunInfo` (the requested parameters) because this is what was
/// *observed*, including whether the hog ever actually held the memory it
/// was asked to.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HogInfo {
    /// Exact MB `hog.sh` computed it would allocate (see `hog_estimated_mb`).
    pub estimated_mb: u64,
    /// Which backend actually ran: "stress-ng" or "dd" — materially
    /// different pressure (see `hog_backend`).
    pub backend: String,
    /// The `--max-seconds`/`RuntimeMaxSec=` cap applied to this run's hog.
    pub max_seconds: u64,
    /// The `MemoryMax=` applied to the hog's transient scope, in bytes.
    pub memory_max_bytes: u64,
    /// The transient slice the hog's scope was placed under.
    pub slice: String,
    /// Whether the hog was confirmed `active` shortly after starting AND
    /// still `active` right before the hold period ended — i.e. it
    /// actually held memory for (approximately) the intended duration,
    /// rather than failing silently (e.g. ENOSPC on `/dev/shm`) and
    /// leaving the rest of the run measuring an unloaded machine.
    pub verified_running: bool,
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
    pub hog: HogInfo,
    pub probes: Vec<ProbeReport>,
    pub psi: PsiReport,
    /// Loud, structured warnings about anything that could make this
    /// report's numbers unreliable (a probe unit that didn't go inactive
    /// before its deadline, a hog that failed to start or died early,
    /// etc.) — surfaced here so a downstream consumer doesn't have to
    /// scrape stderr to find out.
    pub warnings: Vec<String>,
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
    hog: HogInfo,
    probes: Vec<ProbeReport>,
    psi: PsiReport,
    warnings: Vec<String>,
) -> Report {
    Report {
        schema: 2,
        host,
        run,
        hog,
        probes,
        psi,
        warnings,
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

    // -- C2 regression: the three scenarios required by the review's
    // evidence request, using this machine's own /proc/meminfo profile,
    // a much larger box, and a modest run. --

    #[test]
    fn preflight_gates_this_machines_profile_at_full_hog_fraction() {
        // This dev machine: MemTotal ~14.8 GiB, MemAvailable ~6.0 GiB. The
        // original absolute-threshold bug never gated here (a fraction of
        // MemAvailable can never itself exceed 12 GiB when MemAvailable is
        // only ~6 GiB), even though --hog-fraction 1.0 takes 100% of what's
        // currently free. The fixed, relative gate must fire.
        let input = PreflightInput {
            psi_memory_exists: true,
            mem_total_kb: 15_522_732,
            mem_available_kb: 6_244_240,
            hog_fraction: 1.0,
            i_know: false,
        };
        assert!(matches!(
            preflight_check(&input),
            Err(PreflightError::NeedsIKnow { .. })
        ));
    }

    #[test]
    fn preflight_gates_a_64gb_box_at_95_percent_fraction() {
        // A large box with plenty of absolute headroom left afterward
        // (2.5 GiB) -- low_headroom alone would not trip -- but the
        // fraction itself (0.95) is high enough that high_fraction must.
        let mem_total_kb = 64 * 1024 * 1024;
        let mem_available_kb = 50 * 1024 * 1024;
        let input = PreflightInput {
            psi_memory_exists: true,
            mem_total_kb,
            mem_available_kb,
            hog_fraction: 0.95,
            i_know: false,
        };
        assert!(matches!(
            preflight_check(&input),
            Err(PreflightError::NeedsIKnow { .. })
        ));
    }

    #[test]
    fn preflight_allows_a_modest_run_on_a_large_ram_machine() {
        // Large-RAM machine, low fraction, plenty of headroom left over:
        // neither high_fraction nor low_headroom trips.
        let input = PreflightInput {
            psi_memory_exists: true,
            mem_total_kb: 15_522_732,
            mem_available_kb: 6_244_240,
            hog_fraction: 0.05,
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
        let argv = systemd_run_argv("rlm-harness-hog", None, true, &[], &inner);
        assert!(argv.contains(&"--scope".to_string()));
        assert!(argv.contains(&"--collect".to_string()));
        assert!(argv.contains(&"--unit=rlm-harness-hog".to_string()));
        assert_eq!(&argv[argv.len() - 2..], ["bash", "hog.sh"]);
    }

    #[test]
    fn systemd_run_argv_service_with_slice_for_probe() {
        let inner = vec!["/bin/rlm-probe".to_string(), "--mode".to_string()];
        let argv = systemd_run_argv(
            "rlm-harness-probe",
            Some("session.slice"),
            false,
            &[],
            &inner,
        );
        assert!(!argv.contains(&"--scope".to_string()));
        assert!(argv.contains(&"--slice=session.slice".to_string()));
        assert!(argv.contains(&"--unit=rlm-harness-probe".to_string()));
    }

    #[test]
    fn systemd_run_argv_no_slice_when_none() {
        let inner = vec!["/bin/rlm-probe".to_string(), "--psi".to_string()];
        let argv = systemd_run_argv("rlm-harness-psi", None, false, &[], &inner);
        assert!(!argv.iter().any(|a| a.starts_with("--slice=")));
    }

    #[test]
    fn systemd_run_argv_includes_properties() {
        let inner = vec!["bash".to_string(), "hog.sh".to_string()];
        let properties = vec![
            "RuntimeMaxSec=90s".to_string(),
            "MemoryMax=123456".to_string(),
        ];
        let argv = systemd_run_argv(
            "rlm-harness-hog",
            Some(HOG_SLICE),
            true,
            &properties,
            &inner,
        );
        assert!(argv.contains(&"--property=RuntimeMaxSec=90s".to_string()));
        assert!(argv.contains(&"--property=MemoryMax=123456".to_string()));
        assert!(argv.contains(&format!("--slice={HOG_SLICE}")));
        // properties must appear before the `--` separator, not swallowed
        // into the wrapped command's own argv.
        let sep = argv.iter().position(|a| a == "--").expect("separator");
        assert_eq!(&argv[sep + 1..], ["bash", "hog.sh"]);
    }

    #[test]
    fn systemd_run_argv_no_properties_when_empty() {
        let inner = vec!["/bin/rlm-probe".to_string()];
        let argv = systemd_run_argv("rlm-harness-probe", None, false, &[], &inner);
        assert!(!argv.iter().any(|a| a.starts_with("--property=")));
    }

    // -- hog_estimated_mb / hog_max_seconds / hog_memory_max_bytes / hog_backend --

    #[test]
    fn hog_estimated_mb_matches_hog_sh_awk_math() {
        // 0.3 * 6_244_240 kB / 1024 = 1829.4... MB, truncated (matches
        // awk's printf "%d" on a non-integer, which truncates).
        assert_eq!(hog_estimated_mb(0.3, 6_244_240), 1829);
    }

    #[test]
    fn hog_estimated_mb_has_a_1mb_floor() {
        assert_eq!(hog_estimated_mb(0.0001, 100), 1);
    }

    #[test]
    fn hog_max_seconds_sums_baseline_duration_and_slack() {
        assert_eq!(hog_max_seconds(10, 60), 10 + 60 + HOG_MAX_SECONDS_SLACK);
    }

    #[test]
    fn hog_memory_max_bytes_applies_margin() {
        let mb = 1000;
        let expected = (mb as f64 * 1024.0 * 1024.0 * HOG_MEMORY_MAX_MARGIN).round() as u64;
        assert_eq!(hog_memory_max_bytes(mb), expected);
        assert!(
            hog_memory_max_bytes(mb) > mb * 1024 * 1024,
            "must be strictly larger than the raw size"
        );
    }

    #[test]
    fn hog_backend_prefers_stress_ng_when_available() {
        assert_eq!(hog_backend(true), "stress-ng");
        assert_eq!(hog_backend(false), "dd");
    }

    // -- parse_swap_total_kb --

    #[test]
    fn parse_swap_total_kb_extracts_value() {
        let content = "MemTotal:       15522732 kB\nSwapTotal:       8388604 kB\n";
        assert_eq!(parse_swap_total_kb(content), Some(8_388_604));
    }

    #[test]
    fn parse_swap_total_kb_missing_is_none() {
        let content = "MemTotal:       15522732 kB\n";
        assert_eq!(parse_swap_total_kb(content), None);
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
    fn assemble_report_sets_schema_two() {
        let host = HostInfo {
            mem_total_kb: 1,
            kernel: "6.8.0".to_string(),
            rlm_installed: false,
            guard_enabled: false,
            hostname: "test-host".to_string(),
            swap_total_kb: 0,
        };
        let run = RunInfo {
            duration_s: 60,
            baseline_s: 10,
            hog_fraction: 0.5,
            noise_floor_us: 40,
            mem_available_kb: 2,
            interval_ms: 50,
            working_set_mb: 2,
            timestamp_unix_s: 0,
        };
        let hog = HogInfo {
            estimated_mb: 1,
            backend: "dd".to_string(),
            max_seconds: 100,
            memory_max_bytes: 1024 * 1024,
            slice: HOG_SLICE.to_string(),
            verified_running: true,
        };
        let psi = PsiReport {
            samples: vec![],
            stall_some_us: 0,
            stall_full_us: 0,
        };
        let report = assemble_report(host, run, hog, vec![], psi, vec![]);
        assert_eq!(report.schema, 2);
    }
}
