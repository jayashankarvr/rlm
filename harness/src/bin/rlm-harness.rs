//! `rlm-harness` — orchestrates one measurement run: places the three
//! `rlm-probe` instances (session-locked, session-touch, app-touch), starts
//! a PSI sampler, drives a synthetic memory hog, and emits one
//! `report.json`.
//!
//! ## Safety
//!
//! This tool runs a memory hog on a real machine. Two guards protect the
//! operator:
//!
//! - **Preflight** (`harness::runner::preflight_check`): refuses to run at
//!   all without `/proc/pressure/memory`, and refuses to run without
//!   `--i-know` if `MemTotal` is above 12 GiB *and* the requested
//!   `--hog-fraction` would itself allocate more than 12 GiB — i.e. this
//!   looks like it could put a real dent in what is plausibly the
//!   operator's own daily-driver desktop.
//! - **Cleanup is bulletproof, not best-effort-only-on-the-happy-path.**
//!   [`UnitGuard`] is a Drop guard covering every `systemd-run` unit this
//!   process starts (the three probes, the PSI sampler, and the hog scope)
//!   plus the hog's known tmpfs scratch file. Because it is a Drop guard,
//!   it runs on every return path out of [`run`] — success, an `Err` from
//!   any `?`, or a panic unwind — not just the ones we remember to
//!   hand-write a cleanup call for. `main` follows the same shape as
//!   `rlm-probe`: all fallible work lives in `run(args) -> Result<...>`,
//!   and `main` calls `std::process::exit` exactly once, *after* `run`
//!   returns. `std::process::exit` does not run destructors, so calling it
//!   from inside `run` (or anywhere `UnitGuard` might still be alive) would
//!   silently skip the hog teardown — this project has already paid for
//!   that lesson once (see `rlm-probe.rs`), so this binary is built to the
//!   same discipline. SIGINT/SIGTERM are handled the same way `rlm-guard`
//!   does it (`ctrlc` + an `AtomicBool` checked between sleep chunks): a
//!   signal makes `run` return `Err` promptly, `UnitGuard` still drops
//!   normally, and the hog/probes still get torn down.

use clap::Parser;
use harness::runner::{self, HostInfo, PreflightInput, Report, RunInfo};
use harness::ProbeMode;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `hog.sh`'s source, embedded at compile time so the runner never depends
/// on where it's installed relative to the binary — it's written out to
/// `--out-dir` at the start of every run instead of being looked up on
/// disk.
const HOG_SCRIPT: &str = include_str!("../../scripts/hog.sh");

#[derive(Parser, Debug)]
#[command(name = "rlm-harness")]
struct Args {
    /// Directory to write probe output, the hog script, and report.json
    /// into. Created if missing.
    #[arg(long)]
    out_dir: String,

    /// Duration, in seconds, of the hog-under-pressure measurement window
    /// (after the quiet baseline). Probes run for `baseline_s +
    /// duration_s` total, so their ticks cover both windows continuously.
    #[arg(long, default_value_t = 60)]
    duration_s: u64,

    /// Quiet baseline, in seconds, collected before the hog starts.
    #[arg(long, default_value_t = 10)]
    baseline_s: u64,

    /// Fraction (0..1] of `MemAvailable` the hog allocates. Required —
    /// this induces real memory pressure, so there is no default that's
    /// safe to reach for without thinking about it.
    #[arg(long)]
    hog_fraction: f64,

    /// Probe sleep-loop interval, in milliseconds, passed through to every
    /// `rlm-probe` instance.
    #[arg(long, default_value_t = 50)]
    interval_ms: u64,

    /// Anonymous working-set size, in mebibytes, passed through to every
    /// `rlm-probe` instance.
    #[arg(long, default_value_t = 2)]
    working_set_mb: u64,

    /// Confirms a run whose hog fraction could threaten a large-RAM
    /// desktop (see module doc). Required by the preflight gate in that
    /// case; ignored (harmlessly) otherwise.
    #[arg(long)]
    i_know: bool,

    /// Harness noise floor, in microseconds, carried into the report for
    /// downstream decomposition (Task 5). Default is this project's
    /// measured value from Task 2's paired trials on the reference
    /// machine — recalibrate per machine.
    #[arg(long, default_value_t = 40)]
    noise_floor_us: i64,

    /// Override the path to the `rlm-probe` binary. Defaults to a binary
    /// named `rlm-probe` next to this one (the normal case: both binaries
    /// come from the same `cargo build`).
    #[arg(long)]
    rlm_probe_path: Option<String>,
}

fn main() {
    let args = Args::parse();

    // Same discipline as rlm-probe.rs: all fallible work lives in `run`,
    // which returns `Err` instead of calling `std::process::exit` itself.
    // `std::process::exit` does not run destructors, so any RAII guard
    // still alive at the moment of exit -- most importantly `UnitGuard`,
    // which is what actually tears down the hog and the probe/PSI units --
    // would silently skip its cleanup. Returning from `run` lets every
    // guard drop normally before `main` decides whether to exit non-zero.
    if let Err(e) = run(args) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Which kind of transient systemd unit a guard entry stops -- determines
/// the suffix systemctl needs (`.service` vs `.scope`).
#[derive(Debug, Clone, Copy, PartialEq)]
enum UnitKind {
    Service,
    Scope,
}

impl UnitKind {
    fn suffix(self) -> &'static str {
        match self {
            UnitKind::Service => ".service",
            UnitKind::Scope => ".scope",
        }
    }
}

/// RAII guard covering every transient systemd unit this run starts, plus
/// the hog's known tmpfs scratch file. Dropping it (on any return path --
/// success, an early `?`, or a panic unwind) stops every registered unit
/// and best-effort removes the scratch file, so a run that dies partway
/// through never leaves the hog or a probe resident. All cleanup here is
/// best-effort (errors ignored): Drop cannot return a Result, and a
/// cleanup step failing is not a reason to skip the remaining ones.
struct UnitGuard {
    units: Vec<(String, UnitKind)>,
    hog_scratch_path: Option<PathBuf>,
}

impl UnitGuard {
    fn new(hog_scratch_path: PathBuf) -> Self {
        UnitGuard {
            units: Vec::new(),
            hog_scratch_path: Some(hog_scratch_path),
        }
    }

    fn track(&mut self, name: String, kind: UnitKind) {
        self.units.push((name, kind));
    }

    /// Best-effort stop of every currently-tracked unit. Called explicitly
    /// at the natural end of a successful run (so the report can be
    /// written promptly instead of waiting for Drop) as well as from Drop
    /// itself (so an early-return path still tears everything down).
    /// Idempotent: stopping an already-stopped unit is a harmless no-op.
    fn stop_all(&self) {
        for (name, kind) in &self.units {
            let unit = format!("{name}{}", kind.suffix());
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &unit])
                .status();
            let _ = Command::new("systemctl")
                .args(["--user", "reset-failed", &unit])
                .status();
        }
    }
}

impl Drop for UnitGuard {
    fn drop(&mut self) {
        self.stop_all();
        if let Some(path) = &self.hog_scratch_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    if !(0.0..=1.0).contains(&args.hog_fraction) {
        return Err("--hog-fraction must be in (0, 1]".into());
    }

    // SIGINT/SIGTERM: same pattern as rlm-guard (ctrlc + AtomicBool checked
    // between sleep chunks). A signal makes every subsequent
    // interruptible_sleep/wait_for_unit_inactive call return promptly and
    // `run` return Err, which lets UnitGuard drop and tear down the hog and
    // every probe/PSI unit before this process actually exits.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = Arc::clone(&shutdown);
        let _ = ctrlc::set_handler(move || s.store(true, Ordering::SeqCst));
    }

    let meminfo = std::fs::read_to_string("/proc/meminfo")
        .map_err(|e| format!("failed to read /proc/meminfo: {e}"))?;
    let (mem_total_kb, mem_available_kb) = runner::parse_meminfo(&meminfo)
        .ok_or("failed to parse MemTotal/MemAvailable out of /proc/meminfo")?;

    let preflight_input = PreflightInput {
        psi_memory_exists: Path::new("/proc/pressure/memory").exists(),
        mem_total_kb,
        mem_available_kb,
        hog_fraction: args.hog_fraction,
        i_know: args.i_know,
    };
    if let Err(e) = runner::preflight_check(&preflight_input) {
        return Err(format!("preflight check failed: {e}").into());
    }

    std::fs::create_dir_all(&args.out_dir)
        .map_err(|e| format!("failed to create --out-dir {}: {e}", args.out_dir))?;

    let probe_bin = resolve_probe_path(&args)?;

    let hog_script_path = Path::new(&args.out_dir).join("hog.sh");
    std::fs::write(&hog_script_path, HOG_SCRIPT)
        .map_err(|e| format!("failed to write hog script: {e}"))?;

    let run_id = std::process::id();
    let dev_shm_available = Path::new("/dev/shm").is_dir();
    let hog_scratch_dir = runner::hog_scratch_dir(dev_shm_available, &args.out_dir);
    let hog_scratch_path = Path::new(hog_scratch_dir).join(format!(".rlm-hog-scratch-{run_id}"));

    // The guard is created before anything is spawned, and every unit is
    // registered into it the moment it's confirmed started -- so a later
    // failure (a probe fails to place, the hog fails to start, a signal
    // arrives) still tears down everything placed so far when this
    // function returns.
    let mut guard = UnitGuard::new(hog_scratch_path.clone());

    let probe_total_s = args.baseline_s + args.duration_s;
    let probe_specs: [(&str, ProbeMode, Option<&str>); 3] = [
        ("session-locked", ProbeMode::Locked, Some("session.slice")),
        ("session-touch", ProbeMode::Touch, Some("session.slice")),
        // The only probe under Phase 1's future dynamic cap (default
        // app.slice, no --slice) -- the sole source of the
        // foreground-throttling number.
        ("app-touch", ProbeMode::Touch, None),
    ];

    let mut probe_paths: Vec<(String, PathBuf)> = Vec::new();
    for (label, mode, slice) in probe_specs {
        let out_path = Path::new(&args.out_dir).join(format!("{label}.jsonl"));
        let inner = runner::probe_argv(
            &probe_bin,
            label,
            mode,
            slice.unwrap_or(""),
            out_path
                .to_str()
                .ok_or("--out-dir path is not valid UTF-8")?,
            probe_total_s,
            args.interval_ms,
            args.working_set_mb,
        );
        let unit_name = format!("rlm-harness-{run_id}-{label}");
        let sd_argv = runner::systemd_run_argv(&unit_name, slice, false, &inner);
        run_systemd_run(&sd_argv).map_err(|e| format!("failed to place probe {label}: {e}"))?;
        guard.track(unit_name, UnitKind::Service);
        probe_paths.push((label.to_string(), out_path));

        if shutdown.load(Ordering::SeqCst) {
            return Err("interrupted while placing probes".into());
        }
    }

    let psi_out_path = Path::new(&args.out_dir).join("psi.jsonl");
    let psi_inner = runner::psi_probe_argv(
        &probe_bin,
        "psi",
        psi_out_path
            .to_str()
            .ok_or("--out-dir path is not valid UTF-8")?,
        probe_total_s,
        args.interval_ms,
    );
    let psi_unit_name = format!("rlm-harness-{run_id}-psi");
    let psi_sd_argv = runner::systemd_run_argv(&psi_unit_name, None, false, &psi_inner);
    run_systemd_run(&psi_sd_argv).map_err(|e| format!("failed to place PSI sampler: {e}"))?;
    guard.track(psi_unit_name, UnitKind::Service);

    // Quiet baseline before the hog starts.
    if interruptible_sleep(Duration::from_secs(args.baseline_s), &shutdown) {
        return Err("interrupted during baseline".into());
    }

    // The hog: a --scope unit (not --service) because the runner needs to
    // stop it at an arbitrary moment mid-run, unlike the probes which run
    // to their own natural completion.
    let hog_unit_name = format!("rlm-harness-{run_id}-hog");
    let hog_inner = vec![
        "bash".to_string(),
        hog_script_path
            .to_str()
            .ok_or("--out-dir path is not valid UTF-8")?
            .to_string(),
        "--fraction".to_string(),
        args.hog_fraction.to_string(),
        "--mem-available-kb".to_string(),
        mem_available_kb.to_string(),
        "--tmp-file".to_string(),
        hog_scratch_path
            .to_str()
            .ok_or("--out-dir path is not valid UTF-8")?
            .to_string(),
    ];
    let hog_sd_argv = runner::systemd_run_argv(&hog_unit_name, None, true, &hog_inner);
    // `--scope` runs synchronously in the invoking process until the
    // wrapped command exits, so this must be `spawn` (background), never
    // `status`/`output` (which would block until the hog is torn down --
    // exactly what this call is supposed to start, not wait for).
    let mut hog_child = Command::new("systemd-run")
        .args(&hog_sd_argv)
        .spawn()
        .map_err(|e| format!("failed to start hog: {e}"))?;
    guard.track(hog_unit_name.clone(), UnitKind::Scope);

    // Hold while the hog runs.
    let interrupted = interruptible_sleep(Duration::from_secs(args.duration_s), &shutdown);

    // Stop the hog now (rather than waiting for `guard`'s Drop at the end
    // of this function) so its memory pressure ends before we wait for the
    // probes to finish writing their output, and so an interrupted run
    // frees memory immediately instead of after a possibly-slow probe
    // wait. `systemctl stop` sends SIGTERM to every process in the scope,
    // which both `hog.sh`'s own trap and this explicit teardown handle;
    // `hog_child.kill()` is a hard backstop for the (should-not-happen)
    // case where the scope somehow didn't tear down its process tree.
    let hog_unit_full = format!("{hog_unit_name}.scope");
    let _ = Command::new("systemctl")
        .args(["--user", "stop", &hog_unit_full])
        .status();
    let _ = Command::new("systemctl")
        .args(["--user", "reset-failed", &hog_unit_full])
        .status();
    let _ = hog_child.kill();
    let _ = hog_child.wait();
    let _ = std::fs::remove_file(&hog_scratch_path);

    if interrupted {
        return Err("interrupted while the hog was running".into());
    }

    // Wait for the probe/PSI units to finish writing their output. Their
    // process lifetime runs up to one --interval-ms past --duration-s
    // (tick data is bounded to the duration, but the process exits
    // slightly later), so size this off process exit with slack, not off
    // tick timestamps.
    let deadline = Instant::now() + Duration::from_millis(args.interval_ms * 2 + 5_000);
    for (name, kind) in guard.units.clone() {
        if kind != UnitKind::Service {
            continue;
        }
        wait_for_unit_inactive(&format!("{name}{}", kind.suffix()), deadline, &shutdown)?;
    }

    // Explicit stop for tidiness (a unit that hit the deadline above
    // without going inactive, or one that failed, still gets stopped and
    // reset here rather than left for Drop).
    guard.stop_all();

    let mut probes = Vec::new();
    for (label, path) in &probe_paths {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read {label} probe output at {path:?}: {e}"))?;
        probes.push(
            runner::parse_probe_jsonl(label, &content)
                .map_err(|e| format!("failed to parse {label} probe output: {e}"))?,
        );
    }
    let psi_content = std::fs::read_to_string(&psi_out_path)
        .map_err(|e| format!("failed to read PSI sampler output: {e}"))?;
    let psi_report = runner::parse_psi_jsonl(&psi_content)
        .map_err(|e| format!("failed to parse PSI sampler output: {e}"))?;

    let host = HostInfo {
        mem_total_kb,
        kernel: read_kernel_release(),
        rlm_installed: runner::command_on_path("rlm", &std::env::var("PATH").unwrap_or_default()),
        guard_enabled: rlm_guard_running(),
    };
    let run_info = RunInfo {
        duration_s: args.duration_s,
        baseline_s: args.baseline_s,
        hog_fraction: args.hog_fraction,
        noise_floor_us: args.noise_floor_us,
    };
    let report = runner::assemble_report(host, run_info, probes, psi_report);
    write_report(&args.out_dir, &report)?;

    Ok(())
}

fn write_report(out_dir: &str, report: &Report) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = Path::new(out_dir).join("report.json");
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(&report_path, json)
        .map_err(|e| format!("failed to write {report_path:?}: {e}"))?;
    Ok(())
}

/// Resolve the `rlm-probe` binary path: `--rlm-probe-path` if given,
/// otherwise a binary named `rlm-probe` next to this one (the normal case
/// -- both come from the same `cargo build`).
fn resolve_probe_path(args: &Args) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(p) = &args.rlm_probe_path {
        return Ok(p.clone());
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("failed to locate this executable's own path: {e}"))?;
    let dir = exe
        .parent()
        .ok_or("this executable's path has no parent directory")?;
    let sibling = dir.join("rlm-probe");
    if !sibling.exists() {
        return Err(format!(
            "rlm-probe not found next to rlm-harness at {sibling:?}; \
             build both binaries (cargo build -p harness) or pass --rlm-probe-path"
        )
        .into());
    }
    Ok(sibling.to_string_lossy().to_string())
}

/// Run `systemd-run --user ...` for a transient service unit (i.e. NOT
/// `--scope`, which blocks). systemd-run's own process returns once the
/// unit is registered and started; it does not wait for the unit to
/// finish.
fn run_systemd_run(argv: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new("systemd-run")
        .args(argv)
        .output()
        .map_err(|e| format!("failed to spawn systemd-run: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "systemd-run exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

/// Sleep for `total`, checking `shutdown` every 100ms so a signal is
/// noticed promptly rather than only after the full duration elapses.
/// Returns `true` if `shutdown` was observed at any point.
fn interruptible_sleep(total: Duration, shutdown: &AtomicBool) -> bool {
    let step = Duration::from_millis(100);
    let start = Instant::now();
    while start.elapsed() < total {
        if shutdown.load(Ordering::SeqCst) {
            return true;
        }
        let remaining = total - start.elapsed();
        std::thread::sleep(std::cmp::min(step, remaining));
    }
    shutdown.load(Ordering::SeqCst)
}

/// Poll `systemctl --user show <unit> --property=ActiveState --value`
/// until the unit reports inactive/failed (or is no longer known at all),
/// `deadline` passes, or `shutdown` fires. A unit that's still running past
/// `deadline` is not treated as a hard error here -- the caller stops it
/// explicitly afterward regardless, and a probe that genuinely never wrote
/// its output surfaces as a read/parse error a few lines later, which is a
/// clearer failure than this function guessing at a timeout's meaning.
fn wait_for_unit_inactive(
    unit: &str,
    deadline: Instant,
    shutdown: &AtomicBool,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            return Err(format!("interrupted while waiting for {unit} to finish").into());
        }

        let output = Command::new("systemctl")
            .args(["--user", "show", unit, "--property=ActiveState", "--value"])
            .output();
        if let Ok(output) = output {
            let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if state.is_empty() || state == "inactive" || state == "failed" {
                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn read_kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Best-effort detection of a running `rlm-guard` process. Never a hard
/// dependency -- `pgrep` missing or failing just reports `false`.
fn rlm_guard_running() -> bool {
    Command::new("pgrep")
        .args(["-x", "rlm-guard"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
