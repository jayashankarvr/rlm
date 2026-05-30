//! `rlm-guard` — the freeze-guard daemon.
//!
//! Runs as a per-user systemd service. Each tick it samples memory pressure (PSI)
//! and the user's eligible processes, asks the pure [`PolicyEngine`] what to do,
//! and applies the resulting actions via the [`Effector`]. On shutdown it undoes
//! every intervention so nothing is left frozen.

use common::Config;
use rlm_core::guard::{Effector, PolicyEngine, Sampler};
use rlm_core::CgroupManager;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    if let Err(e) = run() {
        tracing::error!("rlm-guard exiting: {e}");
        std::process::exit(1);
    }
}

fn run() -> common::Result<()> {
    let config = Config::load().unwrap_or_default();
    let gcfg = config.guard.clone();

    if !gcfg.enabled {
        tracing::info!("guard disabled in config (guard.enabled = false); exiting");
        return Ok(());
    }

    let self_pid = std::process::id();
    // SAFETY: getuid() is always safe; it just reads our real UID from the kernel.
    let uid = unsafe { libc::getuid() };

    let manager = CgroupManager::new()?;
    let effector = Effector::new(&manager);
    let sampler = Sampler::new(gcfg.clone(), self_pid, uid);
    let mut engine = PolicyEngine::new(gcfg.clone());

    // Startup recovery: thaw/clean anything a prior crash left behind so no
    // process stays frozen across a restart.
    if let Err(e) = effector.sweep_leftovers() {
        tracing::warn!("startup sweep failed: {e}");
    }

    // Graceful shutdown on SIGINT/SIGTERM/SIGHUP (ctrlc "termination" feature).
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let s = Arc::clone(&shutdown);
        let _ = ctrlc::set_handler(move || s.store(true, Ordering::SeqCst));
    }

    let interval = Duration::from_millis(gcfg.timing.sample_interval_ms.max(100));
    let start = Instant::now();
    let mut warned_no_psi = false;

    tracing::info!(
        uid,
        interval_ms = interval.as_millis() as u64,
        "rlm-guard started"
    );

    while !shutdown.load(Ordering::SeqCst) {
        // Monotonic, injected into the pure engine for deterministic behavior.
        let now_ms = start.elapsed().as_millis() as u64;

        if let Some(sample) = sampler.sample() {
            let procs = sampler.eligible();
            for action in engine.tick(now_ms, sample, &procs) {
                if let Err(e) = effector.apply(&action) {
                    tracing::warn!(?action, "action failed: {e}");
                }
            }
        } else if !warned_no_psi {
            tracing::warn!("/proc/pressure/memory unavailable; guard cannot act on PSI");
            warned_no_psi = true;
        }

        sleep_responsive(interval, &shutdown);
    }

    tracing::info!("rlm-guard shutting down; undoing all interventions");
    if let Err(e) = effector.undo_all() {
        tracing::warn!("undo_all failed: {e}");
    }
    Ok(())
}

/// Sleep up to `total`, waking early if shutdown is requested.
fn sleep_responsive(total: Duration, shutdown: &AtomicBool) {
    let step = Duration::from_millis(100);
    let mut slept = Duration::ZERO;
    while slept < total {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }
        let chunk = step.min(total - slept);
        std::thread::sleep(chunk);
        slept += chunk;
    }
}
