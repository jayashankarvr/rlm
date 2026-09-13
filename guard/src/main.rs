//! `rlm-guard` — the freeze-guard daemon.
//!
//! Runs as a per-user systemd service. Each tick it samples memory pressure (PSI)
//! and the user's eligible processes, asks the pure [`PolicyEngine`] what to do,
//! and applies the resulting actions via the [`Effector`]. On shutdown it undoes
//! every intervention so nothing is left frozen.

use common::Config;
use rlm_core::guard::sampler::strip_cgroup_root;
use rlm_core::guard::{cgfs, journal_path, Effector, Journal, PolicyEngine, Sampler, SystemdUser};
use rlm_core::rules::RulesEnforcer;
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
    let enforcer = RulesEnforcer::new(&config);

    let self_pid = std::process::id();
    // SAFETY: getuid() is always safe; it just reads our real UID from the kernel.
    let uid = unsafe { libc::getuid() };

    let manager = CgroupManager::new()?;

    // Open the write-ahead journal. This must happen — and startup recovery
    // (below) must run — BEFORE any early-exit decision: the journal is the
    // only record of an in-place freeze/cap, and a user who disables the
    // guard (or has no rules configured) after a crash must still get their
    // frozen/capped cgroups restored on the next start (D5a fix — this used
    // to run after the early-exit check, so it never ran at all in that
    // case).
    //
    // A journal-open failure is only fatal when there are no rules to fall
    // back to AND the guard is actually enabled: persistent-rule enforcement
    // has no dependency on the journal at all (D5b fix — this used to be
    // fatal unconditionally, killing rules enforcement over a guard-only
    // concern like an unwritable $XDG_STATE_HOME). With rules configured, we
    // log loudly and continue without journal-backed escalation instead —
    // the daemon structurally cannot freeze/cap safely without a durable
    // journal anyway (`Effector` journals before every mutation), so
    // escalation is simply disabled for this run.
    //
    // When the guard is disabled and there are no rules either, there is
    // nothing to recover into: exit cleanly instead of `Err`. Returning
    // `Err` here used to `exit(1)` unconditionally (NEW-2 regression), which
    // under the shipped unit's `Restart=on-failure`/`RestartSec=2` restarts
    // the daemon every 2s forever against a config that can never heal
    // itself (nothing this process does can fix an unwritable
    // $XDG_STATE_HOME, and there's no escalation or rules work to attempt
    // either way).
    let journal = match Journal::open(journal_path(), cgfs::boot_id()) {
        Ok(j) => Some(j),
        Err(e) if enforcer.rule_count() > 0 => {
            tracing::error!(
                error = %e,
                "failed to open guard journal; startup crash-recovery skipped and freeze/cap \
                 escalation disabled for this run (persistent rules are unaffected)"
            );
            None
        }
        Err(e) if !gcfg.enabled => {
            tracing::warn!(
                error = %e,
                "guard disabled and no rules configured; journal unavailable and there is \
                 nothing to recover into; exiting cleanly instead of restart-looping"
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    // No session bus (e.g. headless) -> every action below falls back to raw
    // cgroupfs writes; SystemdUser::connect() already encodes that.
    let systemd = SystemdUser::connect();
    let effector = journal
        .as_ref()
        .map(|j| Effector::new(&manager, j, systemd.as_ref()));

    // Startup recovery: thaw/clean anything a prior crash left behind so no
    // process stays frozen across a restart. Runs whenever the journal is
    // available, regardless of whether escalation or rules end up active
    // for this run.
    if let Some(effector) = &effector {
        if let Err(e) = effector.sweep_leftovers() {
            tracing::warn!("startup sweep failed: {e}");
        }
    }

    // The daemon does two jobs: freeze protection (when enabled AND the
    // journal is available) and enforcing persistent application rules.
    // Only exit if there's truly nothing left to do.
    let escalation_enabled = gcfg.enabled && effector.is_some();
    if !escalation_enabled && enforcer.rule_count() == 0 {
        tracing::info!("guard disabled and no rules configured; exiting");
        return Ok(());
    }

    let rlm_base = strip_cgroup_root(manager.base_path());
    if rlm_base.is_none() {
        tracing::error!(
            "base_path {:?} isn't under /sys/fs/cgroup; disabling escalation target resolution (protect-matching and guard-status still work, but no freeze/cap victim will ever be selected)",
            manager.base_path()
        );
    }
    let sampler = Sampler::new(gcfg.clone(), self_pid, uid, rlm_base);
    let mut engine = PolicyEngine::new(gcfg.clone());

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
        freeze_guard = escalation_enabled,
        rules = enforcer.rule_count(),
        "rlm-guard started"
    );

    while !shutdown.load(Ordering::SeqCst) {
        // Monotonic, injected into the pure engine for deterministic behavior.
        let now_ms = start.elapsed().as_millis() as u64;

        // Freeze protection (PSI-driven), only when enabled and journal-backed.
        if gcfg.enabled {
            if let Some(effector) = &effector {
                if let Some(sample) = sampler.sample() {
                    let procs = sampler.eligible();
                    let live = sampler.live_cgroups();
                    for action in engine.tick(now_ms, sample, &procs, &live) {
                        if let Err(e) = effector.apply(&action) {
                            tracing::warn!(?action, "action failed: {e}");
                        }
                    }
                } else if !warned_no_psi {
                    tracing::warn!("/proc/pressure/memory unavailable; guard cannot act on PSI");
                    warned_no_psi = true;
                }
            }
        }

        // Persistent application rules: reconcile every tick (best-effort,
        // logs internally). Absorbs newly-launched matching instances.
        // Skip any rule cgroup the freeze guard currently holds a freeze or
        // cap intervention on (D1) — the two write to the same cgroups now
        // that the guard acts in place, so the enforcer must not fight it.
        enforcer.reconcile(&manager, &engine.intervened_cgroups());

        sleep_responsive(interval, &shutdown);
    }

    if let Some(effector) = &effector {
        tracing::info!("rlm-guard shutting down; undoing all interventions");
        if let Err(e) = effector.undo_all() {
            tracing::warn!("undo_all failed: {e}");
        }
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
