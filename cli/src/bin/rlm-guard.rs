//! `rlm-guard`, the freeze-guard daemon.
//!
//! Runs as a per-user systemd service. Each tick it samples memory pressure (PSI)
//! and, only when needed, the user's own processes, asks the pure [`PolicyEngine`] what to do,
//! and applies the resulting actions via the [`Effector`]. On shutdown it undoes
//! every intervention so nothing is left frozen.

use common::Config;
use rlm_core::guard::history;
use rlm_core::guard::notify::{
    flags_after_reload, memory_state, AppNames, DesktopSink, Memory, Notifier,
};
use rlm_core::guard::sampler::{live_cgroups, strip_cgroup_root, targets_from_procs};
use rlm_core::guard::{
    cgfs, try_journal_path, Effector, Journal, PolicyEngine, Sampler, SystemdUser,
};
use rlm_core::rules::RulesEnforcer;
use rlm_core::CgroupManager;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Exit status for an invalid config. Matches `RestartPreventExitStatus` in
/// the shipped unit, so systemd does not restart-loop against a file that
/// cannot fix itself.
const EX_CONFIG: i32 = 78;

/// Exit status when another rlm-guard holds the single-instance lock
/// (`EX_TEMPFAIL`). Also in `RestartPreventExitStatus`: restarting every
/// few seconds cannot help while the other guard runs.
const EX_LOCKED: i32 = 75;

/// How often persistent rules are reconciled. New matching processes are
/// absorbed within this delay.
const RULES_INTERVAL_MS: u64 = 5_000;

/// Longest wait at shutdown for the last notifications to go out.
const NOTIFY_FLUSH: Duration = Duration::from_secs(1);

/// The config files whose change reloads the notification settings.
fn config_files() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/rlm/config.yaml")];
    files.extend(Config::user_config_path());
    files
}

/// Modification times of `files` (`None` for a missing one): a cheap stat
/// the loop compares every tick.
fn config_stamp(files: &[PathBuf]) -> Vec<Option<SystemTime>> {
    files
        .iter()
        .map(|f| std::fs::metadata(f).and_then(|m| m.modified()).ok())
        .collect()
}

/// What one tick reads from `/proc`.
#[derive(Debug, PartialEq, Eq)]
struct ScanPlan {
    /// Take a process snapshot (own user only) this tick.
    scan: bool,
    /// Reconcile persistent rules this tick.
    rules: bool,
}

/// A calm tick with plenty of memory reads only the PSI and meminfo files.
/// The process snapshot is taken when the policy wants candidates (pressure
/// above Calm, or memory already scarce so growth rates stay warm) or when
/// rules are due, and is shared by both. `since_rules_ms` is the time since
/// the last reconcile, `None` if there has not been one.
fn plan_scan(
    wants_candidates: bool,
    rules_configured: bool,
    since_rules_ms: Option<u64>,
) -> ScanPlan {
    let rules = rules_configured && since_rules_ms.is_none_or(|d| d >= RULES_INTERVAL_MS);
    ScanPlan {
        scan: wants_candidates || rules,
        rules,
    }
}

fn main() {
    // INFO here is the journal history rlm-guard relies on (journalctl --user
    // -u rlm-guard); it is not noise like a one-shot CLI's INFO would be.
    rlm_core::logging::init(tracing::Level::INFO);

    // One guard per user. A second one would sweep and rewrite the first
    // one's journal, so stop before touching it. Held until exit.
    let _instance_lock = match rlm_core::guard::lock_path() {
        Some(lock_path) => match rlm_core::guard::lock::try_lock(&lock_path) {
            Ok(Some(file)) => Some(file),
            Ok(None) => {
                tracing::error!(
                    "another rlm-guard is already running (lock {} is held); exiting with \
                     status {EX_LOCKED}. systemd will not restart this unit; once the other \
                     guard stops, run: systemctl --user restart rlm-guard",
                    lock_path.display()
                );
                std::process::exit(EX_LOCKED);
            }
            // The state dir is unusable, so the journal cannot open either and
            // no second guard can share it. Keep running so persistent rules
            // still work, as they do when only the journal fails.
            Err(e) => {
                tracing::warn!(
                    "cannot take the lock {}: {e}; continuing without it",
                    lock_path.display()
                );
                None
            }
        },
        // No per-user state or runtime dir. A shared dir such as /tmp would
        // let another user hold the lock and block this guard, so run
        // without one.
        None => {
            tracing::warn!(
                "no per-user state dir or XDG_RUNTIME_DIR; running without the single-instance lock"
            );
            None
        }
    };

    let config = match Config::load_validated() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                "rlm-guard not started: {e}. Fix the file, then run: systemctl --user restart rlm-guard"
            );
            // A crash may have left a cgroup frozen or capped; restore it even though we will not run.
            recover_only();
            std::process::exit(EX_CONFIG);
        }
    };

    if let Err(e) = run(config) {
        tracing::error!("rlm-guard exiting: {e}");
        std::process::exit(1);
    }
}

/// Replay the write-ahead journal so nothing stays frozen or capped, then return.
fn recover_only() {
    let Ok(manager) = CgroupManager::new() else {
        return;
    };
    let Some(path) = try_journal_path() else {
        return;
    };
    let Ok(journal) = Journal::open(path, cgfs::boot_id()) else {
        return;
    };
    let systemd = SystemdUser::connect();
    if let Err(e) = Effector::new(&manager, &journal, systemd.as_ref()).sweep_leftovers() {
        tracing::warn!("journal recovery failed: {e}");
    }
}

fn run(config: Config) -> common::Result<()> {
    let gcfg = config.guard.clone();
    let mut enforcer = RulesEnforcer::new(&config);

    let self_pid = std::process::id();
    // SAFETY: getuid() is always safe; it just reads our real UID from the kernel.
    let uid = unsafe { libc::getuid() };

    let manager = CgroupManager::new()?;

    // Open the write-ahead journal. This must happen, and startup recovery
    // (below) must run, BEFORE any early-exit decision: the journal is the
    // only record of an in-place freeze/cap, and a user who disables the
    // guard (or has no rules configured) after a crash must still get their
    // frozen/capped cgroups restored on the next start (D5a fix: this used
    // to run after the early-exit check, so it never ran at all in that
    // case).
    //
    // A journal-open failure is only fatal when there are no rules to fall
    // back to AND the guard is actually enabled: persistent-rule enforcement
    // has no dependency on the journal at all (D5b fix: this used to be
    // fatal unconditionally, killing rules enforcement over a guard-only
    // concern like an unwritable $XDG_STATE_HOME). With rules configured, we
    // log loudly and continue without journal-backed escalation instead;
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
    // With no per-user state or runtime dir there is nowhere safe for the
    // journal (never a shared dir such as /tmp), so treat it as a journal
    // that failed to open: no freeze or cap this run, rules still apply.
    if try_journal_path().is_none() && enforcer.rule_count() == 0 {
        tracing::warn!(
            "no per-user state dir or XDG_RUNTIME_DIR for the guard journal and no rules \
             configured; nothing to do, exiting"
        );
        return Ok(());
    }
    let opened = match try_journal_path() {
        Some(path) => Journal::open(path, cgfs::boot_id()),
        None => Err(common::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no per-user state dir or XDG_RUNTIME_DIR for the guard journal",
        ))),
    };
    let journal = match opened {
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

    // Without a session bus (headless, or no answer within 2 s) every action
    // below falls back to raw cgroupfs writes.
    let systemd = SystemdUser::connect();
    if systemd.is_none() {
        tracing::warn!("systemd user bus unavailable; using raw cgroupfs writes");
    }
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

    // Desktop notifications about what the guard did. Only `guard.notify`
    // and `guard.notify_pressure` are re-read when the config file changes;
    // every other setting needs a restart, which would release held apps.
    let mut notifier = Notifier::new(DesktopSink::spawn(), &gcfg);
    let mut names = AppNames::in_background();
    let cfg_files = config_files();
    let mut cfg_stamp = config_stamp(&cfg_files);

    let interval = Duration::from_millis(gcfg.timing.sample_interval_ms.max(100));
    let start = Instant::now();
    let mut warned_no_psi = false;
    let mut last_rules_ms: Option<u64> = None;
    let hist = history::try_history_path();
    if hist.is_none() {
        tracing::warn!("no per-user state dir or XDG_RUNTIME_DIR; guard history is not recorded");
    }

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
        let guard_on = gcfg.enabled && effector.is_some();
        let sample = if guard_on { sampler.sample() } else { None };
        let wants = sample.is_some_and(|s| engine.wants_candidates(s));
        let plan = plan_scan(
            wants,
            enforcer.rule_count() > 0,
            last_rules_ms.map(|t| now_ms.saturating_sub(t)),
        );
        let snapshot = if plan.scan {
            rlm_core::process::list_for_uid(uid).unwrap_or_else(|e| {
                tracing::warn!("process scan failed: {e}");
                Vec::new()
            })
        } else {
            Vec::new()
        };

        let mut memory = Memory::Unknown;
        match (&effector, sample) {
            (Some(effector), Some(sample)) if gcfg.enabled => {
                let procs = if wants {
                    sampler.candidates(&snapshot)
                } else {
                    Vec::new()
                };
                let targets = targets_from_procs(&procs, &cgfs::current_bytes);
                let live = live_cgroups(&engine.intervened_cgroups());
                for action in engine.tick(now_ms, sample, &targets, &live) {
                    let outcome = effector.apply(&action);
                    let result = outcome.as_ref().map(|_| ()).map_err(|e| e.to_string());
                    if let Err(e) = &result {
                        tracing::warn!(?action, "action failed: {e}");
                    }
                    notifier.record(&action, outcome.ok());
                    let event = history::event_for(&action, &result, history::unix_now());
                    if let (Some(hist), Some(ev)) = (&hist, event) {
                        if let Err(e) = history::append(hist, &ev) {
                            tracing::debug!("history write failed: {e}");
                        }
                    }
                }
                memory = memory_state(engine.level(), &sample, &gcfg.trigger);
            }
            _ if guard_on && !warned_no_psi => {
                tracing::warn!("memory PSI unavailable; guard cannot act");
                warned_no_psi = true;
            }
            _ => {}
        }
        notifier.end_tick(now_ms, memory, &mut |key, cg| names.name(key, cg));

        // After this tick's actions, so reading a just-saved config never
        // delays a freeze.
        let stamp = config_stamp(&cfg_files);
        if stamp != cfg_stamp {
            cfg_stamp = stamp;
            reload_notify_flags(&mut notifier);
        }

        // Persistent application rules, every RULES_INTERVAL_MS: absorbs
        // newly launched matching instances. Skips any rule cgroup the
        // freeze guard currently holds a freeze or cap on (D1), since the
        // two write to the same cgroups.
        if plan.rules {
            enforcer.reconcile(&manager, &snapshot, &engine.intervened_cgroups());
            last_rules_ms = Some(now_ms);
        }

        sleep_responsive(interval, &shutdown);
    }

    if let Some(effector) = &effector {
        tracing::info!("rlm-guard shutting down; undoing all interventions");
        if let Err(e) = effector.undo_all() {
            tracing::warn!("undo_all failed: {e}");
        }
    }
    notifier.close_all();
    notifier.sink().flush(NOTIFY_FLUSH);
    Ok(())
}

/// The config file changed on disk: apply its notification settings, and
/// nothing else. An invalid file keeps the current ones.
fn reload_notify_flags(notifier: &mut Notifier<DesktopSink>) {
    let current = notifier.flags();
    let loaded = Config::load_validated();
    let flags = flags_after_reload(current, loaded.as_ref().map(|c| &c.guard));
    match &loaded {
        Err(e) => {
            tracing::warn!("config changed but is invalid ({e}); keeping notification settings")
        }
        Ok(_) if flags != current => {
            tracing::info!(
                notify = flags.notify,
                notify_pressure = flags.pressure,
                "config changed; applied new notification settings"
            );
            notifier.set_flags(flags);
        }
        Ok(_) => {}
    }
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

#[cfg(test)]
mod tests {
    const UNIT: &str = include_str!("../../assets/rlm-guard.service");

    #[test]
    fn idle_ticks_do_not_scan_proc() {
        assert_eq!(
            super::plan_scan(false, false, None),
            super::ScanPlan {
                scan: false,
                rules: false
            }
        );
        assert_eq!(
            super::plan_scan(false, true, Some(2_000)),
            super::ScanPlan {
                scan: false,
                rules: false
            }
        );
        assert_eq!(
            super::plan_scan(false, true, None),
            super::ScanPlan {
                scan: true,
                rules: true
            }
        );
        assert_eq!(
            super::plan_scan(false, true, Some(5_000)),
            super::ScanPlan {
                scan: true,
                rules: true
            }
        );
        assert_eq!(
            super::plan_scan(true, false, None),
            super::ScanPlan {
                scan: true,
                rules: false
            }
        );
    }

    fn restart_prevent_codes() -> Vec<i32> {
        UNIT.lines()
            .filter_map(|l| l.strip_prefix("RestartPreventExitStatus="))
            .flat_map(|v| v.split_whitespace())
            .map(|c| c.parse().expect("numeric exit status"))
            .collect()
    }

    #[test]
    fn unit_does_not_restart_on_config_errors() {
        assert!(restart_prevent_codes().contains(&super::EX_CONFIG));
    }

    #[test]
    fn unit_does_not_restart_while_another_guard_holds_the_lock() {
        assert!(restart_prevent_codes().contains(&super::EX_LOCKED));
    }

    #[test]
    fn unit_has_no_directives_a_user_manager_ignores() {
        assert!(
            !UNIT.contains("OOMScoreAdjust"),
            "a user unit cannot lower its OOM score"
        );
        assert!(
            !UNIT.contains("MemoryMin"),
            "MemoryMin is inert without an ancestor chain"
        );
        assert!(UNIT.contains("ExecStart=/usr/bin/rlm-guard"));
    }
}
