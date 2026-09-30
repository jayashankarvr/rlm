mod confirm;
mod doctor;
mod guard_unit;
mod run;

use clap::{Parser, Subcommand};
use common::{build_limit, format_bytes, Config, Error, Limit, Result};
use confirm::Confirm;
use rlm_core::process::{self, current_uid, ProcessInfo};
use rlm_core::CgroupManager;
use std::collections::HashSet;
use std::io::{self, IsTerminal};
use std::process::ExitCode;

fn parse_pid_list(pids_str: &str) -> Result<Vec<u32>> {
    pids_str
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u32>()
                .map_err(|_| Error::InvalidArgs(format!("invalid PID: {}", s.trim())))
        })
        .collect()
}

/// Resolve `--name` to the PIDs owned by `my_uid`. Root (`my_uid == 0`) sees
/// every match, since it can legitimately act on anyone's process. A
/// non-root match against other users' processes is dropped with a note
/// rather than silently limiting (or reporting on) someone else's process.
fn resolve_name_pids(name: &str, my_uid: u32) -> Result<Vec<u32>> {
    if my_uid == 0 {
        return process::find_by_name(name);
    }
    let matches = process::find_by_name_for_uid(name, my_uid)?;
    if matches.other_users > 0 {
        eprintln!(
            "note: skipped {} matching process(es) owned by other users",
            matches.other_users
        );
    }
    if matches.pids.is_empty() {
        return Err(Error::ProcessNameNotFound(name.to_string()));
    }
    Ok(matches.pids)
}

/// Same as [`resolve_name_pids`], but returns full [`ProcessInfo`] for each
/// match so the caller can run [`check_target`] on it.
fn resolve_name_targets(name: &str, my_uid: u32) -> Result<Vec<ProcessInfo>> {
    resolve_name_pids(name, my_uid)?
        .into_iter()
        .map(|pid| process::read_process(pid).ok_or(Error::ProcessNotFound(pid)))
        .collect()
}

/// Keep only `all`'s processes owned by `my_uid`, printing a note about how
/// many were dropped. Root keeps everything (see [`resolve_name_pids`]).
fn filter_own_uid(all: Vec<ProcessInfo>, my_uid: u32) -> Vec<ProcessInfo> {
    if my_uid == 0 {
        return all;
    }
    let (mine, other): (Vec<_>, Vec<_>) = all.into_iter().partition(|p| p.uid == my_uid);
    if !other.is_empty() {
        eprintln!(
            "note: skipped {} matching process(es) owned by other users",
            other.len()
        );
    }
    mine
}

/// A command needs a real [`CgroupManager`] only when it reads or writes
/// cgroup state. Constructing one fails on hosts without cgroups v2 (or
/// without delegation), so commands that don't touch cgroups (doctor,
/// profiles, export/import, rule, and every `guard` subcommand, which reads
/// only the default base path) must not pay that cost or that failure mode.
fn needs_cgroup_manager(cmd: &Commands) -> bool {
    match cmd {
        Commands::Status
        | Commands::Limit { .. }
        | Commands::Unlimit { .. }
        | Commands::Run { .. } => true,
        Commands::Rule { .. }
        | Commands::Profiles
        | Commands::Export { .. }
        | Commands::Import { .. }
        | Commands::Doctor
        | Commands::Guard { .. } => false,
    }
}

/// `--save` persists a rule keyed by the application executable; without
/// `--application` there is nothing to key it by. clap's `requires` on
/// `--save` does not actually enforce this (see the regression test), so it
/// is checked explicitly here before anything else runs. A rule keyed by a
/// version-number program name would stop matching after an update, so
/// `--save` refuses one before anything is applied.
fn validate_limit_args(save: bool, application: Option<&str>) -> Result<()> {
    if !save {
        return Ok(());
    }
    let Some(app) = application else {
        return Err(Error::InvalidArgs(
            "--save requires --application (there is nothing else to key the saved rule by)".into(),
        ));
    };
    if let Some(problem) = common::versioned_rule_name(app) {
        return Err(Error::InvalidArgs(format!(
            "--save: {problem} Nothing was limited; run without --save to limit it without a rule."
        )));
    }
    Ok(())
}

/// The config `rlm limit` uses, given the result of loading it. `limit`
/// reads the guard protect list from the config, so an invalid config is an
/// error (with the file and the parse error) rather than a silent fallback
/// to defaults that would drop the user's protected apps. With `--force` the
/// protect list is not consulted, so the command continues on the defaults
/// and returns a warning to print instead. `--save` writes the rule into
/// the config, so with `save` an invalid config is always an error, decided
/// here before anything is applied.
fn config_for_limit(
    loaded: Result<Config>,
    force: bool,
    save: bool,
    path: &str,
) -> std::result::Result<(Config, Option<String>), String> {
    match loaded {
        Ok(c) => Ok((c, None)),
        Err(e) => {
            let line = rlm_core::guard::report::config_error_line(path, &e);
            if save {
                Err(format!(
                    "error: config {line}\n  --save writes the rule into this file, so it needs a valid config. Fix the file, or run without --save. Nothing was limited."
                ))
            } else if force {
                Ok((
                    Config::default(),
                    Some(format!(
                        "warning: config {line}\n  continuing without your settings because of --force"
                    )),
                ))
            } else {
                Err(format!(
                    "error: config {line}\n  rlm limit reads your guard protect list from it. Fix the file, or pass --force to limit without it."
                ))
            }
        }
    }
}

/// Refuse to limit a process this invocation should not touch: one owned by
/// another user (unless we are root), or one on the guard protect list
/// (desktop session, shells, audio) unless `--force` was given. The uid
/// check is never bypassed by `--force`; only the protect-list check is.
fn check_target(
    p: &ProcessInfo,
    my_uid: u32,
    protect: &HashSet<String>,
    force: bool,
) -> Result<()> {
    if p.uid != my_uid && my_uid != 0 {
        return Err(Error::InvalidArgs(format!(
            "process {} ({}) belongs to uid {}; rlm only limits your own processes",
            p.pid,
            p.display_name(),
            p.uid
        )));
    }
    if !force && common::is_protected(protect, &p.name, p.exe_name()) {
        return Err(Error::InvalidArgs(format!(
            "process {} ({}) is on the guard protect list (desktop session, shells, audio); pass --force to limit it anyway",
            p.pid,
            p.display_name()
        )));
    }
    Ok(())
}

/// What to actually remove for `unlimit --pid`: `found` is whatever cgroup
/// (if any) [`CgroupManager::find_cgroup_for_pid`] reports the pid in. A pid
/// with no cgroup was never limited (or was already unlimited), and a pid
/// sharing a cgroup with other processes must be released as a whole group,
/// not silently for just this one pid.
fn unlimit_pid_target(pid: u32, found: Option<&str>) -> Result<String> {
    match found {
        None => Err(Error::InvalidArgs(format!("pid {pid} is not limited by rlm"))),
        Some(cgroup) if cgroup == format!("pid-{pid}") => Ok(cgroup.to_string()),
        Some(cgroup) => Err(Error::InvalidArgs(format!(
            "pid {pid} shares cgroup '{cgroup}' with other processes; remove the whole group with: rlm unlimit --cgroup {cgroup}"
        ))),
    }
}

/// Run the batch confirmation against the real terminal/stdio, translating
/// the result into either "keep going" (`Ok(None)`) or a final `ExitCode`
/// (`Ok(Some(_))` for a user cancel) or error (stdin is not a terminal and
/// `--yes` was not given).
fn confirm_or_exit(pids: &[u32], action: &str, yes: bool) -> Result<Option<ExitCode>> {
    let interactive = io::stdin().is_terminal();
    let mut input = io::stdin().lock();
    let mut out = io::stdout();
    match confirm::confirm_batch(pids, action, yes, interactive, &mut input, &mut out) {
        Confirm::Proceed => Ok(None),
        Confirm::Cancelled => {
            eprintln!("cancelled");
            Ok(Some(ExitCode::from(1)))
        }
        Confirm::NeedsYes => Err(Error::InvalidArgs(format!(
            "refusing to change {} processes without confirmation because stdin is not a terminal; pass --yes",
            pids.len()
        ))),
    }
}

#[derive(Parser)]
#[command(name = "rlm", bin_name = "rlm")]
#[command(about = "Resource Limit Manager - control process resource usage via cgroups v2")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply resource limits to a running process
    Limit {
        /// Process ID to limit
        #[arg(long, conflicts_with_all = ["name", "application", "all_pids"])]
        pid: Option<u32>,

        /// Process name to limit (limits all matching processes individually)
        #[arg(long, conflicts_with_all = ["pid", "application", "all_pids"])]
        name: Option<String>,

        /// Application name to limit (all processes share the same limit pool)
        /// Use this for applications with multiple processes (e.g., firefox, chrome)
        /// All processes will share the specified limits (combined, not per-process)
        #[arg(long, conflicts_with_all = ["pid", "name", "all_pids"])]
        application: Option<String>,

        /// Comma-separated list of PIDs to limit together (share the same limit pool)
        #[arg(long, conflicts_with_all = ["pid", "name", "application"])]
        all_pids: Option<String>,

        /// Memory limit (K=1024, M=1024K, G=1024M, T=1024G)
        /// Note: For multiple processes, this is shared among all processes
        #[arg(long, value_name = "SIZE")]
        memory: Option<String>,

        /// CPU limit as percentage (50%=half core, 100%=1 core, 200%=2 cores)
        /// Note: For multiple processes, this is shared among all processes
        #[arg(long, value_name = "PERCENT")]
        cpu: Option<String>,

        /// I/O read bandwidth limit per second (K/M/G/T units)
        /// Note: For multiple processes, this is shared among all processes
        #[arg(long, value_name = "SIZE")]
        io_read: Option<String>,

        /// I/O write bandwidth limit per second (K/M/G/T units)
        /// Note: For multiple processes, this is shared among all processes
        #[arg(long, value_name = "SIZE")]
        io_write: Option<String>,

        /// Show what would be done without applying limits
        #[arg(long)]
        dry_run: bool,

        /// Save as a persistent rule (only valid with --application). The limit
        /// is re-applied across reboots and to future instances by rlm-guard.
        #[arg(long, requires = "application")]
        save: bool,

        /// Skip the confirmation prompt for a batch (--name, --application,
        /// --all-pids). Required when stdin is not a terminal.
        #[arg(long, short = 'y')]
        yes: bool,

        /// Limit a process on the guard protect list (desktop session,
        /// shells, audio) anyway. Never bypasses the other-user refusal.
        #[arg(long)]
        force: bool,
    },

    /// Remove resource limits from a process
    Unlimit {
        /// Process ID to unlimit
        #[arg(long, conflicts_with_all = ["name", "application", "cgroup"])]
        pid: Option<u32>,

        /// Process name to unlimit (all matching processes)
        #[arg(long, conflicts_with_all = ["pid", "application", "cgroup"])]
        name: Option<String>,

        /// Application name to unlimit (removes shared cgroup)
        #[arg(long, conflicts_with_all = ["pid", "name", "cgroup"])]
        application: Option<String>,

        /// Cgroup name to remove (for shared application cgroups)
        #[arg(long, conflicts_with_all = ["pid", "name", "application"])]
        cgroup: Option<String>,

        /// Also delete the persistent rule (with --application). Without this,
        /// unlimit drops the live limit but keeps the saved rule.
        #[arg(long)]
        forget: bool,

        /// Skip the confirmation prompt when unlimiting by --name and more
        /// than one process matches. Required when stdin is not a terminal.
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Manage persistent application rules (enforced by rlm-guard)
    Rule {
        #[command(subcommand)]
        action: RuleAction,
    },

    /// Run a command with resource limits
    Run {
        /// Use limits from a named profile
        #[arg(long, short)]
        profile: Option<String>,

        /// Memory limit (K=1024, M=1024K, G=1024M, T=1024G)
        #[arg(long, value_name = "SIZE")]
        memory: Option<String>,

        /// CPU limit as percentage (50%=half core, 100%=1 core, 200%=2 cores)
        #[arg(long, value_name = "PERCENT")]
        cpu: Option<String>,

        /// I/O read bandwidth limit per second (K/M/G/T units)
        #[arg(long, value_name = "SIZE")]
        io_read: Option<String>,

        /// I/O write bandwidth limit per second (K/M/G/T units)
        #[arg(long, value_name = "SIZE")]
        io_write: Option<String>,

        /// Command to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// List available profiles from config
    Profiles,

    /// Export profiles to a file
    Export {
        /// Output file path (YAML format)
        #[arg(value_name = "FILE")]
        file: String,
    },

    /// Import profiles from a file
    Import {
        /// Input file path (YAML format)
        #[arg(value_name = "FILE")]
        file: String,

        /// Overwrite existing profiles with same name
        #[arg(long)]
        overwrite: bool,
    },

    /// Show status of managed processes
    Status,

    /// Check system requirements and diagnose issues
    Doctor,

    /// Manage the freeze-guard daemon (rlm-guard)
    Guard {
        #[command(subcommand)]
        action: GuardAction,
    },
}

#[derive(Subcommand)]
enum GuardAction {
    /// Show whether the guard is running and its current memory pressure and
    /// active interventions
    Status,
    /// Enable and start the guard user service
    Enable,
    /// Disable and stop the guard user service
    Disable,
    /// Dry-run: print what the guard would do right now, without acting
    Test {
        /// Instead, show sample notifications ("paused", then "slowed down",
        /// then cleared) to preview how the guard's notifications look.
        /// Touches no cgroup and not the guard.
        #[arg(long)]
        notify: bool,
    },
    /// Show recent guard interventions (freeze, thaw, cap, lift, and failures)
    History {
        /// Number of most recent entries to show
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
    },
}

#[derive(Subcommand)]
enum RuleAction {
    /// List saved persistent application rules
    List,
    /// Remove a saved rule by name
    Remove {
        /// Rule name (the executable name used when saving)
        name: String,
    },
}

fn main() -> ExitCode {
    rlm_core::logging::init(tracing::Level::WARN);

    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    // Constructing a CgroupManager fails outright on a host without cgroups
    // v2 (or delegation), so it is only built for commands that actually
    // need one; doctor/profiles/export/import/rule/guard must keep working
    // to diagnose or fix exactly that situation.
    let manager = if needs_cgroup_manager(&cli.command) {
        Some(CgroupManager::new()?)
    } else {
        None
    };

    match cli.command {
        Commands::Limit {
            pid,
            name,
            application,
            all_pids,
            memory,
            cpu,
            io_read,
            io_write,
            dry_run,
            save,
            yes,
            force,
        } => {
            let manager = manager.as_ref().expect("checked by needs_cgroup_manager");
            validate_limit_args(save, application.as_deref())?;

            let limit = build_limit(
                memory.as_deref(),
                cpu.as_deref(),
                io_read.as_deref(),
                io_write.as_deref(),
            )?;

            if limit.memory.is_none() && limit.cpu.is_none() && limit.io.is_none() {
                return Err(Error::InvalidArgs(
                    "specify at least one limit (--memory, --cpu, --io-read, --io-write)".into(),
                ));
            }

            // Remember the application name for persisting a rule after apply.
            // validate_limit_args guarantees --save is only set with --application.
            let save_app = if save { application.clone() } else { None };

            let my_uid = current_uid();
            let config = match config_for_limit(
                Config::load(),
                force,
                save,
                &rlm_core::guard::report::config_error_path(),
            ) {
                Ok((config, warning)) => {
                    if let Some(w) = warning {
                        eprintln!("{w}");
                    }
                    config
                }
                Err(msg) => {
                    eprintln!("{msg}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            let protect = common::protect_set(&config.guard.selection.protect);

            // Determine which mode we're in
            let (targets, cgroup_name, is_shared) = if let Some(app_name) = application {
                // Application mode: all processes share limits
                let all = process::find_all_by_executable(&app_name)?;
                let targets = filter_own_uid(all, my_uid);
                if targets.is_empty() {
                    return Err(Error::ProcessNameNotFound(app_name));
                }
                let cgroup_name = format!("app-{}", app_name.replace(['/', ' '], "_"));
                println!(
                    "Found {} process(es) for application '{}'",
                    targets.len(),
                    app_name
                );
                (targets, cgroup_name, true)
            } else if let Some(pids_str) = all_pids {
                // Multiple PIDs mode: all share limits
                let pids = parse_pid_list(&pids_str)?;
                if pids.is_empty() {
                    return Err(Error::InvalidArgs("no valid PIDs specified".into()));
                }
                let targets: Vec<ProcessInfo> = pids
                    .iter()
                    .map(|&pid| process::read_process(pid).ok_or(Error::ProcessNotFound(pid)))
                    .collect::<Result<_>>()?;
                let cgroup_name = format!("multi-{}", pids[0]);
                (targets, cgroup_name, true)
            } else if let Some(name) = name {
                let targets = resolve_name_targets(&name, my_uid)?;
                (targets, String::new(), false)
            } else if let Some(pid) = pid {
                let p = process::read_process(pid).ok_or(Error::ProcessNotFound(pid))?;
                (vec![p], String::new(), false)
            } else {
                return Err(Error::InvalidArgs(
                    "specify --pid, --name, --application, or --all-pids".into(),
                ));
            };

            for p in &targets {
                check_target(p, my_uid, &protect, force)?;
            }
            let pids: Vec<u32> = targets.iter().map(|p| p.pid).collect();

            if dry_run {
                println!(
                    "Dry run - would apply limits to {} process(es):",
                    targets.len()
                );
                for p in &targets {
                    println!("  {}: {}", p.pid, p.display_name());
                }
                if is_shared {
                    println!("\nnote: all processes share these limits (one combined pool)");
                } else {
                    println!("\nLimits (per process):");
                }
                if let Some(ref mem) = limit.memory {
                    println!("  Memory: {}", format_bytes(mem.bytes()));
                }
                if let Some(ref cpu) = limit.cpu {
                    println!("  CPU: {}%", cpu.percent());
                }
                if let Some(ref io) = limit.io {
                    if let Some(r) = io.read_bps {
                        println!("  I/O Read: {}/s", format_bytes(r));
                    }
                    if let Some(w) = io.write_bps {
                        println!("  I/O Write: {}/s", format_bytes(w));
                    }
                }
                return Ok(ExitCode::SUCCESS);
            }

            if let Some(code) = confirm_or_exit(&pids, "Limit", yes)? {
                return Ok(code);
            }

            if is_shared {
                // Apply shared limits to all processes
                for w in manager.apply_limit_to_multiple(&pids, &limit, &cgroup_name)? {
                    eprintln!("warning: {w}");
                }
                println!(
                    "Applied shared limits to {} process(es) in cgroup '{}'",
                    pids.len(),
                    cgroup_name
                );
                println!("note: all processes share these limits (one combined pool)");

                // Persist as a rule so it survives reboot and applies to future
                // instances (enforced by rlm-guard).
                if let Some(app) = save_app {
                    let mut config = Config::load()?;
                    config.add_rule(
                        &app,
                        common::AppRule {
                            match_exe: vec![app.clone()],
                            memory: memory.clone(),
                            cpu: cpu.clone(),
                            io_read: io_read.clone(),
                            io_write: io_write.clone(),
                        },
                    );
                    config.save()?;
                    println!("Saved persistent rule '{app}'");
                    // The daemon reads rules at startup, so a running daemon must
                    // be restarted to pick up the new rule.
                    if is_guard_active() {
                        println!(
                            "  note: restart the daemon to load it: systemctl --user restart rlm-guard"
                        );
                    } else {
                        println!("  note: enable the daemon to enforce it: rlm guard enable");
                    }
                }
            } else {
                // Apply individual limits to each process
                for pid in &pids {
                    for w in manager.apply_limit(*pid, &limit)? {
                        eprintln!("warning: {w}");
                    }
                    println!("applied limits to pid {pid}");
                }
            }
        }

        Commands::Unlimit {
            pid,
            name,
            application,
            cgroup,
            forget,
            yes,
        } => {
            let manager = manager.as_ref().expect("checked by needs_cgroup_manager");
            if let Some(cgroup_name) = cgroup {
                // Remove by cgroup name
                if !manager.cgroup_exists(&cgroup_name) {
                    return Err(Error::InvalidArgs(format!(
                        "no rlm cgroup named '{cgroup_name}' (see: rlm status)"
                    )));
                }
                manager.remove_application_limit(&cgroup_name)?;
                println!("removed limits from cgroup '{}'", cgroup_name);
            } else if let Some(app_name) = application {
                // Remove application cgroup
                let cgroup_name = format!("app-{}", app_name.replace(['/', ' '], "_"));
                if !manager.cgroup_exists(&cgroup_name) {
                    return Err(Error::InvalidArgs(format!(
                        "no rlm cgroup named '{cgroup_name}' (see: rlm status)"
                    )));
                }
                manager.remove_application_limit(&cgroup_name)?;
                println!("removed limits from application '{}'", app_name);

                // The saved rule persists unless --forget is given. Otherwise the
                // daemon would simply re-apply it on the next reconcile.
                if forget {
                    let mut config = Config::load()?;
                    if config.remove_rule(&app_name) {
                        config.save()?;
                        println!("forgot persistent rule '{}'", app_name);
                    }
                } else {
                    let config = Config::load()?;
                    if config.rules.contains_key(&app_name) {
                        println!(
                            "  note: persistent rule '{}' still saved (rlm-guard will re-apply it); use --forget to delete it",
                            app_name
                        );
                    }
                }
            } else if let Some(name) = name {
                // Remove all matching processes by name
                let my_uid = current_uid();
                let pids = resolve_name_pids(&name, my_uid)?;

                if let Some(code) = confirm_or_exit(&pids, "Unlimit", yes)? {
                    return Ok(code);
                }

                let mut removed = 0usize;
                for pid in &pids {
                    match unlimit_pid_target(*pid, manager.find_cgroup_for_pid(*pid).as_deref()) {
                        Ok(cgroup_name) => {
                            manager.remove_application_limit(&cgroup_name)?;
                            println!("removed limits from pid {pid}");
                            removed += 1;
                        }
                        Err(e) => eprintln!("warning: {e}"),
                    }
                }
                if removed == 0 {
                    return Err(Error::InvalidArgs(format!(
                        "no process matching '{name}' is limited by rlm"
                    )));
                }
            } else if let Some(pid) = pid {
                // Remove a single process
                let cgroup_name =
                    unlimit_pid_target(pid, manager.find_cgroup_for_pid(pid).as_deref())?;
                manager.remove_application_limit(&cgroup_name)?;
                println!("removed limits from pid {pid}");
            } else {
                return Err(Error::InvalidArgs(
                    "specify --pid, --name, --application, or --cgroup".into(),
                ));
            }
        }

        Commands::Run {
            profile,
            memory,
            cpu,
            io_read,
            io_write,
            command,
        } => {
            let manager = manager.as_ref().expect("checked by needs_cgroup_manager");
            let base = match profile {
                Some(profile_name) => {
                    let config = Config::load()?;
                    let p = config.get_profile(&profile_name).ok_or_else(|| {
                        Error::Config(format!(
                            "profile '{profile_name}' not found (see: rlm profiles)"
                        ))
                    })?;
                    p.to_limit()?
                }
                None => Limit::default(),
            };
            let flags = build_limit(
                memory.as_deref(),
                cpu.as_deref(),
                io_read.as_deref(),
                io_write.as_deref(),
            )?;
            let limit = base.overlay(&flags);
            if limit.is_empty() {
                return Err(Error::InvalidArgs(
                    "specify --profile or at least one limit".into(),
                ));
            }

            return run::run_with_limits(manager, &limit, &command);
        }

        Commands::Profiles => {
            let config = Config::load()?;
            let all_profiles = config.all_profiles();

            println!(
                "{:<15} {:>10} {:>10} {:>10} {:>10}",
                "NAME", "MEMORY", "CPU", "IO_READ", "IO_WRITE"
            );
            println!("{}", "-".repeat(60));

            // Sort profiles by name
            let mut names: Vec<_> = all_profiles.keys().collect();
            names.sort();

            for name in names {
                let profile = &all_profiles[name];
                let mem = profile.memory.as_deref().unwrap_or("-");
                let cpu = profile.cpu.as_deref().unwrap_or("-");
                let ior = profile.io_read.as_deref().unwrap_or("-");
                let iow = profile.io_write.as_deref().unwrap_or("-");
                println!(
                    "{:<15} {:>10} {:>10} {:>10} {:>10}",
                    name, mem, cpu, ior, iow
                );
            }

            if config.profiles.is_empty() {
                println!("\n(showing built-in presets; add custom profiles to ~/.config/rlm/config.yaml)");
            }
        }

        Commands::Export { file } => {
            let config = Config::load()?;
            // Export only user-defined profiles. Built-in presets are always
            // available, so including them would re-import as user profiles and
            // permanently pollute the user's config on a round-trip.
            let profiles = config.profiles.clone();

            if profiles.is_empty() {
                println!(
                    "no user-defined profiles to export (built-in presets are always available)"
                );
            } else {
                // Create export structure
                let export = serde_yaml_ng::to_string(&profiles)
                    .map_err(|e| Error::Config(format!("Failed to serialize profiles: {e}")))?;

                std::fs::write(&file, export)?;
                println!("exported {} profiles to {}", profiles.len(), file);
            }
        }

        Commands::Import { file, overwrite } => {
            // 1MB limit (same as config loading)
            let metadata = std::fs::metadata(&file)?;
            if metadata.len() > 1024 * 1024 {
                return Err(Error::Config("import file too large (max 1MB)".into()));
            }
            let content = std::fs::read_to_string(&file)?;
            let imported: std::collections::HashMap<String, common::Profile> =
                serde_yaml_ng::from_str(&content)
                    .map_err(|e| Error::Config(format!("Failed to parse profiles: {e}")))?;

            validate_import(&imported)?;

            if imported.is_empty() {
                println!("no profiles in file");
            } else {
                let mut config = Config::load()?;
                let mut added = 0;
                let mut skipped = 0;

                for (name, profile) in imported {
                    if config.profiles.contains_key(&name) && !overwrite {
                        println!("skipped '{}' (already exists, use --overwrite)", name);
                        skipped += 1;
                    } else {
                        config.profiles.insert(name.clone(), profile);
                        println!("imported '{}'", name);
                        added += 1;
                    }
                }

                config.save()?;
                println!("\nimported {} profiles ({} skipped)", added, skipped);
            }
        }

        Commands::Status => {
            let manager = manager.as_ref().expect("checked by needs_cgroup_manager");
            let processes = rlm_core::status::get_managed_processes(manager)?;

            if processes.is_empty() {
                println!("no processes currently managed");
            } else {
                println!(
                    "{}",
                    status_line("PID", "NAME", "MEMORY", "CPU", "I/O", "TYPE")
                );
                println!("{}", "-".repeat(STATUS_WIDTH));

                for p in processes {
                    let mem = p.memory_max.map(format_bytes).unwrap_or_else(|| "-".into());
                    let cpu = p
                        .cpu_quota
                        .map(|q| format!("{}%", q))
                        .unwrap_or_else(|| "-".into());
                    let io = if p.io_read_bps.is_some() || p.io_write_bps.is_some() {
                        "limited".to_string()
                    } else {
                        "-".to_string()
                    };
                    let type_info = status_type(p.is_shared, p.process_count);
                    let comm = (p.name != "?").then_some(p.name.as_str());
                    let exe = rlm_core::appname::exe_of_pid(p.pid);
                    let name = match exe.as_deref() {
                        Some(exe) => rlm_core::appname::program_name(exe, comm),
                        None => p.name.as_str(),
                    };
                    println!(
                        "{}",
                        status_line(
                            &p.pid.to_string(),
                            &fit_name(name),
                            &mem,
                            &cpu,
                            &io,
                            &type_info
                        )
                    );
                }
                println!("\nNote: 'shared' means multiple processes share the same limit pool");
            }

            let empty = rlm_core::status::empty_cgroups(manager);
            if !empty.is_empty() {
                println!(
                    "note: {} empty rlm cgroup(s): {}. Remove with: rlm unlimit --cgroup <name>",
                    empty.len(),
                    empty.join(", ")
                );
            }
        }

        Commands::Doctor => {
            return Ok(doctor::run());
        }

        Commands::Guard { action } => {
            return run_guard(action);
        }

        Commands::Rule { action } => {
            return run_rule(action);
        }
    }

    Ok(ExitCode::SUCCESS)
}

/// Whether the rlm-guard user service is active (best-effort, for hints).
fn is_guard_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "rlm-guard"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_rule(action: RuleAction) -> Result<ExitCode> {
    match action {
        RuleAction::List => {
            let config = Config::load()?;
            if config.rules.is_empty() {
                println!("no persistent rules configured");
                println!("  create one with: rlm limit --application <exe> --memory <size> --save");
                return Ok(ExitCode::SUCCESS);
            }
            println!(
                "{:<20} {:>10} {:>8} {:>10} {:>10}",
                "RULE", "MEMORY", "CPU", "IO_READ", "IO_WRITE"
            );
            println!("{}", "-".repeat(62));
            let mut names: Vec<_> = config.rules.keys().collect();
            names.sort();
            for name in names {
                let r = &config.rules[name];
                println!(
                    "{:<20} {:>10} {:>8} {:>10} {:>10}",
                    name,
                    r.memory.as_deref().unwrap_or("-"),
                    r.cpu.as_deref().unwrap_or("-"),
                    r.io_read.as_deref().unwrap_or("-"),
                    r.io_write.as_deref().unwrap_or("-"),
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        RuleAction::Remove { name } => {
            let mut config = Config::load()?;
            if config.remove_rule(&name) {
                config.save()?;
                println!("removed rule '{name}'");
                println!("  note: this does not drop a currently-applied limit; use `rlm unlimit --application {name}` for that");
                Ok(ExitCode::SUCCESS)
            } else {
                Err(Error::InvalidArgs(format!("no rule named '{name}'")))
            }
        }
    }
}

fn run_guard(action: GuardAction) -> Result<ExitCode> {
    match action {
        GuardAction::Enable => guard_enable(),
        GuardAction::Disable => systemctl(&["disable", "--now", "rlm-guard"]),
        GuardAction::Status => Ok(guard_status()),
        GuardAction::Test { notify: false } => Ok(guard_test()),
        GuardAction::Test { notify: true } => Ok(guard_test_notify()),
        GuardAction::History { lines } => {
            guard_history(lines);
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Validate every imported profile before any of them are written. On
/// failure nothing is saved: the whole import is rejected, naming every
/// invalid profile (sorted by name), so `rlm import` can't leave a config
/// with limits that only fail at use.
fn validate_import(profiles: &std::collections::HashMap<String, common::Profile>) -> Result<()> {
    let mut errors: Vec<(String, String)> = profiles
        .iter()
        .filter_map(|(name, p)| p.validate().err().map(|e| (name.clone(), e.to_string())))
        .collect();
    if errors.is_empty() {
        return Ok(());
    }
    errors.sort_by(|a, b| a.0.cmp(&b.0));
    let list: Vec<String> = errors
        .into_iter()
        .map(|(name, e)| format!("'{name}': {e}"))
        .collect();
    Err(Error::Config(format!(
        "import rejected, nothing was written. Fix these profiles: {}",
        list.join("; ")
    )))
}

/// Install a user unit pointing at the real `rlm-guard` when no packaged
/// unit exists (or refresh one this command wrote earlier), then enable and
/// start the service.
fn guard_enable() -> Result<ExitCode> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| Error::InvalidArgs("cannot find the user config directory".into()))?;
    let unit_path = guard_unit::user_unit_path(&config_dir);
    // Read before `enable --now`, which starts a stopped service.
    let state = rlm_core::guard::service::query();
    if let Some(msg) = guard_unit::masked_error(&state.enabled) {
        eprintln!("error: {msg}");
        return Ok(ExitCode::FAILURE);
    }
    let was_active = state.active == "active";
    let existing = std::fs::read_to_string(&unit_path).ok();
    let current_exe = std::env::current_exe().ok();
    let path_env = std::env::var_os("PATH");
    let guard_bin = guard_unit::find_guard_binary(current_exe.as_deref(), path_env.as_deref());
    let system_dirs: Vec<&std::path::Path> = guard_unit::SYSTEM_UNIT_DIRS
        .iter()
        .map(std::path::Path::new)
        .collect();
    let plan = guard_unit::plan_enable(
        guard_unit::system_unit_installed(&system_dirs),
        existing.as_deref(),
        guard_bin.as_deref(),
        &unit_path,
    );
    if let (Some(problem), Some(bin)) = (
        guard_unit::plan_path_problem(&plan, guard_bin.as_deref()),
        &guard_bin,
    ) {
        eprintln!(
            "error: cannot write a unit for {}: {problem}. Install rlm-guard under a plain path and rerun: rlm guard enable",
            bin.display()
        );
        return Ok(ExitCode::FAILURE);
    }
    let mut unit_written = false;
    match plan {
        guard_unit::EnablePlan::NoBinary => {
            return Err(Error::InvalidArgs(
                "rlm-guard was not found next to rlm or on PATH. Install it with: cargo install --path cli (from a source checkout) or: cargo install rlmctl".into(),
            ));
        }
        guard_unit::EnablePlan::WriteUserUnit { path, contents } => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            // A 0.1 unit may carry the user's edits; keep a copy before replacing it.
            if let Ok(old) = std::fs::read_to_string(&path) {
                if !old.starts_with(guard_unit::GENERATED_MARKER) {
                    let backup = path.with_extension("service.bak");
                    std::fs::write(&backup, old)?;
                    println!("saved the previous unit as {}", backup.display());
                }
            }
            guard_unit::write_atomically(&path, &contents)?;
            println!("wrote {}", path.display());
            unit_written = true;
            let reload = systemctl(&["daemon-reload"])?;
            if reload != ExitCode::SUCCESS {
                return Ok(reload);
            }
        }
        guard_unit::EnablePlan::UserUnitCustom => {
            println!("note: keeping your own {}", unit_path.display());
        }
        guard_unit::EnablePlan::UseSystemUnit | guard_unit::EnablePlan::UserUnitCurrent => {}
    }
    let code = systemctl(&["enable", "--now", "rlm-guard"])?;
    if let Some(note) = guard_unit::restart_note(was_active, unit_written) {
        println!("{note}");
    }
    Ok(code)
}

fn systemctl(args: &[&str]) -> Result<ExitCode> {
    let status = std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .map_err(|e| Error::InvalidArgs(format!("failed to run systemctl: {e}")))?;
    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Print the guard's service state, config validity, current pressure,
/// policy, active interventions, and recent history. Does not need a
/// [`CgroupManager`]: unlike `guard test`, it never resolves escalation
/// targets (`rlm_base = None`), only reads pressure.
///
/// Returns [`ExitCode::FAILURE`] when the config is invalid: everything
/// still prints (using a best-effort fallback config for the pressure/policy
/// lines) so the output stays informative, but scripts checking the exit
/// code see the failure instead of it being silently swallowed.
fn guard_status() -> ExitCode {
    let (cfg, config_err) = match Config::load_validated() {
        Ok(c) => (c, None),
        Err(e) => (Config::load().unwrap_or_default(), Some(e)),
    };

    println!(
        "Service:  {}",
        rlm_core::guard::service::describe(&rlm_core::guard::service::query())
    );
    match &config_err {
        None => println!("Config:   ok"),
        Some(e) => println!(
            "Config:   {}",
            rlm_core::guard::report::config_error_line(
                &rlm_core::guard::report::config_error_path(),
                e
            )
        ),
    }

    let sampler =
        rlm_core::guard::Sampler::new(cfg.guard.clone(), std::process::id(), current_uid(), None);
    match sampler.sample() {
        Some(s) => println!("Pressure: {}", rlm_core::guard::report::pressure_line(&s)),
        None => println!(
            "Pressure: {}",
            rlm_core::guard::report::pressure_unavailable()
        ),
    }
    println!(
        "Policy:   {}",
        rlm_core::guard::report::trigger_line(&cfg.guard.trigger)
    );

    // Active interventions come from the guard's own write-ahead journal.
    // We use `Journal::read_entries` rather than `Journal::open` here
    // because this is the CLI, a *second* process running alongside the
    // daemon's own live `Journal` handle: `open()` can truncate/rewrite the
    // file (header repair) or run WAL tail recovery (`set_len` from a stale
    // read), and with no cross-process lock a daemon `append` landing
    // between that read and truncate would be silently dropped. Reflects
    // what the guard itself believes it's holding; it does not re-verify
    // against the kernel's live cgroup.freeze/memory.high, which
    // `rlm guard status` isn't trying to be a substitute for.
    let entries = rlm_core::guard::Journal::read_entries(
        &rlm_core::guard::journal_path(),
        &rlm_core::guard::cgfs::boot_id(),
    );
    if entries.is_empty() {
        println!("Interventions: none");
    } else {
        println!("Interventions:");
        for e in &entries {
            println!("  {}", rlm_core::guard::report::intervention_line(e));
        }
    }

    let recent =
        rlm_core::guard::history::read_recent(&rlm_core::guard::history::history_path(), 5);
    if recent.is_empty() {
        println!("History:  none recorded yet");
    } else {
        println!("History:");
        let now = rlm_core::guard::history::unix_now();
        for e in &recent {
            println!("  {}", rlm_core::guard::report::history_line(e, now));
        }
    }

    println!("Full history: rlm guard history (also: journalctl --user -u rlm-guard)");

    if config_err.is_some() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn guard_test() -> ExitCode {
    // Single-shot preview: ticks a FRESH engine once at now_ms=0, so it shows
    // what the guard's *first* action would be right now (the escalation gate is
    // open and no prior interventions exist). It does not simulate recovery or
    // cooldown behavior, and applies nothing. Uses the default base path (not a
    // live CgroupManager) so this still works on a host without cgroups v2.
    let cfg = match Config::load_validated() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "error: {}",
                rlm_core::guard::report::config_error_line(
                    &rlm_core::guard::report::config_error_path(),
                    &e
                )
            );
            return ExitCode::FAILURE;
        }
    };
    let base_path = CgroupManager::default_base_path();
    let rlm_base = rlm_core::guard::sampler::strip_cgroup_root(&base_path);
    if rlm_base.is_none() {
        tracing::error!(
            "base_path {:?} isn't under /sys/fs/cgroup; escalation target resolution disabled",
            base_path
        );
    }
    let sampler = rlm_core::guard::Sampler::new(
        cfg.guard.clone(),
        std::process::id(),
        current_uid(),
        rlm_base,
    );
    let mut engine = rlm_core::guard::PolicyEngine::new(cfg.guard);

    let Some(sample) = sampler.sample() else {
        println!(
            "Pressure: {}; cannot evaluate guard actions.",
            rlm_core::guard::report::pressure_unavailable()
        );
        return ExitCode::SUCCESS;
    };
    let snapshot = rlm_core::process::list_for_uid(current_uid()).unwrap_or_default();
    let procs = sampler.candidates(&snapshot);
    let targets =
        rlm_core::guard::sampler::targets_from_procs(&procs, &rlm_core::guard::cgfs::current_bytes);
    // A fresh engine holds no interventions, so nothing needs a liveness check.
    let live = std::collections::HashSet::new();
    println!(
        "{}  |  {} eligible process(es)",
        rlm_core::guard::report::pressure_line(&sample),
        procs.len()
    );

    let actions = engine.tick(0, sample, &targets, &live);
    if actions.is_empty() {
        println!("No action would be taken right now.");
    } else {
        println!("Would take {} action(s):", actions.len());
        for a in &actions {
            println!("  {a:?}");
        }
    }
    ExitCode::SUCCESS
}

/// Prints each notification as it is handed to the desktop.
struct PrintingSink(rlm_core::guard::notify::DesktopSink);

impl rlm_core::guard::notify::NotifySink for PrintingSink {
    fn show(&mut self, key: &str, title: &str, body: &str) {
        println!("shown:  {title}\n        {body}");
        self.0.show(key, title, body);
    }

    fn close(&mut self, key: &str) {
        println!("closed: the {key} notification");
        self.0.close(key);
    }
}

/// Width of the NAME column of `rlm status`.
const NAME_WIDTH: usize = 24;
/// Width of an `rlm status` line up to the end of the longest usual TYPE.
const STATUS_WIDTH: usize = 80;

/// One line of the `rlm status` table.
fn status_line(pid: &str, name: &str, mem: &str, cpu: &str, io: &str, kind: &str) -> String {
    format!("{pid:<8} {name:<NAME_WIDTH$} {mem:>8} {cpu:>6} {io:>8}  {kind}")
}

/// The TYPE column: "shared (1 process)", "shared (9 processes)", "shared"
/// when the count is unknown, or "individual".
fn status_type(is_shared: bool, count: Option<usize>) -> String {
    match (is_shared, count) {
        (true, Some(1)) => "shared (1 process)".to_string(),
        (true, Some(n)) => format!("shared ({n} processes)"),
        (true, None) => "shared".to_string(),
        (false, _) => "individual".to_string(),
    }
}

/// `name` cut to the NAME column, ending in "..." when it was longer.
fn fit_name(name: &str) -> String {
    if name.chars().count() <= NAME_WIDTH {
        name.to_string()
    } else {
        let head: String = name.chars().take(NAME_WIDTH - 3).collect();
        format!("{head}...")
    }
}

/// `rlm guard test --notify`: drive the guard's own notifier through a
/// sample freeze, cap and release of "firefox", so the user sees exactly
/// what the guard would show. Nothing is frozen or capped: the actions are
/// fed to the notifier as if the effector had applied them.
fn guard_test_notify() -> ExitCode {
    use rlm_core::guard::notify::{AppNames, DesktopSink, Notifier};
    use rlm_core::guard::resolve::{Coverage, Mechanism, Resolution, Verdict};
    use rlm_core::guard::{Action, Applied};

    const STEP: std::time::Duration = std::time::Duration::from_secs(3);
    // Show the look even when notifications are off in the config.
    let mut guard = Config::load_validated()
        .map(|c| c.guard)
        .unwrap_or_default();
    guard.notify = true;
    let mut notifier = Notifier::new(PrintingSink(DesktopSink::spawn()), &guard);
    let mut names = AppNames::new();
    let mut name = |key: &str, cg: &str| names.name(key, cg);
    let res = Resolution {
        cgroup: "/rlm-notify-preview".into(),
        unit: None,
        verdict: Verdict::Freeze,
        coverage: Coverage::Full,
        mechanism: Mechanism::Raw,
    };
    let app = "firefox".to_string();
    let done = Some(Applied { cap_bytes: None });

    notifier.record(
        &Action::Freeze {
            res: res.clone(),
            name: app.clone(),
        },
        done,
    );
    notifier.end_tick(0, rlm_core::guard::notify::Memory::Unknown, &mut name);
    std::thread::sleep(STEP);

    notifier.record(&Action::Thaw { res: res.clone() }, done);
    notifier.record(
        &Action::Cap {
            res: res.clone(),
            name: app,
        },
        Some(Applied {
            cap_bytes: Some(3_200_000_000),
        }),
    );
    notifier.end_tick(
        STEP.as_millis() as u64,
        rlm_core::guard::notify::Memory::Unknown,
        &mut name,
    );
    std::thread::sleep(STEP);

    notifier.record(&Action::LiftCap { res }, done);
    notifier.end_tick(
        2 * STEP.as_millis() as u64,
        rlm_core::guard::notify::Memory::Unknown,
        &mut name,
    );
    if !notifier.sink().0.flush(std::time::Duration::from_secs(3)) {
        eprintln!("warning: the notification server did not answer in time");
    }
    ExitCode::SUCCESS
}

/// Print up to `lines` most recent guard interventions, newest last.
fn guard_history(lines: usize) {
    let events =
        rlm_core::guard::history::read_recent(&rlm_core::guard::history::history_path(), lines);
    if events.is_empty() {
        println!("no guard interventions recorded yet");
        return;
    }
    let now = rlm_core::guard::history::unix_now();
    for e in &events {
        println!("{}", rlm_core::guard::report::history_line(e, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_rows_use_full_names_and_count_processes_in_english() {
        assert_eq!(status_type(true, Some(1)), "shared (1 process)");
        assert_eq!(status_type(true, Some(9)), "shared (9 processes)");
        assert_eq!(status_type(true, None), "shared");
        assert_eq!(status_type(false, Some(1)), "individual");
        assert_eq!(fit_name("gnome-calculator"), "gnome-calculator");
        assert_eq!(fit_name(&"x".repeat(NAME_WIDTH)), "x".repeat(NAME_WIDTH));
        assert_eq!(
            fit_name("org.example.AVeryLongProgramName"),
            "org.example.AVeryLong..."
        );
        assert_eq!(
            status_line("PID", "NAME", "MEMORY", "CPU", "I/O", "TYPE"),
            "PID      NAME                       MEMORY    CPU      I/O  TYPE"
        );
        assert_eq!(
            status_line(
                "1217697",
                "gnome-calculator",
                "1.0G",
                "50%",
                "-",
                "shared (1 process)"
            ),
            "1217697  gnome-calculator             1.0G    50%        -  shared (1 process)"
        );
    }

    #[test]
    fn limit_refuses_an_invalid_config_unless_forced() {
        let path = "/h/.config/rlm/config.yaml";
        let bad = || Err(Error::Config("failed to parse: unknown field".into()));
        let msg = config_for_limit(bad(), false, false, path).unwrap_err();
        assert!(msg.contains(path), "{msg}");
        assert!(msg.contains("unknown field"), "{msg}");
        assert!(msg.contains("--force"), "{msg}");
        let (cfg, warning) = config_for_limit(bad(), true, false, path).unwrap();
        assert!(cfg.guard.selection.protect.is_empty());
        let warning = warning.unwrap();
        assert!(warning.starts_with("warning:") && warning.contains(path));
        let (_, none) = config_for_limit(Ok(Config::default()), false, false, path).unwrap();
        assert_eq!(none, None);
    }

    #[test]
    fn save_needs_a_valid_config_even_with_force() {
        let path = "/h/.config/rlm/config.yaml";
        let bad = || Err(Error::Config("failed to parse: unknown field".into()));
        for force in [false, true] {
            let msg = config_for_limit(bad(), force, true, path).unwrap_err();
            assert!(msg.starts_with("error: config"), "{msg}");
            assert!(msg.contains(path) && msg.contains("unknown field"), "{msg}");
            assert!(msg.contains("--save"), "{msg}");
        }
        assert!(config_for_limit(Ok(Config::default()), true, true, path).is_ok());
    }

    #[test]
    fn packaging_metadata_is_consistent() {
        const MANIFEST: &str = include_str!("../Cargo.toml");
        assert!(
            MANIFEST.contains("name = \"rlmctl\""),
            "crates.io package name"
        );
        assert!(
            MANIFEST.contains("name = \"rlm\"\npath = \"src/main.rs\""),
            "binary stays rlm"
        );
        assert!(
            MANIFEST.contains("name = \"rlm-guard\""),
            "guard ships in the same package"
        );
        assert!(MANIFEST.contains("rlm-delegate.conf"));
        assert!(!MANIFEST.contains("dist/delegate.conf"));
        assert!(MANIFEST.contains("maintainer-scripts = \"../dist/deb\""));
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.2.7");
    }

    #[test]
    fn parse_pid_list_basic() {
        assert_eq!(parse_pid_list("1,2,3").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn parse_pid_list_trims_whitespace() {
        assert_eq!(parse_pid_list(" 10 , 20 ,30 ").unwrap(), vec![10, 20, 30]);
    }

    #[test]
    fn parse_pid_list_single() {
        assert_eq!(parse_pid_list("42").unwrap(), vec![42]);
    }

    #[test]
    fn parse_pid_list_rejects_invalid() {
        assert!(parse_pid_list("1,abc,3").is_err());
        assert!(parse_pid_list("1,,3").is_err()); // empty element
        assert!(parse_pid_list("-1").is_err()); // negative
    }

    #[test]
    fn commands_that_need_the_cgroup_manager() {
        let needs =
            |args: &[&str]| needs_cgroup_manager(&Cli::try_parse_from(args).unwrap().command);
        assert!(!needs(&["rlm", "doctor"]));
        assert!(!needs(&["rlm", "profiles"]));
        assert!(!needs(&["rlm", "export", "x.yaml"]));
        assert!(!needs(&["rlm", "import", "x.yaml"]));
        assert!(!needs(&["rlm", "guard", "status"]));
        assert!(!needs(&["rlm", "rule", "list"]));
        assert!(needs(&["rlm", "status"]));
        assert!(needs(&["rlm", "limit", "--pid", "5", "--memory", "1G"]));
        assert!(needs(&["rlm", "unlimit", "--pid", "5"]));
        assert!(needs(&["rlm", "run", "--memory", "1G", "--", "true"]));
    }

    #[test]
    fn save_without_application_is_rejected() {
        // clap's `requires` did not enforce this in 0.1; the check is explicit now.
        assert!(validate_limit_args(true, None).is_err());
        assert!(validate_limit_args(true, Some("firefox")).is_ok());
        assert!(validate_limit_args(false, None).is_ok());
    }

    #[test]
    fn save_refuses_a_version_number_program_name() {
        let e = validate_limit_args(true, Some("2.1.283"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("version number (2.1.283)"), "{e}");
        assert!(e.contains("without --save"), "{e}");
        assert!(validate_limit_args(false, Some("2.1.283")).is_ok());
    }

    #[test]
    fn other_users_and_protected_processes_are_refused() {
        let protect = common::protect_set(&[]);
        let p = |uid: u32, comm: &str, exe: &str| rlm_core::process::ProcessInfo {
            pid: 42,
            uid,
            name: comm.into(),
            executable: Some(exe.into()),
            ..Default::default()
        };
        assert!(check_target(
            &p(1000, "firefox", "/usr/bin/firefox"),
            1000,
            &protect,
            false
        )
        .is_ok());
        let e = check_target(&p(0, "sshd", "/usr/sbin/sshd"), 1000, &protect, true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("belongs to uid 0"), "{e}");
        let e = check_target(&p(1000, "bash", "/usr/bin/bash"), 1000, &protect, false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("--force"), "{e}");
        assert!(check_target(&p(1000, "bash", "/usr/bin/bash"), 1000, &protect, true).is_ok());
        assert!(
            check_target(&p(1000, "bash", "/usr/bin/bash"), 0, &protect, false).is_err(),
            "root still respects the protect list"
        );
    }

    #[test]
    fn unlimit_pid_reports_what_it_would_touch() {
        assert_eq!(unlimit_pid_target(5, Some("pid-5")).unwrap(), "pid-5");
        let e = unlimit_pid_target(5, None).unwrap_err().to_string();
        assert!(e.contains("not limited by rlm"), "{e}");
        let e = unlimit_pid_target(5, Some("app-firefox"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("rlm unlimit --cgroup app-firefox"), "{e}");
    }

    #[test]
    fn import_rejects_the_whole_file_if_any_profile_is_invalid() {
        let mut m = std::collections::HashMap::new();
        m.insert(
            "good".to_string(),
            common::Profile {
                cpu: Some("50%".into()),
                ..Default::default()
            },
        );
        m.insert(
            "bad".to_string(),
            common::Profile {
                memory: Some("1K".into()),
                ..Default::default()
            },
        );
        let e = validate_import(&m).unwrap_err().to_string();
        assert!(e.contains("bad") && !e.contains("good"), "{e}");
    }
}
