use clap::{Parser, Subcommand};
use common::{build_limit, format_bytes, Config, Error, Result};
use rlm_core::CgroupManager;
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn resolve_pids(pid: Option<u32>, name: Option<&str>) -> Result<Vec<u32>> {
    match (pid, name) {
        (Some(pid), None) => Ok(vec![pid]),
        (None, Some(name)) => rlm_core::process::find_by_name(name),
        (None, None) => Err(Error::InvalidArgs("specify either --pid or --name".into())),
        (Some(_), Some(_)) => unreachable!("clap prevents this"),
    }
}

fn resolve_application_pids(application: &str) -> Result<Vec<u32>> {
    let processes = rlm_core::process::find_all_by_executable(application)?;
    Ok(processes.iter().map(|p| p.pid).collect())
}

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

/// Prompt user for confirmation when affecting multiple processes
fn confirm_batch(pids: &[u32], action: &str) -> bool {
    if pids.len() <= 1 {
        return true;
    }

    println!("Found {} processes:", pids.len());
    for pid in pids.iter().take(10) {
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".to_string());
        println!("  {pid}: {name}");
    }
    if pids.len() > 10 {
        println!("  ... and {} more", pids.len() - 10);
    }

    print!("{} all {} processes? [y/N] ", action, pids.len());
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
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
    /// Show current memory pressure and active guard interventions
    Status,
    /// Enable and start the guard user service
    Enable,
    /// Disable and stop the guard user service
    Disable,
    /// Dry-run: print what the guard would do right now, without acting
    Test,
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

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
    let manager = CgroupManager::new()?;

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
        } => {
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

            // Determine which mode we're in
            let (pids, cgroup_name, is_shared) = if let Some(app_name) = application {
                // Application mode: all processes share limits
                let pids = resolve_application_pids(&app_name)?;
                if pids.is_empty() {
                    return Err(Error::ProcessNameNotFound(app_name));
                }
                let cgroup_name = format!("app-{}", app_name.replace(['/', ' '], "_"));
                println!(
                    "Found {} process(es) for application '{}'",
                    pids.len(),
                    app_name
                );
                (pids, cgroup_name, true)
            } else if let Some(pids_str) = all_pids {
                // Multiple PIDs mode: all share limits
                let pids = parse_pid_list(&pids_str)?;
                if pids.is_empty() {
                    return Err(Error::InvalidArgs("no valid PIDs specified".into()));
                }
                let cgroup_name = format!("multi-{}", pids[0]);
                (pids, cgroup_name, true)
            } else {
                // Individual mode: each process gets its own limits
                let pids = resolve_pids(pid, name.as_deref())?;
                (pids, String::new(), false)
            };

            if dry_run {
                println!(
                    "Dry run - would apply limits to {} process(es):",
                    pids.len()
                );
                for pid in &pids {
                    let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|_| "?".to_string());
                    println!("  {pid}: {name}");
                }
                if is_shared {
                    println!("\n⚠️  All processes will SHARE these limits (combined pool):");
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

            if !confirm_batch(&pids, "Limit") {
                println!("cancelled");
                return Ok(ExitCode::SUCCESS);
            }

            if is_shared {
                // Apply shared limits to all processes
                manager.apply_limit_to_multiple(&pids, &limit, &cgroup_name)?;
                println!(
                    "Applied shared limits to {} process(es) in cgroup '{}'",
                    pids.len(),
                    cgroup_name
                );
                println!("⚠️  Note: All processes share these limits (combined pool)");
            } else {
                // Apply individual limits to each process
                for pid in &pids {
                    manager.apply_limit(*pid, &limit)?;
                    println!("applied limits to pid {pid}");
                }
            }
        }

        Commands::Unlimit {
            pid,
            name,
            application,
            cgroup,
        } => {
            if let Some(cgroup_name) = cgroup {
                // Remove by cgroup name
                manager.remove_application_limit(&cgroup_name)?;
                println!("removed limits from cgroup '{}'", cgroup_name);
            } else if let Some(app_name) = application {
                // Remove application cgroup
                let cgroup_name = format!("app-{}", app_name.replace(['/', ' '], "_"));
                manager.remove_application_limit(&cgroup_name)?;
                println!("removed limits from application '{}'", app_name);
            } else {
                // Remove individual processes
                let pids = resolve_pids(pid, name.as_deref())?;

                if !confirm_batch(&pids, "Unlimit") {
                    println!("cancelled");
                    return Ok(ExitCode::SUCCESS);
                }

                for pid in &pids {
                    manager.remove_limit(*pid)?;
                    println!("removed limits from pid {pid}");
                }
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
            let limit = if let Some(profile_name) = profile {
                let config = Config::load()?;
                let Some(p) = config.get_profile(&profile_name) else {
                    return Err(Error::Config(format!("profile '{profile_name}' not found")));
                };
                p.to_limit()?
            } else {
                let limit = build_limit(
                    memory.as_deref(),
                    cpu.as_deref(),
                    io_read.as_deref(),
                    io_write.as_deref(),
                )?;
                if limit.memory.is_none() && limit.cpu.is_none() && limit.io.is_none() {
                    return Err(Error::InvalidArgs(
                        "specify --profile or at least one limit".into(),
                    ));
                }
                limit
            };

            return run_with_limits(&manager, &limit, &command);
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
                println!("no user-defined profiles to export (built-in presets are always available)");
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
            let processes = rlm_core::status::get_managed_processes(&manager)?;

            if processes.is_empty() {
                println!("no processes currently managed");
            } else {
                println!(
                    "{:<8} {:<25} {:>12} {:>15} {:>10} {:>15}",
                    "PID", "NAME", "MEMORY", "CPU", "I/O", "TYPE"
                );
                println!("{}", "-".repeat(85));

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
                    let type_info = if p.is_shared {
                        if let Some(count) = p.process_count {
                            format!("shared ({} procs)", count)
                        } else {
                            "shared".to_string()
                        }
                    } else {
                        "individual".to_string()
                    };
                    println!(
                        "{:<8} {:<25} {:>12} {:>15} {:>10} {:>15}",
                        p.pid, p.name, mem, cpu, io, type_info
                    );
                }
                println!("\nNote: 'shared' means multiple processes share the same limit pool");
            }
        }

        Commands::Doctor => {
            run_doctor();
        }

        Commands::Guard { action } => {
            return run_guard(&manager, action);
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn run_guard(manager: &CgroupManager, action: GuardAction) -> Result<ExitCode> {
    match action {
        GuardAction::Enable => systemctl(&["enable", "--now", "rlm-guard"]),
        GuardAction::Disable => systemctl(&["disable", "--now", "rlm-guard"]),
        GuardAction::Status => {
            guard_status(manager);
            Ok(ExitCode::SUCCESS)
        }
        GuardAction::Test => {
            guard_test();
            Ok(ExitCode::SUCCESS)
        }
    }
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

/// Current real UID from the kernel.
fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe; it only reads our real UID.
    unsafe { libc::getuid() }
}

fn guard_status(manager: &CgroupManager) {
    let cfg = Config::load().unwrap_or_default();
    let sampler = rlm_core::guard::Sampler::new(cfg.guard, std::process::id(), current_uid());

    match sampler.sample() {
        Some(s) => println!(
            "Memory pressure: some(avg10)={:.1}%  full(avg10)={:.1}%  available={} MB",
            s.some_avg10, s.full_avg10, s.mem_available_mb
        ),
        None => println!("Memory pressure: PSI unavailable (/proc/pressure/memory)"),
    }

    let base = manager.base_path();
    let pids = manager.list_guard_pids();
    if pids.is_empty() {
        println!("\nNo active guard interventions.");
        return;
    }

    println!("\n{:<8} {:<20} {:<8} {:<14}", "PID", "NAME", "STATE", "MEM.HIGH");
    println!("{}", "-".repeat(52));
    for pid in pids {
        let gpath = base.join(format!("guard-{pid}"));
        let frozen = std::fs::read_to_string(gpath.join("cgroup.freeze"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        let high = std::fs::read_to_string(gpath.join("memory.high"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".to_string());
        let state = if frozen {
            "frozen"
        } else if !high.is_empty() && high != "max" {
            "capped"
        } else {
            "active"
        };
        println!("{:<8} {:<20} {:<8} {:<14}", pid, name, state, high);
    }
}

fn guard_test() {
    // Single-shot preview: ticks a FRESH engine once at now_ms=0, so it shows
    // what the guard's *first* action would be right now (the escalation gate is
    // open and no prior interventions exist). It does not simulate recovery or
    // cooldown behavior, and applies nothing.
    let cfg = Config::load().unwrap_or_default();
    let sampler =
        rlm_core::guard::Sampler::new(cfg.guard.clone(), std::process::id(), current_uid());
    let mut engine = rlm_core::guard::PolicyEngine::new(cfg.guard);

    let Some(sample) = sampler.sample() else {
        println!("PSI unavailable; cannot evaluate guard actions.");
        return;
    };
    let procs = sampler.eligible();
    println!(
        "Pressure: some={:.1}%  full={:.1}%  available={} MB  |  {} eligible process(es)",
        sample.some_avg10,
        sample.full_avg10,
        sample.mem_available_mb,
        procs.len()
    );

    let actions = engine.tick(0, sample, &procs);
    if actions.is_empty() {
        println!("No action would be taken right now.");
    } else {
        println!("Would take {} action(s):", actions.len());
        for a in &actions {
            println!("  {a:?}");
        }
    }
}

fn run_doctor() {
    println!("rlm doctor - checking system requirements\n");

    let mut all_ok = true;

    // Check cgroups v2
    let cgroup_check = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    print_check("cgroups v2 available", cgroup_check);
    if !cgroup_check {
        println!("  -> ensure kernel supports cgroups v2 and unified hierarchy is mounted");
        all_ok = false;
    }

    // Check available controllers
    if cgroup_check {
        if let Ok(controllers) = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers") {
            let has_memory = controllers.contains("memory");
            let has_cpu = controllers.contains("cpu");
            let has_io = controllers.contains("io");

            print_check("memory controller", has_memory);
            print_check("cpu controller", has_cpu);
            print_check("io controller", has_io);

            if !has_memory || !has_cpu || !has_io {
                all_ok = false;
            }
        }
    }

    // Check user cgroup delegation (for non-root)
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse::<u32>().ok())
        });

    if let Some(uid) = uid {
        if uid != 0 {
            let user_slice =
                format!("/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service");
            let delegation_ok = std::path::Path::new(&user_slice).exists();
            print_check("user cgroup delegation", delegation_ok);
            if !delegation_ok {
                println!("  -> run these commands to enable delegation:");
                println!("     sudo mkdir -p /etc/systemd/system/user@.service.d");
                println!("     echo '[Service]' | sudo tee /etc/systemd/system/user@.service.d/delegate.conf");
                println!("     echo 'Delegate=cpu memory io' | sudo tee -a /etc/systemd/system/user@.service.d/delegate.conf");
                println!("     sudo systemctl daemon-reload");
                println!("     # then log out and back in");
                all_ok = false;
            }
        } else {
            print_check("running as root", true);
        }
    }

    // Check config file
    let config_path = dirs::config_dir()
        .map(|p| p.join("rlm/config.yaml"))
        .unwrap_or_default();
    let config_exists = config_path.exists();
    print_check(
        &format!("config file ({})", config_path.display()),
        config_exists,
    );
    if !config_exists {
        println!("  -> optional: create config for profiles");
    }

    println!();
    if all_ok {
        println!("all checks passed - rlm is ready to use");
    } else {
        println!("some checks failed - see hints above");
    }
}

fn print_check(name: &str, ok: bool) {
    let status = if ok { "[ok]" } else { "[FAIL]" };
    println!("{:>8} {}", status, name);
}

fn run_with_limits(
    manager: &CgroupManager,
    limit: &common::Limit,
    command: &[String],
) -> Result<ExitCode> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| common::Error::InvalidArgs("command is required".into()))?;

    // Generate a collision-resistant cgroup name. Using only the PID risks
    // reusing a stale leaked `run-<pid>` cgroup after PID reuse; the timestamp
    // suffix makes that effectively impossible.
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let cgroup_name = format!("run-{}-{}", std::process::id(), uniq);

    // Create cgroup and set limits BEFORE spawning the process
    let cgroup_path = manager.prepare_cgroup(&cgroup_name, limit)?;

    // Set up signal handler
    let terminated = Arc::new(AtomicBool::new(false));
    let terminated_clone = Arc::clone(&terminated);

    ctrlc::set_handler(move || {
        terminated_clone.store(true, Ordering::SeqCst);
    })
    .ok();

    // Place the child into the cgroup BEFORE it execs, so it is constrained from
    // its first instruction (see CgroupManager::placement_command).
    let mut cmd = manager.placement_command(&cgroup_path, program);
    cmd.args(args);
    let mut child = cmd.spawn()?;

    let pid = child.id();

    // Fallback: ensure the process is in the cgroup even if pre-exec placement
    // failed. Idempotent if it's already there.
    if let Err(e) = manager.add_to_cgroup(&cgroup_path, pid) {
        eprintln!("warning: failed to apply limits: {e}");
    }

    // Track if we've sent SIGTERM
    let mut sigterm_sent = false;

    // Wait for process, checking for signals
    let status = loop {
        if terminated.load(Ordering::SeqCst) && !sigterm_sent {
            // Forward signal to child (only once)
            // SAFETY: pid is a valid process ID obtained from child.id() of a process
            // we just spawned. libc::kill with SIGTERM is safe for any PID - worst case
            // the process already exited and kill returns an error (which we ignore).
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            sigterm_sent = true;
        }

        match child.try_wait()? {
            Some(status) => break status,
            None => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    };

    // Clean up our ephemeral cgroup. Don't propagate a cleanup error here: cgroup
    // v2 can briefly return EBUSY on rmdir right after the last process exits, and
    // we must not let that mask the child program's real exit code.
    if let Err(e) = manager.cleanup_cgroup(&cgroup_name) {
        eprintln!("warning: failed to remove cgroup: {e}");
    }

    Ok(status
        .code()
        .map(|c| ExitCode::from(c as u8))
        .unwrap_or(ExitCode::FAILURE))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
