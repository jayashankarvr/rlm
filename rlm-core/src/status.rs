use crate::CgroupManager;
use common::Result;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct ProcessStatus {
    pub pid: u32,
    pub name: String,
    pub cgroup_name: String,
    pub memory_max: Option<u64>,
    pub cpu_quota: Option<u32>,
    pub io_read_bps: Option<u64>,
    pub io_write_bps: Option<u64>,
    pub is_shared: bool,
    pub process_count: Option<usize>,
}

/// Get status of all processes managed by rlm
pub fn get_managed_processes(manager: &CgroupManager) -> Result<Vec<ProcessStatus>> {
    let base = manager.base_path();
    if !base.exists() {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    let mut dead_cgroups = Vec::new();

    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_dir() {
            continue;
        }

        let Some(cgroup_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        // Skip the "unlimit" cgroup (holds released processes)
        if cgroup_name == "unlimit" {
            continue;
        }

        // Extract PID from cgroup directory name patterns:
        // - "pid-XXXX" (CLI limit command - individual)
        // - "app-XXXX" (CLI limit --application - shared)
        // - "multi-XXXX" (CLI limit --all-pids - shared)
        // - "run-XXXX-XXXX" (CLI run command: pid + timestamp)
        // - "gtk-XXXX-N" (GUI run command)
        let pid = if let Some(pid_str) = cgroup_name.strip_prefix("pid-") {
            pid_str.parse::<u32>().ok()
        } else if cgroup_name.starts_with("app-") || cgroup_name.starts_with("multi-") {
            // For shared cgroups, read first PID from cgroup.procs
            read_first_pid(&path)
        } else if cgroup_name.starts_with("run-") || cgroup_name.starts_with("gtk-") {
            // For run-* and gtk-* cgroups, read PID from cgroup.procs
            read_first_pid(&path)
        } else {
            continue;
        };

        let Some(pid) = pid else {
            // No PID found - cgroup is empty. Only reap it if it isn't freshly
            // created: another `limit`/`run` invocation may have created the
            // cgroup and not yet written its PID into cgroup.procs. Reaping it
            // mid-setup would race-delete a cgroup that's about to be used.
            // Reaping is merely DEFERRED here, not skipped: a genuinely-dead
            // fresh cgroup is collected on the next status pass once 2s elapse.
            if !recently_modified(&path, 2) {
                dead_cgroups.push(cgroup_name.to_string());
            }
            continue;
        };

        // Check if process still exists
        let proc_path = format!("/proc/{pid}/comm");
        let proc_name = match fs::read_to_string(&proc_path) {
            Ok(s) => s.trim().to_string(),
            Err(_) => {
                // Process is dead, mark cgroup for cleanup
                dead_cgroups.push(cgroup_name.to_string());
                continue;
            }
        };

        let memory_max = parse_memory_max(&path);
        let cpu_quota = parse_cpu_quota(&path);
        let (io_read_bps, io_write_bps) = parse_io_limits(&path);

        // Skip processes with no active limits (all set to max/unlimited)
        if memory_max.is_none()
            && cpu_quota.is_none()
            && io_read_bps.is_none()
            && io_write_bps.is_none()
        {
            dead_cgroups.push(cgroup_name.to_string());
            continue;
        }

        // Check if this is a shared cgroup
        let is_shared = cgroup_name.starts_with("app-")
            || cgroup_name.starts_with("multi-")
            || cgroup_name.starts_with("run-")
            || cgroup_name.starts_with("gtk-");

        // Count processes in shared cgroups
        let process_count = if is_shared {
            if let Ok(content) = fs::read_to_string(path.join("cgroup.procs")) {
                Some(content.lines().filter(|l| !l.trim().is_empty()).count())
            } else {
                None
            }
        } else {
            None
        };

        results.push(ProcessStatus {
            pid,
            name: proc_name,
            cgroup_name: cgroup_name.to_string(),
            memory_max,
            cpu_quota,
            io_read_bps,
            io_write_bps,
            is_shared,
            process_count,
        });
    }

    // Clean up dead cgroups
    for cgroup_name in dead_cgroups {
        if let Err(e) = manager.cleanup_cgroup(&cgroup_name) {
            tracing::debug!("Failed to cleanup dead cgroup {}: {}", cgroup_name, e);
        }
    }

    Ok(results)
}

/// Whether `path` was modified within the last `secs` seconds.
fn recently_modified(path: &Path, secs: u64) -> bool {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age.as_secs() < secs)
        .unwrap_or(false)
}

fn read_first_pid(cgroup_path: &Path) -> Option<u32> {
    let content = fs::read_to_string(cgroup_path.join("cgroup.procs")).ok()?;
    content.lines().next()?.trim().parse().ok()
}

fn parse_memory_max(cgroup_path: &Path) -> Option<u64> {
    let content = fs::read_to_string(cgroup_path.join("memory.max")).ok()?;
    let content = content.trim();
    if content == "max" {
        return None;
    }
    content.parse().ok()
}

fn parse_cpu_quota(cgroup_path: &Path) -> Option<u32> {
    let content = fs::read_to_string(cgroup_path.join("cpu.max")).ok()?;
    let content = content.trim();
    if content == "max" || content.starts_with("max ") {
        return None;
    }

    // Format: "quota period" e.g., "50000 100000" = 50%
    let mut parts = content.split_whitespace();
    let quota: u64 = parts.next()?.parse().ok()?;
    let period: u64 = parts.next()?.parse().ok()?;

    if period == 0 {
        return None;
    }

    // Use saturating arithmetic to prevent overflow
    Some(quota.saturating_mul(100).saturating_div(period) as u32)
}

fn parse_io_limits(cgroup_path: &Path) -> (Option<u64>, Option<u64>) {
    let content = match fs::read_to_string(cgroup_path.join("io.max")) {
        Ok(c) => c,
        Err(_) => return (None, None),
    };

    let mut read_bps = None;
    let mut write_bps = None;

    // Format: "major:minor rbps=X wbps=Y" (one line per device)
    for line in content.lines() {
        for part in line.split_whitespace().skip(1) {
            if let Some(val) = part.strip_prefix("rbps=") {
                if val != "max" {
                    read_bps = read_bps.or_else(|| val.parse().ok());
                }
            } else if let Some(val) = part.strip_prefix("wbps=") {
                if val != "max" {
                    write_bps = write_bps.or_else(|| val.parse().ok());
                }
            }
        }
    }

    (read_bps, write_bps)
}
