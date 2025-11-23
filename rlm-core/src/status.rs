use crate::CgroupManager;
use common::Result;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct ProcessStatus {
    pub pid: u32,
    pub name: String,
    pub memory_max: Option<u64>,
    pub cpu_quota: Option<u32>,
    pub io_read_bps: Option<u64>,
    pub io_write_bps: Option<u64>,
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

        // Extract PID from cgroup directory name patterns:
        // - "pid-XXXX" (CLI limit command)
        // - "run-XXXX" (CLI run command)
        // - "gtk-XXXX-N" (GUI run command)
        let pid = if let Some(pid_str) = cgroup_name.strip_prefix("pid-") {
            pid_str.parse::<u32>().ok()
        } else if cgroup_name.starts_with("run-") || cgroup_name.starts_with("gtk-") {
            // For run-* and gtk-* cgroups, read PID from cgroup.procs
            read_first_pid(&path)
        } else {
            continue;
        };

        let Some(pid) = pid else {
            // No PID found - cgroup is empty/dead, mark for cleanup
            dead_cgroups.push(cgroup_name.to_string());
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

        results.push(ProcessStatus {
            pid,
            name: proc_name,
            memory_max,
            cpu_quota,
            io_read_bps,
            io_write_bps,
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
