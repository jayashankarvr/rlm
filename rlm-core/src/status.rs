use crate::cgroup::UNLIMIT_CGROUP_NAME;
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
    pub populated: bool,
}

/// Names of the cgroups under rlm's base that `status` reports on:
/// "pid-N" (`rlm limit`), "app-*" and "multi-*" (shared limits), "run-*"
/// (`rlm run`) and "gtk-*" (GUI run). The `unlimit` bucket is never one.
fn managed_cgroup_names(manager: &CgroupManager) -> Result<Vec<String>> {
    let base = manager.base_path();
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        if !entry.path().is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name == UNLIMIT_CGROUP_NAME {
            continue;
        }
        if ["pid-", "app-", "multi-", "run-", "gtk-"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// Get status of all processes managed by rlm. Read-only: it never removes
/// or changes a cgroup, so a GUI refresh loop can call it safely. A cgroup
/// is listed while it is populated; `pid` is the first PID in its
/// `cgroup.procs` (0 if none) and `name` that process's comm, or "?".
pub fn get_managed_processes(manager: &CgroupManager) -> Result<Vec<ProcessStatus>> {
    let base = manager.base_path();
    let mut results = Vec::new();

    for cgroup_name in managed_cgroup_names(manager)? {
        if manager.is_populated(&cgroup_name) != Some(true) {
            continue;
        }
        let path = base.join(&cgroup_name);

        let memory_max = parse_memory_max(&path);
        let cpu_quota = parse_cpu_quota(&path);
        let (io_read_bps, io_write_bps) = parse_io_limits(&path);

        // Skip cgroups with no active limits (all set to max/unlimited)
        if memory_max.is_none()
            && cpu_quota.is_none()
            && io_read_bps.is_none()
            && io_write_bps.is_none()
        {
            continue;
        }

        let pid = read_first_pid(&path).unwrap_or(0);
        let name = fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .filter(|_| pid != 0)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        let is_shared = !cgroup_name.starts_with("pid-");
        let process_count = if is_shared {
            fs::read_to_string(path.join("cgroup.procs"))
                .ok()
                .map(|c| c.lines().filter(|l| !l.trim().is_empty()).count())
        } else {
            None
        };

        results.push(ProcessStatus {
            pid,
            name,
            cgroup_name,
            memory_max,
            cpu_quota,
            io_read_bps,
            io_write_bps,
            is_shared,
            process_count,
            populated: true,
        });
    }

    Ok(results)
}

/// Names of rlm cgroups that hold no process, sorted. `status` reports them
/// but never removes them.
pub fn empty_cgroups(manager: &CgroupManager) -> Vec<String> {
    managed_cgroup_names(manager)
        .unwrap_or_default()
        .into_iter()
        .filter(|n| manager.is_populated(n) == Some(false))
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn cg(dir: &Path, name: &str, procs: &str, populated: bool) {
        let p = dir.join(name);
        fs::create_dir(&p).unwrap();
        fs::write(p.join("cgroup.procs"), procs).unwrap();
        fs::write(
            p.join("cgroup.events"),
            format!("populated {}\nfrozen 0\n", u8::from(populated)),
        )
        .unwrap();
        fs::write(p.join("memory.max"), "104857600\n").unwrap();
    }

    #[test]
    fn status_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        cg(dir.path(), "run-1-2", "", false);
        let m = CgroupManager::at(dir.path().to_path_buf());
        assert!(get_managed_processes(&m).unwrap().is_empty());
        assert!(
            dir.path().join("run-1-2").exists(),
            "status must never remove cgroups"
        );
        assert_eq!(empty_cgroups(&m), vec!["run-1-2".to_string()]);
    }

    #[test]
    fn populated_cgroup_is_listed_even_if_its_first_pid_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        cg(dir.path(), "app-firefox", "999999999\n", true);
        let m = CgroupManager::at(dir.path().to_path_buf());
        let s = get_managed_processes(&m).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].name, "?");
        assert!(s[0].populated);
    }
}
