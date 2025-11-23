use common::{Error, Result};
use std::fs;
use std::path::Path;

/// Basic process info
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

/// List all running processes
pub fn list_all() -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();

        let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        if let Ok(comm) = fs::read_to_string(path.join("comm")) {
            processes.push(ProcessInfo {
                pid,
                name: comm.trim().to_string(),
            });
        }
    }

    processes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(processes)
}

/// Find all PIDs matching a process name
pub fn find_by_name(name: &str) -> Result<Vec<u32>> {
    let mut pids = Vec::new();

    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();

        // Only look at numeric directories (PIDs)
        let Some(pid_str) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        if matches_name(&path, name) {
            pids.push(pid);
        }
    }

    if pids.is_empty() {
        return Err(Error::ProcessNameNotFound(name.to_string()));
    }

    Ok(pids)
}

fn matches_name(proc_path: &Path, name: &str) -> bool {
    // Try /proc/PID/comm first (max 15 chars, may be truncated)
    if let Ok(comm) = fs::read_to_string(proc_path.join("comm")) {
        let comm = comm.trim();
        if comm == name {
            return true;
        }
        // comm is 15 chars (possibly truncated) and name is longer - verify via exe
        if comm.len() == 15 && name.len() > 15 && name.starts_with(comm) {
            if let Ok(exe) = fs::read_link(proc_path.join("exe")) {
                if let Some(exe_name) = exe.file_name().and_then(|n| n.to_str()) {
                    return exe_name == name;
                }
            }
        }
    }

    // Try /proc/PID/exe symlink (full path)
    if let Ok(exe) = fs::read_link(proc_path.join("exe")) {
        if let Some(exe_name) = exe.file_name().and_then(|n| n.to_str()) {
            if exe_name == name {
                return true;
            }
        }
    }

    false
}
