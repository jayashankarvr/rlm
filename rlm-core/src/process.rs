use common::{Error, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Basic process info
#[derive(Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub ppid: Option<u32>,
    pub session: Option<u32>,
    pub executable: Option<PathBuf>,
}

/// Extended process info with grouping information
pub struct ProcessGroup {
    pub name: String,
    pub executable: Option<PathBuf>,
    pub processes: Vec<ProcessInfo>,
}

/// Read process stat file to get PPID and session
fn read_process_stat(proc_path: &Path) -> Option<(u32, u32)> {
    // Format: pid comm state ppid pgrp session ...
    // Fields: 0   1    2     3    4    5
    if let Ok(content) = fs::read_to_string(proc_path.join("stat")) {
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 6 {
            if let (Ok(ppid), Ok(session)) = (parts[3].parse(), parts[5].parse()) {
                return Some((ppid, session));
            }
        }
    }
    None
}

/// Get executable path for a process
fn get_executable(proc_path: &Path) -> Option<PathBuf> {
    fs::read_link(proc_path.join("exe")).ok()
}

/// List all running processes with extended information
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

        let name = fs::read_to_string(path.join("comm"))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "?".to_string());

        let (ppid, session) = read_process_stat(&path).unwrap_or((0, 0));
        let executable = get_executable(&path);

        processes.push(ProcessInfo {
            pid,
            name,
            ppid: if ppid > 0 { Some(ppid) } else { None },
            session: if session > 0 { Some(session) } else { None },
            executable,
        });
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

/// Group processes by executable path (same application)
pub fn group_by_executable(processes: &[ProcessInfo]) -> Vec<ProcessGroup> {
    let mut groups: HashMap<String, Vec<ProcessInfo>> = HashMap::new();

    for proc in processes {
        let key = proc
            .executable
            .as_ref()
            .and_then(|exe| exe.file_name())
            .and_then(|n| n.to_str())
            .map(String::from)
            .unwrap_or_else(|| proc.name.clone());

        groups.entry(key).or_default().push(proc.clone());
    }

    groups
        .into_iter()
        .map(|(name, procs)| {
            let executable = procs.first().and_then(|p| p.executable.clone());
            ProcessGroup {
                name,
                executable,
                processes: procs,
            }
        })
        .filter(|group| group.processes.len() > 1) // Only groups with multiple processes
        .collect()
}

/// Group processes by session ID (same process group)
pub fn group_by_session(processes: &[ProcessInfo]) -> Vec<ProcessGroup> {
    let mut groups: HashMap<u32, Vec<ProcessInfo>> = HashMap::new();

    for proc in processes {
        if let Some(session) = proc.session {
            groups.entry(session).or_default().push(proc.clone());
        }
    }

    groups
        .into_iter()
        .map(|(session_id, procs)| {
            let name = procs
                .first()
                .map(|p| format!("{} (session {})", p.name, session_id))
                .unwrap_or_else(|| format!("Session {}", session_id));
            let executable = procs.first().and_then(|p| p.executable.clone());
            ProcessGroup {
                name,
                executable,
                processes: procs,
            }
        })
        .filter(|group| group.processes.len() > 1)
        .collect()
}

/// Find all processes that share the same parent process tree
/// Returns processes that are descendants of the given PID
pub fn find_process_tree(root_pid: u32) -> Result<Vec<u32>> {
    let all_processes = list_all()?;
    let mut result = vec![root_pid];
    let mut to_check = vec![root_pid];
    let mut checked = std::collections::HashSet::new();
    checked.insert(root_pid);

    while let Some(pid) = to_check.pop() {
        // Find all processes with this PID as parent
        for proc in &all_processes {
            if let Some(ppid) = proc.ppid {
                if ppid == pid && !checked.contains(&proc.pid) {
                    result.push(proc.pid);
                    to_check.push(proc.pid);
                    checked.insert(proc.pid);
                }
            }
        }
    }

    Ok(result)
}

/// Find all processes matching an executable name (all instances)
pub fn find_all_by_executable(executable_name: &str) -> Result<Vec<ProcessInfo>> {
    let all = list_all()?;
    let mut matches = Vec::new();

    for proc in all {
        let matches_name = proc.name == executable_name
            || proc
                .executable
                .as_ref()
                .and_then(|exe| exe.file_name())
                .and_then(|n| n.to_str())
                .map(|n| n == executable_name)
                .unwrap_or(false);

        if matches_name {
            matches.push(proc);
        }
    }

    if matches.is_empty() {
        return Err(Error::ProcessNameNotFound(executable_name.to_string()));
    }

    Ok(matches)
}
