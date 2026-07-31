use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use common::Result;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Convert a cgroup path (relative to /sys/fs/cgroup) to an absolute path.
/// All paths passed to this module are relative to /sys/fs/cgroup (same convention as Resolution.cgroup).
pub fn abs(cg: &str) -> PathBuf {
    PathBuf::from(CGROUP_ROOT).join(cg)
}

/// Read the frozen state from cgroup.events.
/// Returns Some(true) if frozen, Some(false) if not, None if not readable.
pub fn read_frozen(cg: &str) -> Option<bool> {
    let content = fs::read_to_string(abs(cg).join("cgroup.events")).ok()?;
    parse_frozen(&content)
}

/// Freeze or unfreeze a cgroup (write to cgroup.freeze).
pub fn write_freeze(cg: &str, on: bool) -> Result<()> {
    let value = if on { "1" } else { "0" };
    fs::write(abs(cg).join("cgroup.freeze"), value)
        .map_err(|e| common::Error::Cgroup(format!("failed to write cgroup.freeze: {e}")))?;
    Ok(())
}

/// Read memory.high value (verbatim, trimmed: either "max" or bytes).
pub fn read_high(cg: &str) -> Option<String> {
    fs::read_to_string(abs(cg).join("memory.high"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Write memory.high value.
pub fn write_high(cg: &str, val: &str) -> Result<()> {
    fs::write(abs(cg).join("memory.high"), val)
        .map_err(|e| common::Error::Cgroup(format!("failed to write memory.high: {e}")))?;
    Ok(())
}

/// Get total anonymous + swap memory (anon from memory.stat + memory.swap.current).
pub fn anon_swap_bytes(cg: &str) -> Option<u64> {
    let stat = fs::read_to_string(abs(cg).join("memory.stat")).ok()?;
    let anon = parse_anon(&stat)?;
    let swap = fs::read_to_string(abs(cg).join("memory.swap.current"))
        .ok()?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    Some(anon + swap)
}

/// Get the inode number of the cgroup directory.
pub fn dir_inode(cg: &str) -> Option<u64> {
    let metadata = fs::metadata(abs(cg)).ok()?;
    Some(metadata.ino())
}

/// Get all PIDs currently in the cgroup (reads cgroup.procs).
pub fn pids_in(cg: &str) -> Vec<u32> {
    match fs::read_to_string(abs(cg).join("cgroup.procs")) {
        Ok(content) => content
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Get the executable basename for a process (from /proc/<pid>/exe).
pub fn exe_basename(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    path.file_name()?.to_str().map(|s| s.to_string())
}

/// Get the boot_id from /proc/sys/kernel/random/boot_id, trimmed.
/// Returns empty string on failure.
pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Pure parser: extract frozen state from cgroup.events text.
/// Looks for "frozen <0|1>" line and returns Some(bool), or None if not found.
pub fn parse_frozen(events: &str) -> Option<bool> {
    events.lines().find_map(|l| {
        let rest = l.strip_prefix("frozen ")?;
        Some(rest.trim() == "1")
    })
}

/// Pure parser: extract anon memory value from memory.stat text.
/// Looks for "anon <value>" line and returns the parsed value, or None if not found.
pub fn parse_anon(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|l| l.strip_prefix("anon ")?.trim().parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_frozen_reads_events() {
        assert_eq!(parse_frozen("populated 1\nfrozen 0\n"), Some(false));
        assert_eq!(parse_frozen("populated 1\nfrozen 1\n"), Some(true));
        assert_eq!(parse_frozen("populated 1\n"), None);
    }

    #[test]
    fn parse_anon_reads_memory_stat() {
        let stat = "anon 1073741824\nfile 536870912\nkernel 1000\n";
        assert_eq!(parse_anon(stat), Some(1_073_741_824));
        assert_eq!(parse_anon("file 5\n"), None);
    }
}
