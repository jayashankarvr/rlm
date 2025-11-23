use crate::{CpuLimit, IoLimit, Limit, MemoryLimit, Result};

/// Build a Limit from optional string values
pub fn build_limit(
    memory: Option<&str>,
    cpu: Option<&str>,
    io_read: Option<&str>,
    io_write: Option<&str>,
) -> Result<Limit> {
    let memory = memory
        .filter(|s| !s.is_empty())
        .map(MemoryLimit::parse)
        .transpose()?;

    let cpu = cpu
        .filter(|s| !s.is_empty())
        .map(CpuLimit::parse)
        .transpose()?;

    let read_bps = io_read
        .filter(|s| !s.is_empty())
        .map(IoLimit::parse_bps)
        .transpose()?;

    let write_bps = io_write
        .filter(|s| !s.is_empty())
        .map(IoLimit::parse_bps)
        .transpose()?;

    let io = if read_bps.is_some() || write_bps.is_some() {
        Some(IoLimit {
            read_bps,
            write_bps,
        })
    } else {
        None
    };

    // Note: Zero validation happens at parse time in MemoryLimit/CpuLimit/IoLimit

    Ok(Limit { memory, cpu, io })
}

/// Format bytes as human-readable string
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1}T", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}
