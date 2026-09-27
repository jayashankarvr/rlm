use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// A memory limit below this is rejected: a process cannot start, let alone
/// make progress, in less than 8 MiB.
pub const MIN_MEMORY_BYTES: u64 = 8 * 1024 * 1024;

/// An I/O bandwidth limit below this is rejected: below 64 KiB/s a process
/// cannot make meaningful progress.
pub const MIN_IO_BPS: u64 = 64 * 1024;

/// Parse a byte size: optional decimal fraction, optional unit K/M/G/T with
/// an optional "B" or "iB" suffix, case-insensitive, all binary multiples.
/// A bare number is bytes.
pub fn parse_size(input: &str) -> Result<u64> {
    let s = input.trim();
    let bad = || Error::InvalidMemory(s.to_string());
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        _ => return Err(bad()),
    };
    if num.is_empty() || num.starts_with('.') || num.ends_with('.') || num.matches('.').count() > 1
    {
        return Err(bad());
    }
    let overflow = || Error::InvalidMemory("value too large (overflow)".into());
    let bytes = match num.split_once('.') {
        None => num
            .parse::<u64>()
            .map_err(|_| bad())?
            .checked_mul(mult)
            .ok_or_else(overflow)?,
        Some((whole, frac)) => {
            let whole: u64 = whole.parse().map_err(|_| bad())?;
            let digits = frac.len().min(9);
            let frac_val: u128 = frac[..digits].parse().map_err(|_| bad())?;
            let frac_bytes = (frac_val * u128::from(mult) / 10u128.pow(digits as u32)) as u64;
            whole
                .checked_mul(mult)
                .and_then(|w| w.checked_add(frac_bytes))
                .ok_or_else(overflow)?
        }
    };
    if bytes == 0 {
        return Err(Error::InvalidMemory("value cannot be zero".into()));
    }
    Ok(bytes)
}

/// Resource limits to apply to a process
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Limit {
    pub memory: Option<MemoryLimit>,
    pub cpu: Option<CpuLimit>,
    pub io: Option<IoLimit>,
}

impl Limit {
    /// True if none of memory, cpu or io carry a value.
    pub fn is_empty(&self) -> bool {
        self.memory.is_none() && self.cpu.is_none() && self.io.is_none_or(|io| io.is_empty())
    }

    /// Overlay explicit `over` values on top of `self` (e.g. a profile),
    /// field by field; io read/write bandwidth overlay independently.
    pub fn overlay(self, over: &Limit) -> Limit {
        let io = match (self.io, over.io) {
            (Some(a), Some(b)) => Some(IoLimit {
                read_bps: b.read_bps.or(a.read_bps),
                write_bps: b.write_bps.or(a.write_bps),
            }),
            (a, b) => b.or(a),
        };
        Limit {
            memory: over.memory.or(self.memory),
            cpu: over.cpu.or(self.cpu),
            io,
        }
    }
}

/// I/O bandwidth limit in bytes per second
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct IoLimit {
    /// Read bandwidth limit (bytes/sec)
    pub read_bps: Option<u64>,
    /// Write bandwidth limit (bytes/sec)
    pub write_bps: Option<u64>,
}

impl IoLimit {
    pub fn parse_bps(s: &str) -> Result<u64> {
        let bytes = parse_size(s)?;
        if bytes < MIN_IO_BPS {
            return Err(Error::InvalidMemory(format!(
                "{} per second is below the 64K minimum",
                s.trim()
            )));
        }
        Ok(bytes)
    }

    pub fn is_empty(&self) -> bool {
        self.read_bps.is_none() && self.write_bps.is_none()
    }
}

/// Memory limit in bytes
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MemoryLimit(u64);

impl MemoryLimit {
    pub fn bytes(self) -> u64 {
        self.0
    }

    /// Parse human-readable memory string (e.g., "2G", "512M", "1.5GiB").
    /// Rejects values below the 8 MiB floor: a process cannot run in less.
    pub fn parse(s: &str) -> Result<Self> {
        let bytes = parse_size(s)?;
        if bytes < MIN_MEMORY_BYTES {
            return Err(Error::InvalidMemory(format!(
                "{} is below the 8M minimum; a process cannot run in less",
                s.trim()
            )));
        }
        Ok(Self(bytes))
    }
}

/// CPU limit as percentage (0-100 per core, can exceed 100 for multiple cores)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CpuLimit(u32);

impl CpuLimit {
    pub fn percent(self) -> u32 {
        self.0
    }

    /// Parse CPU percentage string (e.g., "50%", "150%")
    /// Maximum is 10000% (100 cores)
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim().trim_end_matches('%');
        let percent: u32 = s.parse().map_err(|_| Error::InvalidCpu(s.into()))?;
        if percent == 0 {
            return Err(Error::InvalidCpu("value cannot be zero".into()));
        }
        if percent > 10000 {
            return Err(Error::InvalidCpu(
                "value too large (max 10000% = 100 cores)".into(),
            ));
        }
        Ok(Self(percent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_table() {
        let mib = 1024 * 1024u64;
        let ok: &[(&str, u64)] = &[
            ("4096", 4096),
            ("1K", 1024),
            ("512M", 512 * mib),
            ("512MB", 512 * mib),
            ("512 MB", 512 * mib),
            ("512MiB", 512 * mib),
            ("2g", 2048 * mib),
            ("2GiB", 2048 * mib),
            ("1.5G", 1536 * mib),
            ("0.5g", 512 * mib),
            ("  8m  ", 8 * mib),
            ("1T", 1024 * 1024 * mib),
        ];
        for (s, want) in ok {
            assert_eq!(parse_size(s).unwrap(), *want, "{s}");
        }
        for s in [
            "",
            "abc",
            "-1G",
            "1e3M",
            "1..5G",
            ".5G",
            "5.G",
            "0",
            "0M",
            "12X",
            "999999999999999999T",
        ] {
            assert!(parse_size(s).is_err(), "{s:?} should be rejected");
        }
    }

    #[test]
    fn memory_limits_have_a_floor() {
        assert!(MemoryLimit::parse("1K").is_err());
        assert!(MemoryLimit::parse("4M").is_err());
        assert_eq!(MemoryLimit::parse("8M").unwrap().bytes(), MIN_MEMORY_BYTES);
        let e = MemoryLimit::parse("1024").unwrap_err().to_string();
        assert!(e.contains("8M"), "{e}");
    }

    #[test]
    fn io_limits_have_a_floor() {
        assert!(IoLimit::parse_bps("1K").is_err());
        assert_eq!(IoLimit::parse_bps("64K").unwrap(), MIN_IO_BPS);
    }

    #[test]
    fn explicit_values_override_profile_values() {
        let profile = crate::build_limit(Some("512M"), Some("25%"), Some("10M"), None).unwrap();
        let flags = crate::build_limit(Some("1G"), None, None, Some("5M")).unwrap();
        let l = profile.overlay(&flags);
        assert_eq!(l.memory.unwrap().bytes(), 1024 * 1024 * 1024);
        assert_eq!(l.cpu.unwrap().percent(), 25);
        let io = l.io.unwrap();
        assert_eq!(
            (io.read_bps, io.write_bps),
            (Some(10 * 1024 * 1024), Some(5 * 1024 * 1024))
        );
    }

    #[test]
    fn parse_memory_overflow() {
        // Value too large for u64
        assert!(MemoryLimit::parse("999999999999999999T").is_err());
    }

    #[test]
    fn parse_cpu_percent() {
        assert_eq!(CpuLimit::parse("50%").unwrap().percent(), 50);
        assert_eq!(CpuLimit::parse("150").unwrap().percent(), 150);
        assert_eq!(CpuLimit::parse("  75%  ").unwrap().percent(), 75);
    }

    #[test]
    fn parse_cpu_errors() {
        assert!(CpuLimit::parse("abc").is_err());
        assert!(CpuLimit::parse("-50%").is_err());
    }

    #[test]
    fn io_limit_is_empty() {
        let empty = IoLimit::default();
        assert!(empty.is_empty());

        let with_read = IoLimit {
            read_bps: Some(1000),
            write_bps: None,
        };
        assert!(!with_read.is_empty());

        let with_write = IoLimit {
            read_bps: None,
            write_bps: Some(1000),
        };
        assert!(!with_write.is_empty());
    }

    #[test]
    fn parse_io_bps() {
        assert_eq!(IoLimit::parse_bps("100M").unwrap(), 100 * 1024 * 1024);
        assert_eq!(IoLimit::parse_bps("1G").unwrap(), 1024 * 1024 * 1024);
    }
}
