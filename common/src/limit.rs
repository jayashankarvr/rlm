use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Resource limits to apply to a process
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Limit {
    pub memory: Option<MemoryLimit>,
    pub cpu: Option<CpuLimit>,
    pub io: Option<IoLimit>,
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
        // Reuse memory parsing logic - same units work for bandwidth
        MemoryLimit::parse(s).map(|m| m.bytes())
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

    /// Parse human-readable memory string (e.g., "2G", "512M", "1024K")
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::InvalidMemory("empty value".into()));
        }

        let (num_str, multiplier) = match s.chars().last() {
            Some('K' | 'k') => (&s[..s.len() - 1], 1024u64),
            Some('M' | 'm') => (&s[..s.len() - 1], 1024 * 1024),
            Some('G' | 'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
            Some('T' | 't') => (&s[..s.len() - 1], 1024 * 1024 * 1024 * 1024),
            Some(c) if c.is_ascii_digit() => (s, 1),
            _ => return Err(Error::InvalidMemory(s.into())),
        };

        let num: u64 = num_str
            .parse()
            .map_err(|_| Error::InvalidMemory(s.into()))?;

        if num == 0 {
            return Err(Error::InvalidMemory("value cannot be zero".into()));
        }

        let bytes = num
            .checked_mul(multiplier)
            .ok_or_else(|| Error::InvalidMemory("value too large (overflow)".into()))?;

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
    fn parse_memory_units() {
        assert_eq!(MemoryLimit::parse("1024").unwrap().bytes(), 1024);
        assert_eq!(MemoryLimit::parse("1K").unwrap().bytes(), 1024);
        assert_eq!(MemoryLimit::parse("1k").unwrap().bytes(), 1024);
        assert_eq!(MemoryLimit::parse("1M").unwrap().bytes(), 1024 * 1024);
        assert_eq!(MemoryLimit::parse("1m").unwrap().bytes(), 1024 * 1024);
        assert_eq!(
            MemoryLimit::parse("2G").unwrap().bytes(),
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(
            MemoryLimit::parse("1T").unwrap().bytes(),
            1024 * 1024 * 1024 * 1024
        );
    }

    #[test]
    fn parse_memory_with_whitespace() {
        assert_eq!(
            MemoryLimit::parse("  512M  ").unwrap().bytes(),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn parse_memory_errors() {
        assert!(MemoryLimit::parse("").is_err());
        assert!(MemoryLimit::parse("abc").is_err());
        assert!(MemoryLimit::parse("-1G").is_err());
        assert!(MemoryLimit::parse("0M").is_err()); // zero not allowed
        assert!(MemoryLimit::parse("0").is_err()); // zero not allowed
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
