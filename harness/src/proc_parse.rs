//! Pure parsers for the two `/proc` decomposition signals. No I/O here —
//! the probe loop does the (reused-buffer) reading and hands the string to
//! these functions.

/// Field 8 (0-indexed 7) of /proc/self/schedstat is time spent waiting on a
/// runqueue, in nanoseconds. Format: "<run_ns> <wait_ns> <timeslices>".
pub fn parse_schedstat_wait_ns(s: &str) -> Option<u64> {
    s.split_whitespace().nth(1)?.parse().ok()
}

/// Field 12 (1-indexed) of /proc/self/stat is majflt. The comm field may
/// contain spaces and parentheses — split after the LAST ')'.
pub fn parse_majflt(stat: &str) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    // After ')': state, ppid, pgrp, session, tty, tpgid, flags, minflt,
    // cminflt, majflt -> index 9 of this remainder.
    after.split_whitespace().nth(9)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedstat_takes_second_field() {
        assert_eq!(parse_schedstat_wait_ns("12345 67890 42\n"), Some(67890));
        assert_eq!(parse_schedstat_wait_ns("1 2 3"), Some(2));
        assert_eq!(parse_schedstat_wait_ns("only_one_field"), None);
        assert_eq!(parse_schedstat_wait_ns(""), None);
    }

    #[test]
    fn majflt_survives_parens_in_comm() {
        // comm can contain spaces AND parens: "(my (weird) proc)"
        let stat = "42 (my (weird) proc) S 1 42 42 0 -1 4194304 100 0 7 0 5 6 0 0 20 0 1 0 900";
        // After the last ')': fields are state(3) ppid(4) pgrp(5) session(6) tty(7)
        // tpgid(8) flags(9) minflt(10) cminflt(11) majflt(12) -> 7
        assert_eq!(parse_majflt(stat), Some(7));
    }

    #[test]
    fn majflt_simple_comm() {
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560 2000 100 3 0 10 20 0 0 20 0 1 0 5";
        assert_eq!(parse_majflt(stat), Some(3));
    }

    #[test]
    fn majflt_malformed_is_none() {
        assert_eq!(parse_majflt("no parens here"), None);
        assert_eq!(parse_majflt("1 (x) S 1"), None); // too few fields
    }
}
