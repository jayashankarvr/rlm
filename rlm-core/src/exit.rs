//! How a command launched under limits ended, shared by the CLI and GUI.

/// The conventional name of a signal number, or a generic description.
pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        32..=64 => "a real-time signal",
        _ => "an unknown signal",
    }
}

/// (exit code for the caller, messages without a "rlm:" prefix)
///
/// A normal exit keeps its code; a signal death becomes 128 + the signal
/// number, capped at 255; anything else is 1. Messages say which signal
/// ended the command and whether the memory limit made the kernel kill
/// processes in the cgroup.
pub fn exit_report(
    code: Option<i32>,
    signal: Option<i32>,
    oom_kills: u64,
    memory_max: Option<u64>,
) -> (u8, Vec<String>) {
    let exit = code
        .map(|c| (c & 0xff) as u8)
        .or_else(|| signal.map(|s| (128 + s).clamp(0, 255) as u8))
        .unwrap_or(1);
    let mut messages = Vec::new();
    if let Some(s) = signal {
        messages.push(format!(
            "the command was killed by signal {s} ({})",
            signal_name(s)
        ));
    }
    if oom_kills > 0 {
        let limit = memory_max
            .map(common::format_bytes)
            .unwrap_or_else(|| "memory.max".to_string());
        let noun = if oom_kills == 1 {
            "process"
        } else {
            "processes"
        };
        messages.push(format!(
            "the memory limit ({limit}) was reached; the kernel killed {oom_kills} {noun} in this cgroup"
        ));
    }
    (exit, messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    const M150: u64 = 150 * 1024 * 1024;

    #[test]
    fn exit_codes_and_messages() {
        assert_eq!(exit_report(Some(0), None, 0, None), (0, vec![]));
        assert_eq!(exit_report(Some(3), None, 0, None), (3, vec![]));
        let (code, msgs) = exit_report(None, Some(9), 1, Some(M150));
        assert_eq!(code, 137);
        assert_eq!(msgs[0], "the command was killed by signal 9 (SIGKILL)");
        assert_eq!(
            msgs[1],
            "the memory limit (150.0M) was reached; the kernel killed 1 process in this cgroup"
        );
        let (code, msgs) = exit_report(Some(1), None, 2, Some(M150));
        assert_eq!(code, 1);
        assert_eq!(msgs, vec!["the memory limit (150.0M) was reached; the kernel killed 2 processes in this cgroup".to_string()]);
        assert_eq!(exit_report(None, Some(15), 0, None).0, 143);
        assert_eq!(exit_report(None, None, 0, None).0, 1);
    }

    #[test]
    fn unknown_signals_have_a_generic_name() {
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(40), "a real-time signal");
    }
}
