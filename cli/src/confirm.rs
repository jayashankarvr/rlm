//! Confirmation for batch operations (multiple processes at once). Kept pure
//! (no direct stdin/stdout/TTY access) so it is fully testable: the caller
//! decides interactivity and supplies the input/output streams.

use std::io::{BufRead, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum Confirm {
    /// Fewer than 2 targets, `--yes` was given, or the user answered yes.
    Proceed,
    /// The user answered no (or EOF) at an interactive prompt.
    Cancelled,
    /// A batch of 2+ targets with no `--yes` and no terminal to prompt on.
    NeedsYes,
}

/// Decide whether a batch action on `pids` may proceed. A single target
/// never needs confirmation. Two or more do, unless `yes` is set; when
/// stdin is not a terminal there is nothing to prompt, so that case is
/// reported as `NeedsYes` instead of silently proceeding or hanging.
pub fn confirm_batch(
    pids: &[u32],
    action: &str,
    yes: bool,
    interactive: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Confirm {
    if pids.len() <= 1 || yes {
        return Confirm::Proceed;
    }
    if !interactive {
        return Confirm::NeedsYes;
    }

    let _ = writeln!(out, "Found {} processes:", pids.len());
    for pid in pids.iter().take(10) {
        let name = std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "?".to_string());
        let _ = writeln!(out, "  {pid}: {name}");
    }
    if pids.len() > 10 {
        let _ = writeln!(out, "  ... and {} more", pids.len() - 10);
    }
    let _ = write!(out, "{action} all {} processes? [y/N] ", pids.len());
    let _ = out.flush();

    let mut line = String::new();
    if input.read_line(&mut line).unwrap_or(0) == 0 {
        // EOF: nothing typed, treat like a "no".
        return Confirm::Cancelled;
    }
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Confirm::Proceed,
        _ => Confirm::Cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(pids: &[u32], yes: bool, interactive: bool, typed: &str) -> Confirm {
        let mut input = std::io::Cursor::new(typed.as_bytes().to_vec());
        let mut out = Vec::new();
        confirm_batch(pids, "Limit", yes, interactive, &mut input, &mut out)
    }

    #[test]
    fn single_pid_needs_no_confirmation() {
        assert_eq!(run(&[10], false, false, ""), Confirm::Proceed);
    }

    #[test]
    fn non_interactive_batch_without_yes_needs_yes() {
        assert_eq!(run(&[10, 11], false, false, "y\n"), Confirm::NeedsYes);
    }

    #[test]
    fn yes_flag_skips_the_prompt() {
        assert_eq!(run(&[10, 11], true, false, ""), Confirm::Proceed);
    }

    #[test]
    fn interactive_answers() {
        assert_eq!(run(&[10, 11], false, true, "y\n"), Confirm::Proceed);
        assert_eq!(run(&[10, 11], false, true, "YES\n"), Confirm::Proceed);
        assert_eq!(run(&[10, 11], false, true, "n\n"), Confirm::Cancelled);
        assert_eq!(
            run(&[10, 11], false, true, ""),
            Confirm::Cancelled,
            "EOF cancels"
        );
    }
}
