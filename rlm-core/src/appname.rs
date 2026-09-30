//! Friendly app names for people: "Google Chrome" for `chrome`, "Claude"
//! for a versioned binary named `2.1.284`, "Firefox" for `firefox`.
//!
//! The GUI, the CLI and the guard's notifications share these rules. The
//! installed desktop entries are read once per process, on first use, and
//! kept.

use std::collections::HashMap;
use std::sync::OnceLock;

/// A friendly name for an app key (an exe basename, or
/// `<basename>@<cgroup leaf>` as the guard uses for runtimes). In order: the
/// `Name` of an installed desktop entry that runs this program (`desktop`
/// maps program basename to name), else the process name `comm` when the
/// basename has no letters (a versioned binary such as `2.1.283`), else the
/// basename with its first letter upper-cased. The `@leaf` suffix is never
/// shown.
pub fn display_name(key: &str, desktop: &HashMap<String, String>, comm: Option<&str>) -> String {
    let base = key.split('@').next().unwrap_or(key);
    let program = program_name(base, comm);
    if let Some(name) = desktop.get(program).or_else(|| desktop.get(base)) {
        return name.clone();
    }
    if program.is_empty() {
        return "An app".to_string();
    }
    let mut chars = program.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The name a program goes by: its executable basename `exe`, or the
/// process name `comm` when the basename has no letters (a versioned binary
/// such as `2.1.284` whose process calls itself `claude`).
pub fn program_name<'a>(exe: &'a str, comm: Option<&'a str>) -> &'a str {
    let has_letters = |s: &str| s.chars().any(char::is_alphabetic);
    match comm {
        Some(c) if !has_letters(exe) && has_letters(c) => c.trim(),
        _ => exe,
    }
}

/// Installed application names keyed by program basename, read from the
/// desktop entries on first use and cached for the life of the process.
pub fn desktop_names() -> &'static HashMap<String, String> {
    static NAMES: OnceLock<HashMap<String, String>> = OnceLock::new();
    NAMES.get_or_init(crate::desktop::names_by_program)
}

/// [`display_name`] of the program `exe` (a basename) whose process name is
/// `comm`, using the cached [`desktop_names`].
pub fn friendly_name(exe: &str, comm: Option<&str>) -> String {
    display_name(exe, desktop_names(), comm)
}

/// The executable basename of `pid`: the target of `/proc/<pid>/exe`
/// without the ` (deleted)` suffix, else the basename of the first
/// argument in `/proc/<pid>/cmdline`. `None` when neither can be read.
pub fn exe_of_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    if let Some(exe) = crate::guard::cgfs::exe_basename(pid).filter(|e| !e.is_empty()) {
        return Some(exe);
    }
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    argv0_basename(&cmdline)
}

/// Basename of the first NUL-separated argument of a raw cmdline.
fn argv0_basename(cmdline: &[u8]) -> Option<String> {
    let first = cmdline.split(|b| *b == 0).next()?;
    let first = std::str::from_utf8(first).ok()?;
    let base = first.rsplit('/').next()?.trim();
    (!base.is_empty()).then(|| base.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names() {
        let mut desktop = HashMap::new();
        desktop.insert("code".to_string(), "Visual Studio Code".to_string());
        desktop.insert("claude".to_string(), "Claude".to_string());
        assert_eq!(display_name("code", &desktop, None), "Visual Studio Code");
        assert_eq!(display_name("firefox", &desktop, None), "Firefox");
        assert_eq!(display_name("node@app-x.scope", &desktop, None), "Node");
        assert_eq!(
            display_name("python3@run-u12.service", &desktop, None),
            "Python3"
        );
        assert_eq!(
            display_name("2.1.283", &HashMap::new(), Some("claude")),
            "Claude"
        );
        assert_eq!(display_name("2.1.283", &desktop, Some("claude")), "Claude");
        assert_eq!(display_name("2.1.283", &desktop, None), "2.1.283");
        assert_eq!(
            display_name("firefox", &desktop, Some("Isolated Web Co")),
            "Firefox",
            "comm is only used when the basename has no letters"
        );
        assert_eq!(display_name("élan", &desktop, None), "Élan");
        assert_eq!(display_name("", &desktop, None), "An app");
    }

    #[test]
    fn program_names() {
        assert_eq!(program_name("chrome", Some("chrome")), "chrome");
        assert_eq!(
            program_name("gnome-calculator", Some("gnome-calculato")),
            "gnome-calculator"
        );
        assert_eq!(program_name("2.1.284", Some("claude")), "claude");
        assert_eq!(program_name("2.1.284", Some("1.0")), "2.1.284");
        assert_eq!(program_name("2.1.284", None), "2.1.284");
    }

    #[test]
    fn argv0_is_the_basename_of_the_first_argument() {
        assert_eq!(
            argv0_basename(b"/usr/bin/gnome-calculator\0--flag\0").as_deref(),
            Some("gnome-calculator")
        );
        assert_eq!(
            argv0_basename(b"python3\0x.py\0").as_deref(),
            Some("python3")
        );
        assert_eq!(argv0_basename(b""), None);
        assert_eq!(argv0_basename(b"\0"), None);
    }

    #[test]
    fn our_own_exe_is_found() {
        let me = exe_of_pid(std::process::id()).expect("own exe");
        assert!(!me.is_empty());
        assert_eq!(exe_of_pid(0), None);
    }
}
