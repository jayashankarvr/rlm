//! Friendly app names for people: "Google Chrome" for `chrome`, "Claude"
//! for a versioned binary named `2.1.284`, "Firefox" for `firefox`.
//!
//! The GUI, the CLI and the guard's notifications share these rules. The
//! installed desktop entries are read once per process, on first use, and
//! kept.

pub use crate::desktop::DesktopNames;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// A friendly name for an app key (an exe basename, or
/// `<basename>@<cgroup leaf>` as the guard uses for runtimes). In order: the
/// `Name` of an installed desktop entry that runs this program, else of the
/// app installed in `exe_dir` (the directory of the process's executable;
/// not for an interpreter or runtime such as `java`, which runs any app),
/// else the process name `comm` when the basename has no letters (a
/// versioned binary such as `2.1.283`), else the basename with its first
/// letter upper-cased. The `@leaf` suffix is never shown.
pub fn display_name(
    key: &str,
    desktop: &DesktopNames,
    comm: Option<&str>,
    exe_dir: Option<&Path>,
) -> String {
    let base = key.split('@').next().unwrap_or(key);
    let program = program_name(base, comm);
    let name = desktop
        .programs
        .get(program)
        .or_else(|| desktop.programs.get(base))
        .or_else(|| {
            let runtime = crate::desktop::is_launcher(program);
            exe_dir
                .filter(|_| !runtime)
                .and_then(|d| desktop.dirs.get(d))
        });
    if let Some(name) = name {
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

static NAMES: OnceLock<DesktopNames> = OnceLock::new();

/// Installed application names, read from the desktop entries on first use
/// and cached for the life of the process. The first call waits for the
/// read.
pub fn desktop_names() -> &'static DesktopNames {
    NAMES.get_or_init(crate::desktop::installed_names)
}

/// The cached [`desktop_names`] if they have been read, without waiting:
/// `None` until the first [`desktop_names`] call has finished.
pub fn loaded_desktop_names() -> Option<&'static DesktopNames> {
    NAMES.get()
}

/// [`display_name`] of the program `exe` (a basename, run from `exe_dir`)
/// whose process name is `comm`, using the cached [`desktop_names`]. Never
/// waits for them: until they are read, the name falls back to the basename
/// rules.
pub fn friendly_name(exe: &str, comm: Option<&str>, exe_dir: Option<&Path>) -> String {
    let desktop = loaded_desktop_names();
    display_name(
        exe,
        desktop.unwrap_or(&DesktopNames::default()),
        comm,
        exe_dir,
    )
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

/// The directory of the executable of `pid`, from `/proc/<pid>/exe`.
pub fn exe_dir_of_pid(pid: u32) -> Option<PathBuf> {
    if pid == 0 {
        return None;
    }
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    exe.parent().map(Path::to_path_buf)
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

    use std::collections::HashMap;

    fn programs(pairs: &[(&str, &str)]) -> DesktopNames {
        DesktopNames {
            programs: pairs
                .iter()
                .map(|(p, n)| (p.to_string(), n.to_string()))
                .collect(),
            dirs: HashMap::new(),
        }
    }

    #[test]
    fn display_names() {
        let desktop = programs(&[("code", "Visual Studio Code"), ("claude", "Claude")]);
        let none = DesktopNames::default();
        let name = |key: &str, desktop: &DesktopNames, comm| display_name(key, desktop, comm, None);
        assert_eq!(name("code", &desktop, None), "Visual Studio Code");
        assert_eq!(name("firefox", &desktop, None), "Firefox");
        assert_eq!(name("node@app-x.scope", &desktop, None), "Node");
        assert_eq!(name("python3@run-u12.service", &desktop, None), "Python3");
        assert_eq!(name("2.1.283", &none, Some("claude")), "Claude");
        assert_eq!(name("2.1.283", &desktop, Some("claude")), "Claude");
        assert_eq!(name("2.1.283", &desktop, None), "2.1.283");
        assert_eq!(
            name("firefox", &desktop, Some("Isolated Web Co")),
            "Firefox",
            "comm is only used when the basename has no letters"
        );
        assert_eq!(name("élan", &desktop, None), "Élan");
        assert_eq!(name("", &desktop, None), "An app");
    }

    #[test]
    fn an_app_is_named_by_its_install_directory_after_its_program() {
        // google-chrome.desktop runs /usr/bin/google-chrome-stable, which
        // leads to /opt/google/chrome; the browser process is .../chrome.
        let mut desktop = programs(&[
            ("google-chrome-stable", "Google Chrome"),
            ("chrome-tool", "Chrome Tool"),
        ]);
        desktop
            .dirs
            .insert(PathBuf::from("/opt/google/chrome"), "Google Chrome".into());
        let chrome = Some(Path::new("/opt/google/chrome"));
        assert_eq!(
            display_name("chrome", &desktop, Some("chrome"), chrome),
            "Google Chrome"
        );
        assert_eq!(
            display_name("chrome_crashpad_handler", &desktop, None, chrome),
            "Google Chrome"
        );
        assert_eq!(
            display_name("chrome-tool", &desktop, None, chrome),
            "Chrome Tool",
            "a program's own entry comes first"
        );
        assert_eq!(display_name("chrome", &desktop, None, None), "Chrome");
        // A runtime's directory names no app, even if an entry claimed it.
        desktop.dirs.insert(
            PathBuf::from("/usr/lib/jvm/java-17/bin"),
            "OpenJDK 17 Monitoring & Management Console".into(),
        );
        let jvm = Some(Path::new("/usr/lib/jvm/java-17/bin"));
        assert_eq!(display_name("java", &desktop, Some("java"), jvm), "Java");
        assert_eq!(
            display_name(
                "electron30",
                &desktop,
                None,
                Some(Path::new("/opt/google/chrome"))
            ),
            "Electron30"
        );
        assert_eq!(
            display_name("chrome", &desktop, None, Some(Path::new("/opt/other"))),
            "Chrome"
        );
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
