use common::Result;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Desktop application entry
#[derive(Clone)]
pub struct DesktopApp {
    pub name: String,
    pub exec: String,
    pub is_cli: bool,
}

/// Directories searched for `.desktop` files: the system ones, then the
/// user's own.
fn desktop_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = [
        "/usr/share/applications",
        "/usr/local/share/applications",
        "/var/lib/flatpak/exports/share/applications",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    dirs.extend(dirs::data_dir().map(|d| d.join("applications")));
    dirs
}

/// Every shown application entry in [`desktop_dirs`].
fn desktop_entries() -> Vec<Entry> {
    let mut out = Vec::new();
    for dir in desktop_dirs() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "desktop") {
                    if let Some(e) = read_entry(&path) {
                        out.push(e);
                    }
                }
            }
        }
    }
    out
}

/// List installed applications from .desktop files
pub fn list_applications() -> Result<Vec<DesktopApp>> {
    let mut apps: Vec<DesktopApp> = desktop_entries()
        .into_iter()
        .filter_map(|e| {
            Some(DesktopApp {
                exec: exec_command(&e.exec)?,
                name: e.name,
                is_cli: false,
            })
        })
        .collect();
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps.dedup_by(|a, b| a.name == b.name);
    Ok(apps)
}

/// Installed application names, from the desktop entries.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DesktopNames {
    /// By the basename of the program an entry's `Exec` runs (`firefox` to
    /// `Firefox`). See [`names_from_entries`].
    pub programs: HashMap<String, String>,
    /// By the directory an app is installed in (`/opt/google/chrome` to
    /// `Google Chrome`), for a process whose program no entry runs by name.
    /// See [`dirs_from_entries`].
    pub dirs: HashMap<PathBuf, String>,
}

/// The installed applications' [`DesktopNames`].
pub fn installed_names() -> DesktopNames {
    let entries = desktop_entries();
    DesktopNames {
        programs: names_from_entries(&entries),
        dirs: dirs_from_entries(&entries, resolve_program, dirs::home_dir().as_deref()),
    }
}

/// Program basename to app name, from `entries`. Entries that run an
/// interpreter or launcher, or that pass arguments launching something else
/// (a web app, a game shortcut, a terminal command), are skipped: their
/// `Name` is not the program's. When the remaining entries for one program
/// disagree on the name, only those whose file stem or `StartupWMClass`
/// matches the program count; if they still disagree, the program gets no
/// name here.
fn names_from_entries(entries: &[Entry]) -> HashMap<String, String> {
    let mut by_program: HashMap<String, Vec<&Entry>> = HashMap::new();
    for e in entries {
        let Some(program) = own_program(e) else {
            continue;
        };
        let program = basename(&program);
        if !program.is_empty() {
            by_program.entry(program).or_default().push(e);
        }
    }
    let mut names = HashMap::new();
    for (program, entries) in by_program {
        let name = single_name(entries.iter().copied()).or_else(|| {
            single_name(
                entries
                    .iter()
                    .copied()
                    .filter(|e| entry_matches(e, &program)),
            )
        });
        if let Some(name) = name {
            names.insert(program, name);
        }
    }
    names
}

/// App install directory to app name, from `entries`: the directory of the
/// file each entry's program really is, as `resolve` finds it (following
/// symlinks, so `/usr/bin/google-chrome-stable` gives `/opt/google/chrome`).
/// The entries [`names_from_entries`] skips are skipped here too. A
/// directory many apps share (see [`is_shared_dir`]) is left out, and so is
/// one whose entries disagree on the name.
fn dirs_from_entries(
    entries: &[Entry],
    resolve: impl Fn(&str) -> Option<PathBuf>,
    home: Option<&Path>,
) -> HashMap<PathBuf, String> {
    let mut by_dir: HashMap<PathBuf, Vec<&Entry>> = HashMap::new();
    for e in entries {
        let Some(file) = own_program(e).and_then(|p| resolve(&p)) else {
            continue;
        };
        let Some(dir) = file.parent() else {
            continue;
        };
        if !is_shared_dir(dir, home) {
            by_dir.entry(dir.to_path_buf()).or_default().push(e);
        }
    }
    by_dir
        .into_iter()
        .filter_map(|(dir, entries)| Some((dir, single_name(entries.into_iter())?)))
        .collect()
}

/// The file an Exec program really is, symlinks followed: a path as it
/// stands, a bare name as found on `PATH`.
fn resolve_program(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        return fs::canonicalize(program).ok();
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .filter_map(|dir| fs::canonicalize(dir.join(program)).ok())
        .find(|file| file.is_file())
}

/// Whether `dir` holds the programs of many apps, so living there says
/// nothing about which app a program belongs to: the bin and library
/// directories of the system and of the user (`home`), and the like.
fn is_shared_dir(dir: &Path, home: Option<&Path>) -> bool {
    const SHARED: &[&str] = &[
        "/",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/opt",
        "/usr/bin",
        "/usr/sbin",
        "/usr/games",
        "/usr/lib",
        "/usr/lib32",
        "/usr/lib64",
        "/usr/libexec",
        "/usr/share",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/local/games",
        "/usr/local/lib",
        "/usr/local/libexec",
        "/snap/bin",
        "/var/lib/flatpak/exports/bin",
        "/app/bin",
        "/run/current-system/sw/bin",
    ];
    const SHARED_IN_HOME: &[&str] = &[
        "",
        "bin",
        ".local/bin",
        ".cargo/bin",
        ".nix-profile/bin",
        ".local/share/flatpak/exports/bin",
    ];
    if SHARED.iter().any(|s| dir == Path::new(s)) {
        return true;
    }
    // Multiarch library directories such as /usr/lib/x86_64-linux-gnu.
    let multiarch = dir
        .parent()
        .is_some_and(|p| p == Path::new("/usr/lib") || p == Path::new("/lib"))
        && dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.contains("-linux-"));
    multiarch || home.is_some_and(|h| SHARED_IN_HOME.iter().any(|s| dir == h.join(s)))
}

/// The program an entry runs, as its `Exec` names it (past an `env`
/// wrapper). `None` for an entry that runs an interpreter or launcher, or
/// passes arguments launching something else (a web app, a game shortcut,
/// a terminal command): its `Name` is not the program's.
fn own_program(e: &Entry) -> Option<String> {
    let args = exec_args(&e.exec)?;
    let program = program_arg(&args)?;
    if is_launcher(&basename(program)) || args.iter().any(|a| launches_something_else(a)) {
        return None;
    }
    Some(program.to_string())
}

/// The one name all `entries` share, `None` if there are none or several.
fn single_name<'a>(entries: impl Iterator<Item = &'a Entry>) -> Option<String> {
    let mut names = entries.map(|e| e.name.as_str());
    let first = names.next()?;
    names.all(|n| n == first).then(|| first.to_string())
}

/// Whether an entry is the program's own: its file stem (or the last part
/// of a reverse-DNS stem such as `org.mozilla.firefox`) or its
/// `StartupWMClass` is the program name, ignoring case.
fn entry_matches(e: &Entry, program: &str) -> bool {
    let stem = e.stem.to_lowercase();
    let program = program.to_lowercase();
    stem == program
        || stem.rsplit('.').next() == Some(program.as_str())
        || e.wm_class
            .as_deref()
            .is_some_and(|c| c.eq_ignore_ascii_case(&program))
}

/// An Exec argument that makes the program open some other app or a URL:
/// a browser web app, a Steam or Lutris game, or a terminal command.
fn launches_something_else(arg: &str) -> bool {
    arg == "-e"
        || arg.starts_with("--app-id")
        || arg.starts_with("--app=")
        || arg.starts_with("--application-mode")
        || arg.starts_with("steam://")
        || arg.starts_with("lutris:")
}

/// Interpreters and launchers: an entry that runs one of these names some
/// other app, so its `Name` must not label every process of that program.
fn is_launcher(program: &str) -> bool {
    const EXACT: &[&str] = &[
        "sh",
        "bash",
        "dash",
        "zsh",
        "fish",
        "env",
        "java",
        "node",
        "nodejs",
        "electron",
        "flatpak",
        "snap",
        "gjs",
        "gjs-console",
        "perl",
        "ruby",
        "php",
        "mono",
        "dotnet",
        "wine",
        "wine64",
        "xdg-open",
        "gio",
    ];
    EXACT.contains(&program) || program.starts_with("python")
}

/// The basename of the program a raw desktop file `Exec` value runs, looking
/// past an `env VAR=value` wrapper. `None` if there is none.
pub fn exec_program(value: &str) -> Option<String> {
    program_of(&exec_args(value)?)
}

/// A raw desktop file `Exec` value split into arguments, field codes
/// removed. `None` when a quote is left open.
fn exec_args(value: &str) -> Option<Vec<String>> {
    Some(
        split_exec(&unescape_value(value))?
            .into_iter()
            .filter_map(expand_field_codes)
            .collect(),
    )
}

/// The basename of the program `args` run, past an `env` wrapper.
fn program_of(args: &[String]) -> Option<String> {
    let base = basename(program_arg(args)?);
    (!base.is_empty()).then_some(base)
}

/// The last part of a path, the whole of it when it has no `/`.
fn basename(program: &str) -> String {
    program.rsplit('/').next().unwrap_or(program).to_string()
}

/// The program `args` run as they name it, past an `env` wrapper.
fn program_arg(args: &[String]) -> Option<&str> {
    let mut args = args.iter();
    let mut program = args.next()?;
    if program == "env" {
        program = loop {
            let arg = args.next()?;
            match arg.as_str() {
                "-u" | "--unset" | "-C" | "--chdir" => {
                    args.next();
                }
                "--" => break args.next()?,
                a if a.starts_with('-') || a.contains('=') => {}
                _ => break arg,
            }
        };
    }
    Some(program.as_str())
}

/// A shown application entry: its `Name`, raw `Exec` value, file name
/// without `.desktop`, and `StartupWMClass`.
struct Entry {
    name: String,
    exec: String,
    stem: String,
    wm_class: Option<String>,
}

/// Read the `[Desktop Entry]` group of one file. `None` for a hidden entry,
/// a non-application, or one without a usable `Name` and `Exec`.
fn read_entry(path: &Path) -> Option<Entry> {
    let content = fs::read_to_string(path).ok()?;
    let mut name = None;
    let mut exec = None;
    let mut wm_class = None;
    let mut no_display = false;
    let mut in_desktop_entry = false;

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with('[') {
            in_desktop_entry = line == "[Desktop Entry]";
            continue;
        }

        if !in_desktop_entry {
            continue;
        }

        if let Some(value) = line.strip_prefix("Name=") {
            if name.is_none() && !value.trim().is_empty() {
                name = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("Exec=") {
            if exec.is_none() && exec_command(value).is_some() {
                exec = Some(value.to_string());
            }
        } else if let Some(value) = line.strip_prefix("StartupWMClass=") {
            wm_class = Some(value.trim().to_string());
        } else if line == "NoDisplay=true" || line == "Hidden=true" {
            no_display = true;
        } else if line.starts_with("Type=") && line != "Type=Application" {
            return None;
        }
    }

    if no_display {
        return None;
    }

    Some(Entry {
        name: name?,
        exec: exec?,
        stem: path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default(),
        wm_class,
    })
}

/// Turn a desktop file `Exec` value into a shell-quoted command line: field
/// codes (%u, %F, ...) removed and each argument quoted when it holds spaces
/// or shell characters, so a shell-style split gives back the same
/// arguments. An `env VAR=value app` wrapper is kept whole, with `env` as
/// the program, so the app still gets its variables. `None` if nothing is
/// left, an `env` wrapper names no program, or a quote is not closed.
pub fn exec_command(value: &str) -> Option<String> {
    let args = split_exec(&unescape_value(value))?;
    let args: Vec<String> = args.into_iter().filter_map(expand_field_codes).collect();
    if args.is_empty() {
        return None;
    }
    if args[0] == "env" && !env_runs_a_program(&args[1..]) {
        return None;
    }
    Some(
        args.iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Whether the arguments after `env` name a program to run, rather than only
/// settings (`VAR=value`, `-u NAME`, `-i`, ...), in which case `env` would
/// just print the environment.
fn env_runs_a_program(args: &[String]) -> bool {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // These take the next argument as their value.
            "-u" | "--unset" | "-C" | "--chdir" => {
                args.next();
            }
            // The string holds the command line itself.
            "-S" | "--split-string" => return args.next().is_some(),
            "--" => return args.next().is_some(),
            a if a.starts_with("-S") && a.len() > 2 => return true,
            a if a.starts_with('-') => {}
            a if a.contains('=') => {}
            _ => return true,
        }
    }
    false
}

/// Undo the escapes every desktop file string value may use: \s, \n, \t,
/// \r and \\.
fn unescape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Split an Exec value into arguments. Double quotes group an argument;
/// inside them a backslash escapes `"`, `` ` ``, `$` and `\`. `None` when
/// a quote is left open.
fn split_exec(value: &str) -> Option<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_arg = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                in_arg = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => match chars.next()? {
                            e @ ('"' | '`' | '$' | '\\') => current.push(e),
                            other => {
                                current.push('\\');
                                current.push(other);
                            }
                        },
                        other => current.push(other),
                    }
                }
            }
            c if c.is_whitespace() => {
                if in_arg {
                    args.push(std::mem::take(&mut current));
                    in_arg = false;
                }
            }
            c => {
                in_arg = true;
                current.push(c);
            }
        }
    }
    if in_arg {
        args.push(current);
    }
    Some(args)
}

/// Remove field codes from one argument: an argument that is only a code
/// (such as %U) is dropped, `%%` becomes `%`, and codes inside an argument
/// are removed.
fn expand_field_codes(arg: String) -> Option<String> {
    if arg.len() == 2 && arg.starts_with('%') && arg != "%%" {
        return None;
    }
    let mut out = String::with_capacity(arg.len());
    let mut chars = arg.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
        } else if let Some(next) = chars.next() {
            if next == '%' {
                out.push('%');
            }
        }
    }
    Some(out)
}

/// Quote `arg` for a POSIX shell-style split, leaving plain words as they
/// are.
fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if plain {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// Search PATH for executables matching a query
pub fn search_cli_apps(query: &str) -> Vec<DesktopApp> {
    if query.len() < 2 {
        return Vec::new();
    }

    let query_lower = query.to_lowercase();
    let mut apps = Vec::new();

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let dir_path = Path::new(dir);
            if let Ok(entries) = fs::read_dir(dir_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if !name.to_lowercase().contains(&query_lower) {
                        continue;
                    }

                    // Check if executable
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() && (meta.permissions().mode() & 0o111 != 0) {
                            apps.push(DesktopApp {
                                name: format!("{} (CLI)", name),
                                // Quoted, since a file name may hold spaces or
                                // shell characters and the command is split
                                // like a shell line.
                                exec: shell_quote(&name),
                                is_cli: true,
                            });
                        }
                    }
                }
            }
        }
    }

    apps.sort_by(|a, b| a.name.cmp(&b.name));
    apps.dedup_by(|a, b| a.exec == b.exec);
    apps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_drops_field_codes_and_keeps_arguments() {
        assert_eq!(exec_command("firefox %u").as_deref(), Some("firefox"));
        assert_eq!(
            exec_command("code --new-window %F").as_deref(),
            Some("code --new-window")
        );
        assert_eq!(
            exec_command("app --pct=100%%").as_deref(),
            Some("app --pct=100%")
        );
        assert_eq!(
            exec_command("app --file=%f").as_deref(),
            Some("app --file=")
        );
    }

    #[test]
    fn exec_keeps_quoted_arguments_together() {
        assert_eq!(
            exec_command(r#""/opt/My App/app" --flag %U"#).as_deref(),
            Some("'/opt/My App/app' --flag")
        );
        assert_eq!(
            exec_command(r#"sh -c "echo hi; sleep 1""#).as_deref(),
            Some("sh -c 'echo hi; sleep 1'")
        );
        // Inside quotes a backslash escapes ", `, $ and \. The file itself
        // writes a backslash as \\, so \\\\ in the file is one backslash.
        assert_eq!(
            exec_command(r#"app "say \\"hi\\"" "c:\\\\dir""#).as_deref(),
            Some(r#"app 'say "hi"' 'c:\dir'"#)
        );
        assert_eq!(
            exec_command("app \"it's\"").as_deref(),
            Some(r"app 'it'\''s'")
        );
        // \s is unescaped before splitting, so it separates words.
        assert_eq!(exec_command(r"my\sapp").as_deref(), Some("my app"));
    }

    #[test]
    fn exec_keeps_env_wrappers_and_their_variables() {
        assert_eq!(
            exec_command("env FOO=1 BAR=\"a b\" app --x %f").as_deref(),
            Some("env FOO=1 'BAR=a b' app --x")
        );
        assert_eq!(
            exec_command("env -u GTK_THEME app").as_deref(),
            Some("env -u GTK_THEME app")
        );
        assert_eq!(
            exec_command("env -i -- app").as_deref(),
            Some("env -i -- app")
        );
        assert_eq!(exec_command("env -u X"), None);
        assert_eq!(exec_command("env -i"), None);
    }

    #[test]
    fn cli_app_names_are_quoted() {
        assert_eq!(shell_quote("my tool"), "'my tool'");
        assert_eq!(shell_quote("rg"), "rg");
        assert_eq!(shell_quote("a$b"), "'a$b'");
    }

    #[test]
    fn exec_rejects_empty_or_unterminated_lines() {
        assert_eq!(exec_command("%U"), None);
        assert_eq!(exec_command("   "), None);
        assert_eq!(exec_command("env A=1"), None);
        assert_eq!(exec_command(r#"app "open"#), None);
    }

    #[test]
    fn exec_program_is_the_basename_past_env() {
        assert_eq!(exec_program("firefox %u").as_deref(), Some("firefox"));
        assert_eq!(
            exec_program("/usr/bin/google-chrome-stable %U").as_deref(),
            Some("google-chrome-stable")
        );
        assert_eq!(
            exec_program(r#""/opt/My App/app" --flag"#).as_deref(),
            Some("app")
        );
        assert_eq!(
            exec_program("env FOO=1 -u X /snap/bin/code --new-window").as_deref(),
            Some("code")
        );
        assert_eq!(exec_program("env -i -- app").as_deref(), Some("app"));
        assert_eq!(exec_program("env A=1"), None);
        assert_eq!(exec_program("%U"), None);
    }

    #[test]
    fn an_empty_name_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.desktop");
        fs::write(&path, "[Desktop Entry]\nType=Application\nName=\nExec=x\n").unwrap();
        assert!(read_entry(&path).is_none());
        fs::write(&path, "[Desktop Entry]\nType=Application\nName=X\nExec=x\n").unwrap();
        assert_eq!(read_entry(&path).map(|e| e.name).as_deref(), Some("X"));
    }

    fn entry(stem: &str, name: &str, exec: &str, wm_class: Option<&str>) -> Entry {
        Entry {
            name: name.into(),
            exec: exec.into(),
            stem: stem.into(),
            wm_class: wm_class.map(Into::into),
        }
    }

    #[test]
    fn a_single_entry_names_its_program() {
        let names = names_from_entries(&[entry("firefox", "Firefox", "firefox %u", None)]);
        assert_eq!(names.get("firefox").map(String::as_str), Some("Firefox"));
        let names = names_from_entries(&[entry(
            "org.mozilla.firefox",
            "Firefox",
            "/usr/bin/firefox %u",
            None,
        )]);
        assert_eq!(names.get("firefox").map(String::as_str), Some("Firefox"));
    }

    #[test]
    fn a_web_app_does_not_rename_its_browser() {
        let names = names_from_entries(&[
            entry(
                "chrome-abc-Default",
                "YouTube",
                "/usr/bin/chromium --profile-directory=Default --app-id=abc",
                None,
            ),
            entry("chromium", "Chromium", "/usr/bin/chromium %U", None),
        ]);
        assert_eq!(names.get("chromium").map(String::as_str), Some("Chromium"));
        let names = names_from_entries(&[entry(
            "chrome-abc-Default",
            "YouTube",
            "chromium --app=https://youtube.com",
            None,
        )]);
        assert_eq!(names.get("chromium"), None);
    }

    #[test]
    fn a_game_shortcut_does_not_rename_steam() {
        let names = names_from_entries(&[
            entry("Hades", "Hades", "steam steam://rungameid/1145360", None),
            entry("steam", "Steam", "/usr/bin/steam %U", None),
        ]);
        assert_eq!(names.get("steam").map(String::as_str), Some("Steam"));
    }

    #[test]
    fn a_terminal_command_does_not_rename_the_terminal() {
        let names = names_from_entries(&[
            entry("btop", "btop++", "kitty -e btop", None),
            entry("kitty", "kitty", "kitty", None),
        ]);
        assert_eq!(names.get("kitty").map(String::as_str), Some("kitty"));
        assert_eq!(names.get("btop"), None, "btop is not what runs");
    }

    #[test]
    fn disagreeing_entries_need_a_matching_stem_or_class() {
        let names = names_from_entries(&[
            entry("code", "Visual Studio Code", "/usr/bin/code %F", None),
            entry("my-project", "My Project", "/usr/bin/code /home/me/p", None),
        ]);
        assert_eq!(
            names.get("code").map(String::as_str),
            Some("Visual Studio Code")
        );
        let names = names_from_entries(&[
            entry("a", "A", "tool", Some("Tool")),
            entry("b", "B", "tool", None),
        ]);
        assert_eq!(names.get("tool").map(String::as_str), Some("A"));
        let names =
            names_from_entries(&[entry("a", "A", "tool", None), entry("b", "B", "tool", None)]);
        assert_eq!(names.get("tool"), None, "still ambiguous");
    }

    /// A fake filesystem: where each Exec program really is.
    fn resolver(files: &[(&str, &str)]) -> impl Fn(&str) -> Option<PathBuf> {
        let files: HashMap<String, PathBuf> = files
            .iter()
            .map(|(p, f)| (p.to_string(), PathBuf::from(f)))
            .collect();
        move |program| files.get(program).cloned()
    }

    #[test]
    fn an_app_is_indexed_by_the_directory_its_program_leads_to() {
        let resolve = resolver(&[
            (
                "/usr/bin/google-chrome-stable",
                "/opt/google/chrome/google-chrome",
            ),
            (
                "/opt/google/chrome/google-chrome",
                "/opt/google/chrome/google-chrome",
            ),
            ("firefox", "/usr/lib/firefox/firefox"),
        ]);
        let entries = [
            entry(
                "google-chrome",
                "Google Chrome",
                "/usr/bin/google-chrome-stable %U",
                None,
            ),
            // A web app runs the same program; it must not claim the
            // directory (nor make it ambiguous).
            entry(
                "chrome-abc-Default",
                "YouTube",
                "/opt/google/chrome/google-chrome --profile-directory=Default --app-id=abc",
                None,
            ),
            entry("firefox", "Firefox", "firefox %u", None),
            entry("ghost", "Ghost", "/usr/bin/ghost", None),
        ];
        let dirs = dirs_from_entries(&entries, &resolve, None);
        assert_eq!(
            dirs.get(Path::new("/opt/google/chrome"))
                .map(String::as_str),
            Some("Google Chrome")
        );
        assert_eq!(
            dirs.get(Path::new("/usr/lib/firefox")).map(String::as_str),
            Some("Firefox")
        );
        assert_eq!(
            dirs.len(),
            2,
            "an unresolved program adds nothing: {dirs:?}"
        );
    }

    #[test]
    fn a_directory_claimed_by_different_apps_is_dropped() {
        let resolve = resolver(&[
            ("/usr/bin/writer", "/opt/suite/program/soffice"),
            ("/usr/bin/calc", "/opt/suite/program/soffice"),
            ("/usr/bin/tool", "/opt/tool/tool"),
            ("/usr/local/bin/tool", "/opt/tool/tool"),
        ]);
        let dirs = dirs_from_entries(
            &[
                entry("writer", "Writer", "/usr/bin/writer", None),
                entry("calc", "Calc", "/usr/bin/calc", None),
                // The same app installed twice (a system and a user entry)
                // agrees on the name, so it stays.
                entry("tool", "Tool", "/usr/bin/tool", None),
                entry("tool", "Tool", "/usr/local/bin/tool", None),
            ],
            &resolve,
            None,
        );
        assert_eq!(dirs.get(Path::new("/opt/suite/program")), None);
        assert_eq!(
            dirs.get(Path::new("/opt/tool")).map(String::as_str),
            Some("Tool")
        );
    }

    #[test]
    fn shared_bin_directories_and_launchers_are_not_indexed() {
        let home = Path::new("/home/u");
        let resolve = resolver(&[
            ("gedit", "/usr/bin/gedit"),
            ("/snap/bin/spotify", "/usr/bin/snap"),
            ("mytool", "/home/u/.local/bin/mytool"),
            ("python3", "/usr/bin/python3.12"),
            ("/opt/app/run.sh", "/opt/app/run.sh"),
        ]);
        let dirs = dirs_from_entries(
            &[
                entry("gedit", "Text Editor", "gedit %U", None),
                entry("spotify", "Spotify", "/snap/bin/spotify %U", None),
                entry("mytool", "My Tool", "mytool", None),
                entry("game", "Game", "python3 /opt/game/main.py", None),
                entry("app", "App", "sh /opt/app/run.sh", None),
            ],
            &resolve,
            Some(home),
        );
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[test]
    fn shared_directories() {
        let home = Some(Path::new("/home/u"));
        for dir in [
            "/usr/bin",
            "/bin",
            "/usr/local/bin",
            "/usr/games",
            "/snap/bin",
            "/var/lib/flatpak/exports/bin",
            "/usr/lib",
            "/usr/libexec",
            "/usr/lib/x86_64-linux-gnu",
            "/opt",
            "/home/u",
            "/home/u/bin",
            "/home/u/.local/bin",
            "/home/u/.local/bin/",
        ] {
            assert!(is_shared_dir(Path::new(dir), home), "{dir}");
        }
        for dir in [
            "/opt/google/chrome",
            "/usr/lib/firefox",
            "/usr/share/code",
            "/home/u/apps/tool",
            "/home/v/.local/bin",
        ] {
            assert!(!is_shared_dir(Path::new(dir), home), "{dir}");
        }
        assert!(!is_shared_dir(Path::new("/home/u/.local/bin"), None));
    }

    #[test]
    fn interpreters_do_not_take_an_apps_name() {
        assert!(is_launcher("python3.14"));
        assert!(is_launcher("flatpak"));
        assert!(!is_launcher("firefox"));
    }
}
