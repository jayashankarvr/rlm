# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- New app icon in grey, white and black instead of blue. The README hero image uses it too.

### Fixed

- README: a memory limit turns swap off so the app does not thrash swap at its limit, and past it the kernel's OOM killer ends a process in it; the old wording said "does not thrash the disk" and "the kernel stops it".
- `scripts/demo-memory-pressure.sh`: an option given without a value prints usage instead of a bash error, values with a leading zero (`08`) are read as decimal, and the `--hold` error says "more than 5 seconds shorter".

## [0.2.7] - 2026-09-30

### Changed

- The desktop app shows apps by their menu name: "Calculator" instead of "gnome-calculato", and "Claude" with its version number underneath instead of "2.1.285". Limit Running search matches both names.
- `rlm status` shows the full program name (up to 24 characters) instead of the kernel's 15-character process name.
- Process counts read "1 process" and "N processes" in the desktop app and `rlm status`.
- The README and website open with a screenshot of the desktop app, and the README explains when to use rlm instead of `systemd-run`, earlyoom or systemd-oomd.

### Fixed

- Desktop app: after switching pages with Ctrl+1 to Ctrl+5 or a page button, keyboard focus moves to the new page's sidebar row, so the focus ring no longer stays on Managed Processes.
- The "could not be resumed" notification now also closes when the app is no longer paused, not only when it exits.

### Added

- `scripts/demo-memory-pressure.sh`: a gradual, capped memory hog for recording the guard at work. It refuses to run unless the guard is active and stops by itself after 4 minutes.

## [0.2.6] - 2026-09-29

### Fixed

- The guard keeps its lock, journal and history in `$XDG_RUNTIME_DIR` only when that directory is yours and not writable by others.
- When the guard cannot resume a paused app, its notification says "<App> could not be resumed" instead of disappearing. It closes once the app is released, exits or the guard stops.
- `rlm guard enable` checks the path of `rlm-guard` only when it is about to write a user unit, so a packaged or custom unit is no longer refused.
- `rlm limit --save` with an invalid config file now fails before applying any limit, instead of applying and then failing to save the rule.
- A rule is no longer saved for an app whose program name is only a version number (such as `2.1.283`), because it would stop matching after an update. The CLI refuses `--save` before acting; the desktop app applies the limits and says why no rule was saved.
- Desktop app: when turning the guard on or off takes too long, the `systemctl` it started is stopped too.
- Desktop app: after Undo on a limit started from Launch New, the cgroup is removed once its processes exit, instead of staying behind empty.
- Desktop app and website: the guard's policy says "available memory", like the CLI.

## [0.2.5] - 2026-09-28

### Changed

- Guard notifications say what happened to which app: "Firefox paused" when the guard freezes an app, updated in place to "Firefox slowed down" if it caps it, and cleared on their own once the app is released or the guard stops. They carry rlm's name and icon and use the app's name from its menu entry where one clearly matches.
- Notifications are sent only when the guard acts on an app. The old "memory pressure Warn" message is gone; an early "Memory is running low" warning is available with the new `guard.notify_pressure: true` (off by default).
- Notifications go through the desktop's notification service over D-Bus, on a background thread that never delays the guard, and reconnect if that service restarts. Without a session bus the guard falls back to `notify-send`.

### Added

- Desktop app, Guard page: switches for "Notify when an app is paused or slowed" and "Warn when memory runs low".
- The running guard picks up `guard.notify` and `guard.notify_pressure` changes without a restart, so apps it holds stay held.
- `rlm guard test --notify` shows sample notifications without touching any app.

## [0.2.4] - 2026-09-28

### Changed

- `rlm guard status` states when the guard acts in the same words as the desktop app: it steps in when apps stall and available memory is below 20%, or at once below 400 MB.
- Desktop app: the sidebar shows the name as rlm, the Limit Mode options are Whole app and Single process, and the About window is wider, shows "Version" before the number and links to the project website.

### Fixed

- Desktop app: the selected Limit Mode could be cut off at the default window width.

## [0.2.3] - 2026-09-28

A pass over the GUI for people who are not cgroup experts.

### Added

- Limit Running: select whole applications with a Select button on each row; the selection and the PID field always agree. Rows show process count and memory, largest first. Single-process apps are listed too.
- Limit Running and Launch New: the Apply Limits and Run Command button stays in a bar at the bottom of the window, Enter in a field submits, and the success message has an Open button that shows Managed Processes.
- Managed Processes: an empty page with buttons to get started, Undo after removing a limit (only for processes that are still the same ones, checked by start time), and Forget rule when a saved rule would bring the limit back.
- Profiles: the built-in presets are listed and marked Built-in, or Built-in, changed with a Restore button. New and Edit share one dialog that checks the values as you type.
- A menu with Keyboard Shortcuts and an About window, and a banner when resource limiting is unavailable (Apply and Run are then disabled).

### Changed

- Limit Running starts in Whole app (shared limit) mode; the other mode is Single process. Typing PIDs moved under Enter PIDs manually.
- Units: memory in MB or GB, I/O in KB/s, MB/s or GB/s, CPU as a percentage of one core, with the core count and minimums shown.
- Guard page in plain words. The pressure wording follows the guard's own policy, so it never reads calmer than the guard acts; the raw numbers are in a tooltip.
- The About page is gone from the sidebar; pages are Ctrl+1 to Ctrl+5.
- rlmctl-core: `group_by_executable` includes single-process apps and sorts by memory; `DesktopApp.exec` is a quoted command line that keeps `env` wrappers; new `guard::policy::rise_level`, `process::start_time` and `parse_start_time`.

### Fixed

- Choosing a profile replaces every limit field, and values such as 1.5G or 4GiB are shown exactly. The Edit Profile dialog saves fields you did not touch exactly as they were stored.
- Limit Running reloads processes when shown and skips any that exited or whose PID now belongs to another process, instead of limiting the wrong one.
- Errors name the field and are shown instead of failing silently (removing a limit, saving a profile).
- Launch New runs commands and desktop entries with quoted arguments correctly, and holding Enter launches once.
- Managed Processes and Guard update rows in place, so keyboard focus and scrolling survive the refresh.
- Process grouping read the wrong parent and session for processes whose name contains spaces.

## [0.2.2] - 2026-09-27

### Fixed

- GUI, Limit Running: selecting an application no longer merges its PIDs into one bogus PID (for example 2894 and 52896 became 289452896). The PID field keeps the comma-separated list, a long list is never cut inside a number, and a bad entry is reported instead of guessed.
- GUI: the Mode dropdown shows its value in full; switching modes clears the PID field; the space above Apply Limits and Run Command is back to normal; long text in search, command and profile name fields no longer crashes on non-ASCII characters.
- GUI, Guard page: the on/off switch is spaced from the status list, and the protected process list scrolls in its own box.
- GUI: "Also save as a rule for rlm-guard" says after saving whether to restart or turn on the guard, since rlm-guard loads rules when it starts.

### Changed

- GUI: every page's section descriptions and messages were rewritten to match what the app does. The placeholder Credits section is gone, and the About license notice covers 2025-2026.

## [0.2.1] - 2026-09-27

### Upgrading from 0.2.0

- cargo installs: rerun `rlm guard enable` to refresh your user unit (it adds `RestartPreventExitStatus=78 75`), then `systemctl --user restart rlm-guard`. Packaged installs get the new unit with the package.
- `rlm limit` now refuses to run while the config file is invalid, instead of silently using defaults and dropping your protect list. Fix the file, or pass `--force`.
- Guard config values now have upper bounds: `calm_hold_secs` and `freeze_cooldown_secs` at most 86400, `mem_available_floor_mb` and `min_rss_mb` at most 16 TiB. A config above them makes rlm-guard exit with status 78 until it is fixed.

### Fixed

- rlm-guard never keeps its lock, journal or history in a shared directory such as `/tmp`. It uses the per-user state directory, then `$XDG_RUNTIME_DIR/rlm`; with neither, it does not freeze or cap.
- A second rlm-guard exits with status 75 and systemd does not restart it every 2 seconds.
- The cold-start wait for growth data is bounded to 3 samples.
- Startup waits at most 2 seconds for the systemd bus, then restores through cgroupfs directly.
- Guard config arithmetic cannot overflow.
- `rlm guard enable`: `%` in the binary path is escaped, paths systemd cannot run are refused with a clear error, relative `PATH` entries are ignored, the unit is written atomically, and a masked unit is reported with the unmask command.
- GUI: the guard switch gives up after 30 seconds, the Run page removes a leftover cgroup once its processes exit (and stops retrying after a minute of failures), and the service state cache cannot deadlock.
- Packaging: the AUR package stops the guard on removal, the rpm keeps an edited `rlm-delegate.conf` on upgrade, and the deb has a short synopsis.
- crates.io: README links and the hero image resolve, and rlmctl-core and rlmctl-common have readmes.

### Changed

- Common terminal emulators and the tmux and screen multiplexers are on the built-in protect list.
- CI and release workflows use the Node 24 versions of their actions.

## [0.2.0] - 2026-09-26

### Upgrading from 0.1

- rlm-guard 0.1 applied caps as runtime systemd unit properties. The drop-ins it left under `/run` (a cap value, or `infinity` after a restore) can be re-applied by a `systemctl --user daemon-reload` or `set-property` until the next reboot. Reboot once after upgrading to clear them.
- cargo installs: 0.1 installed `rlm` and `rlm-guard` from cargo packages of the same names; in 0.2 both binaries belong to `rlmctl`, and cargo refuses to overwrite a binary owned by another package. Run `cargo uninstall rlm rlm-guard` first, then `cargo install rlmctl` (or `cargo install --path cli`).
- After upgrading the binaries, restart the guard so the new version runs: `systemctl --user restart rlm-guard`.
- The 0.1 .deb installed `/etc/systemd/system/user@.service.d/delegate.conf`; 0.2 installs `rlm-delegate.conf` with the same content. The old file may remain after the upgrade and is safe to delete (then run `sudo systemctl daemon-reload`).
- Config files are now parsed strictly. A config that 0.1 accepted with unknown keys or out-of-range guard values is now an error; `rlm doctor` and `rlm guard status` name the problem.

### Changed

- rlm-guard acts when apps under app.slice are stalling on memory and available memory is below 20% of RAM (new `guard.trigger.act_below_available_pct`), or at once when available memory is below the 400 MB floor, with or without a stall. Stalls inside a cgroup rlm limited are ignored.
- rlm-guard picks the app whose memory grows fastest, treats all cgroups of one app as one, holds at most 3 apps, and waits at least 3 seconds after a partial action.
- Soft caps never ask for more than 10% of an app's current memory, have a 256 MiB floor, and account for hosts without swap. Caps and restores no longer change systemd unit properties.
- Invalid config files are errors: unknown keys and out-of-range guard values are rejected, and rlm-guard exits with status 78 instead of running on defaults.
- rlm-guard scans only your own processes, and only under pressure, while available memory is scarce, or every 5 seconds while persistent rules exist. It rewrites rule limits only when needed.
- Sizes accept decimals and B/iB suffixes (1.5G, 512MB, 2GiB); memory limits below 8M and I/O limits below 64K/s are rejected; profile names are case-insensitive; `--profile` values can be overridden by explicit flags.
- Logs go to stderr, without color when not on a terminal. The default level is WARN for rlm and INFO for rlm-guard; `RUST_LOG` overrides it.
- `rlm status` is read-only.
- Packages: crates.io `rlmctl` (binaries rlm and rlm-guard), `rlmctl-core`, `rlmctl-common`; the delegation drop-in is `rlm-delegate.conf`.
- Building from source or from crates.io needs Rust 1.87 or newer (the zbus release in use requires it).

### Added

- `rlm guard history`, the GUI Guard page (with an on/off switch), and service state in `rlm guard status`.
- `rlm guard enable` installs a user unit pointing at your rlm-guard when no packaged unit exists.
- `--yes` for batch operations; `--force` to limit a process on the protect list.
- `rlm run` reports OOM kills and signal deaths and exits with 128+N for signal N.
- `rlm doctor` checks controller delegation, config validity and the guard binary, unit and service.
- AUR PKGBUILD, deb/rpm removal scripts, release workflow checks and checksums.

### Fixed

- `rlm run` no longer strips limits from processes a launcher leaves behind.
- io.max is written one device at a time; a failing device is a warning.
- A failed limit write no longer empties a cgroup that already existed.
- `rlm unlimit` reports when nothing was limited instead of claiming success, and released processes can be limited again.
- `rlm limit --save` without `--application` is rejected; other users' processes are refused.
- Non-interactive batch commands fail instead of printing "cancelled" and exiting 0.
- doctor, profiles, export, import and guard status work on hosts without cgroup v2 delegation.
- GUI: launched children are reaped, profile and group order is stable, icons exist in stock Adwaita, the sidebar follows keyboard shortcuts.

### Removed

- `OOMScoreAdjust` and `MemoryMin` from the user unit (a user manager cannot apply them usefully).

## [0.1.0] - 2025-12-23

### Added

- Memory, CPU, and I/O bandwidth limiting via cgroups v2
- Process management by PID or name
- `rlm run` command for launching processes with limits
- `rlm doctor` command for diagnosing setup issues
- `rlm export` and `rlm import` for profile portability
- `--dry-run` flag for previewing changes
- Built-in presets: Light, Medium, Heavy, Browser
- Batch confirmation when limiting multiple processes
- Named profiles via `~/.config/rlm/config.yaml`
- GUI with GTK4/Libadwaita
- Keyboard shortcuts (Ctrl+1-5 for pages, Ctrl+Q to quit)
- Refresh buttons on all pages
- Profile create/edit/delete in GUI
- Toast notifications for feedback
- .deb and .rpm packages with auto cgroup delegation setup
