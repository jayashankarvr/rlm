# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-26

### Upgrading from 0.1

- rlm-guard 0.1 applied caps as runtime systemd unit properties. The drop-ins it left under `/run` (a cap value, or `infinity` after a restore) can be re-applied by a `systemctl --user daemon-reload` or `set-property` until the next reboot. Reboot once after upgrading to clear them.
- After upgrading the binaries, restart the guard so the new version runs: `systemctl --user restart rlm-guard`.
- The 0.1 .deb installed `/etc/systemd/system/user@.service.d/delegate.conf`; 0.2 installs `rlm-delegate.conf` with the same content. The old file may remain after the upgrade and is safe to delete (then run `sudo systemctl daemon-reload`).
- Config files are now parsed strictly. A config that 0.1 accepted with unknown keys or out-of-range guard values is now an error; `rlm doctor` and `rlm guard status` name the problem.

### Changed

- rlm-guard acts when apps under app.slice are stalling on memory and available memory is below 20% of RAM (new `guard.trigger.act_below_available_pct`), or at once when available memory is below the 400 MB floor, with or without a stall. Stalls inside a cgroup rlm limited are ignored.
- rlm-guard picks the app whose memory grows fastest, treats all cgroups of one app as one, holds at most 3 apps, and waits at least 3 seconds after a partial action.
- Soft caps never ask for more than 10% of an app's current memory, have a 256 MiB floor, and account for hosts without swap. Caps and restores no longer change systemd unit properties.
- Invalid config files are errors: unknown keys and out-of-range guard values are rejected, and rlm-guard exits with status 78 instead of running on defaults.
- rlm-guard scans only your own processes, and only under pressure or every 5 seconds while persistent rules exist. It rewrites rule limits only when needed.
- Sizes accept decimals and B/iB suffixes (1.5G, 512MB, 2GiB); memory limits below 8M and I/O limits below 64K/s are rejected; profile names are case-insensitive; `--profile` values can be overridden by explicit flags.
- Logs go to stderr, without color when not on a terminal. The default level is WARN for rlm and INFO for rlm-guard; `RUST_LOG` overrides it.
- `rlm status` is read-only.
- Packages: crates.io `rlmctl` (binaries rlm and rlm-guard), `rlmctl-core`, `rlmctl-common`; the delegation drop-in is `rlm-delegate.conf`.
- Building from source or from crates.io needs Rust 1.87 or newer (the zbus release in use requires it).

### Added

- `rlm guard history`, the GUI Guard page, and service state in `rlm guard status`.
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
