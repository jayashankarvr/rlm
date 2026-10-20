# Contributing

## Setup

1. Clone the repository
2. Install Rust 1.87 or newer
3. For the GUI, install the GTK4 and libadwaita development headers (Debian/Ubuntu: `libgtk-4-dev libadwaita-1-dev pkg-config`)
4. Build: `cargo build --workspace`

## Project Structure

```text
rlm/
├── cli/        # package rlmctl: binaries rlm and rlm-guard
├── rlm-core/   # package rlmctl-core: cgroup management and the guard
├── common/     # package rlmctl-common: shared types and config
├── gtk-gui/    # package rlm-gtk: GTK4/libadwaita GUI (not on crates.io)
├── harness/    # memory-pressure test harness (not published)
├── dist/       # delegation drop-in, deb/rpm scripts, AUR PKGBUILD
└── scripts/    # check-docs.sh and other maintainer scripts
```

## Gate

Every commit must pass:

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
scripts/check-docs.sh
```

`scripts/check-docs.sh` checks the README and APPLICATION_LIMITING.md against the code (profile names, drop-in name, required sections). The test `cli/tests/doc_config_examples.rs` parses every YAML example in README.md and CLAUDE.md under the strict config rules, so keep those examples valid.

Tests that touch real cgroups are `#[ignore]` and opt-in. They create `test-*` and `run-*` cgroups under rlm's base and transient systemd scopes (`systemd-run --scope`), and remove what they create before returning. No test may freeze, cap, limit, signal or move a process it did not start itself.

## Code Style

- Keep changes focused and minimal
- Comments, docs and CLI text are plain prose: no em-dashes, arrows, marketing words or emoji. CLI output is ASCII.
- Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `build:`, `ci:`, `chore:`

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure CI passes (build, test, clippy, fmt, check-docs)
5. Submit a pull request

## Release checklist (maintainers)

1. Bump `version` in the workspace `Cargo.toml` (and the path dependency versions in `[workspace.dependencies]`), `dist/aur/PKGBUILD` `pkgver`, and add the CHANGELOG section.
2. Run the gate and `scripts/check-docs.sh`.
3. Tag and push: `git tag -a vX.Y.Z -m "rlm X.Y.Z"` and `git push origin main vX.Y.Z`. Check that the release workflow attached the .deb and .rpm packages, the tarball and `SHA256SUMS`. Its `apt` job then adds the .deb files to the apt repository on the `gh-pages` branch (served at https://jayashankarvr.github.io/rlm), signed with the `APT_SIGNING_KEY` secret. To republish a tag, run the Apt repository workflow by hand with that tag. The signing key's offline backup is kept by the maintainer; if it is ever replaced, update `dist/apt/` and the fingerprint in README.
4. Publish to crates.io in dependency order, waiting for each to appear in the index:
   `cargo publish -p rlmctl-common`, then `cargo publish -p rlmctl-core`, then `cargo publish -p rlmctl`.
5. AUR: the tag tarball must exist first. In `dist/aur`, run `updpkgsums` to replace `sha256sums=('SKIP')` with the real checksum, then `makepkg --printsrcinfo > .SRCINFO`, build in a clean chroot, and push `PKGBUILD`, `rlm.install` and `.SRCINFO` to the AUR.
6. Copy the CHANGELOG section into the GitHub release notes.

## Recording a demo

`scripts/demo-memory-pressure.sh` puts the desktop under memory pressure so rlm-guard can be recorded stepping in. It refuses to run unless rlm-guard is active. It starts a python3 memory hog as you, in its own scope (`rlm-demo-hog-<pid>.scope` under `app.slice`) so the guard sees it as an app of its own. The hog grows by 200 MB a second until available memory is just below the guard's trigger (read from `rlm guard status`, 20% of RAM by default), holds for up to 60 seconds, then exits and frees its memory. It never goes below the guard's floor plus 1 GB, `timeout -s KILL` ends the hog after 240 seconds (later if the guard has it paused at that moment; the kill lands once it is resumed), and Ctrl+C stops it at once. While it holds, the hog keeps writing to its memory so the kernel has to work for room. `--help` lists the options.

1. Save your work and close anything you would mind being paused.
2. Start the screen recorder. On GNOME, press Print Screen and pick the video camera (saved in `~/Videos/Screencasts`); Ctrl+Shift+Alt+R also works but may stop after 30 seconds.
3. Run `scripts/demo-memory-pressure.sh` and confirm. Watch for the "Python3.10 paused" notification (the name follows your Python version) and the Guard page in rlm-gtk.
4. Stop the recording once the script says the hog stopped.

Memory being short is not enough for the guard: it also waits for apps to stall on memory, and a machine with spare cache, zram or fast swap rarely stalls at the trigger. So next to the hog the script runs a small stall helper in its own scope (`rlm-demo-stall-<pid>.scope`) with `MemoryHigh` set to `--stall-mb` (128 MB by default, at most 128) and swap off. It stays under the guard's `min_rss_mb` (200 MB), so the guard never pauses the helper instead of the hog. It keeps allocating past that limit, the kernel throttles it almost all the time, and that throttling counts as a memory stall in `app.slice`, the pressure the guard reads. It starts only once available memory is below the trigger, so the guard acts within seconds, and it runs for at most 15 seconds, less if the session's memory pressure passes 40%: systemd-oomd, on by default in Ubuntu and Fedora, kills the cgroup reclaiming the most memory (it may be your terminal) once that pressure has stayed above 50% for 20 seconds. The floor plus 1 GB still holds with the helper's memory counted. `--stall-mb 0` turns the helper off.

The scene ends as soon as the guard pauses or caps the hog: the script stops the stall helper, leaves the notification up for 3 seconds from the moment the guard acts (so rlm-gtk, which refreshes every 2 seconds, lists the frozen hog), then ends its own hog so the memory is free before the guard's 5-second thaw (the default `freeze_hold_secs`; with a shorter one the guard may move on to your next app). Without that, memory would still be short at the thaw and the guard would move on to your next-largest app, because each python3 scope is an app of its own to the guard. The guard itself never kills anything; the terminal says when the script ends its hog.

## Reporting Issues

Please include:

- Linux distribution and kernel version
- Rust version
- Output of `rlm doctor`
- Steps to reproduce
- Expected vs actual behavior
