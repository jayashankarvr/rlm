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

`scripts/demo-memory-pressure.sh` puts the desktop under memory pressure so rlm-guard can be recorded stepping in. It refuses to run unless rlm-guard is active. It starts a python3 memory hog as you, in its own scope (`rlm-demo-hog-<pid>.scope` under `app.slice`) so the guard sees it as an app of its own. The hog grows by 200 MB a second until available memory is just below the guard's trigger (read from `rlm guard status`, 20% of RAM by default), holds for up to 60 seconds, then exits and frees its memory. It never goes below the guard's floor plus 1 GB, `timeout -s KILL` ends the hog after 240 seconds whatever happens, and Ctrl+C stops it at once. `--help` lists the options.

1. Save your work and close anything you would mind being paused.
2. Start the screen recorder. On GNOME, Ctrl+Shift+Alt+R starts and stops a screencast (saved in `~/Videos/Screencasts`).
3. Run `scripts/demo-memory-pressure.sh` and confirm. Watch for the "Python3 paused" notification and the Guard page in rlm-gtk.
4. Stop the recording once the script says the hog stopped.

## Reporting Issues

Please include:

- Linux distribution and kernel version
- Rust version
- Output of `rlm doctor`
- Steps to reproduce
- Expected vs actual behavior
