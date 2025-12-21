# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
