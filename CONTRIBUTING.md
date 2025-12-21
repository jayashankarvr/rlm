# Contributing

## Setup

1. Clone the repository
2. Ensure you have Rust 1.85+ installed
3. Build: `cargo build --workspace`
4. Run tests: `cargo test --workspace`

## Project Structure

```bash
rlm/
├── cli/        # Command-line interface (rlm)
├── gtk-gui/    # Desktop GUI (GTK4/Libadwaita, rlm-gtk)
├── rlm-core/   # Core cgroup management logic
└── common/     # Shared types and utilities
```

## Code Style

- Run `cargo fmt` before committing
- Ensure `cargo clippy -- -D warnings` passes
- Keep changes focused and minimal

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure CI passes (build, test, clippy, fmt)
5. Submit a pull request

## Reporting Issues

Please include:

- Linux distribution and kernel version
- Rust version
- Steps to reproduce
- Expected vs actual behavior
