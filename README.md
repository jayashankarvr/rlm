# rlm - Resource Limit Manager

A Linux tool for managing process resource limits using cgroups v2. Available as both CLI and GUI.

## Features

- Limit memory, CPU, and I/O bandwidth for running processes
- Run commands with resource limits applied
- Named profiles for reusable limit configurations
- **Freeze guard**: a background daemon that proactively prevents system freezes
- Works with systemd cgroup delegation (no root required for user processes)

## Supported Distros

Any Linux with cgroups v2 and systemd:

| Distro              | Version |
|---------------------|---------|
| Ubuntu              | 22.04+  |
| Debian              | 12+     |
| Fedora              | 31+     |
| RHEL / Rocky / Alma | 9+      |
| Arch                | current |
| openSUSE Tumbleweed | current |

Older versions may work with `systemd.unified_cgroup_hierarchy=1` kernel boot param.

## Installation

### From packages (recommended)

Download from [Releases](https://github.com/jayashankarvr/rlm/releases):

```bash
# Debian/Ubuntu
sudo dpkg -i rlm_*.deb rlm-gtk_*.deb

# Fedora/RHEL
sudo rpm -i rlm-*.rpm rlm-gtk-*.rpm
```

### From source

```bash
cargo install --path cli
cargo install --path gtk-gui
./install-desktop.sh  # desktop entry and icon
```

## CLI Usage

### Limit a running process

```bash
# By PID (individual limit)
rlm limit --pid 1234 --memory 512M --cpu 50%

# By name (limits all matching processes individually)
rlm limit --name firefox --memory 2G

# By application (all processes share the same limit pool)
rlm limit --application firefox --memory 4G --cpu 75%
# Note: All Firefox processes share 4GB total, not 4GB each

# Multiple specific PIDs (share limits)
rlm limit --all-pids 1234,5678,9012 --memory 2G --cpu 50%

# With I/O limits
rlm limit --pid 1234 --memory 1G --io-read 50M --io-write 20M
```

**Important:** When using `--application` or `--all-pids`, all processes **share** the limits (combined pool). For example, 10 processes with 4GB limit = 4GB total shared among all, not 4GB each. See [APPLICATION_LIMITING.md](APPLICATION_LIMITING.md) for details.

### Run a command with limits

```bash
rlm run --memory 1G --cpu 100% -- ./my-program arg1 arg2

# Using a profile
rlm run --profile browser -- firefox
```

### Remove limits

```bash
rlm unlimit --pid 1234
rlm unlimit --name firefox
rlm unlimit --application firefox  # Remove shared application limits
rlm unlimit --cgroup app-firefox   # Remove by cgroup name
```

### View managed processes

```bash
rlm status
```

### List profiles

```bash
rlm profiles
```

### Diagnose setup issues

```bash
rlm doctor
```

### Export/import profiles

```bash
# Export profiles to a file
rlm export profiles.yaml

# Import profiles from a file
rlm import profiles.yaml
rlm import profiles.yaml --overwrite  # Replace existing
```

### Preview changes (dry-run)

```bash
rlm limit --pid 1234 --memory 512M --dry-run
```

## GUI Usage

Launch the GUI with:

```bash
rlm-gtk
```

Pages:

- **Status** - managed processes and their limits
- **Limit** - apply limits by PID or name
- **Run** - launch commands with limits
- **Profiles** - saved limit configurations
- **About** - version and license info

## Freeze Guard (automatic protection)

`rlm-guard` is an optional per-user daemon that watches system memory pressure
(via the kernel's PSI) and, before the machine locks up, proactively **freezes**
or soft-**caps** your biggest memory hog — healing itself once pressure clears.
It is recovery-only and **never kills** processes.

How it escalates as pressure rises: notify → briefly freeze the hog (≈5s circuit
breaker, then auto-thaw) → soft-cap it (`memory.high`, never an OOM-kill) → lift
everything automatically once memory is calm again. It only ever acts on *your*
processes and protects your desktop session, shells, and audio (configurable).

```bash
rlm guard enable    # enable + start the user service (systemctl --user)
rlm guard status    # current pressure + active interventions
rlm guard test      # dry-run: print what it would do right now (no action)
rlm guard disable   # stop and disable
```

Tunable under a `guard:` section in `~/.config/rlm/config.yaml` (all optional —
it works with zero configuration):

```yaml
guard:
  enabled: true
  trigger:   { psi_some_warn: 10, psi_some_high: 30, psi_full_critical: 10, mem_available_floor_mb: 400 }
  timing:    { freeze_hold_secs: 5, calm_hold_secs: 30, freeze_cooldown_secs: 60, sample_interval_ms: 1000 }
  selection: { min_rss_mb: 200, protect: [] }   # names here ADD to the built-in protect-list
  notify: true
```

Requires PSI (`/proc/pressure/memory`); run `rlm doctor` to verify.

## Configuration

Create `~/.config/rlm/config.yaml`:

```yaml
profiles:
  browser:
    memory: "4G"
    cpu: "200%"
  dev:
    memory: "8G"
    cpu: "400%"
    io_read: "100M"
    io_write: "50M"
```

### Built-in Presets

| Preset  | Memory | CPU  | I/O       |
|---------|--------|------|-----------|
| Light   | 512M   | 25%  | -         |
| Medium  | 2G     | 50%  | 50M/25M   |
| Heavy   | 4G     | 100% | 100M/50M  |
| Browser | 4G     | 75%  | -         |

Use with: `rlm run --profile Medium -- ./command`

## Cgroup Delegation (non-root usage)

The .deb and .rpm packages automatically configure cgroup delegation. Just log out and back in after installing.

For manual/source installs, enable delegation:

```bash
sudo mkdir -p /etc/systemd/system/user@.service.d
sudo tee /etc/systemd/system/user@.service.d/delegate.conf << EOF
[Service]
Delegate=cpu memory io
EOF
sudo systemctl daemon-reload
```

Then log out and back in. Run `rlm doctor` to verify.

## License

Apache 2.0
