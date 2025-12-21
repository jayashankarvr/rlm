# rlm - Resource Limit Manager

A Linux tool for managing process resource limits using cgroups v2. Available as both CLI and GUI.

## Features

- Limit memory, CPU, and I/O bandwidth for running processes
- Run commands with resource limits applied
- Named profiles for reusable limit configurations
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
# By PID
rlm limit --pid 1234 --memory 512M --cpu 50%

# By name (limits all matching processes)
rlm limit --name firefox --memory 2G

# With I/O limits
rlm limit --pid 1234 --memory 1G --io-read 50M --io-write 20M
```

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
