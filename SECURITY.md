# Security

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting Vulnerabilities

Don't open a public issue. Email the maintainer (see Cargo.toml).

Include:

- What's vulnerable
- Steps to reproduce
- Impact
- Fix if you have one

## Security Notes

### Permissions

rlm writes to cgroups, so it needs either root or systemd cgroup delegation.

No credentials are stored.

### File Access

- Configs loaded from `/etc/rlm/` and `~/.config/rlm/`
- 1MB size limit on config files
- Cgroup writes only go to `/sys/fs/cgroup/rlm/`

### Input Handling

- Cgroup names sanitized against path traversal
- Numeric limits are bounds-checked
- YAML parsing has size limits (billion-laughs protection)
