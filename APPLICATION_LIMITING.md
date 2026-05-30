# Application-Based Process Limiting

## Overview

rlm now supports limiting applications that spawn multiple processes. When you limit multiple processes together, they **share** the resource limits (combined pool), not per-process limits.

## How Shared Limits Work

In cgroups v2, when multiple processes are placed in the same cgroup, they share the resource limits:

- **Memory**: All processes share the total memory limit (e.g., 10 processes with 4GB limit = 4GB total, not 4GB each)
- **CPU**: All processes share the CPU quota (e.g., 10 processes with 100% limit = 100% total, not 100% each)
- **I/O**: All processes share the I/O bandwidth limits

This is useful for applications like browsers (Firefox, Chrome) that spawn many processes but should be treated as a single application.

## Usage Examples

### Limit All Processes of an Application

```bash
# Limit all Firefox processes to share 4GB memory and 75% CPU
rlm limit --application firefox --memory 4G --cpu 75%

# Limit all Chrome processes
rlm limit --application chrome --memory 6G --cpu 100%
```

### Limit Multiple Specific PIDs Together

```bash
# Limit specific PIDs to share resources
rlm limit --all-pids 1234,5678,9012 --memory 2G --cpu 50%
```

### Individual Process Limiting (Original Behavior)

```bash
# Each process gets its own limits (not shared)
rlm limit --pid 1234 --memory 1G --cpu 50%
rlm limit --name firefox --memory 1G --cpu 50%  # Each firefox process gets 1G
```

## Checking Status

The `rlm status` command now shows whether limits are shared or individual:

```bash
$ rlm status
PID      NAME                     MEMORY         CPU            I/O          TYPE
1234     firefox                  4.0G          75%         limited    shared (12 procs)
5678     chrome                  6.0G         100%         limited    shared (8 procs)
9012     myapp                   1.0G          50%         limited    individual
```

## Removing Limits

### Remove Application Limits

```bash
# Remove limits from all processes of an application
rlm unlimit --application firefox

# Or remove by cgroup name
rlm unlimit --cgroup app-firefox
```

### Remove Individual Process Limits

```bash
# Remove limits from a single process
rlm unlimit --pid 1234
```

## When to Use Shared vs Individual Limits

### Use Shared Limits (`--application` or `--all-pids`) When:
- ✅ Application spawns many processes (browsers, IDEs, etc.)
- ✅ You want to limit the application as a whole
- ✅ Processes are related and should share resources
- ✅ You want simpler management (one limit for all)

### Use Individual Limits (`--pid` or `--name`) When:
- ✅ Each process should have its own limit
- ✅ Processes are independent
- ✅ You need fine-grained control per process
- ✅ Processes have different resource needs

## Technical Details

### Cgroup Naming

- Individual limits: `pid-{PID}` (one cgroup per process)
- Application limits: `app-{application_name}` (one cgroup for all processes)
- Multiple PIDs: `multi-{first_pid}` (one cgroup for specified PIDs)

### Process Detection

The `--application` flag finds processes by:
1. Executable name (from `/proc/PID/exe`)
2. Process name (from `/proc/PID/comm`)

All matching processes are grouped together and share the same cgroup.

### Finding Application Processes

To see which processes would be affected:

```bash
# Dry run to see what would be limited
rlm limit --application firefox --memory 4G --dry-run
```

## Examples

### Example 1: Limit Firefox Browser

Firefox typically spawns 10-20 processes. Instead of limiting each individually:

```bash
# Old way (tedious, each process gets separate limits)
rlm limit --name firefox --memory 1G  # Each of 15 processes gets 1G = 15GB total!

# New way (all processes share limits)
rlm limit --application firefox --memory 4G --cpu 75%
# All 15 processes share 4GB total and 75% CPU total
```

### Example 2: Limit Development Environment

```bash
# Limit all processes of your IDE and related tools together
rlm limit --all-pids 1234,5678,9012 --memory 8G --cpu 200%
```

### Example 3: Mixed Approach

You can mix individual and shared limits:

```bash
# Limit main application processes together
rlm limit --application myapp --memory 4G

# But limit a specific worker process separately
rlm limit --pid 9999 --memory 2G --cpu 50%
```

## Troubleshooting

### Process Not Found

If `--application` doesn't find processes, check the executable name:

```bash
# Check what processes exist
ps aux | grep firefox

# Try with exact executable name
rlm limit --application firefox-bin --memory 4G
```

### Processes Already Limited

If processes are already in individual cgroups, you'll get an error. Remove individual limits first:

```bash
# Remove individual limits
rlm unlimit --name firefox

# Then apply shared limits
rlm limit --application firefox --memory 4G
```

## GUI Support

The GUI will be updated to show process groups and allow selecting all processes of an application with a single click. This feature is coming soon.

## FAQ

**Q: If I limit 10 processes to 4GB, do they get 4GB each or 4GB total?**  
A: They share 4GB total (combined pool).

**Q: Can I mix shared and individual limits?**  
A: Yes, but a process can only be in one cgroup at a time. Remove individual limits before applying shared limits.

**Q: What happens if a new process starts after limiting?**  
A: New processes are not automatically added. You need to re-run the limit command or use `--all-pids` with the new PID.

**Q: How do I see how many processes are in a shared cgroup?**  
A: Use `rlm status` - it shows the process count for shared cgroups.
