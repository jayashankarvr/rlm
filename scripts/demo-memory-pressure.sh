#!/usr/bin/env bash
#
# Memory pressure demo for recording rlm-guard at work.
#
# Starts a memory hog as you, in its own transient scope under app.slice
# (rlm-demo-hog-<pid>.scope), so rlm-guard sees it as an app of its own. The
# hog grows by --step-mb every second until available memory is just below
# the guard's trigger (act_below_available_pct of RAM, read from
# `rlm guard status`, minus --margin-mb), holds there for up to --hold
# seconds, then exits and frees everything.
#
# Memory being short is not enough: the guard also waits for apps to stall
# on memory, and a machine with spare cache, zram or a fast swap rarely
# stalls at the trigger. So a small stall helper runs next to the hog in
# its own scope (rlm-demo-stall-<pid>.scope) with MemoryHigh=--stall-mb and
# swap off. It keeps allocating past that limit, the kernel throttles it
# almost all the time, and that throttling counts as a memory stall in
# app.slice, the pressure the guard reads. It starts only once available
# memory is below the trigger, so the guard acts within seconds, and runs
# for at most 15 s, less if the session's pressure nears systemd-oomd's
# limit (oomd kills the cgroup reclaiming the most memory after 20 s above
# 50%). It stays under the guard's min_rss_mb, so the guard never picks it.
# --stall-mb 0 turns it off.
#
# The scene ends as soon as the guard pauses or caps the hog: the script
# stops the stall helper, leaves the notification up for a few seconds,
# then ends its own hog so the memory is free before the guard's thaw.
# Otherwise memory would still be short when the hog is thawed, and the
# guard would move on to your next-largest app (each python3 scope is an
# app of its own to the guard). The guard itself never kills anything.
#
# Safety:
# - It refuses to run unless rlm-guard is active.
# - It never pushes available memory below the guard's floor
#   (mem_available_floor_mb) plus 1 GB, counting the most the stall helper
#   can ever hold (counted as twice --stall-mb, more than it can reach).
# - The hog is a python3 process holding plain memory, so its memory is
#   freed the moment it exits; nothing is left in tmpfs.
# - `timeout -s KILL` ends it after --max-seconds, even if this script is
#   killed or its terminal closed. The timer runs inside the demo's scope, so
#   if the guard has the hog paused at that moment, the kill lands once it is
#   resumed (5 s by default).
# - Ctrl+C, or this script exiting for any reason, stops both scopes.
#
# Usage: scripts/demo-memory-pressure.sh [--yes] [--step-mb N] [--hold S]
#                                        [--margin-mb N] [--max-seconds S]
#                                        [--stall-mb N]
set -euo pipefail

STEP_MB=200
HOLD_SECS=60
MARGIN_MB=256
MAX_SECONDS=240
# MemoryHigh of the stall helper's scope; 0 turns the helper off. Kept
# small (at most 128) so the helper stays under the guard's min_rss_mb
# (200 MB by default) and is never the app the guard picks; throttling
# depends on how far over the limit it is, not on its size.
STALL_MB=128
ASSUME_YES=0
# Never go below the guard's floor plus this much.
FLOOR_MARGIN_MB=1024

usage() {
    sed -n '3,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; /^set -euo/d' >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes | -y) ASSUME_YES=1; shift ;;
        --step-mb | --hold | --margin-mb | --max-seconds | --stall-mb)
            [[ $# -ge 2 ]] || { echo "$1 needs a value" >&2; usage; }
            case "$1" in
                --step-mb) STEP_MB="$2" ;;
                --hold) HOLD_SECS="$2" ;;
                --margin-mb) MARGIN_MB="$2" ;;
                --max-seconds) MAX_SECONDS="$2" ;;
                --stall-mb) STALL_MB="$2" ;;
            esac
            shift 2 ;;
        -h | --help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

for var in STEP_MB HOLD_SECS MARGIN_MB MAX_SECONDS; do
    [[ "${!var}" =~ ^[0-9]{1,9}$ ]] || { echo "options take positive whole numbers" >&2; exit 2; }
    # Base 10, so a leading zero (08) is not read as octal.
    printf -v "$var" '%d' "$((10#${!var}))"
    (( ${!var} > 0 )) || { echo "options take positive whole numbers" >&2; exit 2; }
done

[[ "$STALL_MB" =~ ^[0-9]{1,9}$ ]] || { echo "--stall-mb takes a whole number" >&2; exit 2; }
STALL_MB=$((10#$STALL_MB))
(( STALL_MB <= 128 )) || { echo "--stall-mb must be at most 128" >&2; exit 2; }

(( HOLD_SECS + 5 < MAX_SECONDS )) \
    || { echo "--hold must be more than 5 seconds shorter than --max-seconds, or the hog has no time to grow" >&2; exit 2; }

say() { printf '[demo] %s\n' "$*"; }
die() { printf '[demo] %s\n' "$*" >&2; exit 1; }

for cmd in python3 systemd-run systemctl timeout rlm; do
    command -v "$cmd" >/dev/null 2>&1 || die "$cmd is not installed"
done

systemctl --user is-active --quiet rlm-guard \
    || die "rlm-guard is not active; start it first (rlm guard enable). Refusing to run."

meminfo_mb() { awk -v k="$1:" '$1 == k { printf "%d", $2 / 1024 }' /proc/meminfo; }

# The trigger and floor, as `rlm guard status` reports them:
# "Policy:   steps in when apps stall and available memory is below 20%, or at once below 400 MB"
status="$(rlm guard status 2>/dev/null || true)"
pct="$(sed -n 's/.*available memory is below \([0-9][0-9]*\)%.*/\1/p' <<<"$status" | head -n 1)"
floor_mb="$(sed -n 's/.*at once below \([0-9][0-9]*\) MB.*/\1/p' <<<"$status" | head -n 1)"
if [[ -z "$pct" ]]; then
    pct=20
    say "could not read the trigger from rlm guard status; using the default 20%"
fi
floor_mb="${floor_mb:-400}"

total_mb="$(meminfo_mb MemTotal)"
avail_mb="$(meminfo_mb MemAvailable)"
trigger_mb=$(( total_mb * pct / 100 ))
target_mb=$(( trigger_mb - MARGIN_MB ))
# The stall helper holds at most STALL_MB plus 32 MB; count twice STALL_MB
# to be safe.
min_mb=$(( floor_mb + FLOOR_MARGIN_MB + 2 * STALL_MB ))
if (( target_mb < min_mb )); then
    say "the trigger (${trigger_mb} MB) is too close to the floor; stopping at ${min_mb} MB instead,"
    say "which is above the trigger, so the guard may not step in on this machine"
    target_mb=$min_mb
fi

say "RAM ${total_mb} MB, available now ${avail_mb} MB"
say "guard trigger: available below ${pct}% (${trigger_mb} MB); floor ${floor_mb} MB"
say "the hog grows by ${STEP_MB} MB a second until about ${target_mb} MB is available,"
say "holds for up to ${HOLD_SECS} s, then exits; hard limit ${MAX_SECONDS} s"
if (( STALL_MB > 0 )); then
    say "a stall helper capped at ${STALL_MB} MB (MemoryHigh) makes apps stall, so the guard steps in"
fi
(( avail_mb > target_mb )) || die "available memory is already at or below ${target_mb} MB; nothing to do"

if (( ! ASSUME_YES )); then
    read -r -p "[demo] Start? Save your work first. [y/N] " answer
    [[ "$answer" == [yY]* ]] || die "cancelled"
fi

UNIT="rlm-demo-hog-$$"
STALL_UNIT="rlm-demo-stall-$$"
HOG_PID=""
STALL_PID=""
# How long the "paused" notification stays up before the hog ends. Long
# enough for rlm-gtk's 2 s refresh to list the frozen hog, and with the
# 0.5 s watch still below the guard's default 5 s freeze (freeze_hold_secs),
# so the hog is gone before the thaw; with a shorter freeze_hold_secs the
# guard may move on to your next app.
SHOW_SECS=4
# Longest the stall helper runs. systemd-oomd (on by default in Ubuntu and
# Fedora) kills the cgroup reclaiming the most memory once the session's
# memory pressure ("full" avg10 of user@UID.service) has stayed above 50%
# for 20 s, so the helper stops well before that, or as soon as that
# pressure passes OOMD_SAFE_PCT.
STALL_MAX_SECS=15
OOMD_SAFE_PCT=40
SESSION_PRESSURE="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/memory.pressure"

# The session's "full" avg10, as a whole number; 0 when unreadable.
session_full_pct() {
    awk '$1 == "full" { split($2, a, "="); printf "%d", a[2]; found = 1 } END { if (!found) print 0 }' \
        "$SESSION_PRESSURE" 2>/dev/null || echo 0
}

cleanup() {
    trap - EXIT INT TERM
    local pid
    for pid in "$HOG_PID" "$STALL_PID"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    # Stops every process left in the demo's own scopes, if any.
    systemctl --user stop "$UNIT.scope" "$STALL_UNIT.scope" 2>/dev/null || true
    say "hog and stall helper stopped; their memory is free again"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

HOG='
import sys, time
target_mb, step_mb, hold_secs, max_secs = (int(a) for a in sys.argv[1:5])
start = time.monotonic()

def available_mb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    return 0

held = []
held_mb = 0
# Leave time to hold and exit before the hard limit.
grow_until = max_secs - hold_secs - 5
while time.monotonic() - start < grow_until:
    avail = available_mb()
    need = min(step_mb, avail - target_mb)
    if need <= 0:
        break
    # Repeating one nonzero byte writes every page, so all of it is resident.
    held.append(bytearray(b"\x5a") * (need * 1024 * 1024))
    held_mb += need
    print(f"[hog] holding {held_mb} MB, available {available_mb()} MB", flush=True)
    time.sleep(1)

print(f"[hog] holding {held_mb} MB for up to {hold_secs} s", flush=True)
end = time.monotonic() + hold_secs
tick = 0
while time.monotonic() < end and time.monotonic() - start < max_secs - 2:
    # Write to every page again, so memory is in active use and the kernel
    # has to work to find room; that is the stall the guard watches for.
    for b in held:
        b[::4096] = bytes([tick & 0xFF]) * len(range(0, len(b), 4096))
    tick += 1
    time.sleep(1)
    if tick % 5 == 0:
        print(f"[hog] available {available_mb()} MB", flush=True)
print("[hog] done, exiting", flush=True)
'

# The stall helper: allocates 16 MB at a time past its MemoryHigh, where
# the kernel throttles it almost continuously. It never holds more than
# the limit plus two blocks (oldest block dropped for each new one), so it
# stays under the guard's min_rss_mb, and the short sleep keeps it from
# spinning when the limit is not applied (no memory delegation).
STALL='
import sys, time
cap_mb, max_secs = (int(a) for a in sys.argv[1:3])
start = time.monotonic()
chunk_mb = 16
held = []
print(f"[stall] throttled at {cap_mb} MB, holding at most {cap_mb + 2 * chunk_mb} MB", flush=True)
while time.monotonic() - start < max_secs - 2:
    if len(held) * chunk_mb >= cap_mb + 2 * chunk_mb:
        held.pop(0)
    held.append(bytearray(b"\x5a") * (chunk_mb * 1024 * 1024))
    time.sleep(0.05)
'

# Start the stall helper and wait up to 3 s for its scope to come up.
start_stall() {
    say "memory is below the trigger; starting the stall helper in $STALL_UNIT.scope"
    systemd-run --user --scope --quiet --slice=app.slice --unit="$STALL_UNIT" \
        --description="rlm memory pressure demo (stall helper)" \
        -p MemoryHigh="${STALL_MB}M" -p MemorySwapMax=0 \
        timeout -s KILL "$MAX_SECONDS" \
        python3 -c "$STALL" "$STALL_MB" "$MAX_SECONDS" &
    STALL_PID=$!
    for _ in 1 2 3 4 5 6; do
        systemctl --user is-active --quiet "$STALL_UNIT.scope" && return 0
        sleep 0.5
    done
    say "the stall helper did not start; the guard may not step in"
}

stop_stall() {
    systemctl --user stop "$STALL_UNIT.scope" 2>/dev/null || true
}

HOG_CG=""

# Watch the hog until the guard pauses (cgroup.freeze 1) or caps
# (memory.high set) its scope; true then, false when the hog ends first.
# Sets HOG_CG. Starts the stall helper only once available memory is below
# the trigger, so the stall and the shortage begin together and the guard
# acts within seconds, and stops it after STALL_MAX_SECS in any case.
guard_acted_on_hog() {
    local cg="" freeze high stall=off started=0
    while kill -0 "$HOG_PID" 2>/dev/null; do
        [[ -n "$cg" ]] || cg="$(systemctl --user show -p ControlGroup --value "$UNIT.scope" 2>/dev/null || true)"
        if [[ -n "$cg" ]]; then
            freeze="$(cat "/sys/fs/cgroup$cg/cgroup.freeze" 2>/dev/null || echo 0)"
            high="$(cat "/sys/fs/cgroup$cg/memory.high" 2>/dev/null || echo max)"
            if [[ "$freeze" == 1 || "$high" != max ]]; then
                HOG_CG="$cg"
                return 0
            fi
        fi
        if [[ "$stall" == off ]] && (( STALL_MB > 0 )) \
            && (( $(meminfo_mb MemAvailable) <= trigger_mb )); then
            started=$SECONDS
            stall=on
            start_stall
        elif [[ "$stall" == on ]] && (( SECONDS - started >= STALL_MAX_SECS )); then
            stop_stall
            stall=done
            say "the guard did not step in within ${STALL_MAX_SECS} s; stopped the stall helper"
            say "before systemd-oomd would (it acts after 20 s of heavy pressure)"
        elif [[ "$stall" == on ]] && (( $(session_full_pct) >= OOMD_SAFE_PCT )); then
            stop_stall
            stall=done
            say "session memory pressure reached ${OOMD_SAFE_PCT}%; stopped the stall helper"
            say "so systemd-oomd does not step in"
        fi
        sleep 0.5
    done
    return 1
}

say "starting the hog in $UNIT.scope"
systemd-run --user --scope --quiet --slice=app.slice --unit="$UNIT" \
    --description="rlm memory pressure demo" \
    timeout -s KILL "$MAX_SECONDS" \
    python3 -c "$HOG" "$target_mb" "$STEP_MB" "$HOLD_SECS" "$MAX_SECONDS" &
HOG_PID=$!
if guard_acted_on_hog; then
    say "rlm-guard stepped in on the hog; the notification shows what it did"
    stop_stall
    sleep "$SHOW_SECS"
    say "ending the demo hog so its memory is free before the guard's thaw"
    # Both end processes even while they are frozen (cgroup v2); cgroup.kill
    # (kernel 5.14+) skips the round trip through systemd.
    echo 1 2>/dev/null > "/sys/fs/cgroup$HOG_CG/cgroup.kill" \
        || systemctl --user kill -s KILL "$UNIT.scope" 2>/dev/null || true
fi
# The redirect hides bash's "Killed" job notice for the hog we just ended.
{ wait "$HOG_PID"; } 2>/dev/null || true
HOG_PID=""
