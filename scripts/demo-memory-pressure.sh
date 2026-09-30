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
# Safety:
# - It refuses to run unless rlm-guard is active.
# - It never pushes available memory below the guard's floor
#   (mem_available_floor_mb) plus 1 GB.
# - The hog is a python3 process holding plain memory, so its memory is
#   freed the moment it exits; nothing is left in tmpfs.
# - `timeout -s KILL` ends it after --max-seconds, even if this script is
#   killed or its terminal closed. The timer runs inside the demo's scope, so
#   it waits while the guard has the hog paused (5 s by default).
# - Ctrl+C, or this script exiting for any reason, stops the scope.
#
# Usage: scripts/demo-memory-pressure.sh [--yes] [--step-mb N] [--hold S]
#                                        [--margin-mb N] [--max-seconds S]
set -euo pipefail

STEP_MB=200
HOLD_SECS=60
MARGIN_MB=256
MAX_SECONDS=240
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
        --step-mb) STEP_MB="$2"; shift 2 ;;
        --hold) HOLD_SECS="$2"; shift 2 ;;
        --margin-mb) MARGIN_MB="$2"; shift 2 ;;
        --max-seconds) MAX_SECONDS="$2"; shift 2 ;;
        -h | --help) usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

for n in "$STEP_MB" "$HOLD_SECS" "$MARGIN_MB" "$MAX_SECONDS"; do
    [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] || { echo "options take positive whole numbers" >&2; exit 2; }
done

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
min_mb=$(( floor_mb + FLOOR_MARGIN_MB ))
if (( target_mb < min_mb )); then
    say "the trigger (${trigger_mb} MB) is too close to the floor; stopping at ${min_mb} MB instead,"
    say "which is above the trigger, so the guard may not step in on this machine"
    target_mb=$min_mb
fi

say "RAM ${total_mb} MB, available now ${avail_mb} MB"
say "guard trigger: available below ${pct}% (${trigger_mb} MB); floor ${floor_mb} MB"
say "the hog grows by ${STEP_MB} MB a second until about ${target_mb} MB is available,"
say "holds for up to ${HOLD_SECS} s, then exits; hard limit ${MAX_SECONDS} s"
(( avail_mb > target_mb )) || die "available memory is already at or below ${target_mb} MB; nothing to do"

if (( ! ASSUME_YES )); then
    read -r -p "[demo] Start? Save your work first. [y/N] " answer
    [[ "$answer" == [yY]* ]] || die "cancelled"
fi

UNIT="rlm-demo-hog-$$"
HOG_PID=""

cleanup() {
    trap - EXIT INT TERM
    if [[ -n "$HOG_PID" ]]; then
        kill "$HOG_PID" 2>/dev/null || true
    fi
    # Stops every process left in the demo's own scope, if any.
    systemctl --user stop "$UNIT.scope" 2>/dev/null || true
    say "hog stopped; its memory is free again"
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

say "starting the hog in $UNIT.scope"
systemd-run --user --scope --quiet --slice=app.slice --unit="$UNIT" \
    --description="rlm memory pressure demo" \
    timeout -s KILL "$MAX_SECONDS" \
    python3 -c "$HOG" "$target_mb" "$STEP_MB" "$HOLD_SECS" "$MAX_SECONDS" &
HOG_PID=$!
wait "$HOG_PID" || true
HOG_PID=""
