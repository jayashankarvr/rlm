#!/usr/bin/env bash
#
# rlm-harness memory hog reproducer.
#
# Allocates and holds real, resident memory (--fraction of
# --mem-available-kb), then blocks until signalled. Placed by rlm-harness
# under a `systemd-run --user --scope` unit, so tearing it down is a single
# `systemctl --user stop` (which delivers SIGTERM to every process in the
# scope) away.
#
# Prefers `stress-ng --vm` when present. `stress-ng` handles SIGTERM/SIGINT
# itself (frees its workers and exits) -- this script `exec`s into it, so
# once that happens the trap below is irrelevant (this process's image is
# gone). Falls back to writing real zero bytes into a tmpfs file via `dd`
# when stress-ng is unavailable, so the harness has no hard external
# dependency beyond coreutils. The fallback path traps EXIT/INT/TERM to
# remove its tmpfs file immediately, so a killed hog never leaves
# multi-gigabyte resident memory behind.
#
# IMPORTANT: the fallback writes to a tmpfs file rather than mapping
# /dev/zero directly -- a direct MAP_PRIVATE mapping of /dev/zero is
# copy-on-write from the kernel's single shared zero page, so merely
# reading it would consume almost no real memory. Writing actual bytes
# through `dd` forces the kernel to allocate a distinct resident page per
# block, so the tmpfs file's size really is resident memory.
set -euo pipefail

FRACTION=""
MEM_AVAILABLE_KB=""
TMP_FILE=""

usage() {
    echo "usage: hog.sh --fraction <0..1> --mem-available-kb <kb> [--tmp-file <path>]" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fraction)
            FRACTION="$2"
            shift 2
            ;;
        --mem-available-kb)
            MEM_AVAILABLE_KB="$2"
            shift 2
            ;;
        --tmp-file)
            TMP_FILE="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

if [[ -z "$FRACTION" || -z "$MEM_AVAILABLE_KB" ]]; then
    usage
fi

# Default tmp file lives in /dev/shm (tmpfs -- backed by RAM, so its size is
# real resident memory) if the caller didn't pin a specific path.
TMP_FILE="${TMP_FILE:-/dev/shm/rlm-hog-$$}"
SLEEP_PID=""

cleanup() {
    rm -f "$TMP_FILE"
    if [[ -n "$SLEEP_PID" ]]; then
        kill "$SLEEP_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

HOG_MB=$(awk -v f="$FRACTION" -v m="$MEM_AVAILABLE_KB" 'BEGIN {
    mb = (f * m) / 1024;
    if (mb < 1) mb = 1;
    printf "%d", mb;
}')

if command -v stress-ng >/dev/null 2>&1; then
    exec stress-ng --vm 1 --vm-bytes "${HOG_MB}M" --vm-keep --vm-hang 0 -t 0
fi

dd if=/dev/zero of="$TMP_FILE" bs=1M count="$HOG_MB" status=none

# Hold in the background: a signal delivered to this process interrupts
# `wait` immediately (rather than waiting for a foreground `sleep infinity`
# to be killed outright), so the EXIT trap above runs right away.
sleep infinity &
SLEEP_PID=$!
wait "$SLEEP_PID"
