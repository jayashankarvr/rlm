#!/usr/bin/env bash
# Phase 0 live gate — the acceptance criterion for the act-in-place freeze guard.
#
# This script deliberately induces real memory pressure on the machine it runs
# on. That is the point: the guard exists to handle a condition that cannot be
# simulated. Read the SAFETY section before running it on a machine you care
# about.
#
# What it proves (from docs/superpowers/specs/2026-07-31-roadmap.md, Phase 0):
#   1. A frozen-then-thawed app is STILL IN ITS OWN SCOPE afterward, with its
#      original memory.high intact — i.e. the guard acted in place and did not
#      migrate the process into a guard-<pid> cgroup.
#   2. kill -9 of the daemon mid-freeze does not strand a frozen process: the
#      journal replay on restart thaws it and restores memory.high.
#
# Exit 0 = both criteria met. Any other exit = gate failed; see the log.

set -uo pipefail

# ---------------------------------------------------------------- SAFETY ----
# - Runs entirely as your user. Never sudo. Touches only your own cgroups.
# - The hog is capped at a FRACTION OF MemAvailable (default 0.6), never a
#   fixed size, so it scales down on a small machine instead of killing it.
# - Every hog and probe lives in a transient systemd scope that this script
#   tears down on EXIT, INT, TERM and ERR. There is no path where a normal
#   interruption leaves a multi-gigabyte allocation resident.
# - Anything already frozen when we start is left alone and reported; we never
#   thaw something we did not freeze.
# - It will REFUSE to run if the guard is not installed, if PSI is missing, or
#   if a previous run left state behind (rather than papering over it).
#
# Recommended: close work you care about first. A freeze guard test that goes
# wrong looks exactly like the freeze it prevents.
# ---------------------------------------------------------------------------

HOG_FRACTION="${HOG_FRACTION:-0.6}"
HOG_UNIT="rlm-gate-hog"
LOG="${LOG:-/tmp/rlm-phase0-gate-$$.log}"
FAILURES=0

log()  { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" | tee -a "$LOG"; }
pass() { log "PASS  $*"; }
fail() { log "FAIL  $*"; FAILURES=$((FAILURES + 1)); }

cleanup() {
  local rc=$?
  log "--- cleanup ---"
  systemctl --user stop "${HOG_UNIT}.scope" 2>/dev/null || true
  systemctl --user reset-failed "${HOG_UNIT}.scope" 2>/dev/null || true
  pkill -f 'rlm-gate-hog-payload' 2>/dev/null || true
  # Never leave anything frozen because this script died.
  local base
  base="$(rlm doctor --print-base 2>/dev/null || true)"
  if [[ -n "$base" && -d "$base" ]]; then
    find "$base" -name cgroup.freeze -exec sh -c 'grep -q 1 "$1" && echo 0 > "$1"' _ {} \; 2>/dev/null || true
  fi
  log "cleanup done (exit $rc); log at $LOG"
}
trap cleanup EXIT INT TERM

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 2; }; }

# ------------------------------------------------------------- preflight ----
log "=== Phase 0 live gate ==="
require systemd-run; require systemctl; require python3

[[ -r /proc/pressure/memory ]] || { echo "PSI unavailable (/proc/pressure/memory) — guard cannot work here" >&2; exit 2; }

if ! systemctl --user is-active --quiet rlm-guard.service; then
  echo "rlm-guard.service is not active. Install this build and start it first:" >&2
  echo "  cargo build --release && ./install.sh && systemctl --user restart rlm-guard" >&2
  exit 2
fi

if systemctl --user list-units --all "${HOG_UNIT}.scope" 2>/dev/null | grep -q "$HOG_UNIT"; then
  echo "a previous ${HOG_UNIT}.scope still exists — clean it up first:" >&2
  echo "  systemctl --user stop ${HOG_UNIT}.scope; systemctl --user reset-failed" >&2
  exit 2
fi

MEM_AVAIL_KB=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
HOG_MB=$(python3 -c "print(int($MEM_AVAIL_KB / 1024 * $HOG_FRACTION))")
log "MemAvailable $((MEM_AVAIL_KB / 1024))MB; hog will allocate ${HOG_MB}MB (fraction $HOG_FRACTION)"
[[ "$HOG_MB" -gt 200 ]] || { echo "computed hog size ${HOG_MB}MB is too small to induce pressure; free some memory first" >&2; exit 2; }

# ------------------------------------------------- criterion 1: in place ----
log "--- criterion 1: freeze acts in place ---"
systemd-run --user --scope --unit="$HOG_UNIT" --quiet \
  python3 -c "
import sys, time
sys.argv[0] = 'rlm-gate-hog-payload'
n = $HOG_MB
chunks = []
for _ in range(n // 64):
    chunks.append(bytearray(64 * 1024 * 1024))   # touched, so it is resident
    time.sleep(0.05)
time.sleep(120)
" &
HOG_SHELL_PID=$!
sleep 3

HOG_PID="$(pgrep -f rlm-gate-hog-payload | head -1)"
[[ -n "$HOG_PID" ]] || { fail "hog did not start"; exit 1; }
SCOPE_BEFORE="$(cat /proc/"$HOG_PID"/cgroup 2>/dev/null | cut -d: -f3)"
HIGH_BEFORE="$(cat "/sys/fs/cgroup${SCOPE_BEFORE}/memory.high" 2>/dev/null || echo missing)"
log "hog pid $HOG_PID in $SCOPE_BEFORE (memory.high=$HIGH_BEFORE)"

log "waiting up to 90s for the guard to intervene..."
INTERVENED=0
for _ in $(seq 90); do
  if journalctl --user -u rlm-guard --since "-2min" 2>/dev/null | grep -qE 'freezing|capping|soft-capping'; then
    INTERVENED=1; break
  fi
  sleep 1
done
[[ "$INTERVENED" -eq 1 ]] && pass "guard intervened" || fail "guard never intervened within 90s"

sleep 12   # let the freeze hold elapse and auto-thaw

SCOPE_AFTER="$(cat /proc/"$HOG_PID"/cgroup 2>/dev/null | cut -d: -f3 || echo GONE)"
HIGH_AFTER="$(cat "/sys/fs/cgroup${SCOPE_AFTER}/memory.high" 2>/dev/null || echo missing)"

if [[ "$SCOPE_AFTER" == "$SCOPE_BEFORE" ]]; then
  pass "process still in its own scope ($SCOPE_AFTER) — acted in place, no migration"
else
  fail "process moved: $SCOPE_BEFORE -> $SCOPE_AFTER"
fi
if [[ "$HIGH_AFTER" == "$HIGH_BEFORE" ]]; then
  pass "memory.high restored to original ($HIGH_AFTER)"
else
  fail "memory.high not restored: was $HIGH_BEFORE, now $HIGH_AFTER"
fi
if [[ -d /sys/fs/cgroup/rlm ]] && find /sys/fs/cgroup -maxdepth 6 -name 'guard-*' 2>/dev/null | grep -q .; then
  fail "a guard-<pid> cgroup exists — the deleted migration machinery is somehow back"
else
  pass "no guard-<pid> cgroups (migration machinery is gone)"
fi

# --------------------------------------- criterion 2: kill -9 mid-freeze ----
log "--- criterion 2: journal replay after kill -9 mid-freeze ---"
log "waiting for a fresh intervention to kill during..."
KILLED=0
for _ in $(seq 60); do
  if journalctl --user -u rlm-guard --since "-15s" 2>/dev/null | grep -qE 'freezing|capping|soft-capping'; then
    GUARD_PID="$(systemctl --user show rlm-guard.service -p MainPID --value)"
    kill -9 "$GUARD_PID" 2>/dev/null && { log "SIGKILLed rlm-guard (pid $GUARD_PID) mid-intervention"; KILLED=1; break; }
  fi
  sleep 1
done

if [[ "$KILLED" -eq 1 ]]; then
  sleep 8   # systemd Restart=on-failure brings it back; sweep runs at startup
  systemctl --user is-active --quiet rlm-guard.service || systemctl --user start rlm-guard.service
  sleep 4
  FROZEN="$(cat "/sys/fs/cgroup${SCOPE_BEFORE}/cgroup.events" 2>/dev/null | awk '/^frozen/{print $2}')"
  HIGH_REPLAY="$(cat "/sys/fs/cgroup${SCOPE_BEFORE}/memory.high" 2>/dev/null || echo missing)"
  [[ "${FROZEN:-0}" == "0" ]] && pass "process not left frozen after daemon SIGKILL + restart" \
                              || fail "process STILL FROZEN after restart — journal replay did not thaw it"
  [[ "$HIGH_REPLAY" == "$HIGH_BEFORE" ]] && pass "memory.high restored by journal replay ($HIGH_REPLAY)" \
                                         || fail "memory.high not restored by replay: expected $HIGH_BEFORE, got $HIGH_REPLAY"
else
  fail "could not catch an intervention to kill during — criterion 2 unverified"
fi

# ------------------------------------------------------------------ done ----
log "=== gate complete: $FAILURES failure(s) ==="
journalctl --user -u rlm-guard --since "-5min" --no-pager | tail -40 | tee -a "$LOG" >/dev/null
log "guard journal excerpt appended to $LOG (paste into the commit message)"
exit "$FAILURES"
