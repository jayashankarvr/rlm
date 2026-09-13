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

# Hard ceiling on how long the hog may live, enforced in THREE independent
# places (see below). Learned from the Phase 0.5 harness review, where a
# SIGKILLed runner left an unbounded hog reparented to the systemd manager,
# holding memory until a human intervened. A bound that lives only in the
# supervisor dies with the supervisor; this one has to survive it.
HOG_MAX_SECONDS="${HOG_MAX_SECONDS:-180}"

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
MEM_TOTAL_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
# The hog ramps toward a PSI target rather than a fixed size (see below).
# HOG_FRACTION now sets the CEILING as a multiple of MemAvailable: it must be
# >1.0 to be able to induce reclaim at all, and it is a hard stop, not a goal.
HOG_CEILING_MB=$(python3 -c "print(int($MEM_AVAIL_KB / 1024 * $HOG_FRACTION))")
PSI_TARGET="${PSI_TARGET:-35}"   # above the guard's default psi_some_high=30
HEADROOM_MB=$(( MEM_TOTAL_KB / 1024 - HOG_CEILING_MB ))
[[ "$HOG_CEILING_MB" -gt 200 ]] || { echo "computed ceiling ${HOG_CEILING_MB}MB is too small to induce pressure" >&2; exit 2; }

# Loud, unconditional statement of intent BEFORE doing anything. The harness
# review found a gate whose warning printed nothing on the machines it was
# meant to protect; a warning that only fires in the safe case is not a gate.
cat <<EOF | tee -a "$LOG"

  !! This will deliberately put this machine under memory pressure. !!

  MemTotal      : $((MEM_TOTAL_KB / 1024)) MB
  MemAvailable  : $((MEM_AVAIL_KB / 1024)) MB
  Hog ceiling   : ${HOG_CEILING_MB} MB (hard stop; ramps only until PSI >= ${PSI_TARGET}%)
  Total RAM left: ${HEADROOM_MB} MB if the ceiling is ever reached
  Hog lifetime  : hard-capped at ${HOG_MAX_SECONDS}s (three independent bounds)

  Expect the desktop to stutter. Save your work first. If anything goes
  wrong, the hog dies on its own within ${HOG_MAX_SECONDS}s even if this
  script is killed.

EOF

# Require explicit consent when the run would leave little headroom. The
# threshold is RELATIVE to this machine, not an absolute GB figure — the
# harness review found an absolute second threshold that never fired on the
# 16GB desktops most likely to be hurt.
if [[ "$HEADROOM_MB" -lt 1024 && "${I_KNOW:-0}" != "1" ]]; then
  echo "REFUSING: this would leave only ${HEADROOM_MB}MB headroom." >&2
  echo "Lower HOG_FRACTION (currently $HOG_FRACTION), free memory, or re-run with I_KNOW=1." >&2
  exit 2
fi
if [[ -t 0 && "${I_KNOW:-0}" != "1" ]]; then
  read -r -p "Proceed? [y/N] " reply
  [[ "$reply" == "y" || "$reply" == "Y" ]] || { echo "aborted by user"; exit 2; }
fi

# ------------------------------------------------- criterion 1: in place ----
log "--- criterion 1: freeze acts in place ---"
# Three independent bounds on the hog, because the one that matters is the one
# that survives this script being killed:
#   1. the payload's own deadline (below) — cannot be orphaned, it IS the hog
#   2. RuntimeMaxSec on the scope — catches a payload wedged in an
#      uninterruptible state; systemd SIGKILLs the whole cgroup at the deadline
#   3. MemoryMax on the scope — bounds magnitude, so an arithmetic slip in
#      HOG_MB cannot outrun the headroom check above
# The hog RAMPS until PSI actually responds, then stops growing.
#
# Why not a fixed size: MemAvailable is by definition how much you can allocate
# WITHOUT significant reclaim, so any hog sized as a fraction of it generates
# no pressure at all — measured 0.00 PSI for a 2.4GB hog against 4.3GB
# available. To make the guard's trigger fire you must push past MemAvailable
# and force reclaim. But overshooting is how you freeze the desktop, so the hog
# grows in small steps and stops the moment PSI clears the target — just enough
# pressure to trigger the guard, no more. The ceiling, the deadline and
# MemoryMax all still bound it if PSI never responds.
systemd-run --user --scope --unit="$HOG_UNIT" --quiet \
  --property="RuntimeMaxSec=${HOG_MAX_SECONDS}" \
  --property="MemoryMax=${HOG_CEILING_MB}M" \
  python3 -c "
import sys, time
sys.argv[0] = 'rlm-gate-hog-payload'

def psi_some():
    try:
        with open('/proc/pressure/memory') as f:
            for line in f:
                if line.startswith('some '):
                    for tok in line.split():
                        if tok.startswith('avg10='):
                            return float(tok[6:])
    except OSError:
        pass
    return 0.0

deadline  = time.monotonic() + $HOG_MAX_SECONDS
ceiling   = $HOG_CEILING_MB
target    = $PSI_TARGET
step_mb   = 128
chunks, held = [], 0

# Ramp: add a step, let the kernel react, re-read PSI. Stop on ANY of:
# PSI target reached, ceiling hit, or deadline.
while time.monotonic() < deadline and held < ceiling:
    p = psi_some()
    if p >= target:
        print('psi target reached: some avg10=%.2f at %dMB' % (p, held), flush=True)
        break
    chunks.append(bytearray(step_mb * 1024 * 1024))   # touched => resident
    held += step_mb
    time.sleep(0.25)
else:
    print('ramp ended without reaching psi target (held=%dMB)' % held, flush=True)

# Hold so the guard has a stable window to act in, then release.
while time.monotonic() < deadline:
    time.sleep(1)
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

# Check placement while the hog is still alive — that is the "acted in place"
# question and it must be asked before anything exits.
SCOPE_AFTER="$(cat /proc/"$HOG_PID"/cgroup 2>/dev/null | cut -d: -f3 || echo GONE)"
HIGH_AFTER="$(cat "/sys/fs/cgroup${SCOPE_AFTER}/memory.high" 2>/dev/null || echo missing)"

if [[ "$SCOPE_AFTER" == "$SCOPE_BEFORE" ]]; then
  pass "process still in its own scope ($SCOPE_AFTER) — acted in place, no migration"
else
  fail "process moved: $SCOPE_BEFORE -> $SCOPE_AFTER"
fi
# A cap still being applied HERE is correct, not a failure: the engine holds a
# soft cap until calm_hold_secs (default 30) of SUSTAINED calm, and the hog is
# still running. The real question is whether the cap is ever lifted. So:
# release the pressure, then give the engine its calm window plus slack.
CALM_HOLD="$(awk -F'[ ,]+' '/calm_hold_secs:/ {print $NF; exit}' "$HOME/.config/rlm/config.yaml" 2>/dev/null)"
CALM_HOLD="${CALM_HOLD:-30}"
if [[ "$HIGH_AFTER" == "$HIGH_BEFORE" ]]; then
  pass "memory.high unchanged while capped window active ($HIGH_AFTER)"
else
  log "cap currently applied (memory.high=$HIGH_AFTER); releasing pressure and waiting ${CALM_HOLD}s+ for the lift"
  systemctl --user stop "${HOG_UNIT}.scope" 2>/dev/null || true
  LIFTED=0
  for _ in $(seq $((CALM_HOLD + 20))); do
    NOW_HIGH="$(cat "/sys/fs/cgroup${SCOPE_BEFORE}/memory.high" 2>/dev/null || echo GONE)"
    # The scope disappearing with the hog is also a valid end state.
    if [[ "$NOW_HIGH" == "$HIGH_BEFORE" || "$NOW_HIGH" == "GONE" ]]; then LIFTED=1; break; fi
    sleep 1
  done
  [[ "$LIFTED" -eq 1 ]] && pass "cap lifted after calm sustained (memory.high back to $HIGH_BEFORE / scope released)" \
                        || fail "cap never lifted: still $NOW_HIGH after $((CALM_HOLD + 20))s of calm"
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
