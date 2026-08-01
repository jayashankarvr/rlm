# rlm-harness

A headless, CI-able measurement harness for Phase 0.5 of the rlm roadmap:
how long does a desktop session actually stall under memory pressure,
measured in numbers instead of intuition.

> **Warning:** running this induces real memory pressure on the machine you
> run it on. Do not run it on a machine doing work that matters (yours, a
> shared build box, a production host). `rlm-harness` refuses to run at all
> without `/proc/pressure/memory`, and refuses a run whose hog fraction
> could threaten a large-RAM desktop unless you pass `--i-know` — but even
> a "small" hog fraction can make an idle machine feel briefly sluggish,
> and can trip real OOM handling on a machine that's already busy. Every
> run prints what it's about to do (hog size, fraction, `MemAvailable`,
> backend) before the hog starts, gated or not. The hog is bounded in both
> duration (`hog.sh --max-seconds`, plus `systemd`'s `RuntimeMaxSec=` as a
> second, independent backstop) and size (`MemoryMax=`) — see
> [Cleanup](#cleanup) for exactly what that does and doesn't guarantee.

## What it measures

One run places three instances of `rlm-probe` and one PSI sampler,
collects a quiet baseline, drives a synthetic memory hog, tears everything
down, and writes a single `report.json`.

| Probe            | Placement                                   | What it isolates |
|------------------|----------------------------------------------|-------------------|
| `session-locked` | `systemd-run --user --slice=session.slice`, `--mode locked` | Scheduling-only control — its working set is `mlockall`'d, so it can never major-fault. |
| `session-touch`  | `systemd-run --user --slice=session.slice`, `--mode touch`  | Treatment: same working set, unlocked and re-touched every tick, so it stays eligible for eviction/refault. |
| `app-touch`      | `systemd-run --user` (default `app.slice`), `--mode touch`  | The only probe under Phase 1's future dynamic cap — the sole source of the foreground-throttling number. |
| PSI sampler      | `systemd-run --user`, `--psi`                | System-wide `/proc/pressure/memory` stall, reduced to an exact counter-delta integral (see `psi.rs`). |

`touch − locked` (per slice) isolates the memory-induced component of
stall from scheduling noise — that's the number later phases are judged
on. Comparing `session-touch` against `app-touch` is what will eventually
show whether Phase 1's dynamic cap on `app.slice` actually changes
foreground responsiveness relative to `session.slice`, which is not
capped.

## Running it

```bash
cargo build --release -p harness
./target/release/rlm-harness \
    --out-dir /tmp/rlm-run-1 \
    --baseline-s 10 \
    --duration-s 60 \
    --hog-fraction 0.3
```

`rlm-harness` looks for `rlm-probe` next to its own binary by default (pass
`--rlm-probe-path` to override). It requires a systemd `--user` session
with cgroup v2 delegation (the same requirement every `systemd-run --user`
placement in this repo has) and `/proc/pressure/memory`.

On a machine with `MemTotal` above 12 GiB, a `--hog-fraction` that would
either consume at least half of current `MemAvailable` or leave less than
2 GiB of headroom afterward is refused unless you also pass `--i-know`
(see `runner::preflight_check`'s doc comments for the exact thresholds and
why they're relative to `MemAvailable`, not a second absolute number) —
this is meant to catch "I ran this on my own laptop without thinking"
before it happens, not to bless every other case as automatically safe.

Output in `--out-dir`:

- `session-locked.jsonl`, `session-touch.jsonl`, `app-touch.jsonl`,
  `psi.jsonl` — each probe/sampler's own JSON-lines output (header line,
  then one `Tick`/`PsiSample` per line).
- `hog.sh` — the embedded reproducer script, written out fresh each run
  (see below).
- `report.json` — the single merged report; see `runner.rs` for the exact
  shape (`schema`, `host`, `run`, `hog`, `probes[]`, `psi`, `warnings[]`).
  `host` includes `hostname` and `swap_total_kb`; `run` includes
  `mem_available_kb` (what `hog_fraction` is a fraction *of* — needed to
  recover a past run's absolute hog size), `interval_ms`,
  `working_set_mb`, and `timestamp_unix_s`; `hog` records the exact size
  actually requested (`estimated_mb`), which backend ran
  (`stress-ng`/`dd`), the duration/size caps applied
  (`max_seconds`/`memory_max_bytes`), its dedicated `slice`, and whether
  it was confirmed to actually hold memory for the run
  (`verified_running`).

## The observer effect

The probes themselves are not free: each one holds a small anonymous
working set (`--working-set-mb`, default 2 MiB) and, in `touch` mode, a
small file-backed mapping, and draws from the same `memory.min`/reclaim
budget the hog is putting under pressure. At the harness's default sizes
this is small relative to a realistic hog fraction, but it is not zero —
a probe is, itself, a (tiny) consumer of the resource it's measuring
contention for. Treat absolute numbers with that in mind; the
`touch − locked` decomposition is designed to cancel out everything the
two share (including this), leaving only the residual that differs
between them.

## The hog

`harness/scripts/hog.sh` is embedded into the `rlm-harness` binary at
compile time (`include_str!`) and written out to `--out-dir/hog.sh` at the
start of every run, so the runner never depends on where it's installed
relative to the binary. It's placed under its own
`systemd-run --user --scope` unit so the runner can tear it down at an
arbitrary moment with a single `systemctl --user stop`.

It prefers `stress-ng --vm` when present. Without `stress-ng`, it falls
back to writing real zero bytes into a tmpfs (`/dev/shm`) file via `dd` —
writing actual bytes (rather than mapping `/dev/zero` directly, which the
kernel serves from a single shared copy-on-write zero page) is what makes
the tmpfs file's size real resident memory. Either way, a `SIGTERM`
(`systemctl --user stop`, or the harness tearing down on error/signal)
frees the memory immediately — the fallback path traps `EXIT`/`INT`/`TERM`
to remove its tmpfs file, and `stress-ng` frees its own workers on the
same signals.

It runs under its own dedicated transient slice (`rlm-harness-hog.slice`),
not `app.slice`: `app-touch` is deliberately placed under `app.slice` as
the sole probe meant to observe Phase 1's future dynamic cap, and sharing
a slice with the hog would throttle that probe alongside the very
pressure it exists to measure.

`hog.sh` accepts `--max-seconds` (the runner always passes
`baseline_s + duration_s + 30`) and enforces it on both backends
(`stress-ng -t`, and `sleep` on the `dd` fallback), defaulting to 120s if
run by hand without the flag — see [Cleanup](#cleanup) for why this,
rather than the runner's own teardown code, is what actually bounds a hog
that gets orphaned.

## Cleanup

`UnitGuard` tears down every `systemd-run` unit this process starts (the
three probes, the PSI sampler, the hog scope) and removes the hog's known
scratch-file path, on every return path this process actually executes:
success, an early `?`, a panic unwind, or `SIGINT`/`SIGTERM` (handled the
same way `rlm-guard` handles them — an `AtomicBool` flag flipped by a
`ctrlc` handler, checked between sleep chunks).

**That is not the same as "never leaves a hog resident."** `Drop` is a
language-level guarantee, not an OS-level one: it does not run at all if
`rlm-harness` is `SIGKILL`ed, `SIGSTOP`ped, OOM-killed by the very
pressure it induced, or the machine loses power. What actually bounds the
worst case in those scenarios is `hog.sh`'s own `--max-seconds` cap: the
hog frees itself and exits on its own after that many seconds even with
nobody left to stop it, on both the `stress-ng` and `dd` fallback paths.
The hog's transient scope also carries a `RuntimeMaxSec=` (a second,
independent backstop for the case where `hog.sh`'s own timer somehow never
fires) and a `MemoryMax=` sized to the intended hog (bounding how large a
runaway hog can get, independent of how long it runs). **Worst case after
these: an orphaned hog holds its memory for at most
`baseline_s + duration_s + 30` seconds — never until reboot.**

The runner also verifies the hog actually started and was still holding
memory at the end of its intended hold period (not just that
`systemd-run` exited 0 — a hog that fails to allocate, e.g. `/dev/shm`
running out of space, can exit within about a second) and records that in
`report.json`'s `hog.verified_running`, along with any other conditions
that could make a report's numbers unreliable in `report.json`'s
top-level `warnings` array.
