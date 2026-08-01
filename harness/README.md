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
> and can trip real OOM handling on a machine that's already busy.

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
itself allocate more than 12 GiB of `MemAvailable` is refused unless you
also pass `--i-know` — this is meant to catch "I ran this on my own laptop
without thinking" before it happens, not to bless every other case as
automatically safe.

Output in `--out-dir`:

- `session-locked.jsonl`, `session-touch.jsonl`, `app-touch.jsonl`,
  `psi.jsonl` — each probe/sampler's own JSON-lines output (header line,
  then one `Tick`/`PsiSample` per line).
- `hog.sh` — the embedded reproducer script, written out fresh each run
  (see below).
- `report.json` — the single merged report; see `runner.rs` for the exact
  shape (`schema`, `host`, `run`, `probes[]`, `psi`).

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

## Cleanup

The runner never leaves a hog or a probe resident, even when it panics or
is interrupted: every `systemd-run` unit it starts (the three probes, the
PSI sampler, the hog scope) and the hog's known scratch-file path are
tracked in a `Drop`-based guard, which stops them and removes the scratch
file on every return path — success, an early `?`, or a panic unwind.
`SIGINT`/`SIGTERM` delivered to `rlm-harness` itself are handled the same
way `rlm-guard` handles them (an `AtomicBool` flag flipped by a `ctrlc`
handler, checked between sleep chunks), so an interrupted run still tears
down cleanly instead of leaving the hog running.
