# Recovery: Roadmap Implementation Loop

If you are a fresh Claude session (or a human) picking this up with zero
context, this file is the complete restart procedure. It is committed to git
precisely so that nothing below depends on any session surviving.

## What is being built

The phases of `docs/superpowers/specs/2026-07-31-roadmap.md` (frozen spec),
in order: 0 → 0.5 → 1 → 2 → 3a → 3b (conditional) → 4 → 5 → 6.

Current phase: **Phase 0** — plan with per-task checkboxes (the durable
progress record) at `docs/superpowers/plans/2026-07-31-phase0-act-in-place.md`.

## Where the work lives

- Branch: `feat/phase0-act-in-place` (branched from `main`). Pushed to
  `origin` after every completed task — `git log origin/feat/phase0-act-in-place`
  is the survivable truth.
- Checked checkboxes in the plan = task steps done and reviewed. A checked
  task always has its commits on the branch.
- Scratch (ledger, task briefs, subagent reports, review diffs):
  `.superpowers/sdd/2026-07-31-phase0-act-in-place/` — git-ignored, loseable.
  The ledger (`progress.md` there) is mirrored into git at
  `docs/superpowers/plans/2026-07-31-phase0-ledger.md` at every durability
  checkpoint; if the scratch copy is gone, restore it from the mirror.

## The workflow invariants (follow these, they are the no-data-loss contract)

1. **Every completed task ends with a durability checkpoint:** update plan
   checkboxes + mirror the ledger + `git add` those two files + commit
   (`chore(sdd): checkpoint after task N`) + `git push origin HEAD`.
2. Implementer/reviewer subagents commit their own code work; the controller
   never lets a reviewed task sit uncommitted or unpushed past its checkpoint.
3. Execution is subagent-driven (superpowers:subagent-driven-development):
   fresh implementer per task (haiku for transcription tasks, sonnet for
   integration), reviewer per task (sonnet+), fix loops per the skill,
   whole-branch review before merging a phase.
4. Never implement on `main`. Merge only after the phase's final review.

## Restart procedure

1. `git checkout feat/phase0-act-in-place && git pull origin feat/phase0-act-in-place`
   (create from origin if local is gone).
2. Read the plan file; the first task with unchecked boxes is next. Check the
   ledger mirror for mid-task fix-loop state (`fix round N/5` lines).
3. Re-create the scratch workspace if missing (`scripts/sdd-workspace` from the
   superpowers subagent-driven-development skill), seed `progress.md` from the
   ledger mirror, and continue the task loop.
4. Re-arm the hourly loop if wanted: session cron `7 * * * *`, one iteration =
   one or two tasks implemented + reviewed + checkpointed; stop rule = delete
   the cron when nothing autonomous remains. (The cron is session-only by
   design; this file is what makes that safe.)

## Out-of-band state (not in git, by design)

- The redesigned GTK icon (`gtk-gui/assets/rlm-icon.svg`, modified in the
  working tree on `main`) is deliberately uncommitted pending the user's
  visual review. If it's lost, it can be regenerated; do not commit it
  without the user's sign-off.
- The system-package leftovers (`sudo apt remove rlm rlm-gtk`) still need the
  user; unrelated to this loop.
