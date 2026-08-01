# SDD ledger — plan: docs/superpowers/plans/2026-07-31-phase0-act-in-place.md
Task 1: complete (commits 91762c9..62ff14e, review clean)
Task 2: review round 1 — Critical: abs() Path::join drops /sys/fs/cgroup prefix on absolute cg paths (cgfs.rs:171). Fix dispatched to impl-task2.
Task 2: minor (deferred): parse_anon lacks anon_thp-collision regression test (cgfs.rs:258)
Task 2: minor (deferred): implementer skipped TDD red step (process note)
Task 2: fix round 1/5 (1 addressed, 0 open — abs() prefix drop fixed + regression test; commits 17003b8..211cb9b)
Task 2: complete (commits 62ff14e..211cb9b, review clean after 1 fix round)
Task 3: implemented 692bd86 (impl-task3 died at rate limit; impl-task3b audited+completed partial work)
Task 3: review round 1 — Critical: torn-write tail swallows later fsynced entry (no WAL tail recovery in open()); Important: no mutation lock + stable temp filename. Fix dispatched to impl-task3b.
Task 3: minor (deferred): no parent-dir fsync on first-ever journal creation (write_header)
Task 3: minor (deferred): temp filename pid-reuse collision (cosmetic)
Task 3: reviewer cannot-verify (track at integration): daemon call pattern single-threaded?; cgfs read_high trim consistency vs our_high string equality in should_restore
Task 3: fix round 1/5 (2 addressed, 0 open — WAL tail recovery + mutation lock/unique temp names; commits 692bd86..9439119)
Task 3: complete (commits e05d7c2..9439119, review clean after 1 fix round)
Task 4: complete (commits 35ad886..8f4788e, review clean first pass; live freeze/thaw roundtrip verified via journalctl)
Task 4: minor (deferred): run_with_timeout maps Disconnected(panic) to "timed out" message (systemd.rs ~1304)
Task 4: minor (deferred): D-Bus errors reuse Error::Cgroup variant; revisit if branches grow
Task 5: complete (commits a97b196..8b59c41, review clean first pass; effector stopgap graded non-destructive+inert)
Task 5: CARRY-FORWARD to Task 6 (Important): dead-prune LiftCap must also thaw (or emit Thaw+LiftCap for Frozen) — a still-frozen cgroup that transiently fails to resolve must never be dropped from tracking while frozen
Task 5: note: plan test unresolvable_process_is_never_selected corrected in substance (Notify fires at High regardless); plan text had a bug
Task 6: implemented aa08663; review round 1 (opus) — Critical: kernel page-truncation defeats should_restore equality (every cap permanent); Critical: lift ordering raw-restore-then-u64::MAX clobbers user MemoryHigh; Important: single-entry replay + remove-all leaks coexisting entries. All empirically verified. Fix dispatched to impl-task6.
Task 6: minor (deferred): inode unwrap_or(0) poison value — Cap in that state never lifted (effector.rs:95,145)
Task 6: minor (deferred): Journal::open failure silently fatal at daemon startup; boot_id "" self-matches (main.rs:47, cgfs.rs:83)
Task 6: spec errata (mine): carry-forward #2 "byte-identical" unachievable vs page-truncation; "additionally set u64::MAX" ambiguous ordering — plan text was the root cause of both Criticals
