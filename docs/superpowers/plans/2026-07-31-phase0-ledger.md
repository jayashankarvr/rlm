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
