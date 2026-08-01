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
Task 6: fix round 1/5 (3 addressed, 1 NEW open — reconcile_our_high remove-then-append durability gap; commits 9203c34..4ec8aac; re-reviewer ran full ignored suite live, 4/4)
Task 6: minor (deferred): cap_page_aligns test can go vacuous on slow machine (assert bytes > MIN_CAP_BYTES)
Task 6: minor (deferred): page-align test is belt-and-braces, not pinpoint (reconcile self-corrects)
Task 6: minor (deferred): RestoreStep::ThawAndRestoreHigh{to} payload vestigial — collapse to unit variant
Task 6: minor (deferred): restore_high_if_any judges liveness on newest entry only ([Cap,Freeze] chain edge)
Task 6: minor (deferred): page_align_down returns 0 for bytes<page — add .max(page) insurance (memory.high=0 would be catastrophic)
Task 6: fix round 2/5 (1 addressed, 0 open — atomic Journal::replace; commits 4ec8aac..52523a1)
Task 6: complete (commits 8a0cc3c..52523a1, review clean after 2 fix rounds; full ignored suite live-verified twice)
Task 6: minor (deferred): reconcile is belt-and-braces not total guarantee (crash-before-replace leaves SkipRemove cap, logged)
Task 6: minor (deferred): entries_for/replace TOCTOU under hypothetical multi-threaded caller
Task 6: minor (deferred): Journal::replace lacks debug_assert that entries belong to cgroup
Task 7: implemented be16f2c (impl-task7 died at rate limit; impl-task7b audited+committed); review round 1 — Critical: non-recursive member scan misses protected exes in descendant cgroups while freeze propagates to subtree (PLAN BRIEF ERRATA — spec's safety-over-coverage governs); Important: strip_cgroup_root unwrap_or_default matches-wrongly on "" rlm_base. Fix dispatched.
Task 7: minor (deferred): comm_of duplicates Name: parsing from parse_proc_status
Task 7: spec errata (mine): task-1/7 brief text "every process in the candidate cgroup" should read "in the candidate cgroup's SUBTREE" — freeze is hierarchical
Task 7: fix round 1/5 (2 addressed, 0 open — cgfs::pids_under recursive scan + Option rlm_base fail-closed; commits be16f2c..47915cc; re-reviewer live-ran nested-cgroup test independently)
Task 7: complete (commits afd6a76..47915cc, review clean after 1 fix round)
Task 8: implemented de2bcef; review round 1 — Critical: CLI Journal::open mutates cross-process (TOCTOU recover_tail can drop live daemon entry); Minor: false "read-only" comment. Fix dispatched (Journal::read_entries).
Task 8: fix round 1/5 (2 addressed, 0 open — Journal::read_entries read-only parse + accurate comment; commits de2bcef..e704a97; impl-task8 died at rate limit, impl-task8b completed)
Task 8: complete (commits 30f73e5..e704a97, review clean after 1 fix round)
PHASE 0 CODE TASKS 1-8 ALL COMPLETE. Task 9 = live gate (needs user) + docs.
FINAL WHOLE-BRANCH REVIEW (workflow, 17 agents, 5 lenses + adversarial verify): READY_WITH_FIXES. 7 survived / 4 refuted / 11 minors. 5 distinct defects: D1 rules enforcer reverts guard CAPS (frozen-skip covers freeze only) — spec-level; D2 prune uses eligibility as liveness proxy → self-defeating cap oscillation; D3 unlimit bucket is a valid guard target — spec-level; D4 swap.current read collapses cap to floor; D5 startup ordering defeats crash recovery when guard disabled. +3 promoted minors (inode sentinel, chain liveness, docs). Fix wave dispatched to fix-final. Report: final-review.md
FIX WAVE (fix-final): D1 fixed — PolicyEngine::intervened_cgroups() + RulesEnforcer::reconcile(held_cgroups) cgroup-keyed skip, alongside the existing kernel-frozen check; plan() gains a `held` param. D2 fixed — Sampler::live_cgroups() (no min-RSS/protect filter) threaded into PolicyEngine::tick; pruning judges liveness against it, victim selection unchanged. D3 fixed — cgroup::UNLIMIT_CGROUP_NAME const, excluded in resolve::candidate_target's Raw branch (status.rs now uses the same const). D4 fixed — cgfs::anon_swap_bytes/combine_anon_swap: unreadable/unparseable swap defaults to 0, anon never discarded. D5 fixed — Journal::open + sweep_leftovers now run before the enabled/rule_count early-exit; a journal-open failure is fatal only when rule_count()==0, else logged and escalation is disabled for the run (effector: Option). Promoted Minor A fixed — effector::freeze/cap fail closed (log+Err, no journal-and-act) when cgfs::dir_inode is unreadable, instead of unwrap_or(0) sentinel. Promoted Minor B fixed — restore_high_if_any judges liveness against the chain's Cap entry, not entries.last(); new ignored integration test chain_restores_cap_value_when_newest_entry_is_freeze. Docs: 2026-05-30-freeze-guard-design.md §6 bullets struck/annotated individually; roadmap.md amended near the permitted-roots (~47-53) and RulesEnforcer (~161-163) sections. page_align_down ledger item CLOSED per the review's verified-unreachable finding — no code change. Gates: cargo test --workspace 108 passed/0 failed/7 ignored, clippy --all-targets -D warnings clean, fmt --check clean.
