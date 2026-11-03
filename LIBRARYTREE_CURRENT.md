# LibraryTree current work

This brief owns current handoff. LIBRARYTREE_PLAN.md owns scope, dependencies, acceptance and durable evidence. PR_DESCRIPTION.md describes final PR11 review scope; never use it for discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-12-native-statement`, HEAD `bb4a3c3701ae8b1c71d76cd3781e2f50642c4d93`, base `10bc8a5f0e56ce5b890b12ac46f653258d2ff505`. Core claim/proof changes are committed; remaining PR12 implementation is modified/untracked. Preserve it. Revalidate Git before continuing. No pushes/GitHub PRs. General goal/M1 remain active; no new design decision is pending.

Active slice: finish PR12 native statement/proof cutover. Read plan PR12, invariants 1/8 and D6; consult D3/D7 only for external profile boundaries. Claim40 v2 is Kentry4||RE4||I16||O16; proof3 rejects legacy transport first. Canonical AIR groups are Core36 I||O||K, Chiplets4 RE, two empty groups; aux4 is deferred only. MASM's internal RE4||deferred4 buffer is distinct from aux4. No kernel-list/count authority; three external terms. Frozen APIs and remaining locations are in `.scratch/librarytree/findings-pr12-cutover.md`.

Ownership: bounded agents own CLI `cli_test.rs`, core-lib `stark_asserts/mod.rs` constant resolution, and native `memory.rs`/`security{,/testing}.rs` snapshots. Root owns integration, AIR projection/observer, generated contracts, fixture promotion, checks and commits. Other PR12 sources are frozen. Fresh agents receive exact task/files/constraints with `fork_turns:none`; no agent builds.

Passed evidence is recorded in the plan: core/AIR378, processor1891, deterministic generation/check, fresh native-verified Eidos fixture, and 464/473 combined checks. Current nine failures concern four CLI fixtures, layout constant resolution, and four memory/security snapshots. Fix them without weakening admission/layout/security oracles, then rerun affected checks and applicable Clippy/no_std. Full recursive/adversarial/guest/fuzz/performance/final gates remain open; PR15a is deferred.

Root centralizes AC/heavy-guarded Rust checks with 16MiB stacks. The default target cache disappeared; reuse `CARGO_TARGET_DIR=$PWD/.scratch/librarytree/build-pr12` and existing test-dev feature graph. Do not run parallel Cargo jobs or repeat passing suites absent changed code or unresolved concerns. Commit reviewed implementation separately from context; verify signatures. Final PR12 description precedes branching.

Cache: `.scratch/librarytree/reference-cache/`, one source copy with Page/date/SHA-256 provenance. Findings, logs and archives stay separate; scratch stays untracked. Preserve shared `/tmp` sources. Security follow-up: `.scratch/librarytree/findings-security-principals.md`.
