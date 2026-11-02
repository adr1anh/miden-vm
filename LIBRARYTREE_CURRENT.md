# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable completion evidence. `PR_DESCRIPTION.md` describes final branch review scope; never use it for discovery.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-04-toolchain-contracts`, HEAD/code `5c9c78799`, base `45be30b96`. Documentation commits follow. Recheck Git HEAD/status before assigning edits; `.scratch/` is uncommitted.

PR 04 is active. Declaration models, semantic paths, existing invocation syntax/word procref printing, and profile-bound Home v1 are implemented. Verified InterfaceArtifact v1 construction, encoding and strict decoding are committed. Current small slice: **repair the package test helper that locates MAST v6 hashes**, then finish branch validation. Reuse shared bounded codec primitives and core hashing. Require the D3 external profile/context/budgets; no package9, ReleaseRecord, fabricated D/forest, derived I or default domain/home/profile.

The `package_mast_hash_fixture` agent owns only mast-package `src/package/serialization/tests.rs`. Its old hash-offset helper omits the new target count/table, breaking five spoofed-hash tests. Preserve trusted/untrusted assertions and production package bytes. All interface/Home production and adversarial tests are released and committed. Root owns integration, plan/brief and final branch-description edits. Generic validity supplies no publisher, association, closure or home authority; FunctionType stays outside wire/hash authority.

Read plan **PR 04**, **invariants 5/9**, **D2/D3**, and **Workflow and completion rules**. Use `.scratch/librarytree/findings-pr04-acceptance.md` for remaining gates. For the fixture, inspect only its locator and the actual core v6 serialization/wire scanner; avoid duplicating a parser where a public offset/view API suffices. Relevant cached specs: assembly lines 172–211, 347–405, 445–465, 554–562, 720–766; shared §2; vmprotocol §7. `reference-cache/provenance.json` owns Page/date/hash provenance. Archives and duplicate temporary snapshots are outside routine input.

Passed: 52 package interface/home tests, full 327-test syntax suite, combined test-inclusive Clippy, package no-default-features and pinned formatting. Full package run: 202 passed, five fixture failures, one ignored. Remaining: repaired full-package validation and external production profile fixtures. Earlier processor/fuzz and later ABI/proof gates remain in the plan. Source lexer restricts quoted Unicode/backslashes; semantic paths preserve them, with frontend reconciliation tracked at PR 09.

Use fresh bounded agents with explicit exclusive files, references and constraints. Agents do no Git mutations or heavy checks; root coordinates power guards, reviews and separate code/documentation commits. No pushes or GitHub PRs. Preserve D2 source/stack/memory conventions and all security gates.
