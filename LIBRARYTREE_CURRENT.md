# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable completion evidence. `PR_DESCRIPTION.md` describes final branch review scope; never use it for discovery.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-04-toolchain-contracts`, HEAD/code `a4ceb8260`, base `45be30b96`. Documentation commits follow. Recheck Git HEAD/status before assigning edits; `.scratch/` is uncommitted.

PR 04 is active. Declaration models, semantic paths, existing invocation syntax/word procref printing, and profile-bound Home v1 are implemented. Current small slice: **verified InterfaceArtifact v1 native construction and canonical encoding**. Strict decoding follows separately. Reuse shared bounded codec primitives and core hashing. Require the D3 external profile/context/budgets; no package9, ReleaseRecord, fabricated D/forest, derived I or default domain/home/profile.

The fresh `artifact_verified_encoding` agent owns new mast-package `interface/artifact.rs`, `interface/artifact/declarations.rs` and focused artifact tests only. Root owns module/export/dependency wiring, integration and plan/brief edits. Existing Home codec files are stable. Preserve immutable private artifact fields; generic validity supplies no publisher, association, closure or home authority. FunctionType remains separate tooling metadata, outside wire/hash authority.

Read plan **PR 04**, **invariants 5/9**, **D2/D3**, and **Workflow and completion rules**. `.scratch/librarytree/findings-artifact-codec-scope.md` provides helper locations; its private-codec-first suggestion is superseded by encoding-first, then decoding, to keep each commit used and lintable. Relevant cached specs: assembly lines 172–211, 347–405, 445–465, 554–562, 720–766; shared §2; vmprotocol §7. `reference-cache/provenance.json` owns Page/date/hash provenance. Archives and duplicate temporary snapshots are outside routine input.

Passed: 29 package interface/home tests, full 327-test syntax suite, combined test-inclusive Clippy, package no-default-features and pinned formatting. Remaining: artifact construction/encoding/decoding checks and external production profile fixtures. Earlier processor/fuzz and later ABI/proof gates remain in the plan. Source lexer restricts quoted Unicode/backslashes; semantic paths preserve them, with frontend reconciliation tracked at PR 09.

Use fresh bounded agents with explicit exclusive files, references and constraints. Agents do no Git mutations or heavy checks; root coordinates power guards, reviews and separate code/documentation commits. No pushes or GitHub PRs. Preserve D2 source/stack/memory conventions and all security gates.
