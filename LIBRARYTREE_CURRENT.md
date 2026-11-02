# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable completion evidence. `PR_DESCRIPTION.md` describes final branch review scope; never use it for discovery.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-04-toolchain-contracts`, HEAD/code `a70fdc8b1`, base `45be30b96`. Documentation commits follow. Recheck Git HEAD/status before assigning edits; `.scratch/` is uncommitted.

PR 04 is active. Declaration models, semantic paths, existing invocation syntax/word procref printing, and profile-bound Home v1 are implemented. Verified InterfaceArtifact v1 construction and encoding are committed. Current small slice: **strict profile-bound artifact decoding** with canonical wire checks before authority callbacks. Reuse shared bounded codec primitives and core hashing. Require the D3 external profile/context/budgets; no package9, ReleaseRecord, fabricated D/forest, derived I or default domain/home/profile.

The next bounded decoder implementer owns mast-package `interface/artifact.rs`, `interface/artifact/declarations.rs` and shared `interface/serialization.rs` envelope extraction. A separate test agent may own new `interface/artifact/tests/decoding.rs` and its test-module declaration. Root owns integration and plan/brief edits. Preserve existing Home behavior. Preserve immutable private artifact fields; generic validity supplies no publisher, association, closure or home authority. FunctionType remains separate tooling metadata, outside wire/hash authority.

Read plan **PR 04**, **invariants 5/9**, **D2/D3**, and **Workflow and completion rules**. `.scratch/librarytree/findings-artifact-decode.md` provides bounded helper locations and the strict decoding sequence. Do not silently sort wire IDs or reinterpret non-Text declaration labels. Relevant cached specs: assembly lines 172–211, 347–405, 445–465, 554–562, 720–766; shared §2; vmprotocol §7. `reference-cache/provenance.json` owns Page/date/hash provenance. Archives and duplicate temporary snapshots are outside routine input.

Passed: 38 package interface/home tests, full 327-test syntax suite, combined test-inclusive Clippy, package no-default-features and pinned formatting. Remaining: strict decoding checks and external production profile fixtures. Earlier processor/fuzz and later ABI/proof gates remain in the plan. Source lexer restricts quoted Unicode/backslashes; semantic paths preserve them, with frontend reconciliation tracked at PR 09.

Use fresh bounded agents with explicit exclusive files, references and constraints. Agents do no Git mutations or heavy checks; root coordinates power guards, reviews and separate code/documentation commits. No pushes or GitHub PRs. Preserve D2 source/stack/memory conventions and all security gates.
