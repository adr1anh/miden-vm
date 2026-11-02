# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-03-chiplet-foundation`, code SHA `411b22f8b2d4921a21afa98faf5f6e4101962974` (Memory relation simplification); stack base `7602d32ed`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 03 is in progress. Current slice: **checked logical Controller-address ownership**, retaining today's zero Library prefix. Distinguish zero-based row positions, nullable one-based logical addresses and operation-log indices. Use existing trace-length limits/errors and checked advance/span arithmetic; overflow must return through existing error paths. Do not change VM clocks, contexts, RAM/overflow addresses or invocation semantics.

The fresh `controller_address_owner` agent owns chiplets/{layout.rs,mod.rs,hasher/trace.rs,hasher/mod.rs,hasher/tests.rs}, execution_tracer.rs and parallel/{mod.rs,tracer/trace_row.rs}, all under processor/src/trace. Coordinate any necessary additional path before editing it. Final physical conversion/state-codec wiring is a separate next slice; retain logical replay/snapshots now. Fast execution's intentional zero remains absent.

Start with this brief and plan **PR 03**, **invariants 3 and 7**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-controller-address-owner.md`; consult cached chiplet.md **section 7.3** only as needed. Cache provenance.json owns source identity. Archives, whole chapters and PR_DESCRIPTION.md are not discovery inputs.

Passed evidence belongs to the plan ledger. Memory unit/generated/Clippy checks pass. Address boundary/memoization/overflow tests remain pending; processor compilation has known old callable consumers deferred to PRs 05/09. No joint decision blocks ownership extraction. Selected Chiplets24/4, 22-cell Library, nine periodic columns, lookup capacity, degree≤9 and four AIRs remain measured final gates. Preserve D2's existing MASM syntax and stack/memory conventions.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
