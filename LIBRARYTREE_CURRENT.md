# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-03-chiplet-foundation`, code SHA `48896072b330bf8b2d368e9a8a3a17db0d8f0627` (checked logical Controller owner); Memory slice `411b22f8b`; stack base `7602d32ed`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 03 is in progress. Current slice: **one checked physical layout at final trace materialization**. Keep saved/replayed addresses and memoization operation indices logical. Translate Controller address roles exactly once, preserving absent zero and valid row zero. Recompute address-dependent helpers from physical values; leave VM clocks, contexts, RAM/overflow addresses, principal and invocation semantics unchanged. Current production Library prefix remains zero.

The fresh `controller_physical_layout` agent owns chiplets/{layout,mod}.rs; parallel/{mod,tracer/mod,tracer/trace_row,tests}.rs; {execution_tracer,block_stack,trace_state,utils}.rs; trace_state/{serde,serialization_tests}.rs under processor/src/trace; plus processor/src/tracer.rs. Coordinate additional paths before editing. Reuse codecs with logical values; add no physical prefix to persisted state. Existing ControllerRow permits exact-cap end cursors: separate cursor representation from actual materializable row bounds.

Start with this brief and plan **PR 03**, **invariants 3 and 7**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-controller-address-owner.md` and its short implementation findings; consult cached chiplet.md **section 7.3** only as needed. Cache provenance.json owns source identity. Archives and PR_DESCRIPTION.md are not discovery inputs.

Passed evidence belongs to the plan ledger. Memory checks pass; logical-address tests remain unrun behind ten known callable-cutover errors. Physical/sentinel/helper/parallel/state-roundtrip cases are pending. No joint decision blocks layout wiring. Selected Chiplets24/4, 22-cell Library, nine periodic columns, lookup capacity, degree≤9 and four AIRs remain measured final gates. Preserve D2's existing MASM syntax and stack/memory conventions.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
