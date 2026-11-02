# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-01-identities`, code SHA `3d389cf588bc1562602a2595f4d01cff0540bb54` (exact labels/TypedId boundary). Documentation commits follow it. Recheck `git rev-parse HEAD` and `git status --short` before assigning edits; local reference scratch is uncommitted.

PR 01 is in progress. The current small slice is **typed initial namespace, child namespace and procedure-key derivation**. Keep it allocation-free using the existing Word/domain hash helpers. Labels are committed, including their explicit external validator boundary. Do not expand into object builders, wire decoding, runtime resolution or verifier configuration.

Start with this brief and the plan's **PR 01 Canonical identities and execution contracts**, **Scope and invariants**, item 5, and **Workflow and completion rules**. Consult `.scratch/librarytree/reference-cache/shared.md`, **section 2**, for namespace/key derivation and hash framing; consult `provenance.json` for source identity. No assembly chapter is needed for this slice. Read further sections only for a demonstrated dependency.

Passed checks are in the plan's **Status ledger**, row **01 Identities**, and **Implementation evidence**, PR 01; do not copy another check ledger here. Namespace/key vectors and scoped checks remain pending. No joint decision blocks these derivations. Node wire format is resolved in plan **D1** but outside this slice. Protocol-specific wrappers/codecs remain external gates.

The fresh `namespace_derivation` agent owns only `core/src/program/environment.rs`; label and re-export modules stay untouched. Bounded research/vectors are in uncommitted `.scratch/librarytree/findings-namespace-derivation.md`. Prefer fresh agents (`fork_turns: none`) with exclusive paths, selected references and mandatory constraints: no commits/staging/branch changes/pushes/PR creation; stop affected work for material shared/product/ABI/security/scope decisions and ask the orchestrator/user. Preserve power/privilege rules. No graph traversal or new codec belongs in this assignment.
