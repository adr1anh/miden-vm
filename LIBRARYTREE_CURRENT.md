# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-01-identities`, code SHA `295809479c54384413175681a1f7a37b7f17f120` (shared size preflight). Documentation commits follow it. Recheck `git rev-parse HEAD` and `git status --short` before assigning edits; local reference scratch is uncommitted.

PR 01 is in progress. The current small slice is **bounded owned-node storage and input/resource preflight** for the complete-environment builder. Reuse encoded_len before hashing/reserving. Complete traversal, uniqueness and a validated result are the following slice; do not certify partial inputs now. This optional full-preimage utility must not become mandatory procedure enumeration for runtime mounting of externally admitted fragments.

Start with this brief and the plan's **PR 01**, **invariant 5**, and **Workflow and completion rules**. Consult cached shared.md **sections 3–3.1** for complete-path uniqueness/composition boundaries; D1 governs node wire bytes. Source identity is in cache provenance.json. Read no invocation/proof chapters or unrelated sources.

Passed checks are in the plan's **Status ledger**, row **01 Identities**, and **Implementation evidence**, PR 01; do not copy another check ledger here. Builder limit/capacity/overflow/failed-insert checks remain pending. No joint decision blocks this utility. Explicit caller limits bound requested storage/work, not allocator overhead or process RSS. Protocol-specific wrappers/codecs remain external gates.

The fresh `builder_storage` agent owns new `core/src/program/environment/builder.rs`, optional `builder/tests.rs`, and re-exports in `environment.rs`/`program/mod.rs`; object/label code stays untouched. Short research is `.scratch/librarytree/findings-environment-builder.md`. Prefer fresh bounded agents with exclusive paths/references and explicit applicable instructions: no Git mutations, pushes or PR creation; no builds/tests by implementers; ask the orchestrator/user before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules. No implicit limits, root authority, availability or opaque-fragment certificate belongs in this slice.
