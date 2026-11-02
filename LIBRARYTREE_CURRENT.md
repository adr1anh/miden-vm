# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-02-keyed-mast`, code SHA `7be0e06c0c0b9df98c37199037717a06b0d38913` (childless keyed invocation nodes). PR 02 starts from PR 01 tip `4f6cda599`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 02 is in progress. Current work is **v0.0.6 codec closure** on the existing shared scanner/layout. Target-only Call/SysCall/Exec now expose target():ProcedureKey, hash K||0 under opcode domains, and have no structural children. Keep External(D) and invocation targets separate. Dense target slots follow node order exactly; hashless payloads retain K.

The fresh `dense_keyed_codec` agent owns serialization/{mod,layout,info,resolved,view}.rs and needed untrusted.rs integration. The separate `sparse_keyed_codec` agent owns serialization/sparse.rs and the ExecutionWitness version constant/tests in processor/src/trace/mod.rs. Shared node implementations remain unchanged; coordinate interfaces rather than overlapping edits. Old core fixture/arbitrary migration follows separately.

Start with this brief and plan **PR 02**, **invariants 2 and 6**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-keyed-codec.md`; consult cached execution.md **lines 508–554** only. Cache provenance.json owns Page/date/hash identity. Do not read whole chapters, archives or PR_DESCRIPTION.md.

Passed evidence belongs to the plan ledger. Current core check has eight known stale dense/sparse codec errors; node tests/Clippy are deferred until closure. No joint decision blocks these codecs. D2 preserves existing MASM syntax and stack/memory conventions, with K references/caller and same-context runtime exec; identity/hash/cycle expectations and wire formats may change.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
