# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-02-keyed-mast`, code/test SHA `90ef69d6d5e16b50a6824d5c489e66e672f737bf`; generator slice `91d52f92c`. PR 02 starts from PR 01 tip `4f6cda599`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 02 is in progress. Current work is **keyed fuzz-oracle and seed coverage**, followed by a bounded final acceptance audit. The fixture migration is validated. Call/SysCall/Exec take ProcedureKeys and have no structural children; dense v0.0.6 preserves K in canonical slots/full/hashless/views, sparse replay carries K under ExecutionWitness v3. Keep External(D) separate.

The fresh `keyed_fuzz_surface` agent owns only mast/serialization/seed_gen.rs and tools/miden-core-fuzz/fuzz_targets/{mast_node_info,mast_forest_wire_view_new}.rs. Preserve existing root-order/large-ID oracles, capture expected keys before serialization, include distinct/repeated keys and all immediate modes, and do not duplicate the wire parser. Actual corpus output remains local/uncommitted.

Start with this brief and plan **PR 02**, **invariants 2 and 6**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-keyed-fuzz-surface.md`; consult cached execution.md **lines 508–554** only when required. Cache provenance.json owns source identity; archives and PR_DESCRIPTION.md are not discovery inputs.

Passed evidence belongs to the plan ledger. MAST tests and test-inclusive Clippy pass; seed generation/final audit remain pending. Processor witness execution checks await downstream invocation migration; bounded fuzz smoke remains PR 16. No joint decision blocks this slice. D2 preserves existing MASM syntax and stack/memory conventions, with K references/caller and same-context runtime exec; hardcoded identities/hash/cycle expectations and wire formats may change.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
