# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-02-keyed-mast`, code SHA `9d80e8eafc287b825c6303c92d1d18589a47c572` (dense v0.0.6); sparse/witness slice `85171ecad`. PR 02 starts from PR 01 tip `4f6cda599`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 02 is in progress. Current work is **core fixture and arbitrary-generator migration**. Call/SysCall/Exec now take ProcedureKey targets and have no structural children. Dense slots preserve target keys through all views/hashless forms; sparse replay uses direct keys and ExecutionWitness v3. Do not rebuild a callee-ID model or add compatibility adapters.

The fresh `core_mast_fixtures` agent owns mast/{tests.rs,merger/tests.rs,multi_forest_node_iterator.rs,node/basic_block_node/arbitrary.rs,serialization/tests.rs}. Keep production code unchanged except the existing arbitrary generator. Tests must distinguish structural traversal/retention from symbolic calls, preserve keys across merging and use explicit independent key fixtures. Existing source identities/hash/cycle expectations may migrate.

Start with this brief and plan **PR 02**, **invariants 2 and 6**, **D2**, and **Workflow and completion rules**. Use the compiler log only for exact locations: `.scratch/librarytree/logs/pr02-core-test-compilation.log`. Consult cached execution.md **lines 151–219 and 508–554** only when required. Cache provenance.json owns source identity; archives and PR_DESCRIPTION.md are not discovery inputs.

Passed evidence belongs to the plan ledger. Production checks pass; test compilation has 42 legacy errors in these five files. Node/codec/MAST tests and test-inclusive Clippy remain pending. No joint decision blocks migration. D2 preserves existing MASM syntax and stack/memory conventions, with K references/caller and same-context runtime exec; hardcoded identities/hash/cycle expectations and wire formats may change.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
