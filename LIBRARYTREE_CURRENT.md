# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-02-keyed-mast`, code/test SHA `9ebac7cc181ce66fa3b736fc401a57c16eab98f0`. PR 02 starts from PR 01 tip `4f6cda599`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 02 is in progress. Current work closes two **explicit cycle/recursion acceptance fixtures** found by final audit. Structural self/two-node cycles must reject; self/mutually recursive ProcedureKey bindings must be representable without structural cycles or implementation-digest fixed points. These are representation tests, not nonterminating runtime execution.

The fresh `mast_cycle_fixtures` agent owns cfg(test) additions in mast/dense_order.rs and a new mast/node/keyed_recursion_tests.rs plus its cfg(test) module declaration in node/mod.rs. Keep production code unchanged. Build real namespace/label-derived keys before code, then bind those keys to resulting D values using the existing optional environment builder. Distinguish defensive corrupted structural cycles from real hash-cycle evidence.

Start with this brief and plan **PR 02**, **invariants 2 and 6**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-pr02-acceptance.md`; consult cached execution.md **lines 151–219** only when required. Cache provenance.json owns source identity; archives and PR_DESCRIPTION.md are not discovery inputs.

Passed evidence belongs to the plan ledger. Full core/arbitrary tests, public API, seeds and Clippy pass. The two explicit cases remain pending; processor witness checks await PRs 05/09 and fuzz smoke PR 16. No joint decision blocks fixtures. D2 preserves existing MASM syntax and stack/memory conventions, with K references/caller and same-context runtime exec; hardcoded identities/hash/cycle expectations and wire formats may change.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
