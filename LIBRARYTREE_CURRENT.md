# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-02-keyed-mast`, code/test SHA `364fbb35c18f2fa503f44c8ad34773f484a7d365`. PR 02 starts from PR 01 tip `4f6cda599`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 02 is implemented-awaiting-validation. Its core acceptance cases pass, including the final explicit structural-cycle and real keyed-recursion fixtures. Processor witness-v3 tests require PRs 05/09 to close old consumers; fuzz compilation/smoke remains PR 16. No agent owns edits during branch closure. Finalize PR_DESCRIPTION.md separately, then create the stacked PR 03 branch.

The next bounded slice simplifies existing Memory conditional inverses and selected delta, preserving the relation and all untouched constraints. No new helper columns or address migration belong to that first commit. Read `.scratch/librarytree/findings-chiplet-foundation.md` for exact source/test locations and the distinction between operation-log indices, one-based public controller addresses and absent-address sentinels.

Start with this brief and plan **PR 03**, **invariants 3 and 7**, **D2**, and **Workflow and completion rules**. Consult only the Memory subsection of cached chiplet.md **section 7.2** when required. Cache provenance.json owns source identity. Archives, whole chapters and PR_DESCRIPTION.md are not discovery inputs.

Passed checks and exact deferred owners belong to the plan ledger; do not create another check ledger here. PR 03 validation is pending. No joint decision blocks the initial Memory refactor. Selected Chiplets24/4 and degree/lookup/periodic/four-AIR gates remain later measured requirements. D2 preserves existing MASM syntax and stack/memory conventions, with K references/caller and same-context runtime exec; identities/hash/cycle expectations and wire formats may change.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
