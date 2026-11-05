# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-01-identities`, code/test SHA `8152f9a34643727616c82f1bf16510ecdd644524`. The working tree contains only uncommitted local reference scratch. Documentation commits follow this checkpoint. Recheck `git rev-parse HEAD` and `git status --short` before assigning edits.

PR 01 is complete. The current small slice is its branch closure: record reviewed acceptance evidence, finalize the branch review description separately, then create the stacked PR 02 branch. No implementation agent owns files during this transition. The next bounded change reserves EXEC opcode 0x5f and keeps it excluded from basic-block decoding; it does not activate runtime execution or AIR semantics.

Start with this brief and the plan's **PR 02**, **invariants 2 and 6**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-keyed-mast.md` and `.scratch/librarytree/findings-mast-compatibility.md` for exact current-source locations. Consult cached execution.md **lines 151–219 and 508–554** only when required. Source identity is in `.scratch/librarytree/reference-cache/provenance.json`; archives and old handoffs are not routine input.

Passed checks are in the plan's **Status ledger** and **Implementation evidence**, PR 01; do not copy another ledger here. PR 02 checks remain pending. No joint decision blocks opcode reservation. D2 preserves existing MASM source after rebuilding and interprets digest-shaped targets as keys; a new serialized MAST format is allowed. Protocol codecs/authority and later ABI/AIR gates remain open in the plan.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
