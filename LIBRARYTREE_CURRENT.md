# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-03-chiplet-foundation`, base `7602d32ed8094e6d7c460153c8d111d03c7726b7`; latest implementation/test SHA `364fbb35c18f2fa503f44c8ad34773f484a7d365`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 03 is in progress. First slice: **simplify Memory conditional inverses and selected delta while preserving the accepted relation**. Keep context Booleanity/closure, constrain the existing same-context/address flag directly, and express the selected delta through that flag. Preserve first-entry, range, read-only, value and untouched-slot constraints. Add no helper columns, address migration or other chiplet changes.

The fresh `memory_inverse_refactor` agent owns only crates/air/source/src/vm/constraints/chiplets/memory.rs and its existing two-row test harness. Prove old/new zero-set equivalence for both context cases, including non-Boolean address-change ratios when context changes, and test malicious inverse/flag assignments. Generated evaluators come from the existing build pipeline.

Start with this brief and plan **PR 03**, **invariants 3 and 7**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-chiplet-foundation.md`; consult only cached chiplet.md **section 7.2** as needed. Cache provenance.json owns source identity. Archives, whole chapters and PR_DESCRIPTION.md are not discovery inputs.

Passed checks and exact deferred owners belong to the plan ledger. Memory equivalence and generated capture/drift checks are pending. PR 02 remains implemented-awaiting-validation for witness/fuzz checks on later dependencies. No joint decision blocks this refactor. Selected Chiplets24/4, 22-cell Library, nine periodic columns, lookup capacity, degree≤9 and four AIRs remain measured final gates. Preserve D2's existing MASM syntax and stack/memory conventions.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
