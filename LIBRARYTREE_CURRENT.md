# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-04-toolchain-contracts`, base `45be30b96d07121fd1ee2ffe2e99fd46e8bf1ca7`; latest code `a8e0daec9ccb352138ca1a528308378d4e71d0cf`. Documentation commits follow; local reference scratch is uncommitted. Recheck Git HEAD/status before assigning edits.

PR 04 is in progress. First slice: **declaration-only in-memory interfaces and explicit NamespacePlan key derivation**. Public source paths and exact optional UTF-8 ABI need no body/D/forest; tooling FunctionType is separate. Require explicit typed home paths and derive labels/keys with existing core helpers. Generic validity grants no identity, publisher or home authority. Do not freeze unreviewed identity/closure fields, activate package9 or implement wire/hash methods yet.

The fresh `interface_declaration_model` agent owns new crates/mast-package/src/{interface.rs,namespace_plan.rs}, their tests and exports in lib.rs only. Existing executable manifest/package behavior stays unchanged. Use parsed Path components rather than splitting rendered names; preserve quoted separators, Unicode bytes, typed home labels and absent/present-empty ABI.

Start with this brief and plan **PR 04**, **invariants 5 and 9**, **D2**, and **Workflow and completion rules**. Read `.scratch/librarytree/findings-frontend-contract-gates.md`; consult only its named assembly/shared/vmprotocol sections. Cache provenance.json owns source identity. Archives, whole chapters and PR_DESCRIPTION.md are not discovery inputs.

Passed checks and deferred owners belong to the plan ledger. PRs 02/03 await processor/fuzz validation after later consumers. Declaration model tests remain pending. User authorized the shared-wire draft for review; `.scratch/librarytree/protocol-interface-v1-draft.txt` is not adopted guidance. No wire-dependent work proceeds until material decisions are resolved. No decision blocks the first in-memory slice. Preserve existing MASM syntax and stack/memory conventions; optional syntax can wait.

Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
