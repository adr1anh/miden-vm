# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable completion evidence. `PR_DESCRIPTION.md` describes final branch review scope; never use it for discovery.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-04-toolchain-contracts`, HEAD/code `2a3f608e3`, base `45be30b96`. Documentation commits follow. Recheck Git HEAD/status before assigning edits; `.scratch/` is uncommitted.

PR 04 generic implementation and local checks are finished. It remains **implemented-awaiting-validation** because production Protocol profile fixtures are missing. Current small slice: finalize/commit this branch's review description, then create the planned PR 05 branch and begin bounded environment opening/Resolve-ledger foundations. Keep PR 04's external validation gate explicit across the branch transition.

All implementer file ownership is released. Root owns final documentation, integration and branch transition. No in-flight code remains. For the next slice, one fresh bounded agent may own new processor `src/environment/{mod,witness,ledger,tests}.rs` plus module/export wiring only; host adapters and invocation transitions will be assigned separately. Do not start coding until root verifies the new branch and assigns exact ownership.

For closure read plan **PR 04**, **D3**, and **Workflow and completion rules**, plus `.scratch/librarytree/findings-pr04-acceptance.md`. For PR 05 preparation read **PR 05**, **invariants 1–4/6/10**, and `.scratch/librarytree/findings-runtime-opening-contract.md`; it names exact cached execution/chiplet/shared ranges and code helpers. `reference-cache/provenance.json` owns Page/date/hash provenance. Archives, duplicate temporary snapshots and whole chapters are outside routine input.

Passed: full package suite: 208 passed with one manual seed generator ignored; interface/Home filter: 52 passed; full syntax suite: 327 passed; scoped/combined test-inclusive Clippy; package no-default-features; pinned formatting. Remaining PR 04 gate: owner-approved descriptor/domain/home/association/closure fixtures. The user has been asked for their source. Earlier processor/fuzz and later ABI/proof gates remain in the plan. Source lexer reconciliation and actual executable key lowering remain PR 09.

Use fresh bounded agents with explicit files, references and constraints. Agents do no Git mutations or heavy checks; root coordinates power guards, independent reviews and separate code/documentation commits. No pushes or GitHub PRs. Preserve immutable environment authority, D2 source/stack/memory conventions and all security gates.
