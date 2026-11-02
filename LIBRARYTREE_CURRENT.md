# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable completion evidence. `PR_DESCRIPTION.md` describes final branch review scope; never use it for discovery.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-05-keyed-execution`, HEAD/base `7223926826fe1ffa1fb4057bf92fbf0b9a7ffec0`; latest code `2a3f608e3`. Documentation commits follow. Recheck Git HEAD/status before assigning edits; `.scratch/` is uncommitted.

PR 05 is active. Current small slice: **bounded environment-opening verification** returning an authenticated parent namespace/implementation for requested K under immutable R_E. Reuse core EnvNode commitments and namespace/key derivation. Validate complete List child material before selection; selective Merkle opening is allowed. No full environment enumeration or root-admission authority is inferred. Occurrence ledger/session and invocation transitions follow in separate slices.

A fresh implementer may own new processor `src/environment/{mod,witness,tests}.rs` plus module/export wiring only. Root will assign exact ownership and review the API checkpoint before expansion. Host adapters, existing invocation transitions, Core arbitrary generator and trace consumers are not yet assigned. No in-flight code exists at this checkpoint. Root owns integration and plan/brief edits.

Read plan **PR 05**, **invariants 1–4/6/10**, **D2**, and **Workflow and completion rules**. Use `.scratch/librarytree/findings-runtime-opening-contract.md` for exact source/API locations, especially cached execution lines 469–504, 556–649, 753–799; chiplet 183–226, 307–422; shared 450–527. Its all-foundation-first suggestion is split into opening verification, then ledger/session. `reference-cache/provenance.json` owns Page/date/hash provenance. Archives, duplicate snapshots and whole chapters are outside routine input.

Prior checks: package: 208 passed/one manual seed ignored; interface: 52 passed; syntax: 327 passed; scoped/combined Clippy; package no-default-features and formatting. New processor checks are pending. Inherited processor has ten known keyed-cutover errors; PRs 02/03 validation remains in the ledger. PR 04 awaits external production Protocol fixtures; source question is pending. Later ABI/proof gates remain explicit.

Use fresh bounded agents with exclusive files/references and constraints. Agents do no Git mutations or heavy checks; root coordinates power guards, independent reviews and separate code/documentation commits. No pushes or GitHub PRs. Preserve D2 source/stack/memory/principals, full N_kernel authorization and immutable environment authority; host resolution alone is not proof completion.
