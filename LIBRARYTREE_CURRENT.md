# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-01-identities`, code SHA `eda3053b452f7a820e8a18747362339f1466139e` (owned object commitments). Documentation commits follow it. Recheck `git rev-parse HEAD` and `git status --short` before assigning edits; local reference scratch is uncommitted.

PR 01 is in progress. The current small slice is **the exact, budgeted D1 environment-node codec**. Reuse the committed EnvNode and existing readers/errors. Do not add another node representation, graph validation, runtime resolution or verifier configuration. Selected hashes remain unchanged.

Start with this brief and the plan's **PR 01**, **invariant 5**, **D1**, and **Workflow and completion rules**. D1 is the user-approved wire authority; the cached shared spec predates that decision. Consult shared.md **sections 2–3** only for hash/admission boundaries, with source identity in cache `provenance.json`. No invocation/proof chapters are needed.

Passed checks are in the plan's **Status ledger**, row **01 Identities**, and **Implementation evidence**, PR 01; do not copy another check ledger here. D1 byte vectors, malformed/truncated/noncanonical fields, overflow and exact-budget tests remain pending. No joint decision blocks this codec. Protocol-specific wrappers/codecs remain external gates.

The fresh `node_codec` agent owns new `core/src/program/environment/object/encoding.rs` and the parent `object.rs` module declaration/helper access only. Re-exports and labels stay untouched. Relevant short findings/vectors: `.scratch/librarytree/findings-node-codec.md` and `evidence/object-vectors.json`. Reject full input exceeding the caller budget before using BudgetedReader: exhausted budgets can hide suffixes. Prefer fresh bounded agents with exclusive paths/references and mandatory constraints: no Git mutations, pushes or PR creation; stop affected work for material shared/product/ABI/security/scope decisions and ask the orchestrator/user. Preserve power/privilege rules.
