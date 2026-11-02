# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-01-identities`, code SHA `27e100e1040f4e1def0a1967c99de199decf1f50` (exact budgeted D1 codec). Documentation commits follow it. Recheck `git rev-parse HEAD` and `git status --short` before assigning edits; local reference scratch is uncommitted.

PR 01 is in progress. The current small slice is **extracting allocation-free encoded-size preflight from EnvNode::to_bytes**. The bounded builder will reuse it before hashing/reserving rather than allocate serialized buffers to count bytes. Add a fallible encoded_len method and make the encoder delegate. Do not change any wire/hash semantics or add the builder yet.

Start with this brief and the plan's **PR 01**, **D1**, and **Workflow and completion rules**. D1 is the user-approved wire authority; the cached spec predates it. Inspect only the existing EnvNode encoder/size checks and byte fixtures. No spec chapter or unrelated source is needed for this behavior-preserving extraction.

Passed checks are in the plan's **Status ledger**, row **01 Identities**, and **Implementation evidence**, PR 01; do not copy another check ledger here. Existing codec tests and scoped checks must verify this extraction. Compare preflight sizes with independent fixture byte lengths. No joint decision blocks it. Protocol-specific wrappers/codecs remain external gates; complete validation is later work.

The fresh `node_size_preflight` agent owns only `core/src/program/environment/object/encoding.rs`; all other source stays untouched. Independent fixture lengths are in `.scratch/librarytree/evidence/object-vectors.json`. Prefer fresh bounded agents with exclusive paths/references and explicit applicable instructions: no Git mutations, pushes or PR creation; no builds/tests by the implementer; stop affected work for material shared/product/ABI/security/scope decisions and ask the orchestrator/user. Preserve power/privilege rules. This refactor grants no authority or completeness and changes no resource-policy defaults.
