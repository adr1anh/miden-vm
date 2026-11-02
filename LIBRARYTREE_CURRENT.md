# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-01-identities`, code SHA `d79a6c34cad43778cfeaa73326441c82f50d9e99` (canonical verifier configuration). Documentation commits follow it. Recheck `git rev-parse HEAD` and `git status --short` before assigning edits. Local reference scratch is uncommitted.

PR 01 is in progress. The current small slice is **verifier identity derivation** over relation ID, entry key and typed configuration commitment. A parallel test-only refactor moves frozen expectations into one shared Rust/MASM-consumable fixture. These are value contracts; construction does not establish trusted mounts, namespace provenance, executable availability or resource authority. Claim/request activation remains PR 12 and recursive trust remains PR 14.

Start with this brief and the plan's **PR 01**, **invariants 5 and 8**, and **Workflow and completion rules**. Consult cached shared.md **section 2** and proofs.md **section 3**, especially lines 222–287, only. Source identity is in `.scratch/librarytree/reference-cache/provenance.json`. Short research is `.scratch/librarytree/findings-verifier-contract.md`. Read no invocation/chiplet chapters or archived handoffs.

Passed checks are in the plan's **Status ledger**, row **01 Identities**, and **Implementation evidence**, PR 01; do not copy another check ledger here. Identity vectors, shared fixture checks and PR-wide acceptance remain pending. No joint decision blocks this contract slice. Protocol codecs and authorization remain external gates.

The fresh `verifier_identity` agent owns only verifier.rs and verifier/tests.rs. `shared_vector_fixture` owns existing environment/domain test blocks plus a new fixture and test-only parser; the orchestrator owns module/export integration in program/mod.rs. Production environment/claim/request behavior stays unchanged. Prefer fresh bounded agents with exclusive paths/references and explicit constraints: no Git mutations/pushes/PRs or implementer builds/tests; ask before material shared/product/ABI/security/scope decisions. Preserve power/privilege rules.
