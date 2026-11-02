# LibraryTree current work

This is the short handoff for the current slice. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) remains the sole backlog, scope, dependency and acceptance authority; its status ledger and implementation evidence own durable completion. `PR_DESCRIPTION.md` describes final branch review scope and is not a discovery source.

Verified implementation checkpoint on 2 November 2026: branch `adr1anh/librarytree-01-identities`, code SHA `ed50330fcd550a52138b0bb1cc8c185900515e83` (namespace/key derivation). Documentation commits follow it. Recheck `git rev-parse HEAD` and `git status --short` before assigning edits; local reference scratch is uncommitted.

PR 01 is in progress. The current small slice is **one owned EnvNode representation and its five object commitments**. Reuse it for later encoding, avoiding borrowed/owned shadow enums. Hashing uses existing helpers with checked List flattening. Do not add wire decoding, graph validation, runtime resolution or verifier configuration in this slice.

Start with this brief and the plan's **PR 01 Canonical identities and execution contracts**, **Scope and invariants**, item 5, and **Workflow and completion rules**. Consult `.scratch/librarytree/reference-cache/shared.md`, **sections 2–3.1**, for hash/object contracts and admission boundaries; consult `provenance.json` for source identity. Stop before invocation/proof sections. Read further material only for a demonstrated dependency.

Passed checks are in the plan's **Status ledger**, row **01 Identities**, and **Implementation evidence**, PR 01; do not copy another check ledger here. Object vectors/length-allocation rejection and scoped checks remain pending. No joint decision blocks hashing. Node wire format is resolved in plan **D1** but remains a separate slice. Protocol-specific wrappers/codecs remain external gates.

The fresh `object_commitments` agent owns new `core/src/program/environment/object.rs` and its re-exports in `environment.rs`/`program/mod.rs`; labels stay untouched. Short findings and independent vectors are `.scratch/librarytree/findings-object-commitments.md` and `evidence/object-vectors.json`. Prefer fresh bounded agents (`fork_turns: none`) with exclusive paths, selected references and mandatory constraints: no commits/staging/branch changes/pushes/PR creation; stop affected work for material shared/product/ABI/security/scope decisions and ask the orchestrator/user. Preserve power/privilege rules. Node commitments confer no completeness or authority.
