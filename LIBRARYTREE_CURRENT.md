# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `91c8cc96ba4f6532bf460c40458cb81e528bf1d5`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; this documentation follows. Recheck Git/status. Core/AIR fixed-root changes are committed. Processor and assembly changes are reviewed, uncommitted. Root owns integration/docs/checks; all authors are frozen. Scratch remains untracked.

**D6/D8:** actual SYSCALL requires authenticated immediate parent equal fixed `N0 = Namespace::initial()`. Public kernel exports occupy root, private helpers/applications child Env; no extra syscall-export list. List/Merkle preserve N. Preserve unique root names, invocation/context/principal conventions and caller/verifier-authorized R_E. Plan: `(K_entry,R_E)`, new claim40/Core36/Chiplets4/deferred4; reject legacy40/obsolete44.

**Revised D3/D7 select C:** generic code package without own_library_id/own_interface_commitment, plus a separate publication/release wrapper (distribution may remain one file). Library identity is a supplied opaque Word; derivation, including the Page formula, and interface policy remain external/open. Optional human-readable maps/tooling traits resolve before assembly; names grant no authority. Complete callable/home/code/entry metadata and every selected-profile validation remain required. **D5:** standard Latest/Pinned naming plus custom bindings; unchanged MASM imports. D4 inline eligibility/inner keys remain.

Overall completion means the full approved plan and final qualification, not a milestone. **M1:** D6–D8 alignment under revised D3/D7 model C, including affected consumer/format/proof validation; source-only correction does not close it. Active PR09: validate/commit processor replay-v5 and assembler fixed-root API removal; then implement kernel public-root/private-child construction validation. Next: C's generic Package9 persistence/readers/commitments/stripping and publication boundary, then project/cache routing. Preserve AssemblyProduct/codec/NamespaceInputs work; it is prerequisite metadata, not admission. Keep PR15a cleanup deferred.

One unfrozen product choice: unspecified dependencies default to Latest or require explicit Latest/Pinned (recommend explicit initially). It does not block fixed-N0 correction. Wrapper/catalog APIs and helper-prefix spelling are implementation design. External production-profile inputs gate that integration, not generic VM progress.

Read Workflow/M1, PR09, invariants1–10 and D2–D8 before assigned excerpts. Current D3/D7 supersede earlier identity-formula/own-field decisions; D6/D8 supersede old kernel/claim assumptions. Cache `assembly.md` §§3.2/4.1/5.1–5.3/6.2/7.1–7.2 remains reference. Findings: `.scratch/librarytree/findings-pr09-{project,inline,assembler,package}.md`.

Fixed-root checks: core408 pass/one ignored, public API pass; AIR387 pass/one known legacy claim-copy failure; core/AIR strict Clippy/no_std pass. Harnesses: session52, native/source22, execution22, witness10 pass. Normal processor still needs prover consumer migration; Package8/project failures and inherited final gates remain. Prior codec/fuzz evidence is in the plan. Root runs AC/heavy guards; use16MiB test stack.

Cache `.scratch/librarytree/reference-cache/` retains Page/date/SHA-256 provenance. Archives, shared /tmp duplicates and logs stay outside routine input. Use bounded fresh agents with explicit ownership/constraints. No pushes or GitHub PRs.
