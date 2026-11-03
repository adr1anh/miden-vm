# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `6a075a069023f978c5ebfce53c8dbfb4a002a1a4` (source `108dc3607`), base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; this documentation follows. Recheck Git/status. All reviewed implementation is committed; scratch remains untracked. Implementation is paused at the user's request while discussing design. No source author is active; root owns documentation/integration.

**The two old questions are closed. D6:** actual SYSCALL requires authenticated immediate parent equal fixed `N0 = Namespace::initial()`, not configurable N_kernel. Root exports are reserved for kernel-safe entry points; application entries/unsafe helpers go beneath Env. List/Merkle preserve N at any physical depth. Ordinary invocation eligibility and all existing context/principal conventions remain. R_E still needs caller/verifier authorization. Descriptor becomes `(K_entry,R_E)`; planned new claim40/Core36/Chiplets4/deferred4 replaces the older claim44 contract without accepting legacy40 semantics.

**D7:** code-only Package9 may omit its own I/public-interface association. Complete callable/home/code/entry requirements remain; selected release/Protocol profiles retain D3 validation. Generic IDs remain supplied opaque Words. **D5:** standard assembler/project Latest/Pinned convention plus custom bindings, with unchanged MASM imports; no generic ID generator/registry/interface-commitment requirement. D4 explicit-inline eligibility/inner keys remain unchanged.

Current code still has configurable kernel fields/checks and Package8; no D6/D7 implementation claim. After discussion resumes implementation, first assign focused core descriptor/verifier, processor session/replay, Library AIR/public inputs and assembler syscall correction; then Package9 persistence/readers/commitments/stripping, then per-target project/cache routing. Keep PR15a cleanup deferred. Raw AssemblyProduct retains naming that Package8 extraction drops; callable codec and atomic NamespaceInputs are prerequisites, not final admission.

Unfrozen UX: default dependency selection and how kernel-target tooling publishes flat root exports versus helpers. Neither blocks this documentation checkpoint or fixed-N0 correction. Do not silently freeze these choices.

Read plan PR09, invariants1–10, D2–D7 and Workflow before assigned spec excerpts. D6/D7 supersede older kernel/claim/own-interface assumptions in cached Pages; keep cache provenance unchanged. Findings: `.scratch/librarytree/findings-pr09-{project,inline,assembler,package}.md`; cache `assembly.md` §§3.2/4.1/5.1–5.3/6.2/7.1–7.2.

Prior-contract evidence: namespace11/assembly465 pass,43 project failures/6 ignored; package251/one ignored; scoped Clippy/no_std and ASan fuzz5916/31s pass, LSan disabled for host ptrace. Processor test build stops at two prover calls missing ExecutionEnvironment. D6 revalidation, standard nextest and inherited gates remain. Root runs AC/heavy guards; use16MiB test-thread stack. Plan owns exact evidence; logs/tools/build/corpus remain separate scratch.

Cache `.scratch/librarytree/reference-cache/` has one copy/source with Page/date/hash provenance. Archives/shared /tmp duplicates stay outside routine agent input. Use bounded fresh agents with exclusive files and explicit constraints. No pushes or GitHub PRs.
