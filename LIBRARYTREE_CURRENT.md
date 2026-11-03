# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `3536ebd7109533900d16cc2dedecd63df3b37ee1` (source `108dc3607`), base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; this documentation follows. Recheck Git/status. Implementation is committed and paused for discussion; scratch is untracked. No source author is active; root owns documentation/integration.

**The two old questions are closed. D6:** actual SYSCALL requires authenticated immediate parent equal fixed `N0 = Namespace::initial()`, not configurable N_kernel. Root is reserved for kernel-safe exports; applications use child Env. List/Merkle preserve N at any physical depth. Ordinary invocation eligibility and all existing context/principal conventions remain. R_E still needs caller/verifier authorization. Plan: `(K_entry,R_E)`, new claim40/Core36/Chiplets4/deferred4; reject legacy40/obsolete44.

**D7:** code-only Package9 may omit its own I/public-interface association. Complete callable/home/code/entry requirements remain; selected release/Protocol profiles retain D3 validation. Generic IDs remain supplied opaque Words. **D5:** standard assembler/project Latest/Pinned convention plus custom bindings, with unchanged MASM imports; no generic ID generator/registry/interface-commitment requirement. D4 explicit-inline eligibility/inner keys remain unchanged. **D8:** public executable kernel exports at root, private helpers beneath child Env; no extra syscall-export list. Root placement alone determines VM eligibility; retain unique root names and canonical alias identities.

Current code still has configurable kernel fields/checks and Package8; no D6–D8 implementation claim. When the user resumes, first coordinate core descriptor/verifier, processor session/replay, Library AIR/public inputs and assembler syscall/placement correction; then Package9 persistence/readers/commitments/stripping, then per-target project/cache routing. Keep PR15a cleanup deferred. AssemblyProduct retains naming lost by Package8 extraction; codec/NamespaceInputs are prerequisites, not admission.

Unfrozen product UX: whether an unspecified dependency selection defaults to Latest or requires explicit Latest/Pinned. It does not block fixed-N0 correction. Helper-prefix spelling and exact fields/APIs remain implementation design, not new architecture blockers.

Read plan PR09, invariants1–10, D2–D8 and Workflow before assigned spec excerpts. D6/D7 supersede older kernel/claim/own-interface assumptions in cached Pages; keep cache provenance unchanged. Findings: `.scratch/librarytree/findings-pr09-{project,inline,assembler,package}.md`; cache `assembly.md` §§3.2/4.1/5.1–5.3/6.2/7.1–7.2.

Prior-contract evidence: namespace11/assembly465 pass,43 project failures/6 ignored; package251/one ignored; scoped Clippy/no_std and ASan fuzz5916/31s pass, LSan disabled for host ptrace. Processor test build stops at two prover calls missing ExecutionEnvironment. D6 revalidation, standard nextest and inherited gates remain. Root runs AC/heavy guards; use16MiB test-thread stack. Plan owns exact evidence; logs/tools/build/corpus remain separate scratch.

Cache `.scratch/librarytree/reference-cache/` has one copy/source with Page/date/hash provenance. Archives/shared /tmp duplicates stay outside routine agent input. Use bounded fresh agents with exclusive files and explicit constraints. No pushes or GitHub PRs.
