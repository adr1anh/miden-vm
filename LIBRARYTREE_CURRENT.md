# LibraryTree current work

This brief owns handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final review scope, never discovery.

Verified source checkpoint 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `694e2b5ce718840a71eb867c20a87df67c44b3c4`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; documentation follows separately. Tracked tree clean before this documentation edit. Recheck Git/status. Root owns integration/docs/checks; one read-only core-producer auditor remains, no Rust checks active.

**D6/D8:** actual SYSCALL requires authenticated immediate parent equal fixed nonzero N0, independent of R_E. Public kernel exports occupy root; helpers/applications child Env. No extra export list. List/Merkle preserve N. Preserve root-name uniqueness, canonical aliases, invocation/context/principals and caller-authorized R_E. Target remains claim40/Core36/Chiplets4/deferred4 with legacy rejection.

**D3/D7 C:** generic packages have no own I/interface fields. Identity is supplied opaque; derivation/publication policy remains external. Readable maps grant no authority; selected-profile checks stay mandatory. Preserve D4 inline eligibility/inner keys.

**D5:** explicit Latest/Pinned/custom source-default requests reach namespace providers and are checked before cache reuse; complete Bound declarations/reexports remain independent. Standard artifact imports require expected callables; automatic target naming/distinct instances remain PR10. TypedId ancestors work in memory; generic writing rejects unsupported persistence. See project README/code.

The overall goal stays broad. **M1:** D6–D8 alignment including downstream proof/format qualification. Active **PR09:** bounded CLI execution-evidence admission is checked in. Caller descriptor/policies remain authoritative; JSON supplies exact node preimages/slots only. Owned files: `miden-vm/src/internal/execution_inputs.rs`, shared core codec/file helpers, and `prover/tests/execution_inputs.rs` (includes the real module). See plan PR09, D3–D8 and the latest evidence checkpoint; preserve their invariants rather than reading every chapter.

**Next:** explicit shared CLI descriptor/policy arguments and core-library producer naming, followed by source/package loader migration retaining or independently admitting PackageNaming. Raw package admission needs a caller-selected profile/context; never infer it from openings/package data. Audit `cli/{run,prove,data,utils}.rs` and `crates/lib/core/build.rs:239`. Keep private advice/code separate. PR10 artifact expectations and PR12 claim transport remain dependencies; PR15a stays deferred.

Fresh checks: admission 21, codec 8 and file-helper 6 tests pass; strict focused Clippy and support-library no_std pass. Whole-VM/CLI compilation, core generation and proof qualification remain pending. No profile/default decision was added. Previous Wasm/fuzz evidence and deferred guest/project E2E checks stay in the ledger. Preserve prover security mutations; zero-root-principal counterfactual assumptions need renewed qualification after PR12. M1/final gates remain open.

User requests parallel source work/review and fewer compilations: fresh bounded agents (`fork_turns:none`), exact ownership; root batches essential AC/heavy-guarded checks with 16MiB stacks. Cache `.scratch/librarytree/reference-cache/` retains Page/date/SHA-256; logs/archives/shared /tmp stay outside routine input. No pushes/GitHub PRs.
