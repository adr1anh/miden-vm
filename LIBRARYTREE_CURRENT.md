# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified source checkpoint 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `8a2fb1cc3ec2b45aea30e0d2fca7f84250b51729`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; documentation follows separately. Recheck Git/status. Root owns integration/docs/checks; source authors/reviewers finished, no Rust checks remain active, scratch is untracked.

**D6/D8:** actual SYSCALL requires authenticated immediate parent equal fixed `N0 = Namespace::initial()`. Public kernel exports occupy root, private helpers/applications child Env; no extra syscall-export list. List/Merkle preserve N. Preserve unique root names, canonical alias keys, invocation/context/principal conventions and caller/verifier-authorized R_E. Statement target remains new claim40/Core36/Chiplets4/deferred4 with legacy rejection.

**Revised D3/D7 C:** generic code packages have no own I/interface fields; separate publication/release semantics remain external. Library identity is a supplied opaque Word; derivation/interface policy stay open. Readable maps grant no authority. Selected-profile validation remains mandatory. D4 inline eligibility/inner keys remain. **D5 requires explicit Latest/Pinned selection; omission rejects.** Custom bindings remain supported; selector/file configuration and PR10 distinct instances remain unimplemented.

The overall goal covers the full plan and qualification. **M1:** D6–D8 alignment under revised D3/D7, including downstream proof/format checks. Active **PR09 next slice:** root owns processor unit fixtures, starting `processor/src/fast/tests/mod.rs`; then trace/execution, CLI/test/fuzz consumers. Legacy Program/ProgramInfo transport needs PR12 cutover. Keep PR15a deferred.

Prover execution now accepts caller ExecutionEnvironment. Shared Test fixtures retain canonical naming, build bounded validated environments and serve bounded openings; no K/root authority comes from body hashes. Use `miden_utils_testing::Test::fixture_environment`/`librarytree` helpers. Processor unit tests need `test_utils::native_fixture_environment` to bridge the dependency and unit-test crate's distinct native types. Kernel naming shares FixtureNamespace::add_kernel_modules. No implicit production home/profile.

Fresh guarded checks: prover regression1 covers both scheduling modes; shared test-utils12 pass; normal processor package-entry4 pass; assembly Nextest540 pass/6 skips. Strict scoped prover/test-utils/processor Clippy, no_std and formatting checks pass. Full processor unit build still has226 older API/fixture errors, largest in fast/tests/mod.rs; no unit tests ran. Native/recursive/generated/final gates remain. Prior package289/one ignored evidence remains in the ledger.

Read plan PR09/10 and relevant invariants/D3–D8. External production-profile inputs gate their integration alone. Scratch findings index sources; reference cache `.scratch/librarytree/reference-cache/` preserves Page/date/SHA-256. Archives/logs/shared /tmp stay outside routine input. Fresh bounded agents need explicit ownership/instructions. Root runs AC/heavy guards and16MiB test stacks. No pushes or GitHub PRs.
