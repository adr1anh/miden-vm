# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified source checkpoint 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `7d15864e0cded6b914bcccd986a1d4fe67483c9a`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; documentation follows separately. Recheck Git/status. Root owns integration/docs/checks; source authors and Rust checks finished; scratch stays untracked.

**D6/D8:** actual SYSCALL requires authenticated immediate parent equal fixed nonzero `N0 = Namespace::initial()`, independent of R_E. Public kernel exports occupy root, private helpers/applications child Env; no extra syscall-export list. List/Merkle preserve N. Preserve root-name uniqueness, canonical alias keys, invocation/context/principal conventions and caller/verifier-authorized R_E. Target remains new claim40/Core36/Chiplets4/deferred4 with legacy rejection.

**Revised D3/D7 C:** generic packages have no own I/interface fields; separate publication/release semantics remain external. Library identity is a supplied opaque Word; derivation/interface policy remain open. Readable maps grant no authority. Selected-profile validation stays mandatory. D4 inline eligibility/inner keys remain. **D5 requires explicit Latest/Pinned selection; omission rejects.** Exact configuration/API design and PR10 distinct instances remain implementation work; custom bindings remain supported.

The overall goal covers the full plan and qualification. **M1:** D6–D8 alignment under revised D3/D7, including downstream proof/format checks. Active **PR09 next slice:** remaining CLI/tooling/test/fuzz consumers and D5 configuration. Root owns processor/prover integration, then affected consumers; consult PR09/10 and applicable invariants. Legacy Program/ProgramInfo/public statements need PR12 cutover. Keep PR15a deferred.

Processor unit/integration fixtures now retain explicit naming, selected code and bounded environments; no K/root authority comes from body hashes. Unit fixtures use `test_utils::named_*` plus the native type bridge; integration sources reuse shared Test preparation. Debug tail frames, unavailable-body diagnostics and context-return locations are corrected. Replay decoding requires native revalidation. Scratch source index identifies exact helpers.

Fresh guarded evidence: unit crate compiles; unfiltered run: 1,866 pass/24 fail/one existing ignore. All 24 fail at Core36 versus legacy32 statement construction, pending PR12; no new skips/ignores or placeholder inputs. All 49 processor integrations and strict library/test Clippy pass. Concurrent replay (69 tests) and no_std checks pass. Previous assembly/package/prover evidence stays in the ledger. M1 and inherited proof/generated/MASM/recursive/security/fuzz gates remain open.

Reference cache `.scratch/librarytree/reference-cache/` retains Page/date/SHA-256; archives/logs/shared /tmp stay outside routine input. Bounded agents require exact ownership/instructions. Root runs AC/heavy guards and 16MiB test stacks. No pushes or GitHub PRs.
