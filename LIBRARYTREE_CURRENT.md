# LibraryTree current work

This brief owns handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final review scope, never discovery.

Verified source checkpoint 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `965c4f7cb10e4a0a06547176ba37acf886a20459`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; documentation follows separately. Tracked tree clean before this edit; recheck Git/checks. Root owns integration/docs/checks; bounded source/review agents finished. Scratch stays untracked.

**D6/D8:** actual SYSCALL requires authenticated immediate parent equal fixed nonzero N0, independent of R_E. Public kernel exports occupy root; helpers/applications child Env. No extra export list. List/Merkle preserve N. Preserve root-name uniqueness, canonical aliases, invocation/context/principals and caller-authorized R_E. Target remains claim40/Core36/Chiplets4/deferred4 with legacy rejection.

**D3/D7 C:** generic packages have no own I/interface fields. Identity derivation/publication policy stays external; readable maps grant no authority and selected-profile checks remain mandatory. Preserve D4 inline eligibility/inner keys. **D5:** explicit Latest/Pinned/custom source-default requests are checked before cache reuse; complete declarations/reexports stay independent. Standard artifact imports still require expected callables; TypedId persistence needs its external writer. See plan PR09/PR10 and D3–D8, plus relevant invariant/spec sections only.

The overall goal stays broad. **M1:** D6–D8 alignment including downstream proof/format qualification. Active **PR09:** caller-owned execution admission, naming-retaining project APIs and embedded core naming are committed. Owned files: CLI `execution_inputs.rs`, `run.rs`, `prove.rs`; internal admission; `assembly/src/project.rs`; core `build.rs`, `source_naming.rs`, `naming_sidecar.rs`, `src/lib.rs` and compilation bench. Core's ordinary sys modules keep child namespace paths. Sidecar checks exact compiler-owned metadata, with no fabricated profile.

**Next:** CLI source/package loaders must retain or independently admit PackageNaming and pass core naming to linking. Raw input needs caller-selected profile/context and expected mappings; never infer them from openings/package data. Command execution arguments/source/trace wiring is present but whole CLI remains uncompiled. PR10 artifact expectations, PR12 claim transport and PR14 verifier identities remain open. Keep private advice/code separate and PR15a deferred.

Fresh checks: project 55 and CLI-adapter 4 tests pass. Core builds; unit tests are **14 pass/1 fail**, the unchanged proof-compatibility root assertion (PR14). Strict focused Clippy and core no_std pass. Earlier admission/Wasm/fuzz evidence and deferred guest/security checks remain in the ledger. M1/final gates stay open.

Use fresh bounded agents (`fork_turns:none`) with exact ownership/instructions. Root centralizes essential AC/heavy-guarded checks with 16MiB stacks; avoid broad builds. Cache `.scratch/librarytree/reference-cache/` keeps Page/date/SHA-256; findings/logs/archives/shared /tmp stay outside routine reads. No pushes/GitHub PRs.
