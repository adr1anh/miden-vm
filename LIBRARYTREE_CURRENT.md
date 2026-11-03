# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD `c0c6ef28c48326cd0219d5b886d2ea53800431e8` (source `108dc3607`), base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; documentation follows. Recheck Git/status. PR09 is in progress; PR02–08 remain implemented-awaiting-validation. All reviewed code/tests are committed; scratch remains untracked. No source author is active. Root owns integration, guarded checks, documentation and commits.

Two required user decisions await answers: (1) complete kernel path required at build time, or supplied when binding code to an authorized execution environment; (2) code-only package9 may omit its own LibraryId/public-interface association, or every package9 must own I/declarations. Hold dependent live manifest/build/read/finalizer policy. K_entry stays explicit; no N0 default. TargetType is a usage tag, not a publication role. A home containing I does not establish ownership or declaration association.

Next ownership: package `{manifest.rs,mod.rs,serialization/}`, then assembly `{assembler.rs,project.rs,linker/}`. Naming must survive stripping and affect commitments/dedup/cache matching; no required unencoded Package8 fields. NamespaceInputs atomically replaces pending homes/declarations; linked identities remain immutable. Per-target project/cache routing remains pending.

AssemblyProduct retains bindings, source selections, homes and entry K; Package8 extraction drops them. Callable v1 bytes require explicit HomeProfile/context and aggregate budgets. Package9/profile acceptance is unclaimed; generic compilation requires no Protocol registry or new release/resource schema.

**D5 approved:** standard assembler/project Latest/Pinned namespace convention plus explicit custom bindings. Paths use the complete supplied base and opaque I; no ID generator or new MASM import syntax. Exact configuration/default-selection UX remains unfrozen. D4 inline eligibility/inner keys remain. D3 Protocol identity/interface/registration requirements apply to that profile, not generic assembly.

Read plan PR09, invariants1–10, D2–D5, Workflow and superseding PR04/08/12 gates, then assigned sources. Findings: `.scratch/librarytree/findings-pr09-{project,inline,assembler,package}.md`. Cache `assembly.md`: frontend §§3.2/4.1/5.1–5.3/6.2; container §§7.1–7.2.

Callable fuzz locked check/Clippy and ASan smoke5916/31s pass; LSan disabled for host ptrace, so no leak/full fuzz qualification. Namespace11/assembly465 pass,43 project failures/6 ignored; assembly Clippy/no_std/testing pass; prior package251/one ignored and codec11 apply. Normal processor compilation stops at two prover calls missing ExecutionEnvironment; no tests ran. Standard test-dev/nextest and inherited gates remain pending. Use16MiB test-thread stack; root runs AC/heavy guards. Plan owns durable evidence; logs stay separate.

Cache `.scratch/librarytree/reference-cache/` retains one copy/source with Page/date/hash provenance. Archives/shared /tmp duplicates stay outside routine input. Use fresh bounded agents, exclusive files and explicit constraints. No pushes or GitHub PRs.
