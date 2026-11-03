# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, source checkpoint `2a9b8db73733631f3746cd2ff390432f94152d1f`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; documentation follows. Recheck Git/status. PR09 is in progress; PR02–08 remain implemented-awaiting-validation. All reviewed code/tests are committed; scratch remains untracked. No source author is active. Root owns integration, guarded checks, documentation and commits.

Two required user decisions await answers: (1) complete kernel path required at build time, or supplied when binding code to an authorized execution environment; (2) code-only package9 may omit its own LibraryId/public-interface association, or every package9 must own I/declarations. Hold dependent live manifest/build/read/finalizer policy. K_entry stays explicit; no N0 default. TargetType is a usage tag, not a publication role. A home containing I does not establish ownership or declaration association.

Next coordinated ownership: `crates/mast-package/src/package/{manifest.rs,mod.rs,serialization/}`, then `crates/assembly/src/{assembler.rs,project.rs,linker/}`. Required naming must survive stripping and affect commitments/dedup/cache matching; do not add required unencoded fields to Package8. NamespaceInputs now replaces pending homes/declarations atomically, with one map; bound linker identities remain immutable. Per-target project routing/cache comparison is still pending.

Raw AssemblyProduct retains bindings, source selections, homes and entry K; Package8 extraction still drops them. Canonical callable v1 bytes use explicit current HomeProfile/context and aggregate caller-budget preflight. Live package9/production-profile acceptance is unclaimed; generic compilation must not require a Protocol registry or invent release/resource schemas.

D3 retains Page-derived I/interface commitment and permanent registration; opaque generic APIs permit no arbitrary Protocol assignment. Full L(I) includes self; stored external(I) excludes self. Exact codecs/domains and publisher/home/profile/registration/closure remain external gates without fallback. D4 eligibility and fixed inner runtime keys remain unchanged.

Read plan PR09, invariants1–10, D2–D4, Workflow and superseding PR04/08/12 gates, then assigned sources. Findings: `.scratch/librarytree/findings-pr09-{project,inline,assembler,package}.md`. Cache `assembly.md`: frontend §§3.2/4.1/5.1–5.3/6.2; container §§7.1–7.2.

Latest namespace11/full assembly465 pass/43 project failures/6 ignored; strict assembly Clippy and no_std/testing pass. Prior package251/one manual ignored and codec11 evidence remains applicable. Normal processor compilation stops at two prover calls missing ExecutionEnvironment; no tests ran. Standard test-dev/nextest and inherited gates remain pending. Use16MiB test-thread stack; root runs AC/heavy guards. Plan owns durable evidence; logs stay separate.

Cache `.scratch/librarytree/reference-cache/` retains one copy/source with Page/date/hash provenance. Archives/shared /tmp duplicates stay outside routine input. Use fresh bounded agents, exclusive files and explicit constraints. No pushes or GitHub PRs.
