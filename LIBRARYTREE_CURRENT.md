# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` describes final branch review scope, never discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, source HEAD `b1e8ee0521a2c5cade992658dcfd4fb892741f12`, base `82935d6733278d871ab1f3f5a7e94f88b6e468d9`; documentation follows. Recheck Git/status. PR09 is in progress; PR02–08 remain implemented-awaiting-validation. Producer/source tests and explicit-inline fixtures are committed; scratch remains untracked.

Root owns integration, guarded checks, documentation and commits. Active author `callables_codec17` exclusively owns `crates/mast-package/src/package/callables.rs`, new `callables/serialization.rs` and tests; minimal shared factoring in `interface/serialization.rs`, `namespace_plan/serialization.rs`, `interface/artifact/declarations.rs`; necessary error reexports in `package/mod.rs` and `lib.rs`. Scope: canonical generic callable payload, exact input, current HomeProfile/context and aggregate caller budget; preserve existing HomeV1/interface bytes and validation. Independent review precedes integration. Authors run no builds, formatting or Git mutations.

The executable kernel-input question awaits the user: require the complete path at build time, or supply it when binding code to an authorized execution environment? Hold dependent live package9 manifest/build/read/finalizer policy. K_entry stays explicit; no N0 default. Raw AssemblyProduct now retains bindings, source selections, homes and entry K; Package8 extraction still drops that metadata. Required naming must survive debug stripping and affect commitments/dedup/cache matching before acceptance. Package9/production-profile acceptance is unclaimed.

D3 retains Page-derived I/interface commitment and permanent registration; opaque generic APIs permit no arbitrary Protocol assignment. Full L(I) includes self; stored external(I) excludes self. Exact codecs/domains and publisher/home/profile/registration/closure inputs remain external gates without fallback. D4 inline eligibility and fixed inner runtime keys remain unchanged.

Read plan PR09, invariants1–10, D2–D4, Workflow and superseding PR04/08/12 gates, then assigned sources. Findings: `.scratch/librarytree/findings-pr09-{project,inline,assembler,package}.md`. Cache `assembly.md`: frontend §§3.2/4.1/5.1–5.3/6.2; package §§7.1–7.2.

Latest full assembly454 pass/43 project failures/6 ignored; debug22, inline13 and final producer6 pass. Strict assembly Clippy with testing and no_std/testing pass. Prior package240/one manual ignored evidence remains applicable. Standard test-dev/nextest and inherited gates remain pending. Use repository16MiB test-thread stack; root runs AC/heavy guards. Plan owns durable evidence; logs stay separate.

Cache `.scratch/librarytree/reference-cache/` retains one copy/source with Page/date/hash provenance. Archives and shared /tmp duplicates stay outside routine input. Use fresh bounded agents, exclusive files and explicit constraints. No pushes or GitHub PRs.
