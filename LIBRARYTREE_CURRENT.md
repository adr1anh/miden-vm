# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` is final branch review scope, never discovery.

Verified 3 November 2026: branch `adr1anh/librarytree-09-keyed-packages`, HEAD/base `82935d6733278d871ab1f3f5a7e94f88b6e468d9` (final PR08 scope). Only `.scratch/` is untracked; documentation commits follow. Recheck Git/status.

PR09 is **in-progress**, research only; PR02–08 remain implemented-awaiting-validation. Root owns tracked documentation, integration/checks/commits and implementation assignment. Completed research owns `.scratch/librarytree/findings-pr09-{assembler,package}.md`. Next small slice: reuse existing NamespacePlan for declaration/K prebinding independent of optional D/body; coordinate typed pending Exec/Call/SYS payloads in `assembly/src/mast_forest_builder.rs` and `{pending_record,finalizer,static_import}.rs`. Frontend keys must be real before validation; no temporary digest keys. General callable paths must cover private/helpers/entry separately from public-interface paths. No PR09 implementation is assigned or checked yet. `PR_DESCRIPTION.md` remains final PR08 scope.

D2 preserves existing MASM syntax and stack/memory conventions after rebuilding. Real EXEC/DYN preserve context/principal; CALL/DYNCALL establish requested K in fresh user contexts; SYS preserves principal in root context and requires full N_kernel. Code availability supplies D, never binding authority. Preserve fixed R_E, native v4/session/interner and real root completion. No duplicate ledger or diagnostic wire fields.

**Superseding D3:** `LibraryId = H_LIBRARY(publisher_id, name, interface_version)`; plan D3 retains exact CommitLibInterface and permanent registration binding. Protocol derives/verifies I; opaque VM types do not authorize arbitrary assignment or merge/code-hash alternatives. API/declared dynamic changes require new interface versions; revisions may change bodies/helpers/pinned choices, retained Latest stays dynamic. Full L(I) includes self; stored external(I)=L(I) minus self. Required identity codec/domain, publisher/home/profile and projection/registration/closure fixtures have no fallback. Correction `a477732bc`; reaffirmation `37546d255`; profile Rustdoc `71bf65973`.

Read plan **PR09**, relevant **PR04/08/12** gates, **invariants 1–8/10**, **D2/D3**, **Workflow**, then assigned findings/source. Selected cache `assembly.md`: frontend §§3.2/4.1/5.1–5.3/6.2; package §§7.1–7.2. Older stage indices are historical.

PR08 execution22/witness9 pass default/testing/concurrent, strict scoped Clippy and no_std. Fresh normal private run stops at three assembly errors; relocation/sidecar unit tests remain unrun. PR07 AIR383 pass/legacy-claim failure remains PR12. Full forged/global/generated/MASM/recursive/security/benchmark/fuzz gates remain. Plan owns durable evidence; logs stay separate. Root runs powerguards before heavy work.

Cache `.scratch/librarytree/reference-cache/` has Page/date/hash provenance. Archives/duplicates/whole chapters are outside routine input. Use fresh bounded agents with exclusive files and applicable constraints. No pushes/GitHub PRs. Continue while required external inputs remain pending.
