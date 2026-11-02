# LibraryTree current work

This brief owns current handoff. [LIBRARYTREE_PLAN.md](LIBRARYTREE_PLAN.md) alone owns backlog, scope, dependencies, acceptance and durable evidence. `PR_DESCRIPTION.md` is final branch review scope, never discovery.

Verified checkpoint on 2 November 2026: branch `adr1anh/librarytree-06-packed-library`, HEAD `240008656` (implementation `59b36d0ec`), base `53acb4837` (final PR05 review-description commit). Documentation commits follow. Recheck Git/status; `.scratch/` stays uncommitted.

PR06 is active. Current slice: **Memory/ACE helpers at final shared coordinates**. Memory owner has AIR `chiplets/memory.rs` and processor `chiplets/memory/{mod,tests}.rs`. ACE owner has AIR `chiplets/ace.rs` and processor `chiplets/ace/{mod,trace,tests/mod}.rs`. Integration owner has `constraints/columns.rs` and processor `trace/chiplets/mod.rs`. They share the named full-row helper accessors and associated `Memory/Ace::fill_row_helpers`. Complete only materialized family bands after scatter; retain compact scratch buffers. Root owns reviews/checks/commits/docs.

Library is not active. Packed migration must coordinate both selectors, views/writers, Controller boundaries and periodic/generated consumers. Today c[0] still means Controller. Preserve checked addresses, one shared row schema and code-supply-only semantics.

**Superseding D3:** retain `LibraryId = H_LIBRARY(publisher_id, name, interface_version)` and Page-defined CommitLibInterface with permanent registration binding. Protocol must derive/verify I, even when VM APIs accept opaque typed values. Arbitrary assignment and merge/code-hash alternatives are rejected. Public API/declared dynamic changes require new interface versions; revisions may change bodies/helpers/pinned choices, while retained Latest stays dynamic. Full L(I) includes self; stored external(I)=L(I) minus self. Required identity codec/domain, publisher/home/profile and production projection/registration/closure fixtures remain external gates without fallback.

Read plan **PR06**, **invariants 5/7/8/10**, **D3**, **Workflow**; cache `chiplet.md` **sections7.2–7.3**, then owned source. Use bounded `findings-pr06-memory-ace-helpers.md` and current code; old Controller findings are historical. Selected packed Chiplets24/4,22 Library cells,nine periodics,[4,4,3,2],four AIRs and measured degree≤9 remain gates. No proof acceptance is established.

Passed current checks: full AIR suite308 (including Controller rejection, captured-degree and exact lookup-annotation checks); strict AIR/test and processor/lib Clippy; no-default-features processor; five public witness/native reconstruction tests. Current degrees≤9 are measured for the present relation, not full packed integration. Library's temporary dead-code expectation must disappear as consumers land. New processor materialization tests and inherited private/legacy/address/state/parallel/fuzz gates remain unrun behind three assembly migration errors. PR05 is implemented-awaiting-validation; durable evidence belongs to the plan. Root powerguards precede heavy work.

Sources: `.scratch/librarytree/reference-cache/` with Page/date/hash provenance. Archives, duplicate snapshots and whole chapters are outside routine input. Use fresh bounded agents and exclusive files. No pushes/GitHub PRs; continue while required external inputs are pending.
