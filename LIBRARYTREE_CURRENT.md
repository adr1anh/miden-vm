# LibraryTree current work

This brief owns current handoff. LIBRARYTREE_PLAN.md owns backlog, dependencies, acceptance and durable evidence. PR_DESCRIPTION.md describes final PR12 scope; never use it for discovery.

Verified 4 November 2026: branch `adr1anh/librarytree-13-core-library`, HEAD `5cec11f38`, base `56f44aa0f589fe16667677503a7714fe1580e299`. Manifest/provider consolidation, package acceptance and first inline slice are committed/signed. Five follow-up files are modified: AEAD, ECDSA, Eidos MASM; claim metadata; domain parity test. Preserve them and revalidate Git. Scratch stays untracked. General goal/M1 active; no pushes/GitHub PRs or new user decision pending.

Read plan PR13 and D4/D8, then `.scratch/librarytree/findings-pr13-packaging.md` only as needed. Focused18/18 and strict four-crate all-target Clippy pass. The unchanged cost caps now pass: VM1097<=1300, PVM2773<=3200, security2200<2250; its complete numeric matrix passes. Package tests establish safe export/import, package-only arbitrary advice/private callback and unchanged caller K across authorized changed D/R_E. VM/PVM generation/check passes with unchanged pins. Evidence belongs in the plan.

Current root check: ordinary675-case baseline in `.scratch/librarytree/pr13-ordinary-checks.log`, session54358; this binary predates follow-up crypto edits. Do not start another heavy job until it finishes. Eight failures found so far: five AEAD exact diagnostic mismatches, missing retired kernel-domain metadata, two crypto exact snapshots. AEAD's identical-D range helper was selecting IES error metadata; seven local inline calls preserve original checks/messages/FMP/zero-event oracles. Claim metadata/parity now tracks active domain2. Eidos/DSA pure leaves inline; no event/deferred helpers or local-scope public wrappers changed. Source frozen; root must measure and qualify exact snapshots after rerunning affected crypto modules. Do not raise upper caps or change rejection oracles.

Root owns integration/regeneration/commits. Former bounded agents own no further edits. Independent manifest/package-test reviews pass. Keep signed implementation and context commits separate; commit final PR13 description before branching. Reuse `.scratch/librarytree/build-pr12`; same test-dev feature graph is recorded in untracked run-pr13-focused.sh. AC/heavy guards and16MiB stacks are mandatory. No parallel Cargo jobs or agent builds; avoid repeating passing suites.

Fifteen request failures remain planned PR14: see findings-pr14-requests.md for K/D versus typed identity/config seams. No fallback/duplicate registration/whitelist blessing. findings-security-principals.md retains counterfactual gates; global diagnostic ambiguity and full recursive/security/guest/fuzz/performance/final qualification remain open. PR15a deferred.

Reference cache `.scratch/librarytree/reference-cache/` has one Page/date/SHA-256 copy per source. Findings/logs/archives stay separate. Preserve shared /tmp sources.
