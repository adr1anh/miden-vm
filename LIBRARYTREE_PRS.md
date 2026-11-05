# LibraryTree GitHub PR stack

Published 5 November 2026 as 19 draft PRs in [adr1anh/miden-vm](https://github.com/adr1anh/miden-vm). The user explicitly authorized this fork-only publication; earlier no-PR/no-push notes describe the pre-publication state. No PR, push, merge or repository-setting change targets 0xMiden.

[Start at the stack overview](https://github.com/adr1anh/miden-vm/pull/3). Every PR has previous/next links and the complete stack index. Each PR targets the previous LibraryTree branch; stage00 targets the fork's next branch. Intermediate descriptions retain their historical validation scope and deferred work; later stages close those gates.

| Stage | Pull request | Base | Original stage tip |
| --- | --- | --- | --- |
| 00 | [#3 — Document implementation plan](https://github.com/adr1anh/miden-vm/pull/3) | `next` | `a53c8b1df36b` |
| 01 | [#4 — Canonical identities and execution contracts](https://github.com/adr1anh/miden-vm/pull/4) | [#3](https://github.com/adr1anh/miden-vm/pull/3) | `4f6cda59906f` |
| 02 | [#5 — Keyed MAST and wire format](https://github.com/adr1anh/miden-vm/pull/5) | [#4](https://github.com/adr1anh/miden-vm/pull/4) | `7602d32ed809` |
| 03 | [#6 — Chiplet layout and logical address ownership](https://github.com/adr1anh/miden-vm/pull/6) | [#5](https://github.com/adr1anh/miden-vm/pull/5) | `45be30b96d07` |
| 04 | [#7 — Namespace plans and declaration interfaces](https://github.com/adr1anh/miden-vm/pull/7) | [#6](https://github.com/adr1anh/miden-vm/pull/6) | `7223926826fe` |
| 05 | [#8 — Authenticated keyed runtime execution](https://github.com/adr1anh/miden-vm/pull/8) | [#7](https://github.com/adr1anh/miden-vm/pull/7) | `53acb4837e8d` |
| 06 | [#9 — Packed Library witnesses and authenticated lookups](https://github.com/adr1anh/miden-vm/pull/9) | [#8](https://github.com/adr1anh/miden-vm/pull/8) | `cc6a74742722` |
| 07 | [#10 — Core invocation binding and root completion](https://github.com/adr1anh/miden-vm/pull/10) | [#9](https://github.com/adr1anh/miden-vm/pull/9) | `12e78f95374f` |
| 08 | [#11 — Replay and debugger integration](https://github.com/adr1anh/miden-vm/pull/11) | [#10](https://github.com/adr1anh/miden-vm/pull/10) | `82935d673327` |
| 09 | [#12 — Keyed assembly and package cutover](https://github.com/adr1anh/miden-vm/pull/12) | [#11](https://github.com/adr1anh/miden-vm/pull/11) | `0ec317994771` |
| 10 | [#13 — Revision-aware project imports and code supply](https://github.com/adr1anh/miden-vm/pull/13) | [#12](https://github.com/adr1anh/miden-vm/pull/12) | `eefae17e7be4` |
| 11 | [#14 — Runtime ABI profiles and resource limits](https://github.com/adr1anh/miden-vm/pull/14) | [#13](https://github.com/adr1anh/miden-vm/pull/13) | `10bc8a5f0e56` |
| 12 | [#15 — Native statement and proof transport](https://github.com/adr1anh/miden-vm/pull/15) | [#14](https://github.com/adr1anh/miden-vm/pull/14) | `56f44aa0f589` |
| 13 | [#16 — Core-library packaging and runtime migration](https://github.com/adr1anh/miden-vm/pull/16) | [#15](https://github.com/adr1anh/miden-vm/pull/15) | `52e914a9a007` |
| 14 | [#17 — Recursive verification and generated identities](https://github.com/adr1anh/miden-vm/pull/17) | [#16](https://github.com/adr1anh/miden-vm/pull/16) | `f4350360dba5` |
| 15 | [#18 — Public API, CLI and consumer integration](https://github.com/adr1anh/miden-vm/pull/18) | [#17](https://github.com/adr1anh/miden-vm/pull/17) | `1afb98f502ea` |
| 15a | [#19 — Controller-local counters and AIR cleanup](https://github.com/adr1anh/miden-vm/pull/19) | [#18](https://github.com/adr1anh/miden-vm/pull/18) | `91011b897a7f` |
| 16 | [#20 — Adversarial and performance qualification](https://github.com/adr1anh/miden-vm/pull/20) | [#19](https://github.com/adr1anh/miden-vm/pull/19) | `18d4a347d96b` |
| 17 | [#21 — Retire obsolete code and compare Blake3 costs](https://github.com/adr1anh/miden-vm/pull/21) | [#20](https://github.com/adr1anh/miden-vm/pull/20) | `fd1007dfc805` |

## Remotes and baseline

`origin` is https://github.com/adr1anh/miden-vm.git. `upstream` is https://github.com/0xMiden/miden-vm.git. The fork's `next` was fast-forwarded without force to upstream `26c11f8c37cc08b1abfd8268997fb0d02fe33214`. Existing local upstream tracking was preserved by renaming the previous origin remote to upstream. LibraryTree branches track origin. Local next is checked out in another worktree and was not moved or reset.

The stack retains its validated history from `00b12150715891582864d256ef51c5ea46bfb282`; upstream next advanced six commits afterward. Publication does not rebase the stack, change implementation commits or assert new integration validation against those additional commits. PR17 additionally contains this publication-only documentation. The pinned Blake3 comparison's historical origin/next label refers to the exact 00b1215 snapshot recorded in its provenance, rather than the newly synchronized next branch.

## Automation and evidence

Fork Actions were temporarily paused during synchronization, branch publication, PR creation and navigation updates to avoid unnecessary CI and cross-repository docs dispatch. The saved repository Actions permissions are restored after setup; the previously inactive fuzz/link-check workflows remain disabled. No workflow dispatch or upstream mutation was requested.

This publication changes no VM code and runs no Rust builds/tests. Existing validation and measurement evidence stays in LIBRARYTREE_PLAN.md and LIBRARYTREE_QUALIFICATION.md. GitHub PRs are drafts for visualization/review, with no reviewers requested and no automatic merges. Scratch publication manifests and original Actions/workflow settings remain in `.scratch/librarytree/github-publication-20261105/`.
