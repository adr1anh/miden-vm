# Chiplet Memory and checked Controller-address foundations

Branch: `adr1anh/librarytree-03-chiplet-foundation`

Git base: `adr1anh/librarytree-02-keyed-mast` (`7602d32ed`). Semantic dependencies: PR 00 and
the selected chiplet layout/address contracts.

Library prefix placement needs a single address boundary and lower-degree Memory equations.
This branch simplifies existing Memory conditional inverses without changing accepted assignments
or its six inverse/selection emission positions. One checked logical Controller owner prevents
span overflow and preserves absence, row zero and exact-cap cursors. Saved/replayed state uses
nominal logical addresses with the existing canonical Felt bytes.

A shared immutable ChipletsLayout now drives final Core/helper/chiplet materialization after
buffered/prebuilt convergence. Only Controller address roles translate; VM clocks, context/RAM,
overflow and unrelated helpers retain their values. Production Library prefix remains zero.
Nonzero prefixes are synthetic tests; actual Library rows and alignment/proof gates belong to PR 06.
The final into_traces host writer is crate-private/fallible and its sole repo caller is updated.

Validation: independent algebra, address, state, final-sink and acceptance reviews; eighteen
chiplet definition tests; eighteen generated capture/drift/ACE tests, with one manual timing test
ignored; definitions test-inclusive Clippy; pinned formatting and whitespace checks. Rust checks
ran after successful power guards. The finite 7,560-assignment matrix complements the algebraic
equivalence argument; it is not exhaustive field enumeration.

Status remains implemented-awaiting-validation. Twenty-five address/state tests are authored
but unrun. The processor library check emits the same six old callee() and four missing Exec
cutover errors. PRs 05/09 must close those consumers before processor/parallel/serde tests and
Clippy run. The plan ledger records exact commands, checkpoints and deferred owners. Final packed
dimensions, degree/lookup gates and D2 MASM syntax/stack/memory regressions remain required.

No GitHub PR has been created. Creating any PR requires the user's explicit instruction.
