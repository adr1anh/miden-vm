The host currently retrieves environment openings through a request wrapper and combines keyed procedure and structural external code loading in one callback. This draft specifies three explicit operations and a bounded in-memory opening source, so callers can use local or delegated retrieval without losing package/source ownership or changing authenticated execution.

This is a specification and worktree-startup draft. Production implementation has not started. The complete contract, migration slices and acceptance gates are in [the PR18 plan card](https://github.com/adr1anh/miden-vm/blob/adr1anh/librarytree-18-host-environment-access/LIBRARYTREE_PLAN.md#pr-18-explicit-host-environment-access-and-bounded-in-memory-openings).

Base: `adr1anh/librarytree-17-cleanup` on `adr1anh/miden-vm`, publication tip `3fc82b2c93ca75d0dc8882fbfee6f9bb0b66c1c7`. Head: `adr1anh/librarytree-18-host-environment-access` on the same fork. The preceding stack is published separately; this PR adds only PR18 startup/review documentation and references the inherited specification.

Planned work:

- Split retrieval into `open_procedure(root, K, limits)`, `load_procedure(K, D)` and `load_external(D)` with existing sync/async conventions and failure semantics.
- Preserve independently expected targets, bounded construction/verification, exact loaded-code owners and source occurrences, callbacks, cancellation and replay behavior.
- Provide a bounded index over a validated environment with exact occurrence slots and preallocation checks.
- Migrate default/custom hosts, CLI sources, tests and public examples; validate supported features.

The opening-budget interface remains a design-review decision. The proposed minimal default retains the VM-supplied `OpeningLimits` argument, while applications configure policy once. Omitting it requires an execution-bound immutable policy contract before implementation. This draft does not introduce a public environment factory, partial-code format, generic blob API, new commitment or AIR relation, or expanded structural retry behavior.

Validation: independent source/specification review and documentation whitespace checks. No new Rust compilation, tests, benchmarks or artifact regeneration were run. The PR17 qualification report is inherited evidence, not a new validation claim for PR18.

Implementation checklist:

- [ ] Settle the budget contract.
- [ ] Split and migrate retrieval methods.
- [ ] Add the bounded in-memory source.
- [ ] Migrate consumers and document local/delegating hosts.
- [ ] Complete the card's focused tests, lint/feature and drift checks.
