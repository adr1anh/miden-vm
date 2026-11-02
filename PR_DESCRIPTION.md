# LibraryTree canonical identities and execution contracts

Branch: `adr1anh/librarytree-01-identities`

Stack base and semantic dependency: `adr1anh/librarytree-00-plan` (`a53c8b1df`).

LibraryTree requires callable keys, implementation roots, environment roots, namespaces and labels
to remain distinct. This branch adds those typed roles, an immutable execution descriptor, exact
canonical labels, environment commitments and the user-approved budgeted v1 node codec. One bounded
preimage builder derives namespace-qualified bindings by complete occurrence traversal and rejects
missing preimages and duplicate executable keys. Typed verifier configuration/identity construction
binds the selected domains, exact ordering and mandatory accumulated kernel namespace.

The builder is an optional local utility. Its result establishes local completeness/uniqueness
under the hash assumptions; it does not authorize roots or namespaces, supply executable code,
validate Protocol codecs or establish trusted verifier mounts/resources. Execution/proof integration
and claim/request activation remain later stack units. Existing Program behavior is unchanged.

Validation: independent implementation/acceptance reviews; 86 program tests including registry
disjointness; twelve verifier tests rerun after the final fixture-only refactor; all three public
API compile fixtures; core Clippy with `--lib --tests -- -D warnings`; no-default-features check;
pinned-nightly formatting and staged whitespace checks. Rust checks ran after successful AC and
heavy-work guards. The 36-row shared text fixture is consumed by Rust and available to future MASM
host tests; MASM/recursive execution is not claimed. Exact commands/evidence are in the plan ledger.

The user's D2 compatibility requirement preserves existing MASM source after rebuilding, while
allowing the new serialized MAST format and interpreting digest-shaped invocation words as keys.
MAST/toolchain changes and their compatibility regressions belong to subsequent branches.

No GitHub PR has been created. Creating any PR requires the user's explicit instruction.
