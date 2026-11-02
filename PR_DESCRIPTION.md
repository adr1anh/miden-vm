# Keyed MAST invocations and canonical v0.0.6 transport

Branch: `adr1anh/librarytree-02-keyed-mast`

Stack base and semantic dependency: `adr1anh/librarytree-01-identities` (`4f6cda599`).

Immediate invocations previously followed callee node IDs and committed the selected implementation.
Call/SysCall now store typed ProcedureKeys; Exec is a childless same-context invocation node with
reserved control opcode 0x5f. Structural traversal, remapping and merging preserve keys independently
of available code. External(D) remains a structural node.

Dense MAST v0.0.6 stores one canonical target slot per immediate invocation in a separate key
section, retained in hashless transport. One shared scanner checks all reader/view paths. Sparse
replay stores direct keys under ExecutionWitness v3. This branch also migrates generators, malformed
wire regressions, fuzz oracles/seeds and explicit structural-cycle/keyed-recursion fixtures.

Validation: independent node/codec/fixture/fuzz/acceptance reviews; 198 default MAST tests; 398
full-core tests with arbitrary enabled; four final focused cycle/recursion cases; focused core seed
generation; public API fixtures; full-feature test-inclusive Clippy; core no-default-features check;
pinned formatting and staged whitespace checks. Rust checks ran after successful power guards.
Generated corpus output stays local. Exact commands/checkpoints are in the plan ledger.

Status remains implemented-awaiting-validation. Processor witness tests require PRs 05/09 to
migrate downstream invocation consumers; fuzz compilation/smoke remains PR 16. Existing MASM syntax
and stack/memory conventions remain requirements for that integration; identities/hash/cycle-count
expectations and rebuilt MAST formats may change. Environment-backed executable generation is a
tracked PR 05 obligation. Runtime/proof integration is outside this core branch.

No GitHub PR has been created. Creating any PR requires the user's explicit instruction.
