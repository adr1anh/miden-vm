# PR09: keyed assembly and Package9 cutover

Assembly now resolves callable identity before supplying bodies: retained exec/call/syscall and procref use K, declaration-only Latest calls need no implementation D, runtime recursion retains independent roots, and explicit eligible inline alone composes bodies. Package9 and MAST0.0.6 carry required canonical naming and callable roots through safe/trusted readers, imports, commitments, cache matching and debug stripping. Fixed-N0 kernel construction places public exports at root and private helpers beneath Env, preserving defining keys across aliases. Shared runtime, benchmark and CLI fixtures now select naming and bounded authenticated environments explicitly.

The execution descriptor fixes `(K_entry, R_E)`; actual syscalls authenticate their immediate parent against fixed nonzero N0, with no separate export list or configurable kernel namespace. Processor/replay/witness and Library AIR interfaces carry this correction while downstream statement/proof qualification remains open. Generic Package9 has no own-library identity/interface fields; selected external profiles retain their required admission checks.

**Stack base:** PR08 `82935d6733278d871ab1f3f5a7e94f88b6e468d9`. Semantic dependencies: PR02/04/05; proof checks require PR12.

Recorded checks, run centrally after AC/heavy guards with 16MiB stacks:

- `cargo test --locked -p miden-mast-package --lib`: 289 passed, one existing ignore.
- `make test-assembly EXTRA=--locked NEXTEST_PROFILE=ci`: 544 passed, six existing skips.
- `cargo test --locked -p miden-core-lib --test core-lib security_estimator_key_matches_procref`: two passed.
- `cargo test --locked -p miden-vm --features internal --test miden-cli selected_fixture_files_admit_and_execute_without_cli_output`: one passed.
- `cargo check --locked -p miden-vm --features internal --bench build_trace --bench program_execution_fast --bench program_execution_for_trace`: passed.
- `cargo clippy --locked -p miden-vm --features internal --test miden-cli -- --cfg 'feature="executable"' -D warnings`: passed; this includes precompile test fixtures, not production CLI qualification.

**Remaining gates:** PR09 is implemented-awaiting-validation. PR10 still owns artifact callable expectations, automatic target naming and distinct dependency instances. Native K assertions reach preserved constraint checks failing expected36/actual32; PR12 owns that public-statement cutover and the production CLI's legacy descriptor call at `miden-vm/src/cli/verify.rs:228`. PR14 owns recursive claim/request identities and compatibility-root regeneration/qualification. Full CLI, proof/native/generated/MASM/recursive, malicious-input/security-counterfactual, guest/project, fuzz, performance and final acceptance gates remain open. No assertion weakening, new skips, proof-constant refresh or release-readiness claim.
