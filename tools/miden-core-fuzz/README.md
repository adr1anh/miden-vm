# Miden core fuzzing

This crate tests Miden core deserialization surfaces against bad inputs. It covers `MastForest` and `ExecutionProof` as well as portable precompile-witness formats.

## Prerequisites

- Rust nightly toolchain
- cargo-fuzz: `cargo install cargo-fuzz`

## Quick start

List all fuzz targets:

```bash
cargo +nightly fuzz list --fuzz-dir tools/miden-core-fuzz
```

Run all targets (5 minutes each):

```bash
make fuzz-all
```

## Fuzz targets

### High-level targets

The **`mast_forest_deserialize`** target tests `MastForest::read_from_bytes` with arbitrary bytes.

```bash
cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`mast_forest_validate`** target tests the full untrusted pipeline from decoding through validation.

```bash
cargo +nightly fuzz run mast_forest_validate --fuzz-dir tools/miden-core-fuzz
```

The **`mast_forest_wire_view_new`** target checks wire-backed structural inspection, procedure
roots and keyed invocation targets. Generated fixtures compare accessors with values captured
before serialization and check full and hashless materialization.

```bash
cargo +nightly fuzz run mast_forest_wire_view_new --fuzz-dir tools/miden-core-fuzz
```

### Core deserialization targets

These targets exercise core deserializers directly.

Executable code uses the bounded package deserializers below; the legacy Program wire format is retired.

The **`stack_io_deserialize`** target tests `StackInputs` and `StackOutputs` deserialization.

```bash
cargo +nightly fuzz run stack_io_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`advice_inputs_deserialize`** target tests `AdviceInputs` and `AdviceMap` deserialization.

```bash
cargo +nightly fuzz run advice_inputs_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`operation_deserialize`** target tests `Operation::read_from_bytes`.

```bash
cargo +nightly fuzz run operation_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`execution_proof_deserialize`** target tests canonical `ExecutionProof` decoding without a
registry, including its portable singleton witness. Successful decodes must encode to the
same bytes and decode to the same proof.

```bash
make fuzz-execution-proof
```

The **`execution_witness_deserialize`** target reads a fuzz-only caller envelope:
`K_entry[32] || R_E[32] || replay-v7 bytes`. Both prefix identities use canonical `Word`
encoding and are supplied to the bounded witness reader as the caller's expected target.
The harness never discovers authority from the witness payload. Fixed explicit policies cap the
payload at 4 MiB and keyed validation peak at 16 MiB, with separate finite opening, ledger,
session, trace-event and validation-work limits. Successful reads must survive two canonical
encode/decode cycles; changed caller identities, explicit zero read limits and trailing bytes
must reject. This envelope does not change the production replay format.

```bash
cargo +nightly fuzz run execution_witness_deserialize --fuzz-dir tools/miden-core-fuzz
```

Regenerate its `ordinary.bin` and `deferred.bin` corpus entries with the ignored
`generate_execution_witness_fuzz_seeds` integration-test generator after format/API changes.
The generator prefixes the independently owned fixture target; older raw replay-only corpus
files do not reach successful bounded decoding under this envelope.

The library tests replay both seeds through the same decoder and rejection oracles. They require
successful decoding, so a seed that merely rejects cannot pass:

```bash
cargo test --manifest-path tools/miden-core-fuzz/Cargo.toml --lib witness_seed_reaches_all_oracles
```

The **`deferred_state_wire_deserialize`** target exercises checked portable singleton-witness
decoding, canonical round trips, and `Vec`/`Option` containers. It rejects unsupported versions,
malformed graph structure, and trailing bytes without evaluating precompile operations.

```bash
cargo +nightly fuzz run deferred_state_wire_deserialize --fuzz-dir tools/miden-core-fuzz
```

### Package deserialization targets

These targets exercise package deserializers used by `.masp`.

The **`package_deserialize`** target tests `Package::read_from_bytes`.

```bash
cargo +nightly fuzz run package_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`package_semantic_deserialize`** target exercises admitted package sections, naming,
embedded kernels, debug diagnostics and canonical round trips through safe and trusted readers.
Its synthetic naming profile does not establish Protocol admission.

```bash
cargo +nightly fuzz run package_semantic_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`callable_inventory_codec`** target combines hostile v1 bytes with 1–4 valid callable
bindings, optional aliases and shared implementation selections. It checks exact canonical round
trips, changed-context rejection and trailing bytes under explicit 4 KiB/32-record/32-component/
512-payload-byte limits. Its small synthetic home/TypedId allowlist establishes no Protocol or
package admission.

```bash
cargo +nightly fuzz run callable_inventory_codec --fuzz-dir tools/miden-core-fuzz -- -max_total_time=30 -runs=10000 -max_len=4097 -timeout=5
```

The `event_handler_section_deserialize` target tests `EventHandlerSection::from_payload` (the
untrusted `event_handlers` package section with its decode-time size caps), the same function
`Package::event_handlers` uses.

```bash
cargo +nightly fuzz run event_handler_section_deserialize --fuzz-dir tools/miden-core-fuzz
```

The `wasm_handler_manifest` target tests `manifest_from_module`, which parses an untrusted
binary with wasmparser and reads its `miden:event-manifest` custom-section records.

```bash
cargo +nightly fuzz run wasm_handler_manifest --fuzz-dir tools/miden-core-fuzz
```

The `wasm_section_walk_differential` target checks that any module wasmi validates also passes the loader.
It must parse with the wasmparser version the handler loader pins and pass the static analysis built on
it (the instantiation-cost estimate and the start-section check), since the loader conservatively
rejects modules that either one refuses. A disagreement means the loader's wasmparser pin and
wasmi's own wasmparser dependency drifted apart.

```bash
cargo +nightly fuzz run wasm_section_walk_differential --fuzz-dir tools/miden-core-fuzz
```

### Project targets

The **`project_toml_parse`** target exercises manifest parsing and TOML round trips, including
workspace/package variant stability.

```bash
cargo +nightly fuzz run project_toml_parse --fuzz-dir tools/miden-core-fuzz
```

The **`project_load`** target loads temporary package and workspace trees, including project
references and checks against known workspace-inherited values.

```bash
cargo +nightly fuzz run project_load --fuzz-dir tools/miden-core-fuzz
```

The **`project_assemble`** target assembles controlled library, executable and kernel layouts
under development and release profiles, then exercises emitted package and debug APIs.

```bash
cargo +nightly fuzz run project_assemble --fuzz-dir tools/miden-core-fuzz
```

### Component targets

These fuzz internal structures through the MastForest deserialization path:

The **`basic_block_data`** target covers operation batches, including their index pointer and padded group data.

```bash
cargo +nightly fuzz run basic_block_data --fuzz-dir tools/miden-core-fuzz
```

The **`debug_info`** target covers debug string tables and CSR structures with their error codes.

```bash
cargo +nightly fuzz run debug_info --fuzz-dir tools/miden-core-fuzz
```

The **`mast_node_info`** target covers fixed-width node entries, digests and separately stored ProcedureKey targets through the MAST wire-view API.

```bash
cargo +nightly fuzz run mast_node_info --fuzz-dir tools/miden-core-fuzz
```

## Seed corpus

Generate seed files from valid serializations:

```bash
make fuzz-seeds
```

Seeds go to `tools/miden-core-fuzz/corpus/<target-name>/`.

## Coverage

Generate coverage report:

```bash
make fuzz-coverage
```

This runs `cargo fuzz coverage` for the main targets and outputs coverage data to `tools/miden-core-fuzz/coverage/`.

## Artifacts

Crash-inducing inputs go to `tools/miden-core-fuzz/artifacts/<target-name>/`. To reproduce:

```bash
cargo +nightly fuzz run <target-name> --fuzz-dir tools/miden-core-fuzz artifacts/<target-name>/crash-XXX
```

Example:

```bash
cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir tools/miden-core-fuzz artifacts/mast_forest_deserialize/crash-da39a3ee5e6b4b0d
```

## Attack surfaces

Where we expect malicious inputs to cause problems:

- Header magic and metadata parsing
- Node count bounds (rejection of excessive allocations)
- Procedure roots deserialization
- Basic block operation batches and padded groups
- MastNodeInfo type discriminants and child data
- DebugInfo decorators and string-table CSR data
- Hash verification in validation
- Portable precompile-witness graph decoding and canonical transport

## Safety properties

Deserialization must never panic on any input. Fuzzing also checks for memory safety bugs and undefined behavior. `UntrustedMastForest::validate()` must reject every invalid forest.
