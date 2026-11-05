# Miden prover

This crate proves post-execution witnesses produced by the
[Miden processor](../processor/) using [Plonky3](https://github.com/0xMiden/Plonky3). The
synchronous `Prover` does not execute programs: it consumes `ExecutionWitness` values and owned
batches of portable `PrecompileWitness` values.

## Usage

`Prover` is synchronous and consumes post-execution witnesses. `Prover::prove(ExecutionWitness)`
proves the VM portion. Its `PrecompileStatus` is `Empty` when there is no deferred work, or
`Deferred` with a portable singleton `PrecompileWitness`. `Prover::prove_full(ExecutionWitness)`
proves the VM and any precompile work locally. `Prover::prove_precompiles(Vec<PrecompileWitness>)`
imports a nonempty batch directly into one Session and returns one proof. Its root metadata preserves
input order and repeated roots.

Use `Prover::with_hash_fn` to select the proof hash function.

Tracing must be selected before execution starts. Ordinary `FastProcessor::execute*` calls use a
no-op tracer and return `ExecutionOutput`, which cannot be promoted to `ExecutionWitness` after the
run because it contains no replay data. Call `FastProcessor::execute_for_proving*` when the result
will be passed to `Prover`.

The processor takes a caller-authorized `ExecutionTarget` (`K_entry`, `R_E`) and a host that owns
the loaded `CodePackage` values. Each package keeps code, checked symbols, advice, and exact source
metadata together. Configure the host's untrusted opening-evidence source with
`DefaultHost::with_environment_source`, and load code with `load_library(code)` or
`with_library(code)`. Packages and evidence never supply target authority. The authenticated
environment selects `D`; the host then supplies code subject to implementation-root and
procedure-root checks.

Before execution, install caller-selected
`ResolutionLimits::new(opening, ledger, session)` and `EnvironmentTraceLimits` with
`ExecutionOptions::with_resolution_limits` and `with_environment_trace_limits`. Neither policy has
a default. Missing policies reject before entry authentication or host calls, and explicit zero
limits remain zero. Trace diagnostics expose the authenticated `entry_implementation`; public
verification instead uses the independently expected target and stack inputs and outputs in
`ExecutionClaim`.

### Deferred precompile workflow

The recipient supplies its expected claim independently of the incoming witness or proof:

```rust,no_run
use miden_core::program::ExecutionClaim;
use miden_processor::ExecutionWitness;
use miden_prover::{ExecutionProof, PrecompileStatus, Prover};
use miden_verifier::Verifier;

fn settle_deferred(
    witness: ExecutionWitness,
    expected_claim: &ExecutionClaim,
) -> Result<ExecutionProof, Box<dyn std::error::Error>> {
    let prover = Prover::new();
    let deferred = prover.prove(witness)?;

    // Transport and decode the proof without a registry.
    let bytes = deferred.to_bytes();
    let proof = ExecutionProof::read_from_bytes(&bytes)?;
    let complete = if let PrecompileStatus::Deferred(precompile_witness) = proof.precompile() {
        // Direct import checks portable operations and assertions when proving begins.
        let precompile_proof = prover.prove_precompiles(vec![precompile_witness.clone()])?;
        proof.complete(precompile_proof)?
    } else {
        proof
    };
    let outcome = Verifier::new().verify(expected_claim, &complete)?;
    assert!(outcome.is_complete());
    Ok(complete)
}
```

To share precompile proving across several deferred proofs, collect their portable singleton
witnesses in the required order and pass the vector to `prove_precompiles` once. Computations are
shared inside proving; no merged portable witness is created. Attach the resulting `PrecompileProof`
to each deferred proof with `complete`, then verify each completed proof.
`complete` performs only the deferred-to-complete lifecycle transition; it does not check artifact
compatibility.

Transport, direct import, structural validity, and fixed limits are specified in the
[deferred-proof semantics](../docs/src/design/deferred/semantics.md).

### Recursive batch settlement

The [batch settlement example](../crates/lib/core/tests/stark/pvm_settlement/batch.rs) verifies
multiple Miden VM proofs and settles their deferred work with one precompile VM proof. It also
proves the batcher itself, leaving no deferred work for the recipient. The
[MASM verification guide](../docs/src/user_docs/core_lib/recursive_verification.md#example-batch-n-executions)
explains the claim list, ordered root fold, and host request.

### Synchronous execution and proving

The FastProcessor-backed
`prove_sync(&Prover, target, stack_inputs, advice_inputs, &mut host, execution_options)` function is
the direct synchronous path for executing and fully proving a target using host-owned code and
explicit resolution and tracing policies. It returns `(StackOutputs, ExecutionProof)`. When
enabled in `ExecutionOptions`, it overlaps execution
with hasher trace construction when a Rayon worker is available. A caller with no separate Rayon
worker uses compact buffered replay. Proof generation remains configured on `Prover`.

## STARK Backend

The prover uses [Plonky3](https://github.com/0xMiden/Plonky3), a modular STARK proving framework.
Relation configuration and runtime setup live in `miden-vm-stark::setup` and
`miden-precompiles-stark::setup`. Import those backends directly for relation proving or setup;
`miden-prover` owns complete/deferred proof orchestration and application proving policy.

### Hash Function Selection

The prover defaults to Eidos. BLAKE3 and Keccak are also selectable for
non-recursive proofs. Recursive Miden VM verification accepts only Eidos proofs.

## Crate features
Miden prover can be compiled with the following features:

The `std` feature is enabled by default and relies on the Rust standard library. The `concurrent`
feature implies `std` and also enables multi-threaded proof generation. A `no_std` build does not
rely on the Rust standard library and can compile to WebAssembly. Only the
`wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent proof generation
When compiled with the `concurrent` feature enabled, the prover generates STARK proofs using
multiple threads. For the benefits of concurrent proof generation, see these
[benchmarks](../README.md#Performance).

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. Use the
`RAYON_NUM_THREADS` environment variable to control the number of threads used to generate a STARK
proof.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and
[Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
