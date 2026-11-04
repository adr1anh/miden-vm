---
title: "Verifying proofs in MASM"
sidebar_position: 9
---

# Verifying proofs in MASM

## Verifier contracts

`C` is the execution-claim commitment (entry procedure key, environment root, input stack, and output
stack), and `D` is its deferred root. `V` is the caller-selected `VerifierIdentity`, which commits to
the verifier's proof relation, entry procedure key, and exact configuration. An implementation root
or the procedure key returned by `procref` cannot substitute for `V`.

| Procedure | Input stack | Output stack |
| --- | --- | --- |
| `sys::vm::verify_proof` | `[C, ...]` | `[security_descriptor(12), D, ...]` |
| `sys::pvm::request_proof` | `[V, D, ...]` | `[D, ...]` |
| `sys::pvm::verify_proof` | `[D, ...]` | `[security_descriptor(12), ...]` |
| `stark::security::compute_conjectured_security_level` | `[security_descriptor(12), ...]` | `[level, ...]` |
| `stark::security::compute_proven_security_level` | `[security_descriptor(12), ...]` | `[level, ...]` |

Both verifiers consume their proof data from the advice stack. `sys::build_proof_request_key`
consumes `[V, C, ...]` and returns `[key, ...]`, where the request-v2 key is
`H(C[4] || V[4])` under Eidos domain `0x01000202`.

`CoreLibrary::vm_recursive_verifier_profile()` and `pvm_recursive_verifier_profile()` derive the
embedded profiles. Select the expected identities independently of proof data. Mount the complete
`shared_fragment()` as an actual subtree at the initial namespace in the owner's execution
environment; flattening its bindings does not preserve that mount. Call each profile's `authorize`
with the independently selected environment root, its validated environment, effective advice, and
an explicit traversal budget. Effective advice includes package static resources and the selected
request's ACE resources, with conflicts rejected. Additional private and proof advice is allowed.
Deriving an identity alone does not authorize a profile.

`D = TRUE_DIGEST` (`[0, 0, 0, 0]`) means the execution left no deferred work,
so no PVM proof is needed.
Otherwise, to fully close verification we need to settle `D` or explicitly propagate it as an obligation for a later verifier.

## Checking proof security

Both verifiers return the same twelve-field descriptor, in this stack order:

```text
[lookup_pow_bits, num_composed_constraints, max_constraint_degree, num_deep_terms,
 max_message_width, num_lookup_boundary_terms, lookup_fractions_per_row,
 log_max_height, num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]
```

Pass the descriptor unchanged to `compute_conjectured_security_level` or
`compute_proven_security_level` and check the returned bit count against your required minimum
security target for each MVM and PVM proof. The proven estimator selects the stronger complete
unique- or list-decoding bound, rounded conservatively to whole bits. It retains the hash and
Fiat-Shamir assumptions, including Eidos pseudorandomness. Because the descriptor omits the
quotient-chunk count, the MASM estimate conservatively uses the verifier's maximum of eight
chunks and constraint degree nine. Its arithmetic bounds can also make it slightly lower than
the native proven estimate. Estimation is optional and does not change either verifier's
root. Hosts can identify the proven estimator with
`miden_core_lib::proven_security_estimator_root()`.
Remember that the weakest proof limits the security of the whole.

## Example: settle a deferred execution

`proof` is a Miden VM `ExecutionProof` with a nonzero deferred root, and `claim` is its
`ExecutionClaim`:

```rust
use miden_core_lib::CoreLibrary;
use miden_processor::StackInputs;
use miden_vm_stark::recursive::RecursiveVerifierInputs;

let core_lib = CoreLibrary::default();
let vm_profile = core_lib.vm_recursive_verifier_profile()?;
let pvm_profile = core_lib.pvm_recursive_verifier_profile()?;
let expected_vm = vm_profile.identity();
let expected_pvm = pvm_profile.identity();
let inputs = RecursiveVerifierInputs::for_request(expected_vm, &proof, &claim)?;
let (advice_inputs, claim_commitment) = inputs.into_parts();
let stack_inputs = StackInputs::new(claim_commitment.as_elements())?;

// Save the MASM block below as settle_deferred.masm. Add the selected identities to the outer
// source before assembly; neither identity belongs inside its own committed core fragment.
let constants: String = [
    ("VM_VERIFIER_IDENTITY", expected_vm),
    ("PVM_VERIFIER_IDENTITY", expected_pvm),
]
.into_iter()
.map(|(name, identity)| {
    let values = identity.as_word().iter()
        .map(|felt| felt.as_canonical_u64().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    format!("const {name} = [{values}]\n")
})
.collect();
let source = format!("{constants}\n{}", include_str!("settle_deferred.masm"));
```

The adapter stores the MVM proof under `proof_request_key(expected_vm, claim_commitment)` and
supplies the exact 40-Felt claim preimage and proof advice. Assemble `source` with the core library,
mount its selected complete fragment, and authorize the initial VM environment and effective
package/request advice before execution. MASM pushes `VM_VERIFIER_IDENTITY` from this outer source
and takes `claim_commitment` as public input. If `proof` includes a PVM proof, supply it through the
separate PVM request described below. The PVM resource subset can be authorized when the response
arrives, against the same prepared environment and the advice available at that point.

This example enforces 96 bits of conjectured security. To enforce proven security, call
`compute_proven_security_level` at both estimation sites and choose the application's required
proven threshold; the same proof generally has a lower proven bound.

```masm title="settle_deferred.masm"
use miden::core::sys
use miden::core::stark::security
use miden::core::sys::pvm
use miden::core::sys::vm

const MIN_SECURITY_BITS = 96

begin
    # Keep C for verify_proof while fetching the proof from advice.
    dupw
    push.VM_VERIFIER_IDENTITY exec.sys::build_proof_request_key
    adv.push_mapval dropw
    exec.vm::verify_proof
    # => [security_descriptor(12), D, ...]

    exec.security::compute_conjectured_security_level
    # => [level, D, ...]
    u32lt.MIN_SECURITY_BITS assertz.err="MVM proof security is below the required minimum"
    # => [D, ...]

    # Request a proof for the root returned by the MVM verifier under the owner's PVM identity.
    push.PVM_VERIFIER_IDENTITY exec.pvm::request_proof
    exec.pvm::verify_proof
    # => [security_descriptor(12), ...]

    exec.security::compute_conjectured_security_level
    u32lt.MIN_SECURITY_BITS assertz.err="PVM proof security is below the required minimum"
end
```

## Supplying the PVM proof

`pvm::request_proof` emits a `miden_core_lib::PVM_PROOF_REQUEST_EVENT_NAME` event. A `Host::on_event`
handler supplies the PVM proof and may await its generation or retrieval. The core library
provides no default handler.

At the event, the operand stack is `[event_id, V, D, D, ...]`: `V` occupies positions 1–4, the
requested `D` positions 5–8, and the preserved `D` positions 9–12. Compare the event word to the
owner-selected typed `expected_pvm` before proving or retrieving a response. Never construct an
authorized identity by wrapping the event word. Then obtain a PVM proof for `D` compatible with
that profile. Generating it requires the original execution's deferred witness data.

Package `pvm_proof` with `PvmRecursiveVerifierInputs::for_request`, which uses
`pvm_proof.aggregate_root()` for the request key. For a single execution and hence for a single root, `pvm_proof.roots` is
`[D]`. Return the advice map and Merkle nodes from the event handler:

```rust
use miden_precompiles_stark::recursive::PvmRecursiveVerifierInputs;
use miden_processor::advice::AdviceMutation;

// expected_pvm was selected from the supported profile before execution.
assert_eq!(process.get_stack_word(1), expected_pvm.into_word());
let package = PvmRecursiveVerifierInputs::for_request(expected_pvm, &pvm_proof)?;
let (advice, _) = package.into_parts();
let (_, advice_map, store) = advice.into_parts();

// The response adds the PVM ACE resource. Check conflicts and the required resource subset
// against the already prepared, owner-authorized environment before returning any mutations.
let mut effective_advice = process.advice_provider().map().clone();
effective_advice.merge(&advice_map)?;
pvm_profile.authorize(
    authorized_environment_root,
    &environment,
    &effective_advice,
    max_environment_visits,
)?;

Ok(vec![
    AdviceMutation::extend_map(advice_map),
    AdviceMutation::extend_merkle_store(store.inner_nodes()),
])
```

`request_proof` loads advice under `proof_request_key(expected_pvm, D)`. The PVM verifier checks
the proof against `D` returned by the MVM verifier.

For proof generation and the event handler, see the
[settlement integration test](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/tests/stark/pvm_settlement.rs).

## Example: batch N executions

`verify_batch` in the [MASM batcher](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/tests/stark/pvm_settlement/batch.masm)
accepts a caller-provided buffer and an even runtime count from 2 through `MAX_CLAIMS` (4).
The [Rust example](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/tests/stark/pvm_settlement/batch.rs)
uses two ECDSA executions as transaction stand-ins. It adds the owner-selected VM and PVM identity
constants to the outer batch module before assembly and mounts the same complete core fragment.
The same approach extends to N executions.

`CLAIMS_COMMITMENT` is the hash of the ordered claim commitments `[C1, ..., CN]`. The
example exposes `[N, CLAIMS_COMMITMENT]` as public inputs and supplies the list and MVM proofs
through advice. MASM checks the list's hash before verifying the claims.

### Combining the deferred roots

Skip TRUE roots and use the first nonzero root unchanged. Append subsequent roots in claim order
using AND nodes. For `[A, TRUE, B, A]`, the folded root is:

```text
D = digest(AND(digest(AND(A, B)), A))
```

Order and repeated nonzero roots are preserved. Each AND node compresses its two child digests
with Eidos under `DEFERRED_AND_FRAME`, matching `miden_core::deferred::fold_deferred_root`.

### Proving the combined work

Collect the singleton witnesses carried by `PrecompileStatus::Deferred` in claim order, including
repeats. Pass this nonempty vector directly to the prover:

```rust
let pvm_proof = prover.prove_precompiles(witnesses)?;
```

The prover imports and evaluates the witnesses, folds their roots into `D`, and proves the
combined work. On the request for `D`, return the packaged advice for this proof.

The resulting `PrecompileProof` contains one STARK proof for `roots = [A, B, A]`. Its `aggregate_root()`
recomputes `D` from the metadata. The batcher verifies the PVM proof against `D`, which it computed
from the deferred roots returned by the MVM verifiers, and checks the proof's security level.

If all roots are TRUE, skip precompile proving and requesting a PVM proof.

### Proving the batcher

After settlement, the batcher's MVM proof has no deferred work. Its claim includes
`[N, CLAIMS_COMMITMENT]` as public inputs, identifying the ordered batch it settles.

For the meaning and composition of deferred roots, see
[deferred proof obligations](../../design/deferred/semantics.md#proof-obligations-and-composition).
