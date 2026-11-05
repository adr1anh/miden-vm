use miden_core::{
    Felt, Word,
    program::{EnvironmentRoot, ExecutionTarget, ProcedureKey, VerifierIdentity},
    proof::ExecutionProofCompatibility,
};
use miden_verifier::Verifier;

#[path = "../benches/recursive_verify/cache_key.rs"]
mod cache_key;

use cache_key::tx_proof_cache_key;

fn target(entry: u32, root: u32) -> ExecutionTarget {
    ExecutionTarget::new(
        ProcedureKey::new(Word::new([Felt::from_u32(entry); 4])),
        EnvironmentRoot::new(Word::new([Felt::from_u32(root); 4])),
    )
}

#[test]
fn verifier_identities_separate_transaction_cache_entries() {
    let compatibility = Verifier::proof_compatibility();
    let execution_target = target(7, 11);
    let key = tx_proof_cache_key(execution_target, &[0, 1], &compatibility);
    let other_identity = VerifierIdentity::new(Word::new([Felt::ONE; 4]));

    for (vm_identities, pvm_identities) in [
        (vec![other_identity], compatibility.pvm_verifier_identities().to_vec()),
        (compatibility.vm_verifier_identities().to_vec(), vec![other_identity]),
    ] {
        let changed = ExecutionProofCompatibility::new(vm_identities, pvm_identities).unwrap();
        assert_ne!(key, tx_proof_cache_key(execution_target, &[0, 1], &changed));
    }
    assert_eq!(key, tx_proof_cache_key(execution_target, &[0, 1], &compatibility));
}

#[test]
fn different_entry_or_environment_separates_transaction_cache_entries() {
    let compatibility = Verifier::proof_compatibility();
    let key = tx_proof_cache_key(target(7, 11), &[0, 1], &compatibility);
    for changed in [target(8, 11), target(7, 12)] {
        assert_ne!(key, tx_proof_cache_key(changed, &[0, 1], &compatibility));
    }
}
