use miden_core::{
    Felt, Word,
    program::{EnvironmentRoot, ExecutionTarget, ProcedureKey, VerifierIdentity},
    proof::ExecutionProofCompatibility,
};
use miden_verifier::Verifier;
use miden_vm::ProgramInfo;

#[path = "../benches/recursive_verify/cache_key.rs"]
mod cache_key;

use cache_key::tx_proof_cache_key;

fn descriptor(entry: u32, root: u32) -> ExecutionTarget {
    ExecutionTarget::new(
        ProcedureKey::new(Word::new([Felt::from_u32(entry); 4])),
        EnvironmentRoot::new(Word::new([Felt::from_u32(root); 4])),
    )
}

#[test]
fn verifier_identities_separate_transaction_cache_entries() {
    let program = ProgramInfo::new(Word::default(), Default::default());
    let compatibility = Verifier::proof_compatibility();
    let environment = descriptor(7, 11);
    let key = tx_proof_cache_key(&program, environment, &[0, 1], &compatibility);
    let other_identity = VerifierIdentity::new(Word::new([Felt::ONE; 4]));

    for (vm_identities, pvm_identities) in [
        (vec![other_identity], compatibility.pvm_verifier_identities().to_vec()),
        (compatibility.vm_verifier_identities().to_vec(), vec![other_identity]),
    ] {
        let changed = ExecutionProofCompatibility::new(vm_identities, pvm_identities).unwrap();
        assert_ne!(key, tx_proof_cache_key(&program, environment, &[0, 1], &changed));
    }
    assert_eq!(key, tx_proof_cache_key(&program, environment, &[0, 1], &compatibility));
}

#[test]
fn equal_program_code_does_not_reuse_a_different_entry_or_environment() {
    let program = ProgramInfo::new(Word::default(), Default::default());
    let compatibility = Verifier::proof_compatibility();
    let key = tx_proof_cache_key(&program, descriptor(7, 11), &[0, 1], &compatibility);
    for changed in [descriptor(8, 11), descriptor(7, 12)] {
        assert_ne!(key, tx_proof_cache_key(&program, changed, &[0, 1], &compatibility));
    }
}
