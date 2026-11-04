//! Claim40 staging and rejection checks independent of proof generation.

use miden_core::{
    Felt, Word,
    program::{
        EnvironmentRoot, ExecutionClaim, ExecutionTarget, NUM_CLAIM_ELEMENTS, ProcedureKey,
        StackInputs, StackOutputs,
    },
};
use miden_crypto::hash::eidos::{DomainTag, Eidos, EidosFrame};
use miden_processor::{ExecutionError, advice::AdviceError};
use miden_utils_testing::{crypto::MerkleStore, expect_exec_error_matches};

use crate::helpers::{masm_push_word, masm_store_felts};

const CLAIM_PTR: u32 = 1000;

fn claim_fixture() -> ExecutionClaim {
    let elements: [Felt; NUM_CLAIM_ELEMENTS] =
        std::array::from_fn(|i| Felt::new_unchecked(i as u64 + 1));
    ExecutionClaim::new(
        ExecutionTarget::new(
            ProcedureKey::new(Word::new(elements[..4].try_into().unwrap())),
            EnvironmentRoot::new(Word::new(elements[4..8].try_into().unwrap())),
        ),
        StackInputs::new(&elements[8..24]).unwrap(),
        StackOutputs::new(&elements[24..40]).unwrap(),
    )
}

fn check_memory(elements: &[Felt], start: u32) -> String {
    elements
        .iter()
        .enumerate()
        .map(|(i, value)| {
            format!(
                "mem_load.{} eq.{} assert.err=\"claim staging changed memory at {}\"\n",
                start + i as u32,
                value.as_canonical_u64(),
                start + i as u32,
            )
        })
        .collect()
}

fn materialize_source(commitment: Word) -> String {
    format!(
        "use miden::core::sys::vm::claim
        begin
            {}
            push.{CLAIM_PTR} exec.claim::materialize_claim
        end",
        masm_push_word(&commitment),
    )
}

#[test]
fn claim40_materialization_is_bounded_and_hash_ignores_adjacent_scratch() {
    let claim = claim_fixture();
    let elements = claim.to_elements();
    assert_eq!(elements.len(), 40);
    let commitment = claim.commitment();
    let commitment_push = masm_push_word(&commitment);
    let end = CLAIM_PTR + 40;
    let claim_checks = check_memory(&elements, CLAIM_PTR);
    const FOLLOWING_ADVICE: u64 = 0x1234_5678_9abc;

    for poison in [71, 0xdead_beef, (1_u64 << 32) + 71] {
        let before = std::array::from_fn::<_, 4, _>(|i| Felt::new_unchecked(poison + i as u64));
        let after = std::array::from_fn::<_, 4, _>(|i| Felt::new_unchecked(poison + 4 + i as u64));
        let before_store = masm_store_felts(&before, CLAIM_PTR - 4);
        let after_store = masm_store_felts(&after, end);
        let stale_claim = masm_store_felts(&[Felt::new_unchecked(poison + 8); 40], CLAIM_PTR);
        let before_check = check_memory(&before, CLAIM_PTR - 4);
        let after_check = check_memory(&after, end);
        let source = format!(
            "use miden::core::sys::vm::claim
            begin
                {before_store}
                {stale_claim}
                {after_store}
                {commitment_push}
                push.{CLAIM_PTR} exec.claim::materialize_claim

                # The map contributes exactly 40 values above the caller's advice tail.
                adv_push eq.{FOLLOWING_ADVICE}
                assert.err=\"claim materialization consumed following advice\"
                {claim_checks}
                {before_check}
                {after_check}

                # Both the materialization hash and the memory hash must use the native claim.
                push.{CLAIM_PTR} exec.claim::claim_commitment
                {commitment_push}
                assert_eqw.err=\"claim hash depends on adjacent scratch\"
                {before_check}
                {after_check}
            end"
        );
        build_test!(
            source.as_str(),
            &[],
            &[FOLLOWING_ADVICE],
            MerkleStore::new(),
            [(commitment, elements.to_vec())]
        )
        .expect_stack(&[0; 16]);
    }
}

#[test]
fn missing_claim_preimage_does_not_fall_back_to_advice_stack() {
    let claim = claim_fixture();
    let commitment = claim.commitment();
    let source = materialize_source(commitment);
    let advice: Vec<u64> = claim.to_elements().iter().map(Felt::as_canonical_u64).collect();
    let test = build_test!(source.as_str(), &[], &advice);
    expect_exec_error_matches!(
        test,
        ExecutionError::AdviceError {
            err: AdviceError::MapKeyNotFound { key },
            ..
        } if key == commitment
    );
}

#[test]
fn retired_claim40_domain_is_rejected_after_map_lookup() {
    let claim = claim_fixture();
    let elements = claim.to_elements();
    // Reconstruct only the retired frame. The accepted commitment oracle stays native.
    let legacy_tag = DomainTag::from_u32(0x0100_0101).unwrap();
    let mut retired = EidosFrame::new(legacy_tag, [40, 0, 0]).initial_chaining_word();
    for &block in elements.as_chunks::<8>().0 {
        retired = Eidos::compress(retired, block);
    }
    assert_ne!(retired, claim.commitment());
    let source = materialize_source(retired);
    let test =
        build_test!(source.as_str(), &[], &[], MerkleStore::new(), [(retired, elements.to_vec())]);
    expect_assert_error_code_from_msg!(test, "claim preimage commitment does not match");
}

#[test]
fn obsolete_44_felt_claim_is_rejected_before_materialization() {
    let claim = claim_fixture();
    let commitment = claim.commitment();
    let mut obsolete = claim.to_elements().to_vec();
    obsolete.extend_from_slice(&[Felt::new_unchecked(91); 4]);
    let source = materialize_source(commitment);
    let test = build_test!(source.as_str(), &[], &[], MerkleStore::new(), [(commitment, obsolete)]);
    expect_assert_error_code_from_msg!(test, "claim preimage has a non-canonical length");
}
