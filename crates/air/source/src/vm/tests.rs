//! VM shape, complete statement binding and external-boundary regressions.

use alloc::{string::ToString, vec::Vec};

use miden_core::{
    WORD_SIZE, Word,
    field::{PrimeCharacteristicRing, QuadFelt},
    program::{EnvironmentRoot, ExecutionTarget, ProcedureKey, StackInputs, StackOutputs},
    serde::{Deserializable, Serializable},
};
use miden_stark::lookup::Challenges;
use p3_challenger::CanObserve;

use super::{
    inputs::NUM_AUX_INPUTS,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    *,
};

#[test]
fn core_shape_and_degree_match_design() {
    let air = MidenAir::CORE;
    let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);

    assert_eq!(air.width(), 48);
    assert_eq!(constraints::columns::NUM_DECODER_COLS, 23);
    assert_eq!(LiftedAir::<Felt, QuadFelt>::aux_width(&air), 4);
    assert_eq!(air.num_public_values(), 36);
    assert_eq!(air.column_shape(), &[4, 7, 4, 3]);
    assert_eq!(trace::TRACE_WIDTH, 72);
    assert_eq!(LOGUP_AUX_TRACE_WIDTH, 8);
    assert_eq!(symbolic, ConstraintDegrees { base: 9, ext: 9 });
    assert_eq!(
        LiftedAir::<Felt, QuadFelt>::constraint_degree(&air),
        symbolic,
        "Core's declared degree must match its handwritten constraints",
    );
    assert_eq!(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air), 3);
}

#[test]
fn chiplets_packed_relation_shape_and_degree_match_design() {
    let air = MidenAir::CHIPLETS;
    let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);

    assert_eq!(air.width(), 24);
    assert_eq!(LiftedAir::<Felt, QuadFelt>::aux_width(&air), 4);
    assert_eq!(AIRS.len(), 4);
    assert_eq!(air.num_public_values(), 4);
    assert_eq!(air.column_shape(), &[4, 4, 3, 2]);
    let periodic = air.periodic_columns();
    assert_eq!(periodic.len(), 9);
    assert_eq!(periodic[8], [Felt::ZERO, Felt::ONE]);
    assert_eq!(
        LiftedAir::<Felt, QuadFelt>::constraint_degree(&air),
        symbolic,
        "Chiplets' declared degree must match its handwritten constraints",
    );
    assert!(symbolic.base <= 9, "Chiplets base constraint degree exceeds nine: {symbolic:?}");
    assert!(
        symbolic.ext <= 9,
        "Chiplets extension constraint degree exceeds nine: {symbolic:?}"
    );
}

#[test]
fn and8_lookup_shape_and_degree_match_design() {
    let air = MidenAir::AND8_LOOKUP;

    assert_eq!(air.width(), 7);
    assert_eq!(air.preprocessed_width(), 5);
    assert_eq!(LiftedAir::<Felt, QuadFelt>::aux_width(&air), 4);
    assert_eq!(constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE, [1, 2, 2, 2],);
    assert_eq!(
        LiftedAir::<Felt, QuadFelt>::constraint_degree(&air),
        ConstraintDegrees { base: 0, ext: 3 }
    );
    assert_eq!(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air), 1);
}

#[test]
fn packed_statement_rejects_missing_and_malformed_air_public_inputs() {
    let challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(11)];
    let aux = vec![Felt::ZERO; NUM_AUX_INPUTS];
    let sum = [QuadFelt::ZERO];
    let sums = [sum.as_slice(); MIDEN_AIR_COUNT];
    let valid = vec![
        vec![Felt::ZERO; NUM_PUBLIC_VALUES],
        vec![Felt::ZERO; NUM_CHIPLETS_PUBLIC_VALUES],
        vec![],
        vec![],
    ];
    for count in [0, 1, 2, 3, 5] {
        let mut public = valid.clone();
        public.resize(count, vec![]);
        assert!(
            statement::eval_external(&challenges, &public, &aux, &sums, &[6, 6, 6, 16]).is_err()
        );
    }
    for count in [0, 4, 8, 32, 35, 37, 40, 44] {
        let mut public = valid.clone();
        public[0].resize(count, Felt::ZERO);
        assert!(
            statement::eval_external(&challenges, &public, &aux, &sums, &[6, 6, 6, 16]).is_err()
        );
    }
    for count in [0, 1, 3, 5, 8, 9] {
        let mut public = valid.clone();
        public[1].resize(count, Felt::ZERO);
        let error = statement::eval_external(&challenges, &public, &aux, &sums, &[6, 6, 6, 16])
            .unwrap_err();
        assert!(error.to_string().contains("Chiplets expects 4 public values"));
    }
}

#[test]
fn chiplets_open_boundary_uses_public_root_without_legacy_aux_authority() {
    let challenges = Challenges::new(
        QuadFelt::from_u32(7),
        QuadFelt::from_u32(11),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let public: Vec<_> = (1..=4).map(Felt::from_u32).collect();
    let expected = MidenAir::CHIPLETS.boundary_correction(&challenges, &public, &[]).unwrap();
    let unrelated_aux = vec![Felt::from_u32(91); 12];
    assert_eq!(
        MidenAir::CHIPLETS
            .boundary_correction(&challenges, &public, &unrelated_aux)
            .unwrap(),
        expected
    );
    let mut wrong_root = public;
    wrong_root[0] += Felt::ONE;
    assert_ne!(
        MidenAir::CHIPLETS.boundary_correction(&challenges, &wrong_root, &[]).unwrap(),
        expected
    );
}

#[test]
fn eval_external_weights_normalized_sums_by_trace_length() {
    let raw_challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(11)];
    let air_inputs = [
        vec![Felt::ZERO; NUM_PUBLIC_VALUES],
        vec![Felt::ZERO; NUM_CHIPLETS_PUBLIC_VALUES],
        vec![],
        vec![],
    ];
    let aux_inputs = vec![Felt::ZERO; NUM_AUX_INPUTS];
    let normalized_sums = [
        QuadFelt::from_u32(13),
        QuadFelt::from_u32(17),
        QuadFelt::from_u32(19),
        QuadFelt::from_u32(23),
    ];
    let core_values = [normalized_sums[0]];
    let chiplets_values = [normalized_sums[1]];
    let eidos_compression_values = [normalized_sums[2]];
    let and8_values = [normalized_sums[3]];
    let aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] =
        [&core_values, &chiplets_values, &eidos_compression_values, &and8_values];
    let log_trace_heights = [6, 9, 7, 16];

    let lookup_challenges = Challenges::new(
        raw_challenges[0],
        raw_challenges[1],
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let mut boundary_correction = QuadFelt::ZERO;
    for (air, public) in AIRS.iter().zip(&air_inputs) {
        boundary_correction +=
            air.boundary_correction(&lookup_challenges, public, &aux_inputs).unwrap();
    }

    let result = statement::eval_external(
        &raw_challenges,
        &air_inputs,
        &aux_inputs,
        &aux_values,
        &log_trace_heights,
    )
    .unwrap();

    let weighted_sum = normalized_sums
        .iter()
        .zip(log_trace_heights)
        .map(|(&value, log_height)| value * Felt::new_unchecked(1_u64 << u32::from(log_height)))
        .sum::<QuadFelt>();
    assert_eq!(result, vec![weighted_sum + boundary_correction]);
}

#[test]
fn eval_external_accepts_only_deferred_aux4_and_rejects_legacy_shapes() {
    let challenges = [QuadFelt::from_u32(3), QuadFelt::from_u32(5)];
    let (public, _) = statement_fixture().to_air_inputs();
    let zero = [QuadFelt::ZERO];
    let sums = [zero.as_slice(); MIDEN_AIR_COUNT];
    assert_eq!(statement::max_aux_inputs(), WORD_SIZE);
    for count in [0, 1, 2, 3, 5, 7, 8, 9, 12, 16, 36, 44, 1032] {
        let aux = vec![Felt::ZERO; count];
        let error = statement::eval_external(&challenges, &public, &aux, &sums, &[8, 8, 8, 16])
            .unwrap_err();
        assert!(error.to_string().contains("expected exactly 4 deferred-root inputs"));
    }
}

fn statement_fixture() -> PublicInputs {
    let word = |start: u32| Word::new(core::array::from_fn(|i| Felt::from_u32(start + i as u32)));
    PublicInputs::new(
        ExecutionTarget::new(ProcedureKey::new(word(101)), EnvironmentRoot::new(word(201))),
        StackInputs::new(&[Felt::from_u32(5), Felt::from_u32(6)]).unwrap(),
        StackOutputs::new(&[Felt::from_u32(7)]).unwrap(),
        word(301),
    )
}

#[test]
fn complete_public_projection_retains_descriptor_and_exact_group_order() {
    let inputs = statement_fixture();
    let claim = inputs.claim();
    let (groups, aux) = inputs.to_air_inputs();
    assert_eq!(groups.len(), 4);
    assert_eq!(groups.iter().map(Vec::len).collect::<Vec<_>>(), vec![36, 4, 0, 0]);
    assert_eq!(&groups[0][..16], claim.stack_inputs().as_ref());
    assert_eq!(&groups[0][16..32], claim.stack_outputs().as_ref());
    assert_eq!(&groups[0][32..], claim.entry_key().as_word().as_elements());
    assert_eq!(groups[1], claim.environment_root().as_word().as_elements());
    assert_eq!(aux, inputs.deferred_root().as_elements());
    assert_eq!(inputs.to_elements().len(), 44);
    assert_eq!(&inputs.to_elements()[..40], claim.to_elements());
    assert_eq!(&inputs.to_elements()[40..], aux);
}

#[test]
fn versioned_public_inputs_roundtrip_complete_claim_and_reject_legacy_or_extra_bytes() {
    let expected = statement_fixture();
    let bytes = expected.to_bytes();
    assert_eq!(bytes[0], 2);
    assert_eq!(PublicInputs::read_from_bytes(&bytes).unwrap(), expected);
    let smallest = PublicInputs::new(
        expected.execution_descriptor(),
        StackInputs::default(),
        StackOutputs::default(),
        expected.deferred_root(),
    );
    assert_eq!(PublicInputs::min_serialized_size(), smallest.to_bytes().len());
    assert_eq!(
        PublicInputs::read_from_bytes_with_budget(&bytes, bytes.len()).unwrap(),
        expected
    );
    assert!(PublicInputs::read_from_bytes_with_budget(&bytes, bytes.len() - 1).is_err());
    for end in 0..bytes.len() {
        assert!(PublicInputs::read_from_bytes(&bytes[..end]).is_err());
    }
    let mut oversized_stack = bytes[..65].to_vec();
    oversized_stack.push(17);
    for _ in 0..17 {
        Felt::ZERO.write_into(&mut oversized_stack);
    }
    assert!(PublicInputs::read_from_bytes(&oversized_stack).is_err());
    for version in [0, 1, 3, 255] {
        let mut wrong = bytes.clone();
        wrong[0] = version;
        assert!(PublicInputs::read_from_bytes(&wrong).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(PublicInputs::read_from_bytes(&trailing).is_err());
}

#[derive(Default)]
struct FeltSink {
    observed: Vec<Felt>,
}
impl CanObserve<Felt> for FeltSink {
    fn observe(&mut self, value: Felt) {
        self.observed.push(value);
    }
}

#[test]
fn observe_matches_execution_claim_commitment_and_binds_each_public_coordinate() {
    let inputs = statement_fixture();
    let (public, aux) = inputs.to_air_inputs();
    let mut sink = FeltSink::default();
    statement::observe(&mut sink, &public, &aux, &[10, 10, 10, 16]);
    let mut expected = inputs.claim().commitment().as_elements().to_vec();
    expected.extend_from_slice(inputs.deferred_root().as_elements());
    assert_eq!(sink.observed, expected, "observe must emit claim_hash4 || deferred4");
    for (group, count) in [(0, 36), (1, 4)] {
        for index in 0..count {
            let mut mutated = public.clone();
            mutated[group][index] += Felt::ONE;
            let mut changed = FeltSink::default();
            statement::observe(&mut changed, &mutated, &aux, &[10, 10, 10, 16]);
            assert_ne!(
                changed.observed[..4],
                sink.observed[..4],
                "group {group} coordinate {index}"
            );
            assert_eq!(changed.observed[4..], sink.observed[4..]);
        }
    }
    for index in 0..4 {
        let mut changed_aux = aux.clone();
        changed_aux[index] += Felt::ONE;
        let mut changed = FeltSink::default();
        statement::observe(&mut changed, &public, &changed_aux, &[10, 10, 10, 16]);
        assert_eq!(changed.observed[..4], sink.observed[..4]);
        assert_ne!(changed.observed[4..], sink.observed[4..]);
    }
}

#[test]
#[should_panic(expected = "expected exactly four deferred-root inputs")]
fn observe_rejects_short_aux_inputs() {
    let mut challenger = FeltSink::default();
    let (public, _) = statement_fixture().to_air_inputs();
    statement::observe(&mut challenger, &public, &[], &[8, 8, 8, 16]);
}
