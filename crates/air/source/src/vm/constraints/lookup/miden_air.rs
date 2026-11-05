//! Boundary corrections and normalized committed-sum metadata for the Miden VM LogUp argument.

use miden_core::{Felt, WORD_SIZE, field::PrimeCharacteristicRing};
use miden_stark::lookup::BoundaryBuilder;

use super::{buses::library::emit_open_seed, messages::LogDeferredMsg};
use crate::vm::{MIDEN_AIR_COUNT, NUM_CHIPLETS_PUBLIC_VALUES};

// COMMITTED NORMALIZED SUM COUNT
// ================================================================================================

/// Number of committed normalized LogUp sums (`sigma_prime`) in the multi-AIR proof shape: one per
/// AIR.
pub const NUM_LOGUP_COMMITTED_FINALS: usize = MIDEN_AIR_COUNT;

// BOUNDARY EMITTERS
// ================================================================================================

/// Emit the two deferred-transcript boundary corrections for Core lookup columns.
///
/// Entry authentication is the in-trace root Resolve demand; no external program-digest
/// seed participates in the block-hash relation.
pub(crate) fn emit_core_boundary<B: BoundaryBuilder>(boundary: &mut B) {
    let inputs = boundary.var_len_public_inputs();
    assert_eq!(inputs.len(), 1, "Core boundary requires one explicit input slice");
    let deferred = inputs[0];
    assert_eq!(deferred.len(), WORD_SIZE, "Core boundary requires exactly its deferred root");
    let final_state: [B::F; 4] = core::array::from_fn(|i| deferred[i]);

    // Log-deferred root terminals: +1 / d_initial − 1 / d_final.
    boundary.add("log_deferred_initial", LogDeferredMsg { state: [B::F::ZERO; 4] });
    boundary.remove("log_deferred_final", LogDeferredMsg { state: final_state });
}

/// Emit boundary corrections for Chiplets lookup columns.
///
/// The caller supplies exactly the Chiplets public vector `R_E` through the
/// existing boundary carrier. No auxiliary kernel list or absent-input default is accepted.
pub(crate) fn emit_chiplets_boundary<B: BoundaryBuilder<F = Felt>>(boundary: &mut B) {
    let [public_values] = boundary.var_len_public_inputs() else {
        panic!("Chiplets boundary requires its validated public input slice");
    };
    assert_eq!(public_values.len(), NUM_CHIPLETS_PUBLIC_VALUES);
    let environment_root: [Felt; WORD_SIZE] = (*public_values)
        .try_into()
        .expect("Chiplets boundary requires exactly four environment-root Felts");
    emit_open_seed(boundary, environment_root);
}

// TESTS
// ================================================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;

    use std::{vec, vec::Vec};

    use miden_core::{
        field::{Field, PrimeCharacteristicRing, QuadFelt},
        utils::{Matrix, RowMajorMatrix},
    };
    use miden_stark::{
        air::BaseAir,
        lookup::{
            BoundaryBuilder, Challenges, LookupMessage, build_lookup_fractions,
            debug::{ValidateLayout, ValidateLookupAir},
        },
    };

    use crate::vm::{
        EidosCompressionAir, Felt, LiftedAir, MidenAir, NUM_EIDOS_COMPRESSION_COLS,
        NUM_PUBLIC_VALUES,
        constraints::{
            columns::NUM_CORE_COLS,
            eidos_compression::lookup::EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE,
            lookup::{BusId, MIDEN_MAX_MESSAGE_WIDTH, main_air::MAIN_COLUMN_SHAPE},
        },
        trace::AUX_TRACE_RAND_CHALLENGES,
    };

    struct CoreBoundary<'a> {
        inputs: &'a [&'a [Felt]],
        events: Vec<(Felt, QuadFelt)>,
    }

    impl BoundaryBuilder for CoreBoundary<'_> {
        type F = Felt;
        type EF = QuadFelt;

        fn var_len_public_inputs(&self) -> &[&[Felt]] {
            self.inputs
        }

        fn insert<M>(&mut self, _name: &'static str, multiplicity: Felt, message: M)
        where
            M: LookupMessage<Felt, QuadFelt>,
        {
            self.events.push((multiplicity, message.encode(&challenges())));
        }
    }

    fn challenges() -> Challenges<QuadFelt> {
        Challenges::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        )
    }

    #[test]
    fn core_boundary_has_only_two_deferred_terms() {
        use crate::vm::constraints::lookup::messages::LogDeferredMsg;

        let final_state = core::array::from_fn(|i| Felt::from_u32(101 + i as u32));
        let inputs = [final_state.as_slice()];
        let mut boundary = CoreBoundary { inputs: &inputs, events: Vec::new() };
        super::emit_core_boundary(&mut boundary);
        let initial = LogDeferredMsg { state: [Felt::ZERO; 4] }.encode(&challenges());
        let final_denominator = LogDeferredMsg { state: final_state }.encode(&challenges());
        assert_eq!(boundary.events, vec![(Felt::ONE, initial), (-Felt::ONE, final_denominator)]);
        let correction: QuadFelt = boundary.events.iter().map(|(m, d)| d.inverse() * *m).sum();
        assert_eq!(correction, initial.inverse() - final_denominator.inverse());
    }

    #[test]
    fn chiplets_boundary_adds_only_the_fixed_initial_namespace_open_seed() {
        use miden_core::program::Namespace;

        use crate::vm::constraints::lookup::messages::LibraryOpenMsg;

        let environment_root = core::array::from_fn(|i| Felt::from_u32(71 + i as u32));
        let inputs = [environment_root.as_slice()];
        let mut boundary = CoreBoundary { inputs: &inputs, events: Vec::new() };
        super::emit_chiplets_boundary(&mut boundary);
        let seed = LibraryOpenMsg {
            depth: Felt::ZERO,
            commitment: environment_root,
            namespace: Namespace::initial().into_word().into_elements(),
        }
        .encode(&challenges());
        assert_eq!(boundary.events, vec![(Felt::ONE, seed)]);
    }

    #[test]
    fn core_boundary_rejects_absent_partial_or_legacy_program_hash_carriers() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        for length in [0, 1, 3, 5, 8, 12] {
            let values = vec![Felt::ZERO; length];
            let inputs = [values.as_slice()];
            let mut boundary = CoreBoundary { inputs: &inputs, events: Vec::new() };
            assert!(
                catch_unwind(AssertUnwindSafe(|| super::emit_core_boundary(&mut boundary)))
                    .is_err()
            );
        }
        let values = [Felt::ZERO; 4];
        for count in [0, 2] {
            let inputs = vec![values.as_slice(); count];
            let mut boundary = CoreBoundary { inputs: &inputs, events: Vec::new() };
            assert!(
                catch_unwind(AssertUnwindSafe(|| super::emit_core_boundary(&mut boundary)))
                    .is_err()
            );
        }
    }

    /// Lookup-structure validation for `CoreAir`.
    #[test]
    fn core_air_lookup_validates() {
        let layout = ValidateLayout {
            preprocessed_width: 0,
            trace_width: NUM_CORE_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            num_periodic_columns: 0,
            permutation_width: MAIN_COLUMN_SHAPE.len(),
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: 1,
        };
        ValidateLookupAir::validate(&MidenAir::Core, layout)
            .unwrap_or_else(|err| panic!("CoreAir LookupAir validation failed: {err}"));
    }

    /// Lookup-structure validation for `ChipletsAir`.
    #[test]
    fn chiplets_air_lookup_validates() {
        let air = MidenAir::CHIPLETS;
        let layout = ValidateLayout {
            preprocessed_width: air.preprocessed_width(),
            trace_width: air.width(),
            num_public_values: air.num_public_values(),
            num_periodic_columns: air.periodic_columns().len(),
            permutation_width: LiftedAir::<Felt, QuadFelt>::aux_width(&air),
            num_permutation_challenges: LiftedAir::<Felt, QuadFelt>::num_randomness(&air),
            num_permutation_values: LiftedAir::<Felt, QuadFelt>::num_aux_values(&air),
        };
        ValidateLookupAir::validate(&air, layout)
            .unwrap_or_else(|err| panic!("ChipletsAir LookupAir validation failed: {err}"));
    }
    #[test]
    fn eidos_compression_air_lookup_validates() {
        let num_periodic = EidosCompressionAir.periodic_columns().len();
        let layout = ValidateLayout {
            preprocessed_width: 0,
            trace_width: NUM_EIDOS_COMPRESSION_COLS,
            num_public_values: 0,
            num_periodic_columns: num_periodic,
            permutation_width: EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len(),
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: 1,
        };
        ValidateLookupAir::validate(&MidenAir::EIDOS_COMPRESSION, layout)
            .unwrap_or_else(|err| panic!("EidosCompressionAir LookupAir validation failed: {err}"));
    }

    #[test]
    fn and8_lookup_air_lookup_validates() {
        let layout = ValidateLayout {
            preprocessed_width:
                crate::vm::constraints::and8_lookup::columns::NUM_AND8_LOOKUP_PREPROCESSED_COLS,
            trace_width: crate::vm::constraints::and8_lookup::columns::NUM_AND8_LOOKUP_COLS,
            num_public_values: 0,
            num_periodic_columns: 0,
            permutation_width:
                crate::vm::constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE.len(),
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: 1,
        };
        ValidateLookupAir::validate(&MidenAir::AND8_LOOKUP, layout)
            .unwrap_or_else(|err| panic!("And8LookupAir LookupAir validation failed: {err}"));
        assert_eq!(
            crate::vm::constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE,
            [1, 2, 2, 2],
        );
    }

    #[test]
    fn and8_lookup_packs_seven_live_interactions_into_four_columns() {
        const NUM_ROWS: usize = 2;

        let air = MidenAir::AND8_LOOKUP;
        let full_preprocessed =
            air.preprocessed_trace().expect("And8 lookup AIR declares a preprocessed table");
        let preprocessed_width = full_preprocessed.width();
        let last_row = full_preprocessed.height() - 1;
        let mut preprocessed_values = Vec::with_capacity(NUM_ROWS * preprocessed_width);
        for row in [0, last_row] {
            let start = row * preprocessed_width;
            preprocessed_values
                .extend_from_slice(&full_preprocessed.values[start..start + preprocessed_width]);
        }
        let preprocessed = RowMajorMatrix::new(preprocessed_values, preprocessed_width);
        let main = RowMajorMatrix::new(
            vec![
                Felt::ONE;
                NUM_ROWS * crate::vm::constraints::and8_lookup::columns::NUM_AND8_LOOKUP_COLS
            ],
            crate::vm::constraints::and8_lookup::columns::NUM_AND8_LOOKUP_COLS,
        );
        let challenges = Challenges::<QuadFelt>::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let fractions = build_lookup_fractions(&air, &main, Some(&preprocessed), &[], &challenges);

        assert_eq!(fractions.shape(), &[1, 2, 2, 2]);
        assert_eq!(fractions.counts(), &[1, 2, 2, 2, 1, 2, 2, 2]);
        assert_eq!(fractions.fractions().len(), NUM_ROWS * 7);
    }
}
