//! Boundary corrections and normalized committed-sum metadata for the Miden VM LogUp argument.

use miden_core::{Felt, WORD_SIZE, field::PrimeCharacteristicRing};
use miden_stark::lookup::BoundaryBuilder;

use super::{
    buses::library::emit_open_seed,
    messages::{BlockHashMsg, LogDeferredMsg},
};
use crate::vm::{MIDEN_AIR_COUNT, NUM_CHIPLETS_PUBLIC_VALUES};

// COMMITTED NORMALIZED SUM COUNT
// ================================================================================================

/// Number of committed normalized LogUp sums (`sigma_prime`) in the multi-AIR proof shape: one per
/// AIR.
pub const NUM_LOGUP_COMMITTED_FINALS: usize = MIDEN_AIR_COUNT;

// BOUNDARY EMITTERS
// ================================================================================================

/// Emit boundary corrections for Core lookup columns.
///
/// The block-hash seed and log-deferred root terminals cancel against these Core
/// bus accumulators:
/// - `BlockHashTable` lives on `MAIN_COLUMN_SHAPE[1]` (block_hash + op_group merged column).
/// - `LogDeferredRoot` lives on `MAIN_COLUMN_SHAPE[0]` (block_stack + range + log-cap merged
///   column).
pub(crate) fn emit_core_boundary<B: BoundaryBuilder>(boundary: &mut B) {
    // Core's legacy program-hash/deferred prefix stays explicit until the root/claim cutover.
    // Bare-trace tools must supply statement data rather than silently invent zero authority.
    let inputs = boundary.var_len_public_inputs();
    assert_eq!(inputs.len(), 1, "Core boundary requires one explicit input slice");
    let stmt = inputs[0];
    assert_eq!(stmt.len(), 2 * WORD_SIZE, "Core boundary requires its complete fixed prefix");
    let program_hash: [B::F; 4] = core::array::from_fn(|i| stmt[i]);
    let final_state: [B::F; 4] = core::array::from_fn(|i| stmt[WORD_SIZE + i]);

    // Block-hash seed: +1 / encode(BLOCK_HASH_TABLE, [ph, 0, 0, 0]).
    //
    // The boundary correction emits a `Child` payload while the in-trace removal at the
    // root END row (in `block_hash_and_op_group.rs`) emits an `End` payload — the two
    // collapse to the same denominator by the algebra below, so a single `Child` here
    // cancels the root END's `-1/d`:
    //
    //   - At the root END row, the next op is HALT, so the decoder forces `addr_next = 0`, hence
    //     `parent = addr_next = 0`.
    //   - `halt_next() = 1` ⇒ `is_first_child = 1 - end_next - repeat_next - halt_next = 0`.
    //   - The root block is not a loop body, so `is_loop_body = 0`.
    //   - `child_hash = h_0 = program_hash` by the decoder's program-hash boundary.
    //
    // With `is_first_child = 0` and `is_loop_body = 0`, the `End` payload encodes
    // identically to `Child { parent: 0, child_hash: program_hash }`, so the boundary
    // `+1/d` here matches the in-trace `-1/d` and the bus balances.
    boundary.add(
        "block_hash_seed",
        BlockHashMsg::Child {
            parent: B::F::ZERO,
            child_hash: program_hash,
        },
    );

    // Log-deferred root terminals: +1 / d_initial − 1 / d_final.
    boundary.add("log_deferred_initial", LogDeferredMsg { state: [B::F::ZERO; 4] });
    boundary.remove("log_deferred_final", LogDeferredMsg { state: final_state });
}

/// Emit boundary corrections for Chiplets lookup columns.
///
/// The caller supplies exactly the Chiplets public vector `R_E || N_kernel` through the
/// existing boundary carrier. No auxiliary kernel list or absent-input default is accepted.
pub(crate) fn emit_chiplets_boundary<B: BoundaryBuilder<F = Felt>>(boundary: &mut B) {
    let [public_values] = boundary.var_len_public_inputs() else {
        panic!("Chiplets boundary requires its validated public input slice");
    };
    assert_eq!(public_values.len(), NUM_CHIPLETS_PUBLIC_VALUES);
    let environment_root = core::array::from_fn(|i| public_values[i]);
    emit_open_seed(boundary, environment_root);
}

// TESTS
// ================================================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;

    use std::{vec, vec::Vec};

    use miden_core::{
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::{Matrix, RowMajorMatrix},
    };
    use miden_stark::{
        air::BaseAir,
        lookup::{
            Challenges, build_lookup_fractions,
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

    /// Pin the `BlockHashMsg::End -> Child` boundary collapse: at the root END row, the
    /// algebra forces `is_first_child = 0`, `is_loop_body = 0`, `parent = 0`, and
    /// `child_hash = program_hash`, so the in-trace `End` removal and the boundary
    /// `Child` seed encode to the same denominator.
    #[test]
    fn block_hash_seed_matches_root_end_removal() {
        use miden_stark::lookup::{Challenges, LookupMessage};

        use crate::vm::constraints::lookup::messages::BlockHashMsg;

        let challenges = Challenges::<QuadFelt>::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let program_hash: [Felt; 4] = [
            Felt::from_u32(101),
            Felt::from_u32(102),
            Felt::from_u32(103),
            Felt::from_u32(104),
        ];

        // Boundary side: emitted by `emit_core_boundary` for the root program hash seed.
        let seed = BlockHashMsg::Child {
            parent: Felt::ZERO,
            child_hash: program_hash,
        };

        // In-trace side: the root END row's removal, with the four conditions documented in
        // `emit_core_boundary` (addr_next=0 via HALT; halt_next=1 so is_first_child=0; root
        // not a loop so is_loop_body=0; child_hash = h_0 = program_hash).
        let root_end = BlockHashMsg::End {
            parent: Felt::ZERO,
            child_hash: program_hash,
            is_first_child: Felt::ZERO,
            is_loop_body: Felt::ZERO,
        };

        assert_eq!(
            <BlockHashMsg<Felt> as LookupMessage<Felt, QuadFelt>>::encode(&seed, &challenges),
            <BlockHashMsg<Felt> as LookupMessage<Felt, QuadFelt>>::encode(&root_end, &challenges),
            "boundary `Child` seed and root-END `End` removal must encode to equal denominators"
        );
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
