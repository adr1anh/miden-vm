//! Chiplet-trace LogUp lookup AIR.
//!
//! Owns the chiplet-trace side of the Miden VM's LogUp argument: four lookup columns, one
//! per `emit_*` function in [`super::buses`]. This module wires them together
//! via a single [`ChipletBusContext`] that carries the two-row window plus a shared
//! [`ChipletActiveFlags`] snapshot.
//!
//! Columns (in emission order):
//! - chiplet responses (memory / bitwise / hasher replies).
//! - hash-kernel virtual table.
//! - shared wiring column: ACE wiring + hasher compression link.
//! - four-Felt hasher result and chaining-value returns.
//!
//! [`ChipletLookupBuilder`] builds the shared active flags from the chiplet selector columns.
//! Adapters may override the default construction while preserving those flag semantics.

use core::borrow::Borrow;

use miden_stark::lookup::LookupBuilder;

use super::buses::{
    ChipletActiveFlags,
    chiplet_responses::{self, emit_chiplet_responses},
    hash_kernel::{self, emit_hash_kernel_table},
    hasher_returns::{self, emit_hasher_returns},
    wiring::{self, emit_v_wiring},
};
use crate::vm::{
    ChipletCols, Felt,
    constraints::chiplets::{columns::PeriodicCols, library::LibraryRowContext},
};

// CHIPLET LOOKUP BUILDER
// ================================================================================================

/// Extension trait the chiplet-trace [`LookupAir`] requires from its [`LookupBuilder`].
///
/// Carries a single hook, [`build_chiplet_active`](Self::build_chiplet_active), for
/// constructing the shared [`ChipletActiveFlags`] snapshot consumed by the four
/// chiplet-trace bus emitters. Symmetric to [`super::main_air::MainLookupBuilder`]; see its
/// docs for the rationale behind the explicit-impl-no-blanket pattern.
pub(crate) trait ChipletLookupBuilder: LookupBuilder<F = Felt> {
    /// Build the shared [`ChipletActiveFlags`] snapshot for one `eval` call.
    ///
    /// Default body calls [`ChipletActiveFlags::from_chiplet_cols`] against the multi-AIR
    /// `ChipletCols` view. Adapters can override this when a cheaper construction path is
    /// worthwhile.
    fn build_chiplet_active(
        &self,
        local: &ChipletCols<Self::Var>,
    ) -> ChipletActiveFlags<Self::Expr> {
        ChipletActiveFlags::from_chiplet_cols(local)
    }
}

// CHIPLET BUS CONTEXT
// ================================================================================================

/// Shared context for the chiplet-trace bus emitters.
///
/// Holds the two-row window plus a single [`ChipletActiveFlags`] snapshot built once per
/// `eval` through [`ChipletLookupBuilder::build_chiplet_active`].
pub(crate) struct ChipletBusContext<'a, LB>
where
    LB: LookupBuilder<F = Felt>,
{
    /// Typed view of the current row (Chiplets half of the trace).
    pub local: &'a ChipletCols<LB::Var>,
    /// Typed view of the next row (Chiplets half of the trace).
    pub next: &'a ChipletCols<LB::Var>,
    /// Per-chiplet `is_active` flags, computed from `local`'s selector columns via the
    /// builder-provided hook.
    pub chiplet_active: ChipletActiveFlags<LB::Expr>,
    /// Direct Library scope and fixed phase inputs for the shared hash-kernel group.
    pub library: LibraryRowContext<LB::Expr>,
}

impl<'a, LB> ChipletBusContext<'a, LB>
where
    LB: ChipletLookupBuilder,
{
    /// Build the shared chiplet-trace context for one `eval` call.
    pub fn new(
        builder: &LB,
        local: &'a ChipletCols<LB::Var>,
        next: &'a ChipletCols<LB::Var>,
    ) -> Self {
        let chiplet_active = builder.build_chiplet_active(local);
        let periodic: &PeriodicCols<LB::PeriodicVar> = builder.periodic_values().borrow();
        let library = LibraryRowContext {
            is_active: chiplet_active.library.clone(),
            next_is_active: next.chiplets[0].into(),
            phase: periodic.library_phase.into(),
            exit_aligned: periodic.aead_stream.phases[7].into(),
        };
        Self { local, next, chiplet_active, library }
    }
}

// CHIPLET LOOKUP COLUMNS
// ================================================================================================

/// Per-column fraction stride, in emission order (see [`emit_chiplet_lookup_columns`]).
pub(crate) const CHIPLET_COLUMN_SHAPE: [usize; 4] = [
    chiplet_responses::MAX_INTERACTIONS_PER_ROW,
    hash_kernel::MAX_INTERACTIONS_PER_ROW,
    wiring::MAX_INTERACTIONS_PER_ROW,
    hasher_returns::MAX_INTERACTIONS_PER_ROW,
];

/// Emit the chiplet-trace LogUp columns.
///
/// Driven by `ChipletsAir`'s [`LookupAir`] impl.
pub(crate) fn emit_chiplet_lookup_columns<LB: ChipletLookupBuilder>(
    builder: &mut LB,
    local: &ChipletCols<LB::Var>,
    next: &ChipletCols<LB::Var>,
) {
    let ctx = ChipletBusContext::new(&*builder, local, next);
    emit_chiplet_responses::<LB>(builder, &ctx);
    emit_hash_kernel_table::<LB>(builder, &ctx);
    emit_v_wiring::<LB>(builder, &ctx);
    emit_hasher_returns::<LB>(builder, &ctx);
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_stark::{
        air::{
            AirBuilder, WindowAccess,
            symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpression},
        },
        lookup::{
            Challenges, ConstraintLookupBuilder, LookupAir, LookupFractions, LookupMessage,
            build_lookup_fractions,
        },
    };

    use super::*;
    use crate::vm::{
        MidenAir, NUM_CHIPLETS_PUBLIC_VALUES,
        constraints::{
            columns::NUM_CHIPLETS_COLS,
            lookup::messages::{
                BusId, BytePairLookupMsg, LibraryResolveMsg, MIDEN_MAX_MESSAGE_WIDTH, RangeMsg,
            },
        },
        trace::chiplets::library::MAST,
    };

    #[test]
    fn packed_library_lookup_scopes_cover_each_boolean_selector_pattern() {
        for code in 0_u8..64 {
            let mut row = [Felt::ZERO; NUM_CHIPLETS_COLS];
            for (index, cell) in row[..6].iter_mut().enumerate() {
                *cell = Felt::from_u8((code >> index) & 1);
            }
            let local: &ChipletCols<_> = row.as_slice().borrow();
            let active = ChipletActiveFlags::<Felt>::from_chiplet_cols(local);
            let [library, controller, aead, memory_end, ace_end, bitwise_end] =
                core::array::from_fn(|index| (code >> index) & 1 == 1);
            let expected = [
                library,
                !library && controller,
                !library && !controller && aead,
                !library && !controller && !aead && !memory_end,
                !library && !controller && !aead && memory_end && !ace_end,
                !library && !controller && !aead && memory_end && ace_end && !bitwise_end,
            ];
            assert_eq!(
                [
                    active.library,
                    active.controller,
                    active.aead_stream,
                    active.memory,
                    active.ace,
                    active.bitwise
                ],
                expected.map(Felt::from_bool),
                "selector pattern {code:06b}",
            );
        }
    }

    #[test]
    fn packed_library_lookup_active_flags_have_selected_degrees() {
        let symbolic = SymbolicAirBuilder::<Felt, QuadFelt>::new(layout());
        let main = symbolic.main();
        let local: &ChipletCols<_> = main.current_slice().borrow();
        let active = ChipletActiveFlags::<SymbolicExpression<Felt>>::from_chiplet_cols(local);
        assert_eq!(
            [
                active.library,
                active.controller,
                active.aead_stream,
                active.memory,
                active.ace,
                active.bitwise
            ]
            .map(|flag| flag.degree_multiple()),
            [1, 2, 3, 4, 5, 6],
        );
    }

    fn layout() -> AirLayout {
        AirLayout {
            preprocessed_width: 0,
            main_width: NUM_CHIPLETS_COLS,
            num_public_values: NUM_CHIPLETS_PUBLIC_VALUES,
            num_periodic_columns: 9,
            permutation_width: 4,
            num_permutation_challenges: 2,
            num_permutation_values: 1,
        }
    }

    #[test]
    fn packed_library_complete_lookup_constraints_stay_within_degree_nine() {
        #[cfg(feature = "std")]
        {
            use miden_stark::lookup::debug::{ValidateLayout, ValidateLookupAir};

            MidenAir::CHIPLETS
                .validate(ValidateLayout {
                    preprocessed_width: 0,
                    trace_width: NUM_CHIPLETS_COLS,
                    num_public_values: NUM_CHIPLETS_PUBLIC_VALUES,
                    num_periodic_columns: 9,
                    permutation_width: 4,
                    num_permutation_challenges: 2,
                    num_permutation_values: 1,
                })
                .unwrap_or_else(|error| panic!("Packed Chiplets lookup metadata: {error}"));
        }
        let mut symbolic = SymbolicAirBuilder::<Felt, QuadFelt>::new(layout());
        let mut builder = ConstraintLookupBuilder::new(&mut symbolic, &MidenAir::CHIPLETS);
        MidenAir::CHIPLETS.eval(&mut builder);
        builder.finish();
        let degrees: Vec<_> = symbolic
            .extension_constraints()
            .iter()
            .map(|constraint| constraint.degree_multiple())
            .collect();
        assert_eq!(degrees.iter().copied().max(), Some(9));
        assert!(degrees.iter().all(|degree| *degree <= 9), "{degrees:?}");
    }

    fn challenges() -> Challenges<QuadFelt> {
        Challenges::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        )
    }

    fn fractions(row: [Felt; NUM_CHIPLETS_COLS]) -> LookupFractions<Felt, QuadFelt> {
        let trace = RowMajorMatrix::new(vec![row; 8].as_flattened().to_vec(), NUM_CHIPLETS_COLS);
        let result = build_lookup_fractions(
            &MidenAir::CHIPLETS,
            &trace,
            None,
            &PeriodicCols::periodic_columns(),
            &challenges(),
        );
        assert_eq!(result.shape(), &[4, 4, 3, 2]);
        for counts in result.counts().as_chunks::<4>().0 {
            for (count, capacity) in counts.iter().zip(result.shape()) {
                assert!(count <= capacity, "{counts:?}");
            }
        }
        result
    }

    fn at(
        fractions: &LookupFractions<Felt, QuadFelt>,
        row: usize,
        column: usize,
    ) -> &[(Felt, QuadFelt)] {
        let index = row * 4 + column;
        let offset = fractions.counts()[..index].iter().sum::<usize>();
        &fractions.fractions()[offset..offset + fractions.counts()[index]]
    }

    fn assert_multiset(mut actual: Vec<(Felt, QuadFelt)>, expected: Vec<(Felt, QuadFelt)>) {
        for fraction in expected {
            let index = actual
                .iter()
                .position(|entry| *entry == fraction)
                .expect("missing original lookup fraction");
            let _ = actual.swap_remove(index);
        }
        assert!(actual.is_empty(), "extra lookup fractions: {actual:?}");
    }

    #[test]
    fn packed_library_mast_batch_uses_existing_column_with_both_resolve_frequencies() {
        let indices = core::array::from_fn::<_, NUM_CHIPLETS_COLS, _>(|index| index);
        let columns: &ChipletCols<_> = indices.as_slice().borrow();
        let library = columns.library();
        let mut row = [Felt::ZERO; NUM_CHIPLETS_COLS];
        row[0] = Felt::ONE;
        for (index, kind) in library.k.into_iter().zip(MAST) {
            row[index] = kind;
        }
        row[library.a] = Felt::from_u8(3);
        row[library.b] = Felt::from_u8(5);
        for index in 0..4 {
            row[library.z[index]] = Felt::from_usize(50 + index);
            row[library.w[index]] = Felt::from_usize(70 + index);
        }
        let expected_resolve: Vec<_> =
            [(Felt::ZERO, Felt::from_u8(3)), (Felt::ONE, Felt::from_u8(5))]
                .map(|(requires_syscall, frequency)| {
                    (
                        frequency,
                        LibraryResolveMsg {
                            requires_syscall,
                            key: library.z.map(|index| row[index]),
                            implementation: library.w.map(|index| row[index]),
                        }
                        .encode(&challenges()),
                    )
                })
                .to_vec();
        let actual = fractions(row);
        for row in 0..8 {
            assert_eq!(
                &actual.counts()[row * 4..row * 4 + 4],
                &[0, if row % 2 == 0 { 2 } else { 3 }, 0, 0]
            );
            if row % 2 == 1 {
                assert_eq!(&at(&actual, row, 1)[1..], expected_resolve);
            }
        }
    }

    #[test]
    fn packed_library_bitwise_redistribution_preserves_raw_four_tuple_multiset() {
        let indices = core::array::from_fn::<_, NUM_CHIPLETS_COLS, _>(|index| index);
        let columns: &ChipletCols<_> = indices.as_slice().borrow();
        let bitwise = columns.bitwise();
        for repeated in [false, true] {
            let mut row = [Felt::ZERO; NUM_CHIPLETS_COLS];
            row[3] = Felt::ONE;
            row[4] = Felt::ONE;
            for index in 0..4 {
                row[bitwise.a_bytes[index]] =
                    Felt::from_usize(if repeated { 21 } else { 21 + index });
                row[bitwise.b_bytes[index]] =
                    Felt::from_usize(if repeated { 37 } else { 37 + index });
                row[bitwise.and_bytes[index]] =
                    Felt::from_usize(if repeated { 5 } else { 5 + index });
            }
            let expected: Vec<_> = (0..4)
                .map(|index| {
                    (
                        -Felt::ONE,
                        BytePairLookupMsg::from_and(
                            row[bitwise.a_bytes[index]],
                            row[bitwise.b_bytes[index]],
                            row[bitwise.and_bytes[index]],
                        )
                        .encode(&challenges()),
                    )
                })
                .collect();
            let actual = fractions(row);
            for row in 0..8 {
                assert_eq!(actual.counts()[row * 4 + 1], 2);
                assert_eq!(actual.counts()[row * 4 + 3], 2);
                let moved =
                    at(&actual, row, 1).iter().chain(at(&actual, row, 3)).copied().collect();
                assert_multiset(moved, expected.clone());
            }
        }
    }

    #[test]
    fn packed_library_memory_redistribution_preserves_raw_five_tuple_multiset() {
        let indices = core::array::from_fn::<_, NUM_CHIPLETS_COLS, _>(|index| index);
        let columns: &ChipletCols<_> = indices.as_slice().borrow();
        for repeated in [false, true] {
            let mut row = [Felt::ZERO; NUM_CHIPLETS_COLS];
            row[columns.memory().d0] = Felt::from_u8(if repeated { 76 } else { 11 });
            row[columns.memory().d1] = Felt::from_u8(13);
            row[columns.memory_word_addr_lo()] = Felt::from_u8(17);
            row[columns.memory_word_addr_hi()] = Felt::from_u8(19);
            let expected = [
                row[columns.memory().d0],
                row[columns.memory().d1],
                row[columns.memory_word_addr_lo()],
                row[columns.memory_word_addr_hi()],
                row[columns.memory_word_addr_hi()] * Felt::from_u8(4),
            ]
            .map(|value| (-Felt::ONE, RangeMsg { value }.encode(&challenges())))
            .to_vec();
            let actual = fractions(row);
            for row in 0..8 {
                assert_eq!(actual.counts()[row * 4 + 1], 4);
                assert_eq!(actual.counts()[row * 4 + 3], 1);
                let moved =
                    at(&actual, row, 1).iter().chain(at(&actual, row, 3)).copied().collect();
                assert_multiset(moved, expected.clone());
            }
        }
    }
}
