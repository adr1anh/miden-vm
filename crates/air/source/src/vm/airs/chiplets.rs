//! Authored Chiplets AIR constraints and lookup bindings.

use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{Felt, field::ExtensionField};
use miden_stark::{
    air::{ReductionError, WindowAccess},
    lookup::{BoundaryBuilder, Challenges, ConstraintLookupBuilder},
};

use super::{MidenAir, MidenAirBuilder, boundary::ReduceBoundaryBuilder};
use crate::vm::{
    NUM_CHIPLETS_PUBLIC_VALUES,
    constraints::{self, columns::ChipletCols, lookup::chiplet_air::ChipletLookupBuilder},
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
};

// CHIPLETS AIR
// ================================================================================================

/// Chiplets trace AIR.
///
/// Enforces the chiplet selector hierarchy, chiplet transition constraints, and
/// chiplet-side LogUp buses.
#[derive(Copy, Clone, Debug, Default)]
pub struct ChipletsAir;

impl ChipletsAir {
    pub(super) fn width(self) -> usize {
        constraints::columns::NUM_CHIPLETS_COLS
    }

    pub(in crate::vm) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    pub(super) fn aux_width(self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the chiplets trace.
    ///
    /// The sole boundary slice is the mandatory four public Felts `R_E`.
    pub(super) fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if boundary_inputs.len() != 1 {
            return Err(format!(
                "ChipletsAir expects 1 boundary input slice, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        if boundary_inputs[0].len() != NUM_CHIPLETS_PUBLIC_VALUES {
            return Err(format!(
                "ChipletsAir expects {} public Felts R_E, got {}",
                NUM_CHIPLETS_PUBLIC_VALUES,
                boundary_inputs[0].len()
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            var_len_public_inputs: boundary_inputs,
            sum: EF::ZERO,
            error: None,
        };
        constraints::lookup::miden_air::emit_chiplets_boundary(&mut reducer);
        reducer.finalize()
    }

    pub(super) fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let main = builder.main();
        let local: &ChipletCols<AB::Var> = (*main.current_slice()).borrow();
        let next: &ChipletCols<AB::Var> = (*main.next_slice()).borrow();

        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(builder, local, next);

        let _: [AB::PublicVar; NUM_CHIPLETS_PUBLIC_VALUES] = builder
            .public_values()
            .try_into()
            .expect("ChipletsAir requires exactly 4 public Felts R_E");
        constraints::enforce_chiplets(builder, local, next, &selectors);

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::Chiplets);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }

    pub(super) fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    pub(super) fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    pub(super) fn lookup_eval<LB: ChipletLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &ChipletCols<_> = main.current_slice().borrow();
        let next: &ChipletCols<_> = main.next_slice().borrow();

        constraints::lookup::chiplet_air::emit_chiplet_lookup_columns(builder, local, next);
    }

    pub(super) fn lookup_eval_boundary<B: BoundaryBuilder<F = Felt>>(self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_chiplets_boundary(boundary);
    }
}

#[cfg(test)]
mod tests {
    use miden_core::field::{PrimeCharacteristicRing, QuadFelt};

    use super::*;

    fn challenges() -> Challenges<QuadFelt> {
        Challenges::new(
            QuadFelt::from_u8(7),
            QuadFelt::from_u8(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        )
    }

    #[test]
    fn packed_boundary_requires_exactly_four_public_felts() {
        let challenges = challenges();
        assert!(ChipletsAir.boundary_correction(&challenges, &[]).is_err());
        for len in [0, 1, 3, 5, 8, 12] {
            let values = alloc::vec![Felt::ONE; len];
            assert!(ChipletsAir.boundary_correction(&challenges, &[&values]).is_err());
        }
        let values = [Felt::ONE; NUM_CHIPLETS_PUBLIC_VALUES];
        assert!(ChipletsAir.boundary_correction(&challenges, &[&values, &values]).is_err());
        assert!(ChipletsAir.boundary_correction(&challenges, &[&values]).is_ok());
    }

    #[test]
    fn packed_boundary_open_seed_binds_every_environment_root_coordinate() {
        let challenges = challenges();
        let public_values = [Felt::ONE; NUM_CHIPLETS_PUBLIC_VALUES];
        let expected = ChipletsAir.boundary_correction(&challenges, &[&public_values]).unwrap();
        for coordinate in 0..4 {
            let mut forged = public_values;
            forged[coordinate] += Felt::ONE;
            assert_ne!(ChipletsAir.boundary_correction(&challenges, &[&forged]).unwrap(), expected,);
        }
    }
}
