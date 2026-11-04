//! Isolated, test-only comparison without the fixed syscall-supplier namespace equations.
//!
//! All production emissions pass through unchanged except the four supplier-local namespace
//! assertions, which become zero assertions. The guard below identifies their full polynomial
//! semantics and forbids any other changed emission. Production metadata and verifiers stay intact.

use miden_air::vm::MidenAir;
use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_stark::air::{LiftedAir, LiftedAirBuilder};

use super::emission_adapter::eval_with_base_replacements;

// Selectors emit 41 assertions, chip_clk emits 2, and Library emits 72 before these four.
// Indices are zero-based in the shared base/extension emission order.
const NAMESPACE_START: usize = 115;
const NAMESPACE_LANES: usize = 4;

pub(super) fn eval<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let replacements: [(usize, AB::Expr); NAMESPACE_LANES] =
        core::array::from_fn(|lane| (NAMESPACE_START + lane, AB::Expr::ZERO));
    eval_with_base_replacements(MidenAir::CHIPLETS, builder, &replacements);
}

#[cfg(test)]
fn namespace_constraints<AB: LiftedAirBuilder<F = Felt>>(
    builder: &AB,
) -> [AB::Expr; NAMESPACE_LANES] {
    use core::borrow::Borrow;

    use miden_air_definitions::vm::ChipletCols;
    use miden_core::program::Namespace;
    use miden_stark::air::WindowAccess;

    let main = builder.main();
    let local: &ChipletCols<AB::Var> = (*main.current_slice()).borrow();
    let library = local.library();
    let [k0, k1, k2]: [AB::Expr; 3] = library.k.map(Into::into);
    let is_mast = k0 * k1 * (AB::Expr::ONE - k2);
    let is_library: AB::Expr = local.chiplet_selectors()[0].into();
    // Slot eight is the fixed Library A/B phase. AEAD phase seven only gates Library exit.
    let phase_b: AB::Expr = builder.periodic_values()[8].into();
    let mast_b = (is_library * phase_b) * is_mast;
    let initial = Namespace::initial().into_word().into_elements();
    core::array::from_fn(|lane| {
        mast_b.clone()
            * (library.b
                * (Into::<AB::Expr>::into(library.x[lane]) - AB::Expr::from(initial[lane])))
    })
}

/// Called by the comparison AIR's test after constructing its namespace-policy alternate.
#[cfg(test)]
pub(super) fn assert_namespace_policy_is_isolated(alternate: super::comparison_air::ComparisonAir) {
    use miden_constraint_compiler::{
        ir::{GraphBuilder, capture_into},
        testing::{EvaluationInputs, constraint_degrees},
    };
    use miden_core::field::QuadFelt;

    use super::comparison_air::ComparisonAir;

    let mut graph = GraphBuilder::new();
    let production = capture_into(&MidenAir::CHIPLETS, &mut graph);
    let changed = capture_into(&alternate, &mut graph);
    assert_eq!(production.base_roots.len(), changed.base_roots.len());
    assert_eq!(production.base_global_indices, changed.base_global_indices);
    assert_eq!(production.ext_global_indices, changed.ext_global_indices);
    assert_eq!(production.ext_roots, changed.ext_roots);
    let changed_indices: alloc::vec::Vec<_> = production
        .base_roots
        .iter()
        .zip(&changed.base_roots)
        .zip(&production.base_global_indices)
        .filter_map(|((before, after), &index)| (before != after).then_some(index))
        .collect();
    assert_eq!(
        changed_indices,
        (NAMESPACE_START..NAMESPACE_START + NAMESPACE_LANES).collect::<alloc::vec::Vec<_>>()
    );

    // Full-field inputs exercise every factor, including non-Boolean selectors. Moving an
    // assertion or changing its scope must fail instead of silently removing another equation.
    for seed in [0, 1, 17, 31, 256, 65537, u32::MAX as u64, u64::MAX] {
        let inputs = EvaluationInputs::<Felt, QuadFelt>::new(
            <MidenAir as LiftedAir<Felt, QuadFelt>>::air_layout(&MidenAir::CHIPLETS),
            seed,
        );
        let mut production_builder = inputs.builder();
        let expected = namespace_constraints(&production_builder);
        <MidenAir as LiftedAir<Felt, QuadFelt>>::eval(&MidenAir::CHIPLETS, &mut production_builder);
        let mut alternate_builder = inputs.builder();
        <ComparisonAir as LiftedAir<Felt, QuadFelt>>::eval(&alternate, &mut alternate_builder);
        for (lane, expected) in expected.into_iter().enumerate() {
            let position = production_builder
                .base_indices
                .iter()
                .position(|&index| index == NAMESPACE_START + lane)
                .expect("supplier namespace assertion must remain a base-field emission");
            assert_eq!(
                production_builder.base_constraints[position], expected,
                "production namespace semantics: seed={seed}, lane={lane}"
            );
            let alternate_position = alternate_builder
                .base_indices
                .iter()
                .position(|&index| index == NAMESPACE_START + lane)
                .expect("removed namespace assertion must remain a base-field emission");
            assert_eq!(
                alternate_builder.base_constraints[alternate_position],
                Felt::ZERO,
                "isolated namespace removal: seed={seed}, lane={lane}"
            );
        }
    }

    // Check actual evaluator degrees independently of the unchanged production declarations.
    let production_degrees = constraint_degrees(&MidenAir::CHIPLETS);
    let alternate_degrees = constraint_degrees(&alternate);
    for (class, (actual, bounds)) in alternate_degrees.iter().zip(&production_degrees).enumerate() {
        assert_eq!(actual.len(), bounds.len());
        for (position, (actual, bound)) in actual.iter().zip(bounds).enumerate() {
            assert!(
                actual <= bound,
                "the isolated comparison must not increase a degree: class={class}, position={position}"
            );
        }
    }
}
