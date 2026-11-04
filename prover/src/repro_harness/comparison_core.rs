//! Isolated, test-only comparison with the historical coarse-END principal selector.
//!
//! All production emissions pass through unchanged except the four `fn_hash` preservation
//! assertions. Their global indices are guarded against the authored semantics below. No trace,
//! lookup, statement, degree declaration, or release verifier is changed.

use core::borrow::Borrow;

use miden_air::vm::MidenAir;
use miden_air_definitions::vm::CoreCols;
use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_stark::air::{LiftedAir, LiftedAirBuilder, WindowAccess};

use super::{comparison_air::CoreMode, emission_adapter::eval_with_base_replacements};

// `system::enforce_main` emits these immediately after the four principal-load assertions.
// The tests identify their actual equations independently and forbid any other changed emission.
const PRESERVE_START: usize = 10;
const PRINCIPAL_LANES: usize = 4;

pub(super) fn eval<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB, mode: CoreMode) {
    if mode == CoreMode::Standard {
        <MidenAir as LiftedAir<Felt, AB::EF>>::eval(&MidenAir::CORE, builder);
        return;
    }

    let replacements = principal_constraints(builder, mode);
    eval_with_base_replacements(
        MidenAir::CORE,
        builder,
        core::array::from_fn(|lane| (PRESERVE_START + lane, replacements[lane].clone())),
    );
}

fn principal_constraints<AB: LiftedAirBuilder<F = Felt>>(
    builder: &AB,
    mode: CoreMode,
) -> [AB::Expr; PRINCIPAL_LANES] {
    let main = builder.main();
    let local: &CoreCols<AB::Var> = (*main.current_slice()).borrow();
    let next: &CoreCols<AB::Var> = (*main.next_slice()).borrow();
    let bits = local.decoder.op_bits.map(Into::<AB::Expr>::into);
    // Match OpFlags' low-degree selectors, including the independently constrained extras.
    let f_call = (AB::Expr::ONE - bits[4].clone())
        * (bits[3].clone() * bits[2].clone())
        * local.decoder.extra[1];
    let f_end = bits[4].clone()
        * ((AB::Expr::ONE - bits[3].clone()) * (AB::Expr::ONE - bits[2].clone()))
        * local.decoder.extra[1];
    let f_dyncall = ((bits[3].clone() * bits[2].clone())
        * (AB::Expr::ONE - bits[1].clone())
        * (AB::Expr::ONE - bits[0].clone()))
        * local.decoder.extra[0];
    let restore = match mode {
        CoreMode::Standard => f_end * local.decoder.end_block_flags().restores_caller_frame,
        CoreMode::Alternate => f_end,
    };
    let preserve = AB::Expr::ONE - (f_call + f_dyncall + restore);
    let transition = builder.is_transition();
    core::array::from_fn(|lane| {
        transition.clone()
            * (preserve.clone()
                * (Into::<AB::Expr>::into(next.system.fn_hash[lane]) - local.system.fn_hash[lane]))
    })
}

#[test]
fn comparison_core_changes_only_the_four_identified_principal_equations() {
    use miden_constraint_compiler::{
        ir::{GraphBuilder, capture_into},
        testing::{EvaluationInputs, constraint_degrees},
    };
    use miden_core::field::QuadFelt;

    use super::comparison_air::ComparisonAir;

    let standard = ComparisonAir::core(CoreMode::Standard);
    let alternate = ComparisonAir::core(CoreMode::Alternate);
    let mut graph = GraphBuilder::new();
    let production = capture_into(&MidenAir::CORE, &mut graph);
    let unchanged = capture_into(&standard, &mut graph);
    let changed = capture_into(&alternate, &mut graph);
    assert_eq!(production.base_roots, unchanged.base_roots);
    assert_eq!(production.ext_roots, unchanged.ext_roots);
    assert_eq!(production.base_global_indices, unchanged.base_global_indices);
    assert_eq!(production.ext_global_indices, unchanged.ext_global_indices);
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
        (PRESERVE_START..PRESERVE_START + PRINCIPAL_LANES).collect::<alloc::vec::Vec<_>>()
    );

    // Check the named semantics with deterministic, non-Boolean full-field inputs. A moved
    // assertion or a selector change must fail instead of silently altering another equation.
    for seed in [0, 1, 17, 31, 256, 65537, u32::MAX as u64, u64::MAX] {
        let inputs = EvaluationInputs::<Felt, QuadFelt>::new(
            <MidenAir as LiftedAir<Felt, QuadFelt>>::air_layout(&MidenAir::CORE),
            seed,
        );
        for (air, mode) in [(standard, CoreMode::Standard), (alternate, CoreMode::Alternate)] {
            let mut builder = inputs.builder();
            let expected = principal_constraints(&builder, mode);
            <ComparisonAir as LiftedAir<Felt, QuadFelt>>::eval(&air, &mut builder);
            for (lane, expected) in expected.into_iter().enumerate() {
                let position = builder
                    .base_indices
                    .iter()
                    .position(|&index| index == PRESERVE_START + lane)
                    .expect("principal assertion must remain a base-field emission");
                assert_eq!(
                    builder.base_constraints[position], expected,
                    "seed={seed}, lane={lane}, mode={mode:?}"
                );
            }
        }
    }

    // The comparison keeps production degree declarations; independently check every assertion
    // against the actual generated evaluator, rather than merely trusting the forwarded bound.
    let production_degrees = constraint_degrees(&MidenAir::CORE);
    assert_eq!(production_degrees, constraint_degrees(&standard));
    for (actual, bound) in constraint_degrees(&alternate)
        .iter()
        .flatten()
        .zip(production_degrees.iter().flatten())
    {
        assert!(actual <= bound, "the isolated comparison must not increase a degree");
    }
}
