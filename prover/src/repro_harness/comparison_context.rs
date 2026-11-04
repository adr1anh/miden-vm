//! Isolated, test-only comparison with the historical coarse-END context selector.
//!
//! All production emissions pass through unchanged except the `ctx` preservation assertion.
//! The guard below identifies its full polynomial semantics and forbids any other changed
//! emission. Principal equations, lookups, statement and production metadata stay intact.

use core::borrow::Borrow;

use miden_air::vm::MidenAir;
use miden_air_definitions::vm::CoreCols;
use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_stark::air::{LiftedAirBuilder, WindowAccess};

use super::emission_adapter::eval_with_base_replacements;

// `system::enforce_main` emits clock/context initialization, clock transition, CALL/DYNCALL
// context loading and SYSCALL context loading before this assertion. Indices are zero-based
// in the shared base/extension emission order.
const CONTEXT_PRESERVE: usize = 5;

pub(super) fn eval<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    let replacement = context_constraint(builder, true);
    eval_with_base_replacements(MidenAir::CORE, builder, &[(CONTEXT_PRESERVE, replacement)]);
}

fn context_constraint<AB: LiftedAirBuilder<F = Felt>>(builder: &AB, coarse_end: bool) -> AB::Expr {
    let main = builder.main();
    let local: &CoreCols<AB::Var> = (*main.current_slice()).borrow();
    let next: &CoreCols<AB::Var> = (*main.next_slice()).borrow();
    let bits = local.decoder.op_bits.map(Into::<AB::Expr>::into);
    // Match OpFlags' low-degree selectors, including the independently constrained extras.
    // CALL/SYSCALL/END use b432 indices 3/2/4; DYNCALL uses b3210 index 12.
    let f_call = (AB::Expr::ONE - bits[4].clone())
        * (bits[3].clone() * bits[2].clone())
        * local.decoder.extra[1];
    let f_syscall = (AB::Expr::ONE - bits[4].clone())
        * (bits[3].clone() * (AB::Expr::ONE - bits[2].clone()))
        * local.decoder.extra[1];
    let f_end = bits[4].clone()
        * ((AB::Expr::ONE - bits[3].clone()) * (AB::Expr::ONE - bits[2].clone()))
        * local.decoder.extra[1];
    let f_dyncall = ((bits[3].clone() * bits[2].clone())
        * (AB::Expr::ONE - bits[1].clone())
        * (AB::Expr::ONE - bits[0].clone()))
        * local.decoder.extra[0];
    let restore = if coarse_end {
        f_end
    } else {
        f_end * local.decoder.end_block_flags().restores_caller_frame
    };
    let preserve = AB::Expr::ONE - (f_call + f_syscall + f_dyncall + restore);
    builder.is_transition()
        * (preserve * (Into::<AB::Expr>::into(next.system.ctx) - local.system.ctx))
}

/// Called by the comparison AIR's test after constructing its context-policy alternate.
#[cfg(test)]
pub(super) fn assert_context_policy_is_isolated(alternate: super::comparison_air::ComparisonAir) {
    use miden_constraint_compiler::{
        ir::{GraphBuilder, capture_into},
        testing::{EvaluationInputs, constraint_degrees},
    };
    use miden_core::field::QuadFelt;
    use miden_stark::air::LiftedAir;

    use super::comparison_air::ComparisonAir;

    let mut graph = GraphBuilder::new();
    let production = capture_into(&MidenAir::CORE, &mut graph);
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
    assert_eq!(changed_indices, alloc::vec![CONTEXT_PRESERVE]);

    // Full-field inputs exercise every factor, including non-Boolean opcode extras and the
    // caller-frame selector. A moved assertion or an incorrectly scoped END exemption fails.
    for seed in [0, 1, 17, 31, 256, 65537, u32::MAX as u64, u64::MAX] {
        let inputs = EvaluationInputs::<Felt, QuadFelt>::new(
            <MidenAir as LiftedAir<Felt, QuadFelt>>::air_layout(&MidenAir::CORE),
            seed,
        );
        let mut production_builder = inputs.builder();
        let expected_current = context_constraint(&production_builder, false);
        <MidenAir as LiftedAir<Felt, QuadFelt>>::eval(&MidenAir::CORE, &mut production_builder);
        let production_position = production_builder
            .base_indices
            .iter()
            .position(|&index| index == CONTEXT_PRESERVE)
            .expect("context preservation must remain a base-field emission");
        assert_eq!(
            production_builder.base_constraints[production_position], expected_current,
            "production context semantics: seed={seed}"
        );

        let mut alternate_builder = inputs.builder();
        let expected_historical = context_constraint(&alternate_builder, true);
        <ComparisonAir as LiftedAir<Felt, QuadFelt>>::eval(&alternate, &mut alternate_builder);
        let alternate_position = alternate_builder
            .base_indices
            .iter()
            .position(|&index| index == CONTEXT_PRESERVE)
            .expect("historical context preservation must remain a base-field emission");
        assert_eq!(
            alternate_builder.base_constraints[alternate_position], expected_historical,
            "historical coarse-END context semantics: seed={seed}"
        );
    }

    // Check actual evaluator degrees independently of the unchanged production declarations.
    let production_degrees = constraint_degrees(&MidenAir::CORE);
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
