//! Test-only isolation of the Controller-local entry counter equation.
//!
//! The production evaluator, lookup interface, statement, setup and degrees are retained. Only
//! the named entry-anchor assertion becomes zero; the full-field guard identifies that assertion.

use miden_air::vm::MidenAir;
use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_stark::air::{LiftedAir, LiftedAirBuilder};

use super::emission_adapter::eval_with_base_replacements;

// Selectors emit 41 assertions, Library emits 128, and Controller emits its increment plus
// the entry selector assertion before the entry counter. Shared indices are zero-based.
const CONTROLLER_ENTRY: usize = 171;

pub(super) fn eval<AB: LiftedAirBuilder<F = Felt>>(builder: &mut AB) {
    eval_with_base_replacements(MidenAir::CHIPLETS, builder, &[(CONTROLLER_ENTRY, AB::Expr::ZERO)]);
}

fn entry_constraint<AB: LiftedAirBuilder<F = Felt>>(builder: &AB) -> AB::Expr {
    use core::borrow::Borrow;

    use miden_air_definitions::vm::ChipletCols;
    use miden_stark::air::WindowAccess;

    let main = builder.main();
    let local: &ChipletCols<AB::Var> = (*main.current_slice()).borrow();
    let next: &ChipletCols<AB::Var> = (*main.next_slice()).borrow();
    let library: AB::Expr = local.chiplet_selectors()[0].into();
    let library_next: AB::Expr = next.chiplet_selectors()[0].into();
    builder.is_transition()
        * library
        * (AB::Expr::ONE - library_next)
        * (Into::<AB::Expr>::into(next.chip_clk) - AB::Expr::ONE)
}

pub(super) fn assert_entry_policy_is_isolated(alternate: super::comparison_air::ComparisonAir) {
    use miden_constraint_compiler::{
        ir::{GraphBuilder, capture_into},
        testing::{EvaluationInputs, constraint_degrees},
    };
    use miden_core::field::QuadFelt;

    use super::comparison_air::ComparisonAir;

    let mut graph = GraphBuilder::new();
    let production = capture_into(&MidenAir::CHIPLETS, &mut graph);
    let changed = capture_into(&alternate, &mut graph);
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
    assert_eq!(changed_indices, [CONTROLLER_ENTRY]);
    for seed in [0, 1, 17, 31, 256, 65537, u32::MAX as u64, u64::MAX] {
        let inputs = EvaluationInputs::<Felt, QuadFelt>::new(
            <MidenAir as LiftedAir<Felt, QuadFelt>>::air_layout(&MidenAir::CHIPLETS),
            seed,
        );
        let mut original = inputs.builder();
        let expected = entry_constraint(&original);
        <MidenAir as LiftedAir<Felt, QuadFelt>>::eval(&MidenAir::CHIPLETS, &mut original);
        let position = original.base_indices.iter().position(|&i| i == CONTROLLER_ENTRY).unwrap();
        assert_eq!(original.base_constraints[position], expected, "entry polynomial: {seed}");
        let mut comparison = inputs.builder();
        <ComparisonAir as LiftedAir<Felt, QuadFelt>>::eval(&alternate, &mut comparison);
        let position = comparison.base_indices.iter().position(|&i| i == CONTROLLER_ENTRY).unwrap();
        assert_eq!(comparison.base_constraints[position], Felt::ZERO);
    }
    let bounds = constraint_degrees(&MidenAir::CHIPLETS);
    for (actual, expected) in constraint_degrees(&alternate).iter().zip(&bounds) {
        assert_eq!(actual.len(), expected.len());
        assert!(actual.iter().zip(expected).all(|(a, b)| a <= b));
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::borrow::BorrowMut;

    use miden_air_definitions::vm::{ChipletCols, trace::RowIndex};
    use miden_core::{Felt, operations::Operation, program::StackOutputs, utils::Matrix};
    use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, StackInputs};

    use crate::repro_harness::{CoreMode, ReproTrace, core_row_mut};

    fn fixture() -> ReproTrace {
        let fixture = crate::named_fixture::named_source("begin nop end");
        let mut host = DefaultHost::default().with_environment_source(fixture.environment.source());
        host.load_library(fixture.code).unwrap();
        let (trace, precompile) =
            FastProcessor::new(StackInputs::default())
                .with_options(
                    ExecutionOptions::default()
                        .with_resolution_limits(fixture.environment.resolution_limits())
                        .with_environment_trace_limits(
                            miden_utils_testing::librarytree::trace_limits(),
                        ),
                )
                .unwrap()
                .execute_and_build_trace_sync(
                    fixture.environment.target(),
                    &mut host,
                    &miden_vm_stark::memory::default_budget(),
                )
                .unwrap();
        assert!(precompile.is_none());
        assert_eq!(*trace.stack_outputs(), StackOutputs::default());
        let main = trace.main_trace();
        let noops = (0..trace.trace_len_summary().core_rows())
            .filter(|&row| {
                main.get_op_code(RowIndex::from(row)) == Felt::from_u8(Operation::Noop.op_code())
            })
            .collect::<Vec<_>>();
        assert!(!noops.is_empty());
        for row in noops {
            // This minimal fixture has no typed nonzero parent or operation-helper addresses.
            assert_eq!(main.decoder_hasher_state_element(1, RowIndex::from(row)), Felt::ZERO);
            for helper in 2..8 {
                assert_eq!(
                    main.decoder_hasher_state_element(helper, RowIndex::from(row)),
                    Felt::ZERO
                );
            }
        }
        ReproTrace::new(&trace)
    }

    #[test]
    fn controller_local_entry_anchor_binds_native_and_recursive_verifiers() {
        let mut trace = fixture();
        let honest = trace.prove_comparison(CoreMode::Standard).unwrap();
        assert!(honest.verification.is_ok());
        trace.assert_native_and_recursive_accept(honest.proof);
        let claim = trace.claim();
        let prefix = trace.summary.chiplets().library_len();
        let len = trace.summary.chiplets().hash_chiplet_len();
        assert!(prefix > 0 && prefix.is_multiple_of(8));
        let delta = Felt::from_u32(u32::try_from(prefix).unwrap());
        for row in 0..trace.core.height() {
            let core = core_row_mut(&mut trace.core, row);
            if core.decoder.addr != Felt::ZERO {
                core.decoder.addr += delta;
            }
        }
        let width = trace.chiplets.width();
        for row in prefix..prefix + len {
            let cols: &mut ChipletCols<Felt> =
                trace.chiplets.values[row * width..(row + 1) * width].borrow_mut();
            assert_eq!(cols.chiplet_selectors()[..2], [Felt::ZERO, Felt::ONE]);
            assert_eq!(cols.chip_clk, Felt::from_u32(u32::try_from(row - prefix + 1).unwrap()));
            cols.chip_clk += delta;
        }
        assert_eq!(trace.claim(), claim);
        let comparison = trace
            .prove_controller_entry_comparison()
            .expect("the address shift must preserve lookup balance and reach proof construction");
        assert!(
            comparison.verification.is_ok(),
            "only the local entry anchor may reject: {:?}",
            comparison.verification
        );
        trace.assert_native_and_recursive_air_rejection(comparison.proof);
    }

    #[test]
    fn controller_increment_control_survives_the_entry_comparison() {
        let mut trace = fixture();
        let prefix = trace.summary.chiplets().library_len();
        let len = trace.summary.chiplets().hash_chiplet_len();
        assert!(len >= 3);
        let row = prefix + 1;
        let width = trace.chiplets.width();
        let cols: &mut ChipletCols<Felt> =
            trace.chiplets.values[row * width..(row + 1) * width].borrow_mut();
        assert_eq!(
            [cols.controller().s0, cols.controller().s1, cols.controller().s2],
            [Felt::ZERO, Felt::ONE, Felt::ZERO]
        );
        cols.chip_clk += Felt::ONE;
        let comparison = trace
            .prove_controller_entry_comparison()
            .expect("a Controller padding counter does not change lookup emissions");
        assert!(comparison.verification.is_err(), "ordinary increments must remain constrained");
        trace.assert_native_and_recursive_air_rejection(comparison.proof);
    }
}
