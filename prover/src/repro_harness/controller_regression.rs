//! Current-production Controller counter regression tests.

use alloc::vec::Vec;
use core::borrow::BorrowMut;

use miden_air_definitions::vm::{ChipletCols, trace::RowIndex};
use miden_core::{Felt, operations::Operation, program::StackOutputs, utils::Matrix};
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, StackInputs};

use super::{ReproTrace, core_row_mut};

fn fixture() -> ReproTrace {
    let fixture = crate::named_fixture::named_source("begin nop end");
    let mut host = DefaultHost::default().with_environment_source(fixture.environment.source());
    host.load_library(fixture.code).unwrap();
    let (trace, precompile) = FastProcessor::new(StackInputs::default())
        .with_options(
            ExecutionOptions::default()
                .with_resolution_limits(fixture.environment.resolution_limits())
                .with_environment_trace_limits(miden_utils_testing::librarytree::trace_limits()),
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
            assert_eq!(main.decoder_hasher_state_element(helper, RowIndex::from(row)), Felt::ZERO);
        }
    }
    ReproTrace::new(&trace)
}

#[test]
fn controller_local_entry_anchor_binds_native_and_recursive_verifiers() {
    let mut trace = fixture();
    let honest = trace
        .prove_current()
        .expect("honest Controller proof construction must complete");
    trace.assert_native_and_recursive_accept(honest);
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
    let proof = trace.prove_current().expect(
        "the address shift must preserve lookup balance and reach production proof construction",
    );
    trace.assert_native_and_recursive_air_rejection(proof);
}

#[test]
fn controller_increment_defect_is_rejected_by_native_and_recursive_verifiers() {
    let mut trace = fixture();
    let claim = trace.claim();
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
    assert_eq!(trace.claim(), claim);
    let proof = trace
        .prove_current()
        .expect("a Controller padding counter does not change lookup emissions");
    trace.assert_native_and_recursive_air_rejection(proof);
}
