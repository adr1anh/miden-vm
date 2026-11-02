//! Public replay-v4 transport and native trace-reconstruction regressions.
//!
//! The single-Mast environment and finite budgets are fixtures, not a Protocol policy. These
//! programs have no retained invocations: native reconstruction uses the current zero Library
//! prefix pending PR 06 and does not establish proof acceptance.

use miden_core::operations::Operation;
use miden_processor::{
    self as processor, ExecutionWitness, Felt, ONE, StackInputs, ZERO,
    trace::{RowIndex, build_trace},
};

#[path = "common/keyed_witness.rs"]
mod common;

use common::{aead_stream_witness, deferred_witness, execution_witness, read_limits, trace_limits};

#[test]
fn witness_reports_precompile_state() {
    let plain = execution_witness(
        vec![Operation::Push(Felt::new_unchecked(1)), Operation::Drop],
        StackInputs::default(),
    );
    assert!(!plain.witness.has_precompiles());
    assert!(!plain.witness.into_parts().0.has_precompiles());

    let deferred = deferred_witness();
    assert!(deferred.witness.has_precompiles());
    let (vm, precompile) = deferred.witness.into_parts();
    assert!(vm.has_precompiles());
    assert!(precompile.is_some());
}

#[test]
fn witness_wire_rejects_unsupported_version() {
    let fixture = deferred_witness();
    let mut bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    assert_eq!(bytes[0], 4, "keyed replay witnesses must use wire version 4");
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &fixture.environment,
            trace_limits(),
            read_limits(),
        )
        .is_ok()
    );

    // Versions reject before any replay or precompile payload is decoded.
    for version in [0, 1, 2, 3, 5] {
        bytes[0] = version;
        let error = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &fixture.environment,
            trace_limits(),
            read_limits(),
        )
        .expect_err("unsupported witness format must be rejected");
        assert!(error.to_string().contains("unsupported execution witness wire version"));
    }
}

#[test]
fn witness_wire_rejects_trailing_bytes() {
    let fixture = deferred_witness();
    let mut bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    bytes.push(0);
    let error = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &fixture.environment,
        trace_limits(),
        read_limits(),
    )
    .expect_err("witness payload with trailing bytes should be rejected");
    assert!(
        error.to_string().contains("extra bytes after execution witness payload"),
        "unexpected error: {error}"
    );
}

#[test]
fn deferred_witness_round_trip_preserves_claim_descriptor_and_precompile() {
    let fixture = deferred_witness();
    let bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &fixture.environment,
        trace_limits(),
        read_limits(),
    )
    .expect("deferred witness should round trip");
    assert_eq!(restored.claim(), fixture.witness.claim());
    assert_eq!(restored.execution_descriptor(), fixture.environment.descriptor());
    assert!(restored.has_precompiles());
    assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
    let (vm, precompile) = restored.into_parts();
    assert!(vm.has_precompiles());
    assert!(precompile.is_some());
}

#[test]
fn aead_stream_witness_round_trip_rebuilds_the_same_native_trace() {
    let fixture = aead_stream_witness();
    let bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let claim = fixture.witness.claim();
    let (original_vm, original_precompile) = fixture.witness.into_parts();
    assert!(original_precompile.is_none());
    let original_trace = build_trace(original_vm, &miden_vm_stark::memory::default_budget())
        .expect("original native trace should build");

    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &fixture.environment,
        trace_limits(),
        read_limits(),
    )
    .expect("AEAD witness should round trip");
    assert_eq!(restored.claim(), claim);
    assert_eq!(restored.execution_descriptor(), fixture.environment.descriptor());
    assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
    let (restored_vm, restored_precompile) = restored.into_parts();
    assert!(restored_precompile.is_none());
    let restored_trace = build_trace(restored_vm, &miden_vm_stark::memory::default_budget())
        .expect("restored native trace should build");

    assert_eq!(restored_trace.public_inputs(), original_trace.public_inputs());
    assert_eq!(restored_trace.trace_len_summary(), original_trace.trace_len_summary());
    assert_eq!(
        restored_trace.main_trace().clone_air_matrices(),
        original_trace.main_trace().clone_air_matrices()
    );
}

#[test]
fn memory_write_helpers_survive_native_trace_materialization() {
    let mut operations = Vec::new();
    let mut expected = Vec::new();
    let mut values = [0; 4];
    // Independent helper expectations cover both low index bits at both high index bits.
    for (slot, (value, helpers)) in
        [11, 22, 33, 44].into_iter().zip([[1, 0], [0, 1], [1, 0], [0, 1]]).enumerate()
    {
        let address = Felt::new_unchecked(100 + u64::try_from(slot).unwrap());
        operations.extend([
            Operation::Push(Felt::new_unchecked(value)),
            Operation::Push(address),
            Operation::MStore,
            Operation::Drop,
            Operation::Push(address),
            Operation::MLoad,
            Operation::Push(Felt::new_unchecked(value)),
            Operation::Eq,
            Operation::Assert(ZERO),
        ]);
        values[slot] = value;
        expected.push((Operation::MStore, slot, values, helpers));
        expected.push((Operation::MLoad, slot, values, [0, 0]));
    }

    values = [91, 92, 93, 94];
    for value in values.into_iter().rev() {
        operations.push(Operation::Push(Felt::new_unchecked(value)));
    }
    operations.extend([
        Operation::Push(Felt::new_unchecked(100)),
        Operation::MStoreW,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Push(Felt::new_unchecked(100)),
        Operation::MLoadW,
    ]);
    expected.push((Operation::MStoreW, 0, values, [0, 0]));
    expected.push((Operation::MLoadW, 0, values, [0, 0]));

    let fixture = execution_witness(operations, StackInputs::default());
    let claim = fixture.witness.claim();
    // Scalar reads already passed native assertions; the final word read is observable output.
    assert_eq!(claim.stack_outputs().get_num_elements(4), &values.map(Felt::new_unchecked));
    let bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &fixture.environment,
        trace_limits(),
        read_limits(),
    )
    .expect("memory witness should round trip");
    assert_eq!(restored.claim(), claim);
    let (vm, precompile) = fixture.witness.into_parts();
    assert!(precompile.is_none());
    let trace = build_trace(vm, &miden_vm_stark::memory::default_budget())
        .expect("native memory trace should build");
    assert_eq!(trace.stack_outputs(), claim.stack_outputs());
    let main = trace.main_trace();

    // The semantic classifier must include Memory rows with e1=1 in shared c22.
    // Migrate the asserted legacy prefix deliberately with the packed selectors.
    let memory_rows: Vec<_> = (0..main.chiplets_height())
        .map(RowIndex::from)
        .filter(|&row| main.is_memory_row(row))
        .collect();
    let memory_opcodes =
        [Operation::MStore, Operation::MLoad, Operation::MStoreW, Operation::MLoadW]
            .map(|op| Felt::new_unchecked(u64::from(op.op_code())));
    let core_rows: Vec<_> = (0..main.core_height())
        .map(RowIndex::from)
        .filter(|&row| memory_opcodes.contains(&main.get_op_code(row)))
        .collect();
    assert_eq!(memory_rows.len(), expected.len());
    assert_eq!(core_rows.len(), expected.len());
    let mut previous_clk = None;
    for ((memory_row, core_row), (op, slot, word, helpers)) in
        memory_rows.into_iter().zip(core_rows).zip(expected)
    {
        let shared = main.chiplet_cols(memory_row);
        assert_eq!(shared.chiplet_selectors()[..3], [ZERO, ONE, ZERO]);
        let memory = shared.memory();
        assert_eq!(shared.chip_clk, Felt::from(memory_row + 1));
        assert_eq!(main.get_op_code(core_row), Felt::new_unchecked(u64::from(op.op_code())));
        assert_eq!(memory.ctx, main.ctx(core_row));
        assert_eq!(memory.clk, main.clk(core_row));
        assert_eq!(memory.word_addr, Felt::new_unchecked(100));
        assert_eq!(
            memory.word_addr + memory.idx0 + memory.idx1 * Felt::new_unchecked(2),
            main.stack_element(0, core_row)
        );
        assert_eq!(memory.idx0, Felt::new_unchecked(u64::try_from(slot % 2).unwrap()));
        assert_eq!(memory.idx1, Felt::new_unchecked(u64::try_from(slot / 2).unwrap()));
        assert_eq!(
            memory.is_read,
            if matches!(op, Operation::MLoad | Operation::MLoadW) {
                ONE
            } else {
                ZERO
            }
        );
        assert_eq!(
            memory.is_word,
            if matches!(op, Operation::MStoreW | Operation::MLoadW) {
                ONE
            } else {
                ZERO
            }
        );
        assert_eq!(memory.values, word.map(Felt::new_unchecked));
        let delta = previous_clk.map_or(ONE, |clk| memory.clk - clk);
        previous_clk = Some(memory.clk);
        assert_eq!(memory.d0, delta);
        assert_eq!(memory.d1, ZERO);
        assert_eq!(memory.d_inv * delta, ONE);
        assert_eq!(memory.is_same_ctx_and_addr, ONE);
        assert_eq!(shared.memory_word_addr_lo(), Felt::new_unchecked(25));
        assert_eq!(shared.memory_word_addr_hi(), ZERO);
        assert_eq!(shared.memory_write_helpers(), helpers.map(Felt::new_unchecked));
    }

    let (restored_vm, restored_precompile) = restored.into_parts();
    assert!(restored_precompile.is_none());
    let restored_trace = build_trace(restored_vm, &miden_vm_stark::memory::default_budget())
        .expect("round-tripped memory trace should build");
    assert_eq!(restored_trace.public_inputs(), trace.public_inputs());
    assert_eq!(restored_trace.main_trace().clone_air_matrices(), main.clone_air_matrices());
}
