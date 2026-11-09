//! Public replay transport and native trace-reconstruction regressions.
//!
//! The single-Mast environment and finite budgets are fixtures, not a Protocol policy. These
//! programs retain entry resolution, whose completed session supplies the packed Library prefix.
//! Native reconstruction does not establish proof acceptance.

use std::{
    future::Future,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use miden_air_definitions::vm::trace::{
    chiplets::library::{PAD, ROOT_MAST},
    eidos_compression::{
        EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_MULTIPLICITY_COL, NUM_EIDOS_COMPRESSION_COLS,
    },
};
use miden_core::{
    operations::Operation,
    program::{CanonicalLabel, Namespace},
    serde::DeserializationError,
};
use miden_mast_package::{
    CodePackage, PackageProcedureOccurrence, Section, SectionId,
    debug_info::{DebugSourceAsmOp, DebugSourceNode, PackageDebugInfoBuilder},
};
use miden_processor::{
    self as processor, EnvironmentTraceLimits, ExecutionError, ExecutionOptions, ExecutionWitness,
    FastProcessor, Felt, LoadedMastForest, ONE, ReplayReadLimits, StackInputs, ZERO,
    trace::{KeyedReplayError, ReplayResource, RowIndex, build_trace},
};
use miden_utils_testing::librarytree::fixture_entry_root;

#[path = "common/keyed_witness.rs"]
mod common;

use common::{
    aead_stream_witness, deferred_witness, execution_fixture, execution_witness, read_limits,
    trace_limits,
};

/// This fixture contains one authenticated Mast pair and the complete required Library PAD pairs.
fn assert_single_mast_prefix(
    trace: &processor::trace::VmTrace,
    target: processor::ExecutionTarget,
) {
    let main = trace.main_trace();
    let rows: Vec<_> = (0..main.chiplets_height())
        .map(RowIndex::from)
        .take_while(|&row| main.is_library_row(row))
        .collect();
    assert_eq!(rows.len(), 8);
    for (index, row) in rows.into_iter().enumerate() {
        let shared = main.chiplet_cols(row);
        assert_eq!(shared.chiplet_selectors()[0], ONE);
        assert_eq!(shared.chip_clk, ZERO, "Library rows do not carry Controller addresses");
        if index < 2 {
            assert_eq!(shared.library().k, ROOT_MAST);
            assert_eq!(shared.library().d, ZERO);
        } else {
            assert_eq!(shared.library().k, PAD);
            let pad = shared.library();
            for word in [pad.x, pad.y, pad.z, pad.w] {
                assert_eq!(word, [ZERO; 4]);
            }
            assert_eq!((pad.d, pad.a, pad.b), (ZERO, ZERO, ZERO));
        }
    }
    let label = CanonicalLabel::text("entry").unwrap().commitment().into_word().into_elements();
    let descriptor = target;
    let a = main.chiplet_cols(RowIndex::from(0)).library();
    let b = main.chiplet_cols(RowIndex::from(1)).library();
    assert_eq!(a.x, label);
    assert_eq!(a.y, trace.entry_implementation().as_word().into_elements());
    assert_eq!(a.z, descriptor.environment_root().into_word().into_elements());
    assert_eq!(a.w, Namespace::initial().into_word().into_elements());
    assert_eq!(b.x, a.w);
    assert_eq!(b.y, label);
    assert_eq!(b.w, a.y);
    assert_eq!(b.y, descriptor.entry_key().into_word().into_elements());
    assert_eq!(b.z, [ZERO; 4]);
    assert_eq!((b.a, b.b), (ONE, ZERO), "entry resolution contributes one normal request");
    let first_controller = RowIndex::from(8);
    assert!(main.is_hash_row(first_controller));
    assert_eq!(main.chiplet_cols(first_controller).chiplet_selectors()[..2], [ZERO, ONE]);
    assert_eq!(main.chiplet_clk(first_controller), ONE);
    assert_eq!(main.addr(RowIndex::from(0)), ZERO, "the absent root address stays zero");
    assert_eq!(main.addr(RowIndex::from(1)), ONE);

    let entry = descriptor.entry_key().into_word().into_elements();
    assert_eq!(main.fn_hash(RowIndex::from(0)), [ZERO; 4]);
    let mut root_ends = 0;
    let mut halt_system = None;
    for index in 0..main.core_height() {
        let row = RowIndex::from(index);
        let core = main.core_row(row);
        assert_eq!(main.decoder_resolved_digest(row).into_elements(), [ZERO; 4]);
        assert_eq!(core.system.clk, Felt::new_unchecked(index as u64));
        assert_eq!(core.system.fn_hash, [ZERO; 4]);
        if main.is_root_end(row) == ONE {
            root_ends += 1;
            assert_eq!(main.get_op_code(row), Felt::from_u8(miden_core::operations::opcodes::END));
            assert_eq!(main.is_loop_body_flag(row), ZERO);
            assert_eq!(
                main.decoder_hasher_state_first_half(row),
                *trace.entry_implementation().as_word()
            );
            let next = RowIndex::from(index + 1);
            assert_eq!(
                main.get_op_code(next),
                Felt::from_u8(miden_core::operations::opcodes::HALT)
            );
            halt_system = Some(main.core_row(next).system.clone());
        }
        if let Some(system) = &halt_system
            && main.get_op_code(row) == Felt::from_u8(miden_core::operations::opcodes::HALT)
        {
            assert_eq!(core.system.ctx, system.ctx);
            assert_eq!(core.system.fn_hash, system.fn_hash);
            assert_eq!(main.decoder_hasher_state_second_half(row).into_elements(), entry);
        }
    }
    assert_eq!(root_ends, 1);
}

#[test]
fn completed_entry_prefix_registers_compressions_once_before_exact_budget_admission() {
    let fixture = execution_witness(vec![Operation::Noop], StackInputs::default());
    let bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let budget = miden_vm_stark::memory::default_budget();
    let (vm, _) = fixture.witness.into_parts();
    let trace = build_trace(vm, &budget).expect("completed entry should materialize its prefix");
    assert_single_mast_prefix(&trace, fixture.target);
    // One span compression and one Mast compression. The write traversal adds no requests.
    assert_eq!(trace.trace_len_summary().eidos_compression_count(), 2);
    let (_, _, eidos, _) = trace.main_trace().clone_air_matrices();
    let multiplicities: Vec<_> = eidos
        .values
        .as_chunks::<{ NUM_EIDOS_COMPRESSION_COLS * EIDOS_COMPRESSION_CYCLE_LEN }>()
        .0
        .iter()
        .map(|block| {
            block[(EIDOS_COMPRESSION_CYCLE_LEN - 1) * NUM_EIDOS_COMPRESSION_COLS
                + F_COMPRESSION_MULTIPLICITY_COL]
        })
        .collect();
    assert_eq!(multiplicities.iter().filter(|&&count| count == ONE).count(), 2);
    assert!(multiplicities.iter().all(|&count| count == ZERO || count == ONE));

    let estimated = budget.prover_peak_bytes(trace.trace_len_summary().padded_heights()).unwrap();
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        fixture.target,
        fixture.resolution_limits,
        trace_limits(),
        read_limits(),
    )
    .unwrap();
    let (vm, _) = restored.into_parts();
    assert!(matches!(
        build_trace(vm, &miden_vm_stark::memory::canonical_budget(estimated - 1)),
        Err(ExecutionError::ProverMemoryExceeded { estimated_bytes, budget_bytes })
            if estimated_bytes == estimated && budget_bytes == estimated - 1
    ));
}

fn retained_limit(bytes: usize) -> EnvironmentTraceLimits {
    EnvironmentTraceLimits {
        max_retained_bytes: bytes,
        ..trace_limits()
    }
}

// Search only within the fixture's explicit finite policy. Live capture and wire decoding can
// retain different queue capacities, so each operation has its own measured boundary.
fn minimum_retained_limit(mut admits: impl FnMut(usize) -> bool) -> usize {
    let mut rejected = 0;
    let mut admitted = trace_limits().max_retained_bytes;
    assert!(!admits(rejected), "zero retained storage must reject this witness");
    assert!(admits(admitted), "the explicit fixture policy must admit this witness");
    while admitted - rejected > 1 {
        let candidate = rejected + (admitted - rejected) / 2;
        if admits(candidate) {
            admitted = candidate;
        } else {
            rejected = candidate;
        }
    }
    admitted
}

fn retained_export_admits(result: Result<Vec<u8>, DeserializationError>, limit: usize) -> bool {
    match result {
        Ok(_) => true,
        Err(DeserializationError::InvalidValue(reason))
            if reason == "keyed export exceeds caller limits" =>
        {
            false
        },
        Err(error) => panic!("unexpected export error at retained limit {limit}: {error}"),
    }
}

fn retained_capture_admits(result: Result<ExecutionWitness, ExecutionError>, limit: usize) -> bool {
    match result {
        Ok(_) => true,
        Err(ExecutionError::KeyedTrace(KeyedReplayError::LimitExceeded {
            resource: ReplayResource::RetainedBytes,
            ..
        })) => false,
        Err(error) => panic!("unexpected capture error at retained limit {limit}: {error}"),
    }
}

fn retained_read_admits(
    result: Result<ExecutionWitness, DeserializationError>,
    limit: usize,
) -> bool {
    match result {
        Ok(_) => true,
        Err(DeserializationError::InvalidValue(reason))
            if reason.contains("RetainedBytes limit") =>
        {
            false
        },
        Err(error) => panic!("unexpected read error at retained limit {limit}: {error}"),
    }
}

fn poll_ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("the fixture's DefaultHost unexpectedly suspended"),
    }
}

#[test]
fn completed_witness_source_and_async_paths_rebuild_the_same_native_trace() {
    let operations = vec![Operation::Push(Felt::new_unchecked(7)), Operation::Drop];
    let mut fixture = execution_fixture(operations.clone());
    let root = fixture_entry_root(&fixture.code);
    let mut builder = PackageDebugInfoBuilder::default();
    let context = builder.add_string("fixture::entry");
    let operation = builder.add_string("push.7 drop");
    let source = builder
        .add_node(DebugSourceNode {
            exec_node: root,
            children: Vec::new(),
            op_start: 0,
            op_end: u32::try_from(operations.len()).unwrap(),
            asm_ops: vec![DebugSourceAsmOp::new(0, None, context, operation, 1)],
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        })
        .unwrap();
    builder.add_root(source);
    let debug = builder.build();
    let symbols = fixture.code.symbols().clone();
    let mut package = (**fixture.code.package()).clone();
    package.sections.push(Section::new(
        SectionId::DEBUG_INFO,
        debug.to_bytes_with_standard_limits().unwrap(),
    ));
    let package = package
        .with_procedure_occurrences(
            [PackageProcedureOccurrence::new(fixture.target.entry_key(), root, Some(source))],
            &symbols,
        )
        .unwrap();
    let source_code = CodePackage::new(Arc::new(package), symbols).unwrap();
    let source_host = |exact| {
        let mut host = execution_fixture(operations.clone()).host;
        *host.mast_forest_store_mut() = Default::default();
        let loaded = if exact {
            LoadedMastForest::from_code_package(source_code.clone())
        } else {
            LoadedMastForest::with_package_debug_info(
                fixture.code.package().mast_forest().clone(),
                Ok(Some((*debug).clone())),
            )
        };
        host.mast_forest_store_mut().insert_loaded(loaded);
        host
    };
    let target = fixture.target;
    let resolution_limits = fixture.resolution_limits;
    let processor = || {
        FastProcessor::new(StackInputs::default())
            .with_options(
                ExecutionOptions::default()
                    .with_resolution_limits(resolution_limits)
                    .with_environment_trace_limits(trace_limits()),
            )
            .unwrap()
    };
    let plain = processor().execute_for_proving_sync(target, &mut fixture.host).unwrap();
    let asynchronous = poll_ready(
        processor().execute_for_proving(target, &mut execution_fixture(operations.clone()).host),
    )
    .unwrap();
    let mut witnesses = vec![plain, asynchronous];
    for exact in [false, true] {
        witnesses
            .push(processor().execute_for_proving_sync(target, &mut source_host(exact)).unwrap());
        witnesses.push(
            poll_ready(processor().execute_for_proving(target, &mut source_host(exact))).unwrap(),
        );
    }
    let bytes = witnesses[0].to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    assert_eq!(bytes[0], 7);
    let claim = witnesses[0].claim();
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        target,
        resolution_limits,
        trace_limits(),
        read_limits(),
    )
    .unwrap();
    witnesses.push(restored);
    let mut traces = Vec::new();
    for witness in witnesses {
        assert_eq!(witness.claim(), claim);
        assert_eq!(witness.execution_descriptor(), target);
        assert_eq!(witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
        let (vm, precompile) = witness.into_parts();
        assert!(precompile.is_none());
        traces.push(build_trace(vm, &miden_vm_stark::memory::default_budget()).unwrap());
    }
    for trace in &traces {
        assert_single_mast_prefix(trace, target);
    }
    for trace in &traces[1..] {
        assert_eq!(trace.public_inputs(), traces[0].public_inputs());
        assert_eq!(trace.trace_len_summary(), traces[0].trace_len_summary());
        assert_eq!(
            trace.main_trace().clone_air_matrices(),
            traces[0].main_trace().clone_air_matrices()
        );
    }
}

#[test]
fn completed_witness_retained_limits_admit_exact_boundaries_and_reject_less() {
    let execute = |limit| {
        let mut fixture = execution_fixture(vec![Operation::Push(ONE), Operation::Drop]);
        FastProcessor::new(StackInputs::default())
            .with_options(
                ExecutionOptions::default()
                    .with_resolution_limits(fixture.resolution_limits)
                    .with_environment_trace_limits(retained_limit(limit)),
            )
            .unwrap()
            .execute_for_proving_sync(fixture.target, &mut fixture.host)
    };
    let capture_minimum =
        minimum_retained_limit(|limit| retained_capture_admits(execute(limit), limit));
    let witness = execute(capture_minimum).expect("exact retained capture limit must admit");
    let error = execute(capture_minimum - 1)
        .expect_err("insufficient retained capture storage must not publish a witness");
    assert!(
        matches!(
            error,
            ExecutionError::KeyedTrace(KeyedReplayError::LimitExceeded {
                resource: ReplayResource::RetainedBytes,
                ..
            })
        ),
        "unexpected capture error: {error}"
    );
    let policy = execution_fixture(vec![Operation::Push(ONE), Operation::Drop]);
    let target = policy.target;
    let resolution_limits = policy.resolution_limits;
    let bytes = witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let export_minimum = minimum_retained_limit(|limit| {
        retained_export_admits(
            witness.to_bytes_with_limits(retained_limit(limit), read_limits()),
            limit,
        )
    });
    assert_eq!(
        witness
            .to_bytes_with_limits(retained_limit(export_minimum), read_limits())
            .unwrap(),
        bytes
    );
    assert!(
        witness
            .to_bytes_with_limits(retained_limit(export_minimum - 1), read_limits())
            .expect_err("insufficient retained export storage must not publish bytes")
            .to_string()
            .contains("caller limits")
    );
    let read = |limit| {
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            target,
            resolution_limits,
            retained_limit(limit),
            read_limits(),
        )
    };
    let read_minimum = minimum_retained_limit(|limit| retained_read_admits(read(limit), limit));
    let restored = read(read_minimum).expect("exact retained read limit must admit");
    let error = read(read_minimum - 1)
        .expect_err("insufficient retained read storage must not publish a witness");
    assert!(error.to_string().contains("RetainedBytes"), "unexpected read error: {error}");
    assert_eq!(restored.claim(), witness.claim());
    assert_eq!(restored.execution_descriptor(), target);
    let restored_export_minimum = minimum_retained_limit(|limit| {
        retained_export_admits(
            restored.to_bytes_with_limits(retained_limit(limit), read_limits()),
            limit,
        )
    });
    assert_eq!(
        restored
            .to_bytes_with_limits(retained_limit(restored_export_minimum), read_limits())
            .unwrap(),
        bytes
    );
    assert!(
        restored
            .to_bytes_with_limits(retained_limit(restored_export_minimum - 1), read_limits())
            .expect_err("insufficient retained re-export storage must not publish bytes")
            .to_string()
            .contains("caller limits")
    );
}

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
fn witness_wire_limits_accept_exact_size_and_reject_one_byte_less() {
    let fixture = deferred_witness();
    let bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let exact = ReplayReadLimits {
        max_wire_bytes: bytes.len(),
        ..read_limits()
    };
    assert_eq!(fixture.witness.to_bytes_with_limits(trace_limits(), exact).unwrap(), bytes);
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        fixture.target,
        fixture.resolution_limits,
        trace_limits(),
        exact,
    )
    .unwrap();
    assert_eq!(restored.execution_descriptor(), fixture.target);
    let below = ReplayReadLimits { max_wire_bytes: bytes.len() - 1, ..exact };
    assert!(fixture.witness.to_bytes_with_limits(trace_limits(), below).is_err());
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            fixture.target,
            fixture.resolution_limits,
            trace_limits(),
            below,
        )
        .is_err()
    );
}

#[test]
fn witness_wire_rejects_unsupported_version() {
    let fixture = deferred_witness();
    let mut bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    assert_eq!(bytes[0], 7, "keyed replay witnesses must use wire version 7");
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            fixture.target,
            fixture.resolution_limits,
            trace_limits(),
            read_limits(),
        )
        .is_ok()
    );

    // Versions reject before any replay or precompile payload is decoded.
    for version in [0, 1, 2, 3, 4, 5, 6, 8] {
        bytes[0] = version;
        let error = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            fixture.target,
            fixture.resolution_limits,
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
        fixture.target,
        fixture.resolution_limits,
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
        fixture.target,
        fixture.resolution_limits,
        trace_limits(),
        read_limits(),
    )
    .expect("deferred witness should round trip");
    assert_eq!(restored.claim(), fixture.witness.claim());
    assert_eq!(restored.execution_descriptor(), fixture.target);
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
        fixture.target,
        fixture.resolution_limits,
        trace_limits(),
        read_limits(),
    )
    .expect("AEAD witness should round trip");
    assert_eq!(restored.claim(), claim);
    assert_eq!(restored.execution_descriptor(), fixture.target);
    assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
    let (restored_vm, restored_precompile) = restored.into_parts();
    assert!(restored_precompile.is_none());
    let restored_trace = build_trace(restored_vm, &miden_vm_stark::memory::default_budget())
        .expect("restored native trace should build");

    assert_single_mast_prefix(&original_trace, fixture.target);
    assert_single_mast_prefix(&restored_trace, fixture.target);
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
        fixture.target,
        fixture.resolution_limits,
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

    // The semantic classifier includes Memory rows with e1=1 in shared c22.
    assert_single_mast_prefix(&trace, fixture.target);
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
        assert_eq!(shared.chiplet_selectors()[..4], [ZERO, ZERO, ZERO, ZERO]);
        let memory = shared.memory();
        assert_eq!(shared.chip_clk, ZERO, "Memory rows do not carry Controller addresses");
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
