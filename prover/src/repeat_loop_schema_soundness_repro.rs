//! Prover and verifier regressions for the LOOP body and REPEAT parent constraints.

use alloc::{vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};
use std::collections::{BTreeMap, HashMap};

use miden_air::vm::MidenAir;
use miden_air_definitions::vm::{
    ChipletCols,
    logup::{BlockHashMsg, BusId, MIDEN_MAX_MESSAGE_WIDTH},
    trace::{
        MIN_TRACE_LEN, RowIndex,
        chiplets::hasher::{HASH_ABSORB, LINEAR_HASH, PADDING, STATE_WIDTH},
        eidos_compression::{
            EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_CYCLE_ID_COL,
            F_COMPRESSION_MULTIPLICITY_COL, FOOTER_START, NUM_EIDOS_COMPRESSION_COLS, TraceMode,
            generate_felt_trace_block, retag_felt_trace_block_cycle_id,
        },
    },
};
use miden_assembly::CodePackage;
use miden_core::{
    Felt,
    field::QuadFelt,
    mast::{BasicBlockNodeBuilder, LoopNodeBuilder, MastForest},
    operations::{Operation, opcodes},
    program::StackOutputs,
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{
    DefaultHost, FastProcessor, StackInputs,
    trace::{VmTrace, chiplets::build_external_eidos_compression_traces},
};
use miden_stark::{
    air::BaseAir,
    lookup::{Challenges, LookupMessage, build_lookup_fractions},
};
use miden_utils_testing::librarytree::fixture_code;

use crate::repro_harness::{ReproTrace, core_row_mut};

fn build_loop_program(body_ops: Vec<Operation>) -> CodePackage {
    let mut mast_forest = MastForest::new();
    let body = BasicBlockNodeBuilder::new(body_ops).add_to_forest(&mut mast_forest).unwrap();
    let root = LoopNodeBuilder::new(body).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(root);
    fixture_code(mast_forest.into(), root)
}

fn build_basic_program(ops: Vec<Operation>) -> CodePackage {
    let mut mast_forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(ops).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(root);
    fixture_code(mast_forest.into(), root)
}

fn execute(program: &CodePackage, stack: &[u64]) -> VmTrace {
    let stack = stack.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<_>>();
    let environment = crate::named_fixture::raw_environment(program, "repeat-loop-schema");
    let mut host = DefaultHost::default().with_environment_source(environment.source());
    host.load_library(program.clone()).unwrap();
    let (trace, precompile_witness) = FastProcessor::new(StackInputs::new(&stack).unwrap())
        .with_options(
            miden_processor::ExecutionOptions::default()
                .with_resolution_limits(environment.resolution_limits())
                .with_environment_trace_limits(miden_utils_testing::librarytree::trace_limits()),
        )
        .unwrap()
        .execute_and_build_trace_sync(
            environment.target(),
            &mut host,
            &miden_vm_stark::memory::default_budget(),
        )
        .unwrap();
    assert!(precompile_witness.is_none());
    trace
}

fn core_row(
    matrix: &RowMajorMatrix<Felt>,
    row: usize,
) -> &miden_air_definitions::vm::CoreCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

fn chiplet_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &ChipletCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width].borrow()
}

/// Controller addresses are one-based within their band, after the physical Library prefix.
fn controller_row_index(matrix: &RowMajorMatrix<Felt>, address: Felt) -> usize {
    assert_ne!(address, Felt::ZERO, "a Controller row must have a present address");
    let mut matches = (0..matrix.height()).filter(|&index| {
        let row = chiplet_row(matrix, index);
        row.chiplet_selectors()[..2] == [Felt::ZERO, Felt::ONE] && row.chip_clk == address
    });
    let index = matches.next().expect("Controller address must exist in its own band");
    assert!(matches.next().is_none(), "Controller address must identify exactly one row");
    index
}

fn copy_chiplet_row(
    dst: &mut RowMajorMatrix<Felt>,
    dst_row: usize,
    src: &RowMajorMatrix<Felt>,
    src_row: usize,
) {
    assert_eq!(chiplet_row(dst, dst_row).chiplet_selectors()[..2], [Felt::ZERO, Felt::ONE]);
    assert_eq!(chiplet_row(src, src_row).chiplet_selectors()[..2], [Felt::ZERO, Felt::ONE]);
    let width = dst.width();
    let row: &mut ChipletCols<Felt> =
        dst.values[dst_row * width..(dst_row + 1) * width].borrow_mut();
    let clock = row.chip_clk;
    *row = chiplet_row(src, src_row).clone();
    row.chip_clk = clock;
}

/// Compares a generated packed compression cycle independently of its physical ID.
fn same_compression(block: &[Felt], generated: &[Felt]) -> bool {
    assert_eq!(block.len(), generated.len());
    block.iter().zip(generated).enumerate().all(|(index, (actual, expected))| {
        let col = index % NUM_EIDOS_COMPRESSION_COLS;
        col == F_COMPRESSION_CYCLE_ID_COL || actual == expected
    })
}

/// Regenerates the footer CV corrections as well as the provider frequency, including zero.
fn compression_cycle(state: [u64; STATE_WIDTH], multiplicity: u64) -> Vec<Felt> {
    let block = core::array::from_fn(|i| (state[i / 2] >> (32 * (i % 2))) as u32);
    let cv = core::array::from_fn(|i| (state[8 + i / 2] >> (32 * (i % 2))) as u32);
    generate_felt_trace_block(block, cv, TraceMode::CompressionWithMultiplicity { multiplicity })
        .rows
        .into_iter()
        .flatten()
        .collect()
}

fn replace_byte_counts(and8: &mut RowMajorMatrix<Felt>, old: &[Felt], new: &[Felt]) {
    assert_eq!(and8.values.len(), old.len());
    assert_eq!(and8.values.len(), new.len());
    for ((count, old), new) in and8.values.iter_mut().zip(old).zip(new) {
        assert!(count.as_canonical_u64() >= old.as_canonical_u64());
        *count = *count - *old + *new;
    }
}

/// Changes only Controller request demand in the captured shared Library/Controller witness.
fn rebuild_hash_witnesses(
    trace: &VmTrace,
    chiplets: &RowMajorMatrix<Felt>,
) -> (RowMajorMatrix<Felt>, RowMajorMatrix<Felt>) {
    let (_, honest_chiplets, mut compression, mut and8) = trace.main_trace().clone_air_matrices();
    let mut deltas = BTreeMap::<[u64; STATE_WIDTH], i64>::new();
    for (matrix, sign) in [(&honest_chiplets, -1), (chiplets, 1)] {
        for index in 0..matrix.height() {
            let row = chiplet_row(matrix, index);
            if row.chiplet_selectors()[..2] != [Felt::ZERO, Felt::ONE] {
                continue;
            }
            let controller = row.controller();
            let selectors = [controller.s0, controller.s1, controller.s2];
            if selectors == PADDING {
                continue;
            }
            assert!(selectors == LINEAR_HASH || selectors == HASH_ABSORB);
            let state = controller.state.map(|value| value.as_canonical_u64());
            *deltas.entry(state).or_default() += sign;
        }
    }
    deltas.retain(|_, delta| *delta != 0);
    if deltas.is_empty() {
        // An unchanged Controller multiset preserves the complete honest witness byte-for-byte.
        return (compression, and8);
    }

    let block_cells = EIDOS_COMPRESSION_CYCLE_LEN * NUM_EIDOS_COMPRESSION_COLS;
    assert_eq!(compression.values.len() % block_cells, 0);
    let mut reusable = Vec::new();
    let mut additions = Vec::new();
    for (state, delta) in deltas {
        let (mut generated, counts) =
            build_external_eidos_compression_traces([(state.map(Felt::new_unchecked), 1)]);
        assert_eq!(generated.height(), EIDOS_COMPRESSION_CYCLE_LEN);
        assert_eq!(and8.values.len(), counts.values.len());
        let mut matching =
            compression.values.chunks_exact(block_cells).enumerate().filter(|(_, block)| {
                let multiplicity = block
                    [FOOTER_START * NUM_EIDOS_COMPRESSION_COLS + F_COMPRESSION_MULTIPLICITY_COL]
                    .as_canonical_u64();
                multiplicity != 0
                    && same_compression(block, &compression_cycle(state, multiplicity))
            });
        let cycle = matching.next().map(|(cycle, _)| cycle);
        assert!(matching.next().is_none(), "packed request must have one interned cycle");
        if let Some(cycle) = cycle {
            let captured = &mut compression.values[cycle * block_cells..(cycle + 1) * block_cells];
            let old = captured
                [FOOTER_START * NUM_EIDOS_COMPRESSION_COLS + F_COMPRESSION_MULTIPLICITY_COL]
                .as_canonical_u64();
            let new = if delta < 0 {
                old.checked_sub(delta.unsigned_abs()).expect("Controller demand must exist")
            } else {
                old.checked_add(delta as u64).unwrap()
            };
            generated.values = compression_cycle(state, old);
            retag_felt_trace_block_cycle_id(
                generated.values.as_chunks_mut::<NUM_EIDOS_COMPRESSION_COLS>().0,
                cycle as u64,
            );
            assert_eq!(&*captured, generated.values.as_slice(), "captured cycle must match");
            generated.values = compression_cycle(state, new);
            retag_felt_trace_block_cycle_id(
                generated.values.as_chunks_mut::<NUM_EIDOS_COMPRESSION_COLS>().0,
                cycle as u64,
            );
            captured.copy_from_slice(&generated.values);
            if new == 0 {
                // Mode-zero real cycles may have zero demand. Retaining one also retains its byte
                // lookups; reuse it preferentially if this mutation introduces another state.
                reusable.push((cycle, Some(counts)));
            }
        } else {
            assert!(delta > 0, "retired Controller request must have a captured provider");
            generated.values = compression_cycle(state, delta as u64);
            additions.push((generated, counts));
        }
    }
    if additions.is_empty() {
        return (compression, and8);
    }

    let (mut padding, padding_counts) = build_external_eidos_compression_traces([]);
    assert_eq!(padding.height(), EIDOS_COMPRESSION_CYCLE_LEN);
    assert_eq!(and8.values.len(), padding_counts.values.len());
    for (cycle, block) in compression.values.chunks_exact(block_cells).enumerate() {
        if block[FOOTER_START * NUM_EIDOS_COMPRESSION_COLS + F_COMPRESSION_MULTIPLICITY_COL]
            == Felt::ZERO
            && same_compression(block, &padding.values)
            && reusable.iter().all(|(retired, _)| *retired != cycle)
        {
            reusable.push((cycle, None));
        }
    }
    let mut reusable = reusable.into_iter();
    for (mut generated, counts) in additions {
        let replacement = reusable.next();
        let cycle = replacement
            .as_ref()
            .map_or(compression.height() / EIDOS_COMPRESSION_CYCLE_LEN, |(cycle, _)| *cycle);
        retag_felt_trace_block_cycle_id(
            generated.values.as_chunks_mut::<NUM_EIDOS_COMPRESSION_COLS>().0,
            cycle as u64,
        );
        if let Some((_, old_counts)) = replacement {
            compression.values[cycle * block_cells..(cycle + 1) * block_cells]
                .copy_from_slice(&generated.values);
            let old_counts = old_counts.as_ref().unwrap_or(&padding_counts);
            replace_byte_counts(&mut and8, &old_counts.values, &counts.values);
        } else {
            compression.values.extend(generated.values);
            for (count, added) in and8.values.iter_mut().zip(counts.values) {
                *count += added;
            }
        }
    }
    let height = compression.height().next_power_of_two().max(MIN_TRACE_LEN);
    while compression.height() < height {
        let cycle = compression.height() / EIDOS_COMPRESSION_CYCLE_LEN;
        retag_felt_trace_block_cycle_id(
            padding.values.as_chunks_mut::<NUM_EIDOS_COMPRESSION_COLS>().0,
            cycle as u64,
        );
        compression.values.extend_from_slice(&padding.values);
        for (count, added) in and8.values.iter_mut().zip(&padding_counts.values) {
            *count += *added;
        }
    }
    (compression, and8)
}

/// Compares lookup-message multiplicities at a fixed challenge point, including the hash and byte
/// tables. Public boundary messages stay unchanged in these fixtures.
fn assert_lookup_delta(
    trace: &VmTrace,
    forged: [&RowMajorMatrix<Felt>; 4],
    expected: &[(BlockHashMsg<Felt>, Felt)],
) {
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::new([Felt::from_u32(3), Felt::from_u32(5)]),
        QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let (core, chiplets, compression, and8) = trace.main_trace().clone_air_matrices();
    let mut delta = HashMap::new();
    for ((air, honest), forged) in [
        MidenAir::CORE,
        MidenAir::CHIPLETS,
        MidenAir::EIDOS_COMPRESSION,
        MidenAir::AND8_LOOKUP,
    ]
    .into_iter()
    .zip([&core, &chiplets, &compression, &and8])
    .zip(forged)
    {
        let preprocessed = air.preprocessed_trace();
        let periodic = BaseAir::<Felt>::periodic_columns(&air);
        for (matrix, sign) in [(honest, -Felt::ONE), (forged, Felt::ONE)] {
            let fractions =
                build_lookup_fractions(&air, matrix, preprocessed.as_ref(), &periodic, &challenges);
            for &(multiplicity, denominator) in fractions.fractions() {
                *delta.entry(denominator).or_insert(Felt::ZERO) += sign * multiplicity;
            }
        }
    }
    delta.retain(|_, multiplicity| *multiplicity != Felt::ZERO);
    let expected: HashMap<_, _> = expected
        .iter()
        .map(|(message, multiplicity)| (message.encode(&challenges), *multiplicity))
        .collect();
    assert_eq!(delta, expected, "forged witness must change only the expected lookup messages");
}

fn decode_opcode(op_bits: &[Felt; 7]) -> u8 {
    op_bits.iter().enumerate().fold(0u8, |opcode, (bit_idx, bit)| {
        opcode | ((bit.as_canonical_u64() as u8) << bit_idx)
    })
}

fn count_loop_body_end_removals(
    core: &RowMajorMatrix<Felt>,
    parent: Felt,
    child_hash: [Felt; 4],
) -> usize {
    (0..core.height() - 1)
        .filter(|&row| {
            let local = core_row(core, row);
            let next = core_row(core, row + 1);
            let next_is_not_first_child =
                [opcodes::END, opcodes::REPEAT, opcodes::RESPAN, opcodes::HALT]
                    .contains(&decode_opcode(&next.decoder.op_bits));
            local.decoder.op_bits
                == core::array::from_fn(|bit_idx| Felt::from_u8((opcodes::END >> bit_idx) & 1))
                && local.decoder.hasher_state[..4] == child_hash
                && local.decoder.hasher_state[4] == Felt::ONE
                && next.decoder.addr == parent
                && next_is_not_first_child
        })
        .count()
}

fn find_first_iteration_window(trace: &VmTrace) -> (usize, usize, usize) {
    let main = trace.main_trace();
    let is =
        |row: usize, opcode: u8| main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcode);

    let span = (1..main.core_height() - 5)
        .find(|&row| {
            is(row - 1, opcodes::LOOP)
                && is(row, opcodes::SPAN)
                && main.is_in_span(RowIndex::from(row + 1)) == Felt::ONE
                && main.is_in_span(RowIndex::from(row + 2)) == Felt::ONE
                && is(row + 3, opcodes::END)
                && is(row + 4, opcodes::REPEAT)
        })
        .expect("fixture must contain LOOP | SPAN | op | op | END | REPEAT");
    (span, span + 4, span + 1)
}

#[test]
fn honest_repeated_loop_verifies() {
    let program = build_loop_program(vec![Operation::Not, Operation::Not]);
    let trace = execute(&program, &[1, 1, 0]);
    assert!(
        (0..trace.main_trace().core_height()).any(|row| {
            trace.main_trace().get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::REPEAT)
        }),
        "fixture must execute REPEAT"
    );
    let (_, chiplets, compression, and8) = trace.main_trace().clone_air_matrices();
    let (rebuilt, rebuilt_counts) = rebuild_hash_witnesses(&trace, &chiplets);
    assert_eq!(rebuilt.values, compression.values, "unchanged compression witness");
    assert_eq!(rebuilt_counts.values, and8.values, "unchanged byte-table demand");
    assert!(ReproTrace::new(&trace).prove_and_verify_current().unwrap().is_complete());
}

#[test]
fn forged_early_loop_iteration_body_is_rejected() {
    let victim = execute(&build_loop_program(vec![Operation::Not, Operation::Not]), &[1, 1, 0]);
    let attacker = execute(&build_loop_program(vec![Operation::Noop, Operation::Noop]), &[1, 1, 0]);
    assert_eq!(victim.stack_outputs(), attacker.stack_outputs());
    let (span, repeat, body_op) = find_first_iteration_window(&victim);
    assert_eq!((span, repeat, body_op), find_first_iteration_window(&attacker));
    let (mut core, mut chiplets, ..) = victim.main_trace().clone_air_matrices();
    let (attacker_core, attacker_chiplets, ..) = attacker.main_trace().clone_air_matrices();
    let parent = core_row(&core, span).decoder.addr;
    let committed = core_row(&core, span - 1).decoder.hasher_state[..4].try_into().unwrap();
    let substituted =
        core_row(&attacker_core, span - 1).decoder.hasher_state[..4].try_into().unwrap();
    assert_ne!(committed, substituted);

    // Keep LOOP's commitment and later iterations intact; replace only the first body and REPEAT.
    for row in span..=repeat {
        *core_row_mut(&mut core, row) = core_row(&attacker_core, row).clone();
    }
    let controller_addr = core_row(&core, body_op).decoder.addr;
    let controller_row = controller_row_index(&chiplets, controller_addr);
    let attacker_controller_row = controller_row_index(&attacker_chiplets, controller_addr);
    copy_chiplet_row(&mut chiplets, controller_row, &attacker_chiplets, attacker_controller_row);
    let (compression, and8) = rebuild_hash_witnesses(&victim, &chiplets);
    assert_lookup_delta(
        &victim,
        [&core, &chiplets, &compression, &and8],
        &[
            (BlockHashMsg::LoopBody { parent, child_hash: committed }, Felt::ONE),
            (BlockHashMsg::LoopBody { parent, child_hash: substituted }, -Felt::ONE),
        ],
    );
    let error = ReproTrace::new(&victim)
        .prove_and_verify_parts_allowing_lookup_rejection(
            core,
            chiplets,
            compression,
            and8,
            *victim.stack_outputs(),
        )
        .expect_err("each iteration must execute the body committed by LOOP");
    assert!(error.starts_with("prover rejected an unbalanced lookup:"), "{error}");
}

#[test]
fn loop_skip_body_with_retired_hasher_rows_is_rejected() {
    let trace = execute(&build_loop_program(vec![Operation::Noop, Operation::Noop]), &[0]);
    let (mut core, mut chiplets, ..) = trace.main_trace().clone_air_matrices();
    let honest_core = core.clone();
    let honest_chiplets = chiplets.clone();
    let loop_end = (1..core.height())
        .find(|&row| {
            let row = core_row(&core, row);
            decode_opcode(&row.decoder.op_bits) == opcodes::END
                && row.decoder.hasher_state[5] == Felt::ONE
        })
        .unwrap();
    assert_eq!(decode_opcode(&core_row(&core, loop_end + 1).decoder.op_bits), opcodes::HALT);
    let body_controller = controller_row_index(&chiplets, core_row(&core, 2).decoder.addr);
    for row in 1..=loop_end {
        let source = if row == 1 { loop_end } else { loop_end + 1 };
        *core_row_mut(&mut core, row) = core_row(&honest_core, source).clone();
        core_row_mut(&mut core, row).system.clk = Felt::from_u32(row as u32);
    }
    core_row_mut(&mut core, 0).decoder.group_count = Felt::ZERO;

    let padding = (0..chiplets.height())
        .find(|&row| {
            let row = chiplet_row(&chiplets, row);
            let controller = row.controller();
            row.chiplet_selectors()[..2] == [Felt::ZERO, Felt::ONE]
                && [controller.s0, controller.s1, controller.s2] == PADDING
        })
        .unwrap();
    copy_chiplet_row(&mut chiplets, body_controller, &honest_chiplets, padding);
    let (compression, and8) = rebuild_hash_witnesses(&trace, &chiplets);
    assert_lookup_delta(&trace, [&core, &chiplets, &compression, &and8], &[]);
    let error = ReproTrace::new(&trace)
        .prove_and_verify_parts_allowing_lookup_rejection(
            core,
            chiplets,
            compression,
            and8,
            *trace.stack_outputs(),
        )
        .expect_err("LOOP must execute its body even when its lookup multiplicity is zero");
    assert!(error.starts_with("verifier rejected:"), "balanced lookup fixture: {error}");
}

#[test]
fn forged_in_span_repeat_with_body_hash_evidence_is_rejected() {
    // Hash evidence is valid; lookup construction rejects the unauthorized loop-body removal.
    // This exercises the block-hash relation without isolating the REPEAT predecessor constraint.
    let victim = execute(&build_basic_program(vec![Operation::Noop]), &[1, 1]);
    let body_program = build_loop_program(vec![Operation::Not]);
    let body = execute(&body_program, &[1]);
    let repeated = execute(&body_program, &[0, 1]);
    let (mut core, mut chiplets, ..) = victim.main_trace().clone_air_matrices();
    let (body_core, body_chiplets, ..) = body.main_trace().clone_air_matrices();
    let (repeat_core, ..) = repeated.main_trace().clone_air_matrices();
    let victim_end = core_row(&core, 2).clone();
    assert_eq!(decode_opcode(&victim_end.decoder.op_bits), opcodes::END);
    assert_eq!(decode_opcode(&core_row(&repeat_core, 4).decoder.op_bits), opcodes::REPEAT);

    // SPAN_A | NOOP | REPEAT | SPAN_X | NOT | END_X | END_A | HALT...
    *core_row_mut(&mut core, 2) = core_row(&repeat_core, 4).clone();
    for (dst, src) in [(3, 1), (4, 2), (5, 3)] {
        *core_row_mut(&mut core, dst) = core_row(&body_core, src).clone();
    }
    *core_row_mut(&mut core, 6) = victim_end;
    for row in 2..=6 {
        core_row_mut(&mut core, row).system.clk = Felt::from_u32(row as u32);
    }
    let final_stack = core_row(&core, 5).stack.clone();
    for row in 6..core.height() {
        core_row_mut(&mut core, row).stack = final_stack.clone();
    }
    let outputs = StackOutputs::from(final_stack.top);
    assert_ne!(outputs, *victim.stack_outputs());

    let controller_addr = core_row(&core, 4).decoder.addr;
    let controller_row = controller_row_index(&chiplets, controller_addr);
    let body_controller_row = controller_row_index(&body_chiplets, controller_addr);
    copy_chiplet_row(&mut chiplets, controller_row, &body_chiplets, body_controller_row);
    let (compression, and8) = rebuild_hash_witnesses(&victim, &chiplets);
    assert_lookup_delta(
        &victim,
        [&core, &chiplets, &compression, &and8],
        &[(
            BlockHashMsg::LoopBody {
                parent: core_row(&core, 6).decoder.addr,
                child_hash: core_row(&core, 5).decoder.hasher_state[..4].try_into().unwrap(),
            },
            -Felt::ONE,
        )],
    );
    let error = ReproTrace::new(&victim)
        .prove_and_verify_parts_allowing_lookup_rejection(
            core,
            chiplets,
            compression,
            and8,
            outputs,
        )
        .expect_err("an injected REPEAT cannot authorize an uncommitted body");
    assert!(error.starts_with("prover rejected an unbalanced lookup:"), "{error}");
}

#[test]
fn loop_body_end_flag_cannot_be_reassigned_to_another_end() {
    let program = build_loop_program(vec![Operation::Not, Operation::Not]);
    let trace = execute(&program, &[1, 1, 0]);
    let main = trace.main_trace();
    let (first_span, first_repeat, first_body_op) = find_first_iteration_window(&trace);
    let loop_row = first_span - 1;
    assert_eq!(main.get_op_code(RowIndex::from(loop_row)), Felt::from_u8(opcodes::LOOP));
    assert_eq!(main.get_op_code(RowIndex::from(first_body_op)), Felt::from_u8(opcodes::NOT));
    let body_end_row = first_repeat - 1;
    assert_eq!(main.is_loop_body_flag(RowIndex::from(body_end_row)), Felt::ONE);

    let non_body_end_row = ((first_repeat + 1)..main.core_height())
        .find(|&row| {
            main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::END)
                && main.is_loop_body_flag(RowIndex::from(row)) == Felt::ZERO
        })
        .expect("fixture must end the root LOOP after ending its bodies");

    let loop_parent = main.addr(RowIndex::from(first_span));
    let hasher_state = main.decoder_hasher_state(RowIndex::from(loop_row));
    let loop_body_hash = [hasher_state[0], hasher_state[1], hasher_state[2], hasher_state[3]];
    let (mut core, chiplets, eidos_compression, and8) = main.clone_air_matrices();
    let honest_body_count = count_loop_body_end_removals(&core, loop_parent, loop_body_hash);
    assert_eq!(
        core_row(&core, loop_row).decoder.group_count,
        Felt::new_unchecked(honest_body_count as u64),
        "fixture LOOP multiplicity must match the body END count"
    );

    core_row_mut(&mut core, body_end_row).decoder.hasher_state[4] = Felt::ZERO;
    core_row_mut(&mut core, non_body_end_row).decoder.hasher_state[4] = Felt::ONE;

    let result = ReproTrace::new(&trace).prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        eidos_compression,
        and8,
        *trace.stack_outputs(),
    );
    let error = result.expect_err("reassigning is_loop_body between END rows must be rejected");
    assert!(
        error.starts_with("prover rejected an unbalanced lookup:"),
        "the forged END flags must fail at lookup construction: {error}"
    );
}

#[test]
fn forged_intermediate_repeat_parent_addr_is_rejected() {
    let program = build_loop_program(vec![Operation::Not, Operation::Not]);
    let trace = execute(&program, &[1, 1, 0]);
    let (first_span, first_repeat, _) = find_first_iteration_window(&trace);
    let second_span = first_repeat + 1;
    let second_repeat = second_span + (first_repeat - first_span);

    let main = trace.main_trace();
    assert_eq!(main.get_op_code(RowIndex::from(second_span)), Felt::from_u8(opcodes::SPAN));
    assert_eq!(main.get_op_code(RowIndex::from(second_repeat)), Felt::from_u8(opcodes::REPEAT));

    let (mut core, chiplets, eidos_compression, and8) = main.clone_air_matrices();
    let forged_parent = Felt::new_unchecked(99);
    core_row_mut(&mut core, second_span).decoder.addr = forged_parent;
    core_row_mut(&mut core, second_repeat).decoder.addr = forged_parent;

    let result = ReproTrace::new(&trace).prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        eidos_compression,
        and8,
        *trace.stack_outputs(),
    );
    assert!(result.is_err(), "REPEAT must preserve its parent address: {result:?}");
}

#[test]
fn direct_repeat_without_body_hash_evidence_is_rejected() {
    let victim = build_basic_program(vec![Operation::Noop]);
    let victim_trace = execute(&victim, &[1, 1]);
    let loop_program = build_loop_program(vec![Operation::Not]);
    let loop_trace = execute(&loop_program, &[0, 1]);
    let (mut core, chiplets, eidos_compression, and8) =
        victim_trace.main_trace().clone_air_matrices();
    let (repeat_core, ..) = loop_trace.main_trace().clone_air_matrices();
    assert_eq!(decode_opcode(&core_row(&repeat_core, 4).decoder.op_bits), opcodes::REPEAT);

    let repeat = core_row(&repeat_core, 4).clone();
    *core_row_mut(&mut core, 2) = repeat;
    core_row_mut(&mut core, 2).system.clk = Felt::from_u32(2);
    let final_stack = core_row(&core, 2).stack.clone();
    for row in 3..core.height() {
        core_row_mut(&mut core, row).stack = final_stack.clone();
    }
    let forged_outputs = StackOutputs::from(final_stack.top);

    let result = ReproTrace::new(&victim_trace).prove_and_verify_parts_allowing_lookup_rejection(
        core,
        chiplets,
        eidos_compression,
        and8,
        forged_outputs,
    );
    assert!(
        result.is_err(),
        "REPEAT without body hash evidence must be rejected: {result:?}"
    );
}
