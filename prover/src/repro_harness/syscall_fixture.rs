//! A complete, lookup-balanced non-root SYSCALL witness under one captured public claim.

use alloc::vec;
use core::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;

use miden_air::vm::MidenAir;
use miden_air_definitions::vm::{
    ChipletCols, ControllerCols, CoreCols, LibraryCols,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    trace::{
        RowIndex,
        chiplets::{
            NUM_CONTROLLER_SELECTORS,
            hasher::{LINEAR_HASH, STATE_WIDTH},
            library::{LIBRARY_COL_RANGE, MAST},
        },
        eidos_compression::{
            EIDOS_COMPRESSION_CYCLE_LEN, F_COMPRESSION_CYCLE_ID_COL,
            F_COMPRESSION_MULTIPLICITY_COL, FOOTER_START, NUM_EIDOS_COMPRESSION_COLS,
            retag_felt_trace_block_cycle_id,
        },
    },
};
use miden_assembly::package::{
    CallableProcedurePath, NamespacePath, PackageCallables, PackageSymbols, ProcedureName,
};
use miden_core::{
    Felt,
    advice::{AdviceInputs, AdviceStack},
    chiplets::hasher::{DIGEST_RANGE, compress_state},
    field::QuadFelt,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, ExecNodeBuilder, JoinNodeBuilder, MastForest,
        MastNodeExt, SplitNodeBuilder,
    },
    operations::{Operation, opcodes},
    program::{CanonicalLabel, ImplementationRoot, Namespace},
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs,
    trace::chiplets::build_external_eidos_compression_traces,
};
use miden_stark::{
    air::BaseAir,
    lookup::{Challenges, build_lookup_fractions},
};
use miden_utils_testing::librarytree::{FixtureEnvironment, fixture_code, fixture_entry_digest};

use super::{ReproTrace, core_row_mut};

/// Captures a valid root syscall, then changes it to an authenticated equal-D child alias.
/// The child syscall already belongs to the entry's committed SPLIT; only its selector and the
/// corresponding invocation, resolution frequency and compression witness change.
pub(super) fn build_nonroot_syscall_fixture() -> (ReproTrace, ReproTrace) {
    let child_home =
        NamespacePath::new(vec![CanonicalLabel::text("prover-nonroot-syscall").unwrap()]);
    let root_binding = binding(NamespacePath::new(vec![]), "target");
    let child_binding = binding(child_home.clone(), "target");
    let entry_binding = binding(child_home.clone(), "entry");
    let [root_key, child_key, entry_key] =
        [&root_binding, &child_binding, &entry_binding].map(ProcedureName::key);
    assert_ne!(root_key, child_key);
    assert_eq!(root_binding.parent_namespace(), Namespace::initial());
    assert_ne!(child_binding.parent_namespace(), Namespace::initial());
    assert_eq!(entry_binding.parent_namespace(), child_binding.parent_namespace());

    let mut forest = MastForest::new();
    let body = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(body);
    let implementation = ImplementationRoot::new(forest[body].digest());
    let exec = ExecNodeBuilder::new(child_key).add_to_forest(&mut forest).unwrap();
    let advice = BasicBlockNodeBuilder::new(vec![Operation::AdvPop])
        .add_to_forest(&mut forest)
        .unwrap();
    let child_sys = CallNodeBuilder::new_syscall(child_key).add_to_forest(&mut forest).unwrap();
    let root_sys = CallNodeBuilder::new_syscall(root_key).add_to_forest(&mut forest).unwrap();
    let [child_sys_digest, root_sys_digest] =
        [child_sys, root_sys].map(|node| forest[node].digest().into_elements());
    assert_ne!(child_sys_digest, root_sys_digest);
    let split = SplitNodeBuilder::new([child_sys, root_sys]).add_to_forest(&mut forest).unwrap();
    let tail = JoinNodeBuilder::new([advice, split]).add_to_forest(&mut forest).unwrap();
    let entry = JoinNodeBuilder::new([exec, tail]).add_to_forest(&mut forest).unwrap();
    forest.make_root(entry);
    let program = fixture_code(forest.into(), entry);
    let callables = PackageCallables::new(
        [root_binding, child_binding, entry_binding],
        [],
        [
            (root_key, implementation),
            (child_key, implementation),
            (entry_key, ImplementationRoot::new(fixture_entry_digest(&program))),
        ],
    )
    .unwrap();
    let naming = PackageSymbols::new(child_home, callables, Some(entry_key)).unwrap();
    let environment = FixtureEnvironment::new(entry_key, [&naming]).unwrap();
    let mut host = DefaultHost::default().with_environment_source(environment.source());
    host.load_library(program).unwrap();
    let (trace, precompile) = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_stack(AdviceStack::from(vec![Felt::ZERO])))
        .unwrap()
        .with_options(
            ExecutionOptions::default()
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
    assert!(precompile.is_none());
    let honest = ReproTrace::new(&trace);
    let mut forged = ReproTrace::new(&trace);
    let main = trace.main_trace();
    let find_opcode = |opcode| {
        unique(
            (0..honest.core.height())
                .filter(|&row| main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcode)),
            "opcode",
        )
    };
    let adv = find_opcode(opcodes::ADVPOP);
    let split = find_opcode(opcodes::SPLIT);
    let syscall = find_opcode(opcodes::SYSCALL);
    assert!(find_opcode(opcodes::EXEC) < adv && adv < split && split < syscall);
    let syscall_end = unique(
        ((syscall + 1)..honest.core.height()).filter(|&row| {
            main.get_op_code(RowIndex::from(row)) == Felt::from_u8(opcodes::END)
                && core_row(&honest.core, row).decoder.hasher_state[..4] == root_sys_digest
        }),
        "syscall END",
    );
    assert_eq!(main.restores_caller_frame_flag(RowIndex::from(syscall_end)), Felt::ONE);
    assert_eq!(
        core_row(&honest.core, syscall).decoder.hasher_state[..4],
        root_key.into_word().into_elements()
    );
    assert_eq!(
        core_row(&honest.core, syscall).decoder.resolved_digest,
        implementation.into_word().into_elements()
    );
    assert_eq!(core_row(&honest.core, split).decoder.hasher_state[..4], child_sys_digest);
    assert_eq!(core_row(&honest.core, split).decoder.hasher_state[4..], root_sys_digest);

    // AdvPop's output is private advice. SPLIT consumes it, restoring the same later stack.
    for row in (adv + 1)..=split {
        assert_eq!(core_row(&honest.core, row).stack.top[0], Felt::ZERO);
        core_row_mut(&mut forged.core, row).stack.top[0] = Felt::ONE;
    }
    core_row_mut(&mut forged.core, syscall).decoder.hasher_state[..4]
        .copy_from_slice(child_key.as_word().as_elements());
    core_row_mut(&mut forged.core, syscall_end).decoder.hasher_state[..4]
        .copy_from_slice(&child_sys_digest);

    // The first ordinary EXEC retained the child opening and its normal demand before SYSCALL.
    for (key, namespace, old_count, new_count, normal_count) in [
        (root_key, Namespace::initial(), Felt::ONE, Felt::ZERO, Felt::ZERO),
        (
            child_key,
            naming.callables().binding(child_key).unwrap().parent_namespace(),
            Felt::ZERO,
            Felt::ONE,
            Felt::ONE,
        ),
    ] {
        let row = unique(
            (1..honest.chiplets.height()).step_by(2).filter(|&row| {
                let cols = chiplet_row(&honest.chiplets, row);
                cols.chiplet_selectors()[0] == Felt::ONE
                    && cols.library().k == MAST
                    && cols.library().z == key.into_word().into_elements()
            }),
            "Library Mast B binding",
        );
        let cols = chiplet_row(&honest.chiplets, row).library();
        assert_eq!(cols.x, namespace.into_word().into_elements());
        assert_eq!(cols.w, implementation.into_word().into_elements());
        assert_eq!(cols.a, normal_count);
        assert_eq!(cols.b, old_count);
        let width = forged.chiplets.width();
        let cells = &mut forged.chiplets.values[row * width..(row + 1) * width];
        let cols: &mut LibraryCols<Felt> = cells[LIBRARY_COL_RANGE].borrow_mut();
        cols.b = new_count;
    }

    let controller_row = unique(
        (0..honest.chiplets.height()).filter(|&row| {
            let cols = chiplet_row(&honest.chiplets, row);
            let controller = cols.controller();
            cols.chiplet_selectors()[..2] == [Felt::ZERO, Felt::ONE]
                && [controller.s0, controller.s1, controller.s2] == LINEAR_HASH
                && controller.state[..4] == root_key.into_word().into_elements()
                && controller.row_data == root_sys_digest
        }),
        "SYS Controller hash",
    );
    let controller = chiplet_row(&honest.chiplets, controller_row);
    assert_eq!(controller.controller_op_final(), Felt::ONE);
    assert_eq!(controller.chip_clk, core_row(&honest.core, syscall + 1).decoder.addr);
    assert_eq!(controller.chip_clk, core_row(&honest.core, syscall_end).decoder.addr);
    let old_state = controller.controller().state;
    assert_eq!(&old_state[4..8], &[Felt::ZERO; 4]);
    let mut new_state = old_state;
    new_state[..4].copy_from_slice(child_key.as_word().as_elements());
    let mut compressed = new_state;
    compress_state(&mut compressed);
    assert_eq!(compressed[DIGEST_RANGE], child_sys_digest);
    let width = forged.chiplets.width();
    let cells = &mut forged.chiplets.values[controller_row * width..(controller_row + 1) * width];
    let end = NUM_CONTROLLER_SELECTORS + size_of::<ControllerCols<u8>>();
    let controller: &mut ControllerCols<Felt> = cells[NUM_CONTROLLER_SELECTORS..end].borrow_mut();
    controller.state = new_state;
    controller.row_data = child_sys_digest;
    replace_compression(&mut forged, old_state, new_state);

    assert_eq!(honest.execution_descriptor, forged.execution_descriptor);
    assert_eq!(honest.claim(), forged.claim());
    assert_eq!(honest.precompile_root, forged.precompile_root);
    for (old, new) in matrices(&honest).into_iter().zip(matrices(&forged)) {
        assert_eq!((old.width(), old.height()), (new.width(), new.height()));
    }
    assert_lookup_delta(&honest, &forged);
    (honest, forged)
}

fn binding(home: NamespacePath, name: &str) -> ProcedureName {
    ProcedureName::new(
        home,
        CallableProcedurePath::from_semantic_components(vec![name.into()]).unwrap(),
    )
    .unwrap()
}

fn unique(mut rows: impl Iterator<Item = usize>, name: &str) -> usize {
    let row = rows.next().unwrap_or_else(|| panic!("missing {name}"));
    assert!(rows.next().is_none(), "ambiguous {name}");
    row
}

fn core_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &CoreCols<Felt> {
    matrix.values[row * matrix.width()..(row + 1) * matrix.width()].borrow()
}

fn chiplet_row(matrix: &RowMajorMatrix<Felt>, row: usize) -> &ChipletCols<Felt> {
    matrix.values[row * matrix.width()..(row + 1) * matrix.width()].borrow()
}

fn matrices(trace: &ReproTrace) -> [&RowMajorMatrix<Felt>; 4] {
    [&trace.core, &trace.chiplets, &trace.eidos_compression, &trace.and8]
}

/// Compare deterministic compression states independently of their physical cycle and demand.
fn same_compression(block: &[Felt], generated: &[Felt]) -> bool {
    block.iter().zip(generated).enumerate().all(|(index, (actual, expected))| {
        let row = index / NUM_EIDOS_COMPRESSION_COLS;
        let col = index % NUM_EIDOS_COMPRESSION_COLS;
        col == F_COMPRESSION_CYCLE_ID_COL
            || (row >= FOOTER_START && col == F_COMPRESSION_MULTIPLICITY_COL)
            || actual == expected
    })
}

/// Replace exactly one interned request, retaining every Library compression and padding cycle.
fn replace_compression(
    forged: &mut ReproTrace,
    old_state: [Felt; STATE_WIDTH],
    new_state: [Felt; STATE_WIDTH],
) {
    let (mut old, old_counts) = build_external_eidos_compression_traces([(old_state, 1)]);
    let (mut new, new_counts) = build_external_eidos_compression_traces([(new_state, 1)]);
    assert_eq!(old.height(), EIDOS_COMPRESSION_CYCLE_LEN);
    assert_eq!(new.height(), EIDOS_COMPRESSION_CYCLE_LEN);
    let block_cells = EIDOS_COMPRESSION_CYCLE_LEN * NUM_EIDOS_COMPRESSION_COLS;
    assert_eq!(forged.eidos_compression.values.len() % block_cells, 0);
    let cycle = unique(
        forged
            .eidos_compression
            .values
            .chunks_exact(block_cells)
            .enumerate()
            .filter_map(|(cycle, block)| same_compression(block, &old.values).then_some(cycle)),
        "old SYS compression cycle",
    );
    assert!(
        !forged
            .eidos_compression
            .values
            .chunks_exact(block_cells)
            .any(|block| same_compression(block, &new.values)),
        "new SYS compression state must be absent from the captured witness",
    );
    let captured =
        &mut forged.eidos_compression.values[cycle * block_cells..(cycle + 1) * block_cells];
    let cycle_id = captured[F_COMPRESSION_CYCLE_ID_COL].as_canonical_u64();
    assert_eq!(cycle_id, cycle as u64);
    for generated in [&mut old, &mut new] {
        retag_felt_trace_block_cycle_id(
            generated.values.as_chunks_mut::<NUM_EIDOS_COMPRESSION_COLS>().0,
            cycle_id,
        );
    }
    // Exact equality also requires the captured provider multiplicity to be one.
    assert_eq!(&*captured, old.values.as_slice(), "old compression block must match exactly");
    captured.copy_from_slice(&new.values);
    assert_eq!(forged.and8.values.len(), old_counts.values.len());
    assert_eq!(forged.and8.values.len(), new_counts.values.len());
    for ((count, old), new) in
        forged.and8.values.iter_mut().zip(old_counts.values).zip(new_counts.values)
    {
        assert!(count.as_canonical_u64() >= old.as_canonical_u64());
        *count = *count - old + new;
    }
}

/// Checks aggregate lookup deltas across all four AIRs at fixed independent challenges.
/// Public-boundary messages remain fixed because the descriptor, claim and deferred root do.
fn assert_lookup_delta(honest: &ReproTrace, forged: &ReproTrace) {
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::new([Felt::from_u32(3), Felt::from_u32(5)]),
        QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let mut delta = HashMap::new();
    for ((air, honest), forged) in [
        MidenAir::CORE,
        MidenAir::CHIPLETS,
        MidenAir::EIDOS_COMPRESSION,
        MidenAir::AND8_LOOKUP,
    ]
    .into_iter()
    .zip(matrices(honest))
    .zip(matrices(forged))
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
    assert!(delta.is_empty(), "forged syscall must preserve all lookup messages: {delta:?}");
}

#[test]
fn actual_nonroot_syscall_fails_native_and_masm() {
    let (honest, mut forged) = build_nonroot_syscall_fixture();
    let expected_claim = honest.claim();
    let baseline = honest.prove_current().expect("honest root SYS proof construction must finish");
    honest.assert_native_and_recursive_accept(baseline);

    assert_eq!(forged.claim(), expected_claim);
    let proof = forged
        .prove_current()
        .expect("the lookup-balanced child SYS witness must finish production proof construction");
    forged.assert_native_and_recursive_air_rejection(proof);

    // Adding an unrelated HALT clock defect preserves lookup demands and expected public inputs.
    // This combined mutation must also reach rejection in both production consumers.
    let last = forged.core.height() - 1;
    assert_eq!(decode_opcode(&core_row(&forged.core, last).decoder.op_bits), opcodes::HALT);
    core_row_mut(&mut forged.core, last).system.clk += Felt::ONE;
    assert_eq!(forged.claim(), expected_claim);
    let control = forged
        .prove_current()
        .expect("the lookup-balanced clock control must finish production proof construction");
    forged.assert_native_and_recursive_air_rejection(control);
}

fn decode_opcode(bits: &[Felt; 7]) -> u8 {
    bits.iter()
        .enumerate()
        .fold(0, |opcode, (index, bit)| opcode | ((bit.as_canonical_u64() as u8) << index))
}
