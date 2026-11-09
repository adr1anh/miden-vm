//! A complete, lookup-balanced non-root SYSCALL witness under one captured public claim.

use alloc::vec;
use core::borrow::{Borrow, BorrowMut};
use std::collections::HashMap;

use miden_air::vm::MidenAir;
use miden_air_definitions::vm::{
    ChipletCols, CoreCols, LibraryCols,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    trace::chiplets::library::{LIBRARY_COL_RANGE, MAST, ROOT_MAST},
};
use miden_assembly::package::{
    CallableProcedurePath, NamespacePath, PackageCallables, PackageSymbols, ProcedureName,
};
use miden_core::{
    Felt,
    field::QuadFelt,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, ExecNodeBuilder, JoinNodeBuilder, MastForest,
        MastNodeExt,
    },
    operations::{Operation, opcodes},
    program::{CanonicalLabel, ImplementationRoot, Namespace},
    utils::{Matrix, RowMajorMatrix},
};
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, StackInputs};
use miden_stark::{
    air::BaseAir,
    lookup::{Challenges, build_lookup_fractions},
};
use miden_utils_testing::librarytree::{FixtureEnvironment, fixture_code, fixture_entry_digest};

use super::{ReproTrace, core_row_mut};

/// Captures a valid root syscall, then forges its supplier from an authenticated child occurrence
/// with the same local label and implementation.
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
    let root_sys = CallNodeBuilder::new_syscall(root_key).add_to_forest(&mut forest).unwrap();
    let entry = JoinNodeBuilder::new([exec, root_sys]).add_to_forest(&mut forest).unwrap();
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
    let supplier = |kind, key| {
        unique(
            (1..honest.chiplets.height()).step_by(2).filter(|&row| {
                let cols = chiplet_row(&honest.chiplets, row);
                let binding = cols.library();
                let supplied = if kind == ROOT_MAST { binding.y } else { binding.z };
                cols.chiplet_selectors()[0] == Felt::ONE && binding.k == kind && supplied == key
            }),
            "Library Mast B binding",
        )
    };
    let root_row = supplier(ROOT_MAST, root_key.into_word().into_elements());
    let child_row = supplier(MAST, child_key.into_word().into_elements());
    let mut root = chiplet_row(&honest.chiplets, root_row).library().clone();
    let mut child = chiplet_row(&honest.chiplets, child_row).library().clone();
    assert_eq!(root.x, Namespace::initial().into_word().into_elements());
    assert_ne!(child.x, root.x);
    assert_eq!(root.y, child.y);
    assert_eq!(root.w, child.w);
    assert_eq!(root.w, implementation.into_word().into_elements());
    assert_eq!((root.a, root.b), (Felt::ZERO, Felt::ONE));
    assert_eq!((child.a, child.b), (Felt::ONE, Felt::ZERO));

    // The A headers still open their original leaves under their original namespaces. RootMast
    // B does not hash its key, so it can carry the child's namespace in x without changing any
    // lookup. Move the ordinary hashed response to the old root B to preserve the normal demand
    // and its compression request. Keep each pair's original depth.
    library_row_mut(&mut forged.chiplets, root_row - 1).k = MAST;
    let child_header = library_row_mut(&mut forged.chiplets, child_row - 1);
    child_header.k = ROOT_MAST;
    child_header.a = Felt::ZERO;
    child_header.b = Felt::ZERO;
    root.x = child.x;
    core::mem::swap(&mut root.d, &mut child.d);
    *library_row_mut(&mut forged.chiplets, root_row) = child;
    *library_row_mut(&mut forged.chiplets, child_row) = root;

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

fn library_row_mut(matrix: &mut RowMajorMatrix<Felt>, row: usize) -> &mut LibraryCols<Felt> {
    let width = matrix.width();
    matrix.values[row * width..(row + 1) * width][LIBRARY_COL_RANGE].borrow_mut()
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
