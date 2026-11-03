use alloc::vec::Vec;

use miden_air_definitions::vm::PublicInputs;
use miden_core::{
    deferred::TRUE_DIGEST,
    mast::{BasicBlockNodeBuilder, MastForest, MastNode},
    operations::Operation,
    program::{CanonicalLabel, Program},
};
use miden_mast_package::{CallableBinding, CallableProcedurePath, NamespacePlan};

use super::VmTrace;
use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, Felt, StackInputs,
    test_utils::{NamedFixture, named_program, native_trace_limits},
    trace::build_trace,
};

mod chiplets;
mod decoder;
mod lookup;
mod lookup_harness;
mod range;
mod stack;

/// Size of trace fragments used in tests.
///
/// We make it relatively small to speed up the tests and reduce memory usage.
const TEST_TRACE_FRAGMENT_SIZE: usize = 1 << 10;

// TEST HELPERS
// ================================================================================================

/// Selects an independent child-home entry for a pure control/arithmetic forest. Runtime
/// invocation fixtures must supply their complete named inventory through build_trace_from_fixture.
fn pure_trace_fixture(program: Program) -> NamedFixture {
    assert!(
        program.mast_forest().nodes().iter().all(|node| {
            !matches!(node, MastNode::Call(_) | MastNode::Exec(_) | MastNode::Dyn(_))
        }),
        "invocation fixtures require explicit target names and openings"
    );
    trace_named_program(program, [])
}

pub(super) fn trace_binding(name: &str) -> CallableBinding {
    CallableBinding::new(
        NamespacePlan::new(vec![CanonicalLabel::text("processor-trace-fixtures").unwrap()]),
        CallableProcedurePath::from_semantic_components(vec![name.into()]).unwrap(),
    )
    .unwrap()
}

pub(super) fn trace_named_program(
    program: Program,
    targets: impl IntoIterator<Item = (CallableBinding, miden_core::program::ImplementationRoot)>,
) -> NamedFixture {
    named_program(program, trace_binding("entry"), targets).unwrap()
}

/// Builds a trace for a pure forest using this test helper's explicit entry convention.
pub fn build_trace_from_program(program: &Program, stack_inputs: &[u64]) -> VmTrace {
    build_trace_from_fixture(&pure_trace_fixture(program.clone()), stack_inputs)
}

pub fn build_trace_from_fixture(fixture: &NamedFixture, stack_inputs: &[u64]) -> VmTrace {
    let stack = stack_inputs.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<_>>();
    build_trace_from_fixture_with_stack(fixture, StackInputs::new(&stack).unwrap())
}

pub fn build_trace_from_fixture_with_stack(
    fixture: &NamedFixture,
    stack_inputs: StackInputs,
) -> VmTrace {
    let mut host = DefaultHost::default().with_environment_source(fixture.source.clone());
    let processor = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_environment_trace_limits(native_trace_limits())
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");
    let execution_witness = processor
        .execute_for_proving_sync(&fixture.program, fixture.environment, &mut host)
        .unwrap();
    let (vm_witness, _) = execution_witness.into_parts();
    build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap()
}

/// Builds a sample trace by executing a span block containing the specified operations. This
/// results in 1 additional hash cycle (8 rows) at the beginning of the hash chiplet.
pub fn build_trace_from_ops(operations: Vec<Operation>, stack: &[u64]) -> VmTrace {
    let mut mast_forest = MastForest::new();

    let basic_block_id =
        BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);

    build_trace_from_program(&program, stack)
}

/// Builds a sample trace by executing a span block containing the specified operations. Unlike
/// [`build_trace_from_ops`], this variant accepts the full [`AdviceInputs`] object, so the
/// program can run against an initialised advice provider (e.g. to seed a Merkle tree for the
/// sibling-table tests).
pub fn build_trace_from_ops_with_inputs(
    operations: Vec<Operation>,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
) -> VmTrace {
    let mut mast_forest = MastForest::new();
    let basic_block_id =
        BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
    mast_forest.make_root(basic_block_id);

    let program = Program::new(mast_forest.into(), basic_block_id);
    let fixture = pure_trace_fixture(program.clone());
    let mut host = DefaultHost::default().with_environment_source(fixture.source.clone());
    let processor = FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs,
        ExecutionOptions::default()
            .with_environment_trace_limits(native_trace_limits())
            .with_core_trace_fragment_size(TEST_TRACE_FRAGMENT_SIZE)
            .unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");
    let execution_witness = processor
        .execute_for_proving_sync(&program, fixture.environment, &mut host)
        .unwrap();
    let (vm_witness, _) = execution_witness.into_parts();
    build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap()
}

#[test]
fn non_empty_execution_witness_splits_with_matching_precompile_root() {
    let mut mast_forest = MastForest::new();
    let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::LogDeferred])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);
    let program = Program::new(mast_forest.into(), basic_block_id);
    let stack_inputs =
        StackInputs::new(&[0, 0, 0, 0, 1, 2, 3, 4].map(Felt::new_unchecked)).unwrap();

    let fixture = pure_trace_fixture(program.clone());
    let mut host = DefaultHost::default().with_environment_source(fixture.source.clone());
    let execution_witness = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default().with_environment_trace_limits(native_trace_limits()),
    )
    .unwrap()
    .execute_for_proving_sync(&program, fixture.environment, &mut host)
    .unwrap();
    let claim = execution_witness.claim();
    let (vm_witness, precompile_witness) = execution_witness.into_parts();
    let precompile_root = vm_witness.precompile_root;
    assert_ne!(precompile_root, TRUE_DIGEST);

    let precompile_witness = precompile_witness.expect("logged statement must be retained");
    assert_eq!(vm_witness.claim(), claim);
    let output = FastProcessor::new(stack_inputs)
        .execute_sync(&program, fixture.environment, &mut host)
        .unwrap();
    assert_eq!(output.precompile_root(), precompile_root);
    assert_eq!(output.precompile_witness.as_ref(), Some(&precompile_witness));

    let trace = build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
    assert_eq!(trace.precompile_root(), precompile_root);
}

#[test]
fn empty_execution_witness_splits_and_replays_with_explicit_stack_inputs() {
    let mut mast_forest = MastForest::new();
    let basic_block_id = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut mast_forest)
        .unwrap();
    mast_forest.make_root(basic_block_id);
    let program = Program::new(mast_forest.into(), basic_block_id);
    let stack_inputs = StackInputs::new(&[7, 9].map(Felt::new_unchecked)).unwrap();

    let fixture = pure_trace_fixture(program.clone());
    let mut host = DefaultHost::default().with_environment_source(fixture.source.clone());
    let execution_witness = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default().with_environment_trace_limits(native_trace_limits()),
    )
    .unwrap()
    .execute_for_proving_sync(&program, fixture.environment, &mut host)
    .unwrap();

    let claim = execution_witness.claim();
    assert_eq!(claim.to_program_info(), program.to_info());
    assert_eq!(claim.stack_inputs(), &stack_inputs);
    let expected_public_inputs = PublicInputs::new(
        claim.to_program_info(),
        *claim.stack_inputs(),
        *claim.stack_outputs(),
        TRUE_DIGEST,
    );

    let (vm_witness, precompile_witness) = execution_witness.into_parts();
    assert_eq!(vm_witness.claim(), claim);
    assert_eq!(vm_witness.precompile_root, TRUE_DIGEST);
    assert!(precompile_witness.is_none());
    let output = FastProcessor::new(stack_inputs)
        .execute_sync(&program, fixture.environment, &mut host)
        .unwrap();
    assert_eq!(output.precompile_root(), TRUE_DIGEST);
    assert!(output.precompile_witness.is_none());

    let trace = build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
    assert_eq!(trace.init_stack_state(), stack_inputs);
    assert_eq!(trace.precompile_root(), TRUE_DIGEST);
    assert_eq!(trace.to_public_values(), expected_public_inputs.to_elements());
}
