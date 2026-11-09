use alloc::{format, sync::Arc, vec};

use miden_assembly::{
    Assembler, DefaultSourceManager, Path,
    ast::{Module, ModuleKind},
};
use miden_core::{
    mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
    operations::Operation,
};

use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, ExecutionWitness, FastProcessor, ReplayReadLimits,
    StackInputs,
    test_utils::{named_module, native_trace_limits},
    trace::build_trace,
};

#[test]
fn digest_dyncall_replays_code_loaded_by_digest_only() {
    let mut callee = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::Caller])
        .add_to_forest(&mut callee)
        .unwrap();
    callee.make_root(root);
    let digest = callee[root].digest();
    let [a, b, c, d] = digest.into_elements().map(|element| element.as_canonical_u64());
    let source =
        format!("begin push.[{a},{b},{c},{d}] mem_storew_le.40 dropw push.40 dyncalldigest end");
    let manager = Arc::new(DefaultSourceManager::default());
    let module = Module::parser(Some(ModuleKind::Executable))
        .parse_str(Some(Path::exec_path()), &source, manager.clone())
        .unwrap();
    let fixture = named_module(Assembler::new(manager), module, []).unwrap();
    assert!(fixture.package.mast_forest().find_procedure_root(digest).is_none());

    let mut host = DefaultHost::default()
        .with_environment_source(fixture.source)
        .with_library(fixture.code)
        .unwrap();
    // Supply the target body without a procedure name or environment binding.
    host.mast_forest_store_mut().insert(Arc::new(callee));
    let trace_limits = native_trace_limits();
    let witness = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default()
            .with_resolution_limits(fixture.resolution_limits)
            .with_environment_trace_limits(trace_limits),
    )
    .unwrap()
    .execute_for_proving_sync(fixture.target, &mut host)
    .unwrap();
    let claim = witness.claim();
    assert_eq!(claim.stack_outputs().get_word(0), Some(digest));

    let read_limits = ReplayReadLimits {
        max_wire_bytes: 1 << 20,
        max_validation_peak_bytes: 1 << 20,
    };
    let bytes = witness.to_bytes_with_limits(trace_limits, read_limits).unwrap();
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        fixture.target,
        fixture.resolution_limits,
        trace_limits,
        read_limits,
    )
    .unwrap();
    assert_eq!(restored.claim(), claim);
    let (vm_witness, _) = restored.into_parts();
    build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
}
