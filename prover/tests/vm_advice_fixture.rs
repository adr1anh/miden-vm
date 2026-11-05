#![cfg(feature = "std")]

#[path = "common/named_source.rs"]
mod named_source;

use miden_core::{
    program::{KernelDescriptor, StackInputs, StackOutputs},
    proof::HashFunction,
};

/// Explicit fixture maintenance; standard tests consume the checked-in proof instead.
#[test]
#[ignore = "set MIDEN_VM_FIXTURE_OUTPUT_DIR to regenerate fixtures outside the source tree"]
fn regenerate_vm_advice_fixture() {
    use miden_core::serde::Serializable;

    let directory = std::path::PathBuf::from(
        std::env::var_os("MIDEN_VM_FIXTURE_OUTPUT_DIR")
            .expect("set MIDEN_VM_FIXTURE_OUTPUT_DIR to an output directory"),
    );
    std::fs::create_dir_all(&directory).unwrap();
    rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| {
        let (program, environment) = named_source::named_source("begin push.5 push.8 add drop end");
        let mut host =
            miden_processor::DefaultHost::default().with_environment_source(environment.source());
        let witness =
            miden_processor::FastProcessor::new(StackInputs::default())
                .with_options(
                    miden_processor::ExecutionOptions::default().with_environment_trace_limits(
                        miden_utils_testing::librarytree::trace_limits(),
                    ),
                )
                .unwrap()
                .execute_for_proving_sync(&program, environment.execution(), &mut host)
                .unwrap();
        let claim = witness.claim();
        assert_eq!(*claim.kernel(), KernelDescriptor::default());
        assert_eq!(*claim.stack_inputs(), StackInputs::default());
        assert_eq!(*claim.stack_outputs(), StackOutputs::default());
        let (vm, _) = witness.into_parts();
        let trace =
            miden_processor::trace::build_trace(vm, &miden_vm_stark::memory::default_budget())
                .unwrap();
        let proof = miden_vm_stark::prover::prove(trace, HashFunction::Eidos, false).unwrap();
        std::fs::write(directory.join("vm_eidos_v1_0.bin"), proof.to_bytes()).unwrap();
        std::fs::write(directory.join("vm_eidos_v1_0.program"), claim.program_root().to_bytes())
            .unwrap();
    });
}
