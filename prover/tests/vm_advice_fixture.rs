#![cfg(feature = "std")]

#[path = "common/named_source.rs"]
mod named_source;

use miden_core::{
    program::{ExecutionClaim, StackInputs, StackOutputs},
    proof::HashFunction,
};

/// Explicit maintenance for the native descriptor-based Eidos v3 fixture. Standard tests consume
/// the checked-in proof and its independently selected, canonical 40-felt expected claim.
#[test]
#[ignore = "set MIDEN_VM_FIXTURE_OUTPUT_DIR to regenerate fixtures outside the source tree"]
fn regenerate_vm_eidos_v3_advice_fixture() {
    use miden_core::serde::Serializable;

    let directory = std::path::PathBuf::from(
        std::env::var_os("MIDEN_VM_FIXTURE_OUTPUT_DIR")
            .expect("set MIDEN_VM_FIXTURE_OUTPUT_DIR to an output directory"),
    );
    std::fs::create_dir_all(&directory).unwrap();
    rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap().install(|| {
        let (program, environment) = named_source::named_source("begin push.5 push.8 add drop end");
        // The fixture owner selects the expected statement from the named environment and the
        // source's known zero I/O. Neither the proof nor a program implementation root chooses it.
        let expected_claim = ExecutionClaim::new(
            environment.execution().descriptor(),
            StackInputs::default(),
            StackOutputs::default(),
        );
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
        assert_eq!(witness.claim(), expected_claim);
        let (vm, _) = witness.into_parts();
        let trace =
            miden_processor::trace::build_trace(vm, &miden_vm_stark::memory::default_budget())
                .unwrap();
        let proof = miden_vm_stark::prover::prove(trace, HashFunction::Eidos, false).unwrap();
        miden_vm_stark::verifier::verify(&expected_claim, &proof)
            .expect("new native fixture must verify against its owner's expected claim");
        std::fs::write(directory.join("vm_eidos_v3.bin"), proof.to_bytes()).unwrap();
        let claim_bytes = expected_claim.to_elements().to_bytes();
        assert_eq!(claim_bytes.len(), 40 * 8, "claim metadata has no transport header");
        std::fs::write(directory.join("vm_eidos_v3.claim"), claim_bytes).unwrap();
    });
}
