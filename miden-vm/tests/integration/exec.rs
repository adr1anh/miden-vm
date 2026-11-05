use alloc::sync::Arc;
use core::assert_matches;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{ONE, Word, advice::AdviceMap};
use miden_processor::{
    ExecutionOptions, FastProcessor, StackInputs,
    advice::{AdviceError, AdviceInputs},
};
use miden_utils_testing::librarytree::assemble_fixture_program;
use miden_vm::DefaultHost;

#[test]
fn advice_map_loaded_before_execution() {
    let source = "\
    begin
        push.1.1.1.1
        adv.push_mapval
        dropw
    end";

    // compile and execute program
    let source_manager = Arc::new(DefaultSourceManager::default());
    let named =
        assemble_fixture_program(Assembler::new(source_manager.clone()), "program", source, &[]);
    let program_without_advice_map = named.0;

    // Test `FastProcessor::execute_sync` fails if no advice map provided with the program
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager.clone())
        .with_environment_source(named.1.source());
    host.load_library(program_without_advice_map.clone()).unwrap();
    match FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_resolution_limits(named.1.resolution_limits()),
    )
    .expect("failed to construct FastProcessor")
    .execute_sync(named.1.target(), &mut host)
    {
        Ok(_) => panic!("Expected error"),
        Err(e) => {
            assert_matches!(
                e,
                miden_processor::ExecutionError::AdviceError {
                    err: AdviceError::MapKeyNotFound { .. },
                    ..
                }
            );
        },
    }

    // Test `FastProcessor::execute_sync` works if advice map provided with the program
    let key = Word::new([ONE, ONE, ONE, ONE]);
    let value = vec![ONE, ONE];

    let package = program_without_advice_map
        .package()
        .as_ref()
        .clone()
        .with_advice_map(AdviceMap::from_iter([(key, value)]));
    let program_with_advice_map = miden_mast_package::CodePackage::new(
        Arc::new(package),
        program_without_advice_map.symbols().clone(),
    )
    .unwrap();

    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_environment_source(named.1.source());
    host.load_library(program_with_advice_map).unwrap();
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_resolution_limits(named.1.resolution_limits()),
    )
    .expect("failed to construct FastProcessor")
    .execute_sync(named.1.target(), &mut host)
    .unwrap();
}

#[cfg(feature = "internal")]
#[test]
fn canonical_deferred_ecdsa4_keccak100_example_executes() {
    use std::path::PathBuf;

    use miden_assembly::Linkage;
    use miden_core::{Felt, Word, crypto::hash::Eidos};
    use miden_core_lib::CoreLibrary;
    use miden_vm::internal::InputFile;

    let program_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("masm-examples/precompiles/deferred_ecdsa4_keccak100")
        .join("deferred_ecdsa4_keccak100.masm");
    let source = std::fs::read_to_string(&program_path).expect("example source must be readable");
    let inputs = InputFile::read(&None, &program_path).expect("example inputs must be readable");
    let advice_values = inputs
        .advice_stack
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|value| {
            let value = value.parse::<u64>().expect("advice-stack value must be a u64");
            Felt::new(value).expect("advice-stack value must be canonical")
        })
        .collect::<Vec<_>>();
    let (fixtures, remainder) = advice_values.as_chunks::<40>();
    assert!(remainder.is_empty(), "ECDSA fixtures must contain 40 Felts each");
    let (stored_commitments, derived_commitments): (Vec<_>, Vec<_>) = fixtures
        .iter()
        .map(|fixture| {
            let stored = Word::new(fixture[4..8].try_into().expect("commitment is one word"));
            let derived = Eidos::hash_elements(&fixture[8..24]);
            (stored, derived)
        })
        .unzip();
    assert_eq!(
        stored_commitments, derived_commitments,
        "ECDSA fixture commitments must match their public-key limbs"
    );
    let stack_values = inputs
        .operand_stack
        .iter()
        .map(|value| {
            let value = value.parse::<u64>().expect("operand-stack value must be a u64");
            Felt::new(value).expect("operand-stack value must be canonical")
        })
        .collect::<Vec<_>>();
    let stack_inputs = StackInputs::new(&stack_values).expect("example stack inputs must fit");
    let advice_inputs = inputs.parse_advice_inputs().expect("example advice must be valid");

    let core_lib = CoreLibrary::default();
    let source_manager = Arc::new(DefaultSourceManager::default());
    let named = assemble_fixture_program(
        Assembler::new(source_manager.clone())
            .with_package(core_lib.code_package().clone(), Linkage::Dynamic)
            .expect("core library must link"),
        "deferred_ecdsa4_keccak100",
        source,
        &[core_lib.naming().as_ref()],
    );
    let mut host = DefaultHost::default()
        .with_source_manager(source_manager)
        .with_environment_source(named.1.source())
        .with_library(&core_lib)
        .expect("core library must load into the host");

    host.load_library(named.0.clone()).unwrap();
    FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs,
        ExecutionOptions::default().with_resolution_limits(named.1.resolution_limits()),
    )
    .expect("processor initialization must succeed")
    .execute_sync(named.1.target(), &mut host)
    .expect("canonical deferred ECDSA/Keccak example must execute");
}
