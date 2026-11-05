use miden_assembly::Assembler;
use miden_processor::{ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs};
use miden_utils_testing::librarytree::assemble_fixture_program;

use super::TestHost;

#[test]
fn test_event_handling() {
    let source = "\
    begin
        push.1000
        emit
        drop
        push.2000
        emit
        drop
        swapw dropw
    end";

    // compile and execute program
    let mut host = TestHost::default();
    let named = assemble_fixture_program(
        Assembler::new(host.source_manager.clone()),
        "program",
        source,
        &[],
    );
    host = host.with_environment_source(named.environment.source());
    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("failed to construct FastProcessor")
    .execute_sync(&named.program, named.environment.execution(), &mut host)
    .unwrap();

    // make sure events were handled correctly
    let expected = vec![1000, 2000];
    assert_eq!(host.event_handler, expected);
}
