/// Test case for issue #2456: statically linked library calls should preserve valid MAST
/// structure when copying nodes between forests.
use miden_assembly::{
    Assembler,
    ast::{Module, ModuleKind},
    testing::FixtureNamespace,
};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
};
use miden_utils_testing::librarytree::FixtureEnvironment;

#[test]
fn test_issue_2456_statically_linked_library_call() {
    use std::sync::Arc;

    use miden_assembly::DefaultSourceManager;

    let test_module_source = "
        namespace test::module_1

        pub proc foo
            push.3.4
            add
            swapw dropw
        end
    ";

    let source_manager = Arc::new(DefaultSourceManager::default());
    let library_module = Module::parser(Some(ModuleKind::Library))
        .parse_str(None, test_module_source, source_manager.clone())
        .unwrap();
    let mut names = FixtureNamespace::assembly_tests();
    names.add_module(&library_module).unwrap();
    let assembler = names
        .configure(Assembler::new(source_manager.clone()), [library_module.as_ref()])
        .unwrap();

    let product = assembler
        .assemble_library_modules(
            "library".into(),
            library_module,
            [],
            miden_mast_package::TargetType::Library,
        )
        .unwrap();
    let library_naming = product.naming().clone();
    let library = Arc::from(product.into_artifact(true).unwrap());

    // This program calls a procedure from a statically linked library.
    let source = "
        use test::module_1

        begin
            push.1.2
            call.module_1::foo
            dropw dropw dropw dropw
        end
    ";

    let mut assembler = Assembler::new(source_manager.clone());
    assembler
        .link_package(library, miden_assembly::Linkage::Static, library_naming.clone())
        .unwrap();
    let root = Module::parser(Some(ModuleKind::Executable))
        .parse_str(None, source, source_manager)
        .unwrap();
    let mut names = FixtureNamespace::assembly_tests();
    names.add_module(&root).unwrap();
    let assembler = names.configure(assembler, [root.as_ref()]).unwrap();
    let product = assembler.assemble_executable_modules("program".into(), root, []).unwrap();
    let naming = product.naming().clone();
    let package = product.into_artifact(true).unwrap();
    let program = package.try_into_program(&naming).unwrap();
    let environment =
        FixtureEnvironment::new(naming.entry_key().unwrap(), [&naming, &library_naming]).unwrap();

    // Execute the program. This should succeed after static linking.
    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default().with_environment_source(environment.source());
    let options = ExecutionOptions::default();

    let result = FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
        .expect("failed to construct FastProcessor")
        .execute_sync(&program, environment.execution(), &mut host);
    assert!(result.is_ok(), "Execution should succeed but got error: {:?}", result.err());
}
