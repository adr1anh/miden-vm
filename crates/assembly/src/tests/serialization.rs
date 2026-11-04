// EXECUTABLE PACKAGE SERIALIZATION AND SYMBOL ADMISSION
// ================================================================================================
use super::*;
use crate::testing::{FixtureNamespace, FixtureProgram, fixture_package_naming};

#[test]
fn test_executable_package_serde_simple() {
    let source = "
    begin
        push.1.2
        add
        drop
    end
    ";

    let context = TestContext::default();
    let module = context.parse_module(source).unwrap();
    let mut fixture_namespace = FixtureNamespace::assembly_tests();
    fixture_namespace.add_module(&module).unwrap();
    let assembler = fixture_namespace
        .configure(Assembler::new(context.source_manager()), [&*module])
        .unwrap();
    let original_code = assembler.assemble_program("test", module).unwrap().fixture_program();

    let mut target = Vec::new();
    original_code.package().write_into(&mut target);
    let deserialized_package = Package::read_from_bytes(&target).unwrap();
    let symbols = fixture_package_naming(&deserialized_package).unwrap();
    deserialized_package.check_executable_code(&symbols).unwrap();
    let deserialized_code =
        CodePackage::new(Arc::new(deserialized_package), Arc::new(symbols)).unwrap();

    assert_eq!(original_code.package(), deserialized_code.package());
    assert_eq!(original_code.symbols(), deserialized_code.symbols());
    assert_eq!(entry_node(&original_code), entry_node(&deserialized_code));
    assert_eq!(render_entry(&original_code), render_entry(&deserialized_code));
}
