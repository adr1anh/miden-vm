// PROGRAM SERIALIZATION AND DESERIALIZATION
// ================================================================================================

use super::*;
use crate::testing::FixtureNamespace;

#[test]
fn test_program_serde_simple() {
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
    let original_program = assembler.assemble_program("test", module).unwrap().unwrap_program();

    let mut target = Vec::new();
    original_program.write_into(&mut target);
    let deserialized_program = Program::read_from_bytes(&target).unwrap();

    assert_eq!(original_program, deserialized_program);
}
