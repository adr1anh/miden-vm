// MAST ROOT CALLS
// ================================================================================================
use super::*;
use crate::testing::{FixtureNamespace, FixtureProgram};

#[test]
fn program_with_incorrect_mast_root_length() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin call.0x1234 end");

    let err = context
        .assemble(source)
        .expect_err("expected incorrect MAST root length to be rejected");
    assert_diagnostic!(&err, "invalid procedure key literal");
    assert_diagnostic!(&err, "begin call.0x1234 end");
}

#[test]
fn program_with_invalid_mast_root_chars() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "begin call.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a21xyzb end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected invalid MAST root chars to be rejected");
    assert_diagnostic!(&err, "invalid literal: expected 2, 4, 8, 16, or 64 hex digits");
    assert_diagnostic!(&err, "xyzb");
}

#[test]
fn program_with_invalid_mast_digest_call() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "begin call.0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected invalid MAST digest call to be rejected");
    assert_diagnostic!(&err, "invalid literal: value overflowed the field modulus");
    assert_diagnostic!(
        &err,
        "call.0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
}

#[test]
fn program_with_phantom_mast_call() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "begin call.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae end"
    );
    let ast = context.parse_program(source)?;

    let mut fixture = FixtureNamespace::assembly_tests();
    fixture.add_module(&ast)?;
    let assembler = fixture.configure(Assembler::new(context.source_manager()), [&*ast])?;
    let program = assembler.assemble_program("test", ast)?.fixture_program();
    let targets = program
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Call(call) => {
                assert!(!call.is_syscall());
                assert!(!call.has_children());
                Some(call.target())
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        vec![miden_core::program::ProcedureKey::new(
            Word::parse("0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae")
                .unwrap()
        )],
    );
    Ok(())
}
