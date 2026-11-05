// PROGRAM WITH PROCREF
// ================================================================================================

use super::*;
use crate::testing::FixtureNamespace;

#[test]
fn procref_call() -> TestResult {
    let mut context = TestContext::default();
    let mut fixture = FixtureNamespace::assembly_tests();
    // compile first module
    let module_one = context.parse_module(source_file!(
        &context,
        "
        namespace module::path::one

        pub proc aaa
            push.7.8
        end

        pub proc foo
            push.1.2
        end"
    ))?;
    fixture.add_module(&module_one)?;
    let aaa_key = fixture.binding(&module_one.path().join("aaa")).unwrap().key();
    let foo_key = fixture.binding(&module_one.path().join("foo")).unwrap().key();
    context.add_module(module_one)?;

    // compile second module
    let module_two = context.parse_module(source_file!(
        &context,
        "
        namespace module::path::two

        use module::path::one
        pub use {foo} from module::path::one

        pub proc bar
            procref.one::aaa
        end"
    ))?;
    fixture.add_module(&module_two)?;
    let bar_key = fixture.binding(&module_two.path().join("bar")).unwrap().key();
    assert!(fixture.binding(&module_two.path().join("foo")).is_none());
    context.add_module(module_two)?;

    // compile program with procref calls
    let source = source_file!(
        &context,
        "
        use module::path::two

        @locals(4)
        proc baz
            push.3.4
        end

        begin
            procref.two::bar
            procref.two::foo
            procref.baz
        end"
    );
    let module = context.parse_program(source.clone())?;
    fixture.add_module(&module)?;
    let baz_key = fixture.binding(&module.path().join("baz")).unwrap().key();
    let program = context.assemble(source)?;

    // The re-export uses the concrete definition's key, preserving procref's stack ordering.
    let mut expected = fmp_initialization_sequence();
    for key in [bar_key, foo_key, baz_key] {
        expected.extend(key.as_word().iter().rev().copied().map(Operation::Push));
    }
    let main_ops = program.mast_forest()[program.entrypoint()]
        .unwrap_basic_block()
        .operations()
        .filter(|op| **op != Operation::Noop)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(main_ops, expected);
    let aaa_ref = aaa_key.as_word().iter().rev().copied().map(Operation::Push).collect::<Vec<_>>();
    assert!(program.mast_forest().procedure_roots().iter().any(|root| {
        program.mast_forest()[*root].get_basic_block().is_some_and(|block| {
            block
                .operations()
                .filter(|op| **op != Operation::Noop)
                .copied()
                .collect::<Vec<_>>()
                == aaa_ref
        })
    }));
    assert_eq!(program.num_procedures(), 5);
    assert_all_nodes_reachable_from_roots(program.mast_forest());
    Ok(())
}

#[test]
fn get_proc_name_of_unknown_module() -> TestResult {
    let context = TestContext::default();
    // Module `two` is unknown, our error should identify that it is undefined
    let module_source1 = source_file!(
        &context,
        "
    namespace module::path::one

    use module::path::two

    pub proc foo
        procref.two::bar
    end"
    );
    let module1 = context.parse_module(module_source1)?;

    let report = Assembler::new(context.source_manager())
        .assemble_library("test", module1, None::<Box<Module>>)
        .expect_err("expected unknown module error");

    assert_diagnostic!(&report, "undefined item 'module::path::two'");
    assert_diagnostic!(&report, "use module::path::two");
    assert_diagnostic!(&report, "you might be missing an import");

    Ok(())
}
