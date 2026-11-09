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
    let main_ops = program.package().mast_forest()[entry_node(&program)]
        .unwrap_basic_block()
        .operations()
        .filter(|op| **op != Operation::Noop)
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(main_ops, expected);
    let aaa_ref = aaa_key.as_word().iter().rev().copied().map(Operation::Push).collect::<Vec<_>>();
    assert!(program.package().mast_forest().procedure_roots().iter().any(|root| {
        program.package().mast_forest()[*root].get_basic_block().is_some_and(|block| {
            block
                .operations()
                .filter(|op| **op != Operation::Noop)
                .copied()
                .collect::<Vec<_>>()
                == aaa_ref
        })
    }));
    assert_eq!(program.package().mast_forest().num_procedures(), 5);
    assert_all_nodes_reachable_from_roots(program.package().mast_forest());
    Ok(())
}

#[test]
fn digest_and_key_invocations_lower_in_one_program() -> TestResult {
    let context = TestContext::default();
    let library = context.parse_module("namespace lib\npub proc other push.3 drop end")?;
    let (library, mut fixture) = context.assemble_library_with_fixture("lib", None, library, [])?;
    let naming = fixture.admit_package(&library)?;
    let other_key = fixture.binding(Path::new("::lib::other")).unwrap().key();
    let other_digest = naming.callables().selected_implementation(other_key).unwrap().into_word();
    let library = CodePackage::new(library.into(), naming.into()).map_err(Report::msg)?;
    let literal = Word::new([Felt::from_u32(81); 4]);
    let reference = Word::new([Felt::from_u32(82); 4]);
    let source = format!(
        "
        use lib
        proc helper push.2 drop end
        begin
            calldigest.helper
            calldigest.lib::other
            calldigest.{literal}
            procdigest.helper
            procdigest.lib::other
            procdigest.{reference}
            dynexecdigest
            dyncalldigest
            call.helper
            exec.helper
            procref.helper
            dynexec
            dyncall
        end
        "
    );
    let module = context.parse_program(source_file!(&context, source))?;
    fixture.add_module(&module)?;
    let key = fixture.binding(&module.path().join("helper")).unwrap().key();
    let assembler =
        Assembler::new(context.source_manager()).with_package(library, Linkage::Dynamic)?;
    let assembler = fixture.configure(assembler, [&*module])?;
    let code = assembler
        .assemble_executable_modules("program".into(), module, [])?
        .into_code_package(true)?;
    let implementation = code.symbols().callables().selected_implementation(key).unwrap();
    let forest = code.package().mast_forest();
    assert_ne!(key.as_word(), implementation.as_word());
    assert!(forest.nodes().iter().any(|node| matches!(
        node, MastNode::Call(call)
            if call.digest_callee().is_some_and(|callee| forest[callee].digest() == implementation.into_word())
    )));
    assert!(forest.nodes().iter().any(|node| matches!(
        node, MastNode::Call(call) if call.digest_callee().is_none() && call.target() == key
    )));
    assert_eq!(
        forest.nodes().iter().filter(|node| matches!(node, MastNode::Exec(_))).count(),
        1,
    );
    for digest in [literal, other_digest] {
        assert!(forest.nodes().iter().any(|node| matches!(
            node, MastNode::Call(call)
                if call.digest_callee().is_some_and(|callee|
                    forest[callee].is_external() && forest[callee].digest() == digest)
        )));
    }
    assert!(
        !forest
            .nodes()
            .iter()
            .any(|node| node.is_external() && node.digest() == reference)
    );
    for is_digest in [false, true] {
        for is_dyncall in [false, true] {
            assert!(forest.nodes().iter().any(|node| matches!(
                node, MastNode::Dyn(dyn_node)
                    if dyn_node.is_digest() == is_digest && dyn_node.is_dyncall() == is_dyncall
            )));
        }
    }
    for word in [*implementation.as_word(), *key.as_word(), other_digest, reference] {
        let expected = word.iter().rev().copied().map(Operation::Push).collect::<Vec<_>>();
        assert!(
            forest.nodes().iter().any(|node| {
                node.get_basic_block().is_some_and(|block| {
                    let ops = block
                        .operations()
                        .filter(|op| **op != Operation::Noop)
                        .copied()
                        .collect::<Vec<_>>();
                    ops.windows(expected.len()).any(|window| window == expected)
                })
            }),
            "expected pushes for {word}"
        );
    }
    Ok(())
}

#[test]
fn digest_edges_require_acyclic_implementation_dependencies() -> TestResult {
    let context = TestContext::default();
    for instruction in ["calldigest", "procdigest"] {
        let source = format!("proc a {instruction}.b end proc b call.a end begin call.a end");
        context.assemble(source_file!(&context, source))?;

        let source = format!("proc a {instruction}.b end proc b calldigest.a end begin call.a end");
        let error = context.assemble(source_file!(&context, source)).unwrap_err();
        assert_diagnostic!(&error, "cycle in implementation dependencies");
    }
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
