// LINK CYCLES
// ================================================================================================

use miden_core::program::CanonicalLabel;
use miden_mast_package::{CallableProcedurePath, NamespacePath};

use super::*;

fn graph_assembler(context: &TestContext, declarations: &[(&str, &[&str])]) -> Assembler {
    let mut assembler =
        Assembler::new(context.source_manager()).with_namespace_plan(NamespacePath::new(vec![
            CanonicalLabel::text("runtime-graph-tests").unwrap(),
        ]));
    for &(declaration, components) in declarations {
        let canonical = CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| (*component).to_string()).collect(),
        )
        .unwrap();
        assembler = assembler
            .with_callable_path(Arc::from(Path::new(declaration)), canonical)
            .unwrap();
    }
    assembler
}

#[test]
fn imported_main_alias_self_call_retains_runtime_reference() {
    let context = TestContext::new();
    let program = r#"
        use {"$main" as alias_main} from ::$exec

        begin
            call.alias_main
        end
    "#;
    let package = graph_assembler(&context, &[("::$exec::$main", &["entry"])])
        .assemble_program("test", program)
        .expect("an import alias may reference the caller's runtime key");
    let forest = package.mast_forest();
    assert_eq!(forest.procedure_roots().len(), 1);
    assert_eq!(
        forest.nodes().iter().filter(|node| matches!(node, MastNode::Call(_))).count(),
        1
    );
    assert_all_nodes_reachable_from_roots(forest);
}

#[test]
fn mutually_recursive_runtime_calls_compile_independent_roots() {
    let context = TestContext::new();
    let program = r#"
        begin
            call.b
        end

        proc b
            exec."$main"
        end
    "#;
    let package = graph_assembler(
        &context,
        &[("::$exec::$main", &["entry"]), ("::$exec::b", &["helpers", "b"])],
    )
    .assemble_program("test", program)
    .expect("keyed runtime cycles do not form structural MAST cycles");
    let forest = package.mast_forest();
    assert_eq!(forest.procedure_roots().len(), 2);
    assert_eq!(
        forest.nodes().iter().filter(|node| matches!(node, MastNode::Call(_))).count(),
        1
    );
    assert_eq!(
        forest.nodes().iter().filter(|node| matches!(node, MastNode::Exec(_))).count(),
        1
    );
    assert_all_nodes_reachable_from_roots(forest);
}

#[test]
fn recursive_runtime_link_can_be_repeated() {
    use crate::linker::Linker;

    let context = TestContext::new();
    let module = context
        .parse_program(source_file!(
            &context,
            r#"
                begin
                    call.b
                end

                proc b
                    call."$main"
                end
            "#
        ))
        .expect("program parsing must succeed");
    let mut linker = Linker::new(context.source_manager());
    let module_index = linker.link([module], []).expect("runtime recursion must link")[0];
    let roots = linker[module_index]
        .symbols()
        .enumerate()
        .map(|(index, _)| module_index + crate::ast::ItemIndex::new(index))
        .collect::<Vec<_>>();
    let reachable = linker.runtime_reachable_from([roots[0]]);
    assert_eq!(reachable, roots);
    linker
        .link([], [])
        .expect("repeated linking must accept committed runtime recursion");
    assert_eq!(linker.runtime_reachable_from([roots[0]]), reachable);
}

#[test]
fn public_helpers_and_address_taken_roots_survive_retention() {
    let context = TestContext::new();
    let source = r#"
        namespace roots

        pub proc entry
            procref.callback
        end

        proc callback
            push.11
        end

        proc computed_helper
            push.22
        end

        pub proc public_unused
            push.33
        end

        proc unselected
            push.44
        end
    "#;
    let package = graph_assembler(
        &context,
        &[
            ("::roots::entry", &["entry"]),
            ("::roots::callback", &["helpers", "callback"]),
            ("::roots::computed_helper", &["helpers", "computed"]),
            ("::roots::public_unused", &["public_unused"]),
        ],
    )
    .assemble_library("roots", source, core::iter::empty::<&str>())
    .expect("explicit helper roots must be retained without a direct runtime reference");
    let forest = package.mast_forest();
    assert_eq!(forest.procedure_roots().len(), 4);
    let pushed = forest
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Block(block) => Some(block),
            _ => None,
        })
        .flat_map(miden_core::mast::BasicBlockNode::operations)
        .filter_map(|op| match op {
            Operation::Push(value) => Some(value.as_canonical_u64()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for retained in [11, 22, 33] {
        assert!(pushed.contains(&retained));
    }
    assert!(
        !pushed.contains(&44),
        "unselected private code must not become a retention root"
    );
    assert_all_nodes_reachable_from_roots(forest);
}

#[test]
fn private_only_library_retains_selected_callable_without_manufacturing_export() {
    let context = TestContext::new();
    let package =
        graph_assembler(&context, &[("::private_only::computed_helper", &["helpers", "computed"])])
            .assemble_library(
                "private-only",
                "namespace private_only\nproc computed_helper push.55 end",
                core::iter::empty::<&str>(),
            )
            .expect("a selected private callable does not require an exported procedure");
    assert_eq!(package.manifest.exports().count(), 0);
    let forest = package.mast_forest();
    assert_eq!(forest.procedure_roots().len(), 1);
    let MastNode::Block(body) = &forest[forest.procedure_roots()[0]] else {
        panic!("the selected helper body must remain independently callable");
    };
    assert!(
        body.operations()
            .any(|op| matches!(op, Operation::Push(value) if *value == Felt::from_u32(55)))
    );
    assert_all_nodes_reachable_from_roots(forest);
}

#[test]
fn test_cross_module_constant_cycle_in_procedure_scope_is_structured_error() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();

    let a = parse_module!(
        &context,
        r#"
            namespace cycle::a

            use cycle::b

            pub proc use_cycle
                push.A
                drop
            end

            pub const A = b::B + 1
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace cycle::b

            use cycle::a
            pub const B = a::A + 1
        "#
    );

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_library("cycle", a, [b])
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled.unwrap().expect_err("expected cyclic constants to be rejected");
    assert_diagnostic!(&err, "constant evaluation terminated due to infinite recursion");
    assert_diagnostic!(&err, "pub const A = b::B + 1");
    assert_diagnostic!(&err, "pub const B = a::A + 1");
}

#[test]
fn imported_error_message_cycle_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();

    let a = parse_module!(
        &context,
        r#"
            namespace cycle::errs::a

            use cycle::errs::b

            pub proc use_cycle
                assert.err=ERR_A
            end

            pub const ERR_A = b::ERR_B
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace cycle::errs::b

            use cycle::errs::a
            pub const ERR_B = a::ERR_A
        "#
    );

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_library("cycle", a, [b])
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled
        .unwrap()
        .expect_err("expected cyclic error message constants to be rejected");
    assert_diagnostic!(&err, "constant evaluation terminated due to infinite recursion");
    assert_diagnostic!(&err, "pub const ERR_A = b::ERR_B");
    assert_diagnostic!(&err, "pub const ERR_B = a::ERR_A");
}
