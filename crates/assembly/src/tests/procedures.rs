// PROGRAMS WITH PROCEDURES
// ================================================================================================

use miden_core::{mast::MastNodeId, program::ProcedureKey};

use super::*;
use crate::testing::FixtureNamespace;

#[derive(Debug, PartialEq, Eq)]
enum ProcedureBodyItem {
    Op(Operation),
    Exec(ProcedureKey),
}

/// Inspect each independent callable body; the program display only follows the entrypoint.
fn procedure_body(program: &CodePackage, root: MastNodeId) -> Vec<ProcedureBodyItem> {
    match &program.package().mast_forest()[root] {
        MastNode::Block(block) => block
            .operations()
            .filter(|op| **op != Operation::Noop)
            .copied()
            .map(ProcedureBodyItem::Op)
            .collect(),
        MastNode::Join(join) => {
            let mut body = procedure_body(program, join.first());
            body.extend(procedure_body(program, join.second()));
            body
        },
        MastNode::Exec(exec) => vec![ProcedureBodyItem::Exec(exec.target())],
        node => panic!("unexpected node in straight-line procedure body: {node:?}"),
    }
}

fn assert_runtime_procedure_roots(
    program: &CodePackage,
    module: &Module,
    names: &[&str],
) -> Result<Vec<Vec<ProcedureBodyItem>>, Report> {
    let mut fixture = FixtureNamespace::assembly_tests();
    fixture.add_module(module)?;
    let expected_targets = names
        .iter()
        .map(|name| fixture.binding(&module.path().join(*name)).unwrap().key())
        .collect::<BTreeSet<_>>();
    let targets = program
        .package()
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Exec(exec) => Some(exec.target()),
            MastNode::Call(_) => panic!("exec source must retain EXEC mode"),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(targets, expected_targets);
    let bodies = program
        .package()
        .mast_forest()
        .procedure_roots()
        .iter()
        .copied()
        .filter(|root| *root != entry_node(program))
        .map(|root| procedure_body(program, root))
        .collect::<Vec<_>>();
    assert_eq!(bodies.len(), names.len());
    assert_all_nodes_reachable_from_roots(program.package().mast_forest());
    Ok(bodies)
}

#[test]
fn program_with_one_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "proc foo push.3 push.7 mul end begin push.2 push.3 add exec.foo end"
    );
    let module = context.parse_program(source.clone())?;
    let program = context.assemble(source)?;
    let bodies = assert_runtime_procedure_roots(&program, &module, &["foo"])?;
    assert_eq!(
        bodies,
        vec![vec![
            ProcedureBodyItem::Op(Operation::Push(Felt::from_u32(3))),
            ProcedureBodyItem::Op(Operation::Push(Felt::from_u32(7))),
            ProcedureBodyItem::Op(Operation::Mul),
        ]],
    );
    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn program_with_nested_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
        proc foo push.3 push.7 mul end \
        proc bar push.5 exec.foo add end \
        begin push.2 push.4 add exec.foo push.11 exec.bar sub end"
    );
    let module = context.parse_program(source.clone())?;
    let program = context.assemble(source)?;
    let bodies = assert_runtime_procedure_roots(&program, &module, &["foo", "bar"])?;
    let mut fixture = FixtureNamespace::assembly_tests();
    fixture.add_module(&module)?;
    let foo_key = fixture.binding(&module.path().join("foo")).unwrap().key();
    assert!(bodies.contains(&vec![
        ProcedureBodyItem::Op(Operation::Push(Felt::from_u32(3))),
        ProcedureBodyItem::Op(Operation::Push(Felt::from_u32(7))),
        ProcedureBodyItem::Op(Operation::Mul),
    ]));
    assert!(bodies.contains(&vec![
        ProcedureBodyItem::Op(Operation::Push(Felt::from_u32(5))),
        ProcedureBodyItem::Exec(foo_key),
        ProcedureBodyItem::Op(Operation::Add),
    ]));
    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn program_with_proc_locals() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
        @locals(4) proc foo \
            loc_store.0 \
            add \
            loc_load.0 \
            mul \
        end \
        begin \
            push.10 push.9 push.8 \
            exec.foo \
        end"
    );
    let module = context.parse_program(source.clone())?;
    let program = context.assemble(source)?;
    let bodies = assert_runtime_procedure_roots(&program, &module, &["foo"])?;
    let fmp_addr = Felt::from_u32(4294967294);
    let minus_four = -Felt::from_u32(4);
    // Preserve the complete locals/FMP sequence formerly visible in the inlined entrypoint.
    let expected = vec![
        Operation::Push(Felt::from_u32(4)),
        Operation::Push(fmp_addr),
        Operation::MLoad,
        Operation::Add,
        Operation::Push(fmp_addr),
        Operation::MStore,
        Operation::Drop,
        Operation::Push(minus_four),
        Operation::Push(fmp_addr),
        Operation::MLoad,
        Operation::Add,
        Operation::MStore,
        Operation::Drop,
        Operation::Add,
        Operation::Push(minus_four),
        Operation::Push(fmp_addr),
        Operation::MLoad,
        Operation::Add,
        Operation::MLoad,
        Operation::Mul,
        Operation::Push(minus_four),
        Operation::Push(fmp_addr),
        Operation::MLoad,
        Operation::Add,
        Operation::Push(fmp_addr),
        Operation::MStore,
        Operation::Drop,
    ];
    assert_eq!(
        bodies,
        vec![expected.into_iter().map(ProcedureBodyItem::Op).collect::<Vec<_>>()]
    );
    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn program_with_proc_locals_fail() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
proc foo
    loc_store.0
    add
    loc_load.0
    mul
end
begin
    push.4 push.3 push.2
    exec.foo
end"
    );
    let err = context
        .assemble(source)
        .expect_err("expected invalid procedure local reference to be rejected");
    assert_diagnostic!(&err, "invalid procedure local reference");
    assert_diagnostic!(&err, "the procedure local index referenced here is invalid");
    assert_diagnostic!(&err, "this procedure definition does not allocate any locals");
    assert_diagnostic!(&err, "loc_store.0");
}

#[test]
fn program_with_exported_procedure() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "pub proc foo push.3 push.7 mul end begin push.2 push.3 add exec.foo end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected exported program procedure to be rejected");
    assert_diagnostic!(&err, "invalid program: procedure exports are not allowed");
    assert_diagnostic!(&err, "perhaps you meant to use `proc` instead of `export`");
    assert_diagnostic!(&err, "pub proc foo");
}
