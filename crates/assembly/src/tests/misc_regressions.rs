// MISC REGRESSIONS
// ================================================================================================

use super::*;
use crate::{
    fmp::{fmp_end_frame_sequence, fmp_start_frame_sequence, push_offset_fmp_sequence},
    testing::FixtureNamespace,
};

#[test]
fn test_issue_2181_locaddr_bug_assembly() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        r#"
proc some_proc
    nop
end

@locals(4)
proc main
    locaddr.0
    locaddr.0
    locaddr.0
    exec.some_proc
    dropw
end

begin
    exec.main
end"#
    );
    let module = context.parse_module(source)?;
    let mut naming = FixtureNamespace::assembly_tests();
    naming.add_module(&module)?;
    let some_proc = naming.binding(&Path::exec_path().join("some_proc")).unwrap().key();
    let main = naming.binding(&Path::exec_path().join("main")).unwrap().key();
    let program = context.assemble(module)?;
    let forest = program.package().mast_forest();
    let mut targets = forest
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Exec(exec) => {
                assert!(!node.has_children());
                Some(exec.target())
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    targets.sort();
    let mut expected_targets = vec![some_proc, main];
    expected_targets.sort();
    assert_eq!(targets, expected_targets);

    // The caller snapshot ends at EXEC.main; retain the locaddr/FMP regression in main's body.
    assert_eq!(program.package().mast_forest().num_procedures(), 3);
    let main_root = forest
        .procedure_roots()
        .iter()
        .copied()
        .find(|&root| root != entry_node(&program) && matches!(&forest[root], MastNode::Join(_)))
        .expect("main's runtime body should remain a procedure root");
    #[derive(Debug, PartialEq, Eq)]
    enum BodyStep {
        Op(Operation),
        Exec(miden_core::program::ProcedureKey),
    }
    let mut body = Vec::new();
    let mut pending = vec![main_root];
    while let Some(node) = pending.pop() {
        match &forest[node] {
            MastNode::Join(join) => {
                pending.push(join.second());
                pending.push(join.first());
            },
            MastNode::Block(block) => {
                body.extend(block.raw_operations().copied().map(BodyStep::Op));
            },
            MastNode::Exec(exec) => body.push(BodyStep::Exec(exec.target())),
            node => panic!("unexpected node in main's body: {node:?}"),
        }
    }
    let mut expected_ops = fmp_start_frame_sequence(4);
    for _ in 0..3 {
        expected_ops.extend(push_offset_fmp_sequence(-Felt::from_u32(4)));
    }
    let mut expected_body = expected_ops.into_iter().map(BodyStep::Op).collect::<Vec<_>>();
    expected_body.push(BodyStep::Exec(some_proc));
    expected_body.extend([Operation::Drop; 4].into_iter().map(BodyStep::Op));
    expected_body.extend(fmp_end_frame_sequence(4).into_iter().map(BodyStep::Op));
    assert_eq!(body, expected_body);
    assert!(
        forest.procedure_roots().iter().any(|&root| {
            matches!(&forest[root], MastNode::Block(block) if
                block.raw_operations().copied().collect::<Vec<_>>() == [Operation::Noop])
        }),
        "some_proc's nop body should remain a procedure root",
    );
    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

/// Tests conditional debug info functionality
///
/// This test is disabled because with debug mode always enabled (issue #1821),
/// we no longer have the ability to turn debug mode off. The old functionality
#[test]
fn test_assembler_debug_info_present() {
    let context = TestContext::default();
    let source = r#"
    namespace test::foo

    pub proc foo
        push.1 push.2 add
    end
    "#;

    let module = parse_module!(&context, source);

    // Test: With debug mode always enabled (issue #1821), debug info should always be present
    let library = context.assemble_library("test", None, module, None::<Box<Module>>).unwrap();
    // Debug info should be present since debug mode is enabled by default.
    // AssemblyOps are stored in package-owned source debug metadata.
    assert_package_has_source_asm_ops(
        &library,
        "Package-owned AssemblyOps should be present for tracking instructions",
    );
}
