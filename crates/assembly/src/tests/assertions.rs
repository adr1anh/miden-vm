// ASSERTIONS
// ================================================================================================
use super::*;
use crate::testing::{FixtureNamespace, FixtureProgram};

#[test]
fn assert_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert
        assert.err=ERR1
        assert.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn assertz_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assertz
        assertz.err=ERR1
        assertz.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn assert_eq_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert_eq
        assert_eq.err=ERR1
        assert_eq.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn assert_eqw_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert_eqw
        assert_eqw.err=ERR1
        assert_eqw.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn u32assert_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assert
        u32assert.err=ERR1
        u32assert.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn u32assert2_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assert2
        u32assert2.err=ERR1
        u32assert2.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn u32assertw_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assertw
        u32assertw.err=ERR1
        u32assertw.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

/// Ensure that assertion and `mtree_verify` error codes are preserved after assembly, including
/// through duplicate procedures with metadata-neutral MAST roots.
#[test]
fn asserts_and_mpverify_with_code_in_duplicate_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    proc f1
        u32assert.err=\"1\"
    end
    proc f2
        u32assert.err=\"2\"
    end
    proc f12
        u32assert.err=\"1\"
        u32assert.err=\"2\"
    end
    proc f21
        u32assert.err=\"2\"
        u32assert.err=\"1\"
    end
    proc g1
        assert.err=\"1\"
    end
    proc g2
        assert.err=\"2\"
    end
    proc g12
        assert.err=\"1\"
        assert.err=\"2\"
    end
    proc g21
        assert.err=\"2\"
        assert.err=\"1\"
    end
    proc fg
        assert.err=\"1\"
        u32assert.err=\"1\"
        assert.err=\"2\"
        u32assert.err=\"2\"

        u32assert.err=\"1\"
        assert.err=\"1\"
        u32assert.err=\"2\"
        assert.err=\"2\"
    end

    proc mpverify
        mtree_verify.err=\"1\"
        mtree_verify.err=\"2\"
        mtree_verify.err=\"2\"
        mtree_verify.err=\"1\"
    end

    begin
        exec.f1
        exec.f2
        exec.f12
        exec.f21
        exec.g1
        exec.g2
        exec.g12
        exec.g21
        exec.fg
        exec.mpverify
    end
    "
    );
    let module = context.parse_module(source)?;
    let mut naming = FixtureNamespace::assembly_tests();
    naming.add_module(&module)?;
    let names = ["f1", "f2", "f12", "f21", "g1", "g2", "g12", "g21", "fg", "mpverify"];
    let targets = names.map(|name| {
        let path = Path::exec_path().join(name);
        naming.binding(&path).unwrap().key()
    });
    let package = naming
        .configure(Assembler::new(context.source_manager()), [&*module])?
        .assemble_program("test", module)?;
    let program = package.fixture_program();
    let forest = program.package().mast_forest();
    let mut exec_targets = Vec::new();
    let mut pending = vec![entry_node(&program)];
    while let Some(node) = pending.pop() {
        match &forest[node] {
            MastNode::Join(join) => {
                pending.push(join.second());
                pending.push(join.first());
            },
            MastNode::Exec(exec) => {
                let node = &forest[node];
                assert!(!node.has_children());
                exec_targets.push(exec.target());
            },
            MastNode::Block(_) => {},
            node => panic!("unexpected caller node: {node:?}"),
        }
    }
    assert_eq!(exec_targets, targets);

    // Runtime EXEC display ends at K. Check every original callee's operations and error codes
    // by defining name, including equal code hashes with different error metadata. Debug metadata
    // provides compiler-fixture associations here; runtime execution still authenticates K.
    let code1 = Felt::new(13948122101519563734).unwrap();
    let code2 = Felt::new(17575088163785490049).unwrap();
    let u32assert = |code| vec![Operation::Pad, Operation::U32assert2(code), Operation::Drop];
    let expected_bodies = [
        u32assert(code1),
        u32assert(code2),
        [u32assert(code1), u32assert(code2)].concat(),
        [u32assert(code2), u32assert(code1)].concat(),
        vec![Operation::Assert(code1)],
        vec![Operation::Assert(code2)],
        vec![Operation::Assert(code1), Operation::Assert(code2)],
        vec![Operation::Assert(code2), Operation::Assert(code1)],
        [
            vec![Operation::Assert(code1)],
            u32assert(code1),
            vec![Operation::Assert(code2)],
            u32assert(code2),
            u32assert(code1),
            vec![Operation::Assert(code1)],
            u32assert(code2),
            vec![Operation::Assert(code2)],
        ]
        .concat(),
        vec![
            Operation::MpVerify(code1),
            Operation::MpVerify(code2),
            Operation::MpVerify(code2),
            Operation::MpVerify(code1),
        ],
    ];
    let debug = package.debug_info().into_diagnostic()?.unwrap();
    for (name, expected) in names.into_iter().zip(expected_bodies) {
        let path = Path::exec_path().join(name).to_string();
        let mut functions = debug.functions().iter().filter(|function| {
            let index = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
            debug[index].as_ref() == path.as_str()
        });
        let function = functions.next().unwrap_or_else(|| panic!("missing function {path}"));
        assert!(functions.next().is_none(), "ambiguous function {path}");
        let source = function.source_node.into_option().expect("private definition is retained");
        let root = debug.source_node(source).unwrap().exec_node;
        assert!(forest.procedure_roots().contains(&root));
        assert_eq!(forest[root].digest(), function.mast_root);
        assert_eq!(
            forest[root].unwrap_basic_block().raw_operations().copied().collect::<Vec<_>>(),
            expected,
            "wrong operations for {path}",
        );
    }
    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}

#[test]
fn mtree_verify_with_code() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const ERR1 = \"1\"

    begin
        mtree_verify
        mtree_verify.err=ERR1
        mtree_verify.err=\"2\"
    end
    "
    );

    let program = context.assemble(source)?;

    insta::assert_snapshot!(render_entry(&program));
    Ok(())
}
