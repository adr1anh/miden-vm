// IMPORTS
// ================================================================================================

use miden_core::program::ProcedureKey;

use super::*;
use crate::testing::FixtureNamespace;

fn assert_imported_procedure_root(library: &Package, path: &str, digest: &str) {
    let root = library.get_export_node_id(Path::new(path));
    assert!(library.mast_forest().procedure_roots().contains(&root));
    assert_eq!(library.mast_forest()[root].digest(), Word::parse(digest).unwrap());
}

fn bind_import_reexports(
    bindings: &mut FixtureNamespace,
    defining_module: &str,
    exporting_module: &str,
) -> TestResult {
    for (definition, alias) in [("checked_eqz", "checked_eqz"), ("unchecked_eqz", "notchecked_eqz")]
    {
        let definition = format!("::{defining_module}::{definition}");
        let binding = bindings.binding(Path::new(&definition)).unwrap().clone();
        let alias = format!("::{exporting_module}::{alias}");
        bindings.add_binding(Arc::from(Path::new(&alias)), binding)?;
    }
    Ok(())
}

fn imported_reexport_targets(
    library: &Package,
    bindings: &FixtureNamespace,
    exporting_module: &str,
) -> [ProcedureKey; 2] {
    [
        (
            "checked_eqz",
            "0x0c4bbef7c722554dc2aa498067ed8920b2fb10c66babad7137161797f5d8765d",
        ),
        (
            "notchecked_eqz",
            "0x97ffb6ae921f7e0080ba47bbd5111f21ffb569de24f7923ee1c379395ede815e",
        ),
    ]
    .map(|(name, digest)| {
        let path = format!("::{exporting_module}::{name}");
        assert_imported_procedure_root(library, &path, digest);
        bindings.binding(Path::new(&path)).unwrap().key()
    })
}

fn assert_imported_runtime_targets(
    program: &Program,
    expected_exec: &[ProcedureKey],
    expected_call: &[ProcedureKey],
) {
    let exec = program
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Exec(exec) => Some(exec.target()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let call = program
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Call(call) => {
                assert!(!call.is_syscall());
                Some(call.target())
            },
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(exec, expected_exec.iter().copied().collect());
    assert_eq!(call, expected_call.iter().copied().collect());
}

#[test]
fn program_with_one_import_and_hex_call() -> TestResult {
    const MODULE: &str = "dummy::math::u256";
    const PROCEDURE: &str = r#"
        pub proc iszero_unsafe
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end"#;

    let mut context = TestContext::default();
    let ast =
        context.parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))?;
    let (library, bindings) = context
        .assemble_library_with_fixture("dummy", None, ast, None::<Box<Module>>)
        .unwrap();

    let target = bindings.binding(Path::new("::dummy::math::u256::iszero_unsafe")).unwrap().key();
    assert_imported_procedure_root(
        &library,
        "::dummy::math::u256::iszero_unsafe",
        "0xea4386710a2f3a5e4efb64d894343e14cae4f7daaa9e4b6e2a8b091e63f0fe28",
    );
    context.add_library_with_bindings(Arc::from(library), &bindings)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::iszero_unsafe
            call.{}
        end"#,
            target.as_word().to_hex(),
        )
    );
    let program = context.assemble(source)?;

    assert_imported_runtime_targets(&program, &[target], &[target]);
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_two_imported_procs_with_same_mast_root() -> TestResult {
    const MODULE: &str = "dummy::math::u256";
    const PROCEDURE: &str = r#"
        pub proc iszero_unsafe_dup
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end

        pub proc iszero_unsafe
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end"#;

    let mut context = TestContext::default();
    let ast =
        context.parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))?;
    let (library, bindings) = context
        .assemble_library_with_fixture("dummy", None, ast, None::<Box<Module>>)
        .unwrap();

    let first = Path::new("::dummy::math::u256::iszero_unsafe");
    let second = Path::new("::dummy::math::u256::iszero_unsafe_dup");
    assert_eq!(library.get_export_node_id(first), library.get_export_node_id(second));
    let targets = [bindings.binding(first).unwrap().key(), bindings.binding(second).unwrap().key()];
    assert_ne!(targets[0], targets[1]);
    context.add_library_with_bindings(Arc::from(library), &bindings)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::iszero_unsafe
            exec.u256::iszero_unsafe_dup
        end"#
        )
    );
    let program = context.assemble(source)?;
    assert_imported_runtime_targets(&program, &targets, &[]);
    Ok(())
}

#[test]
fn program_with_reexported_proc_in_same_library() -> TestResult {
    // exprted proc is in same library
    const REF_MODULE: &str = "dummy1::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        # checked_eqz checks if the value is u32 and zero and returns 1 if it is, 0 otherwise
        pub use {checked_eqz} from dummy1::math::u64 # re-export

        # unchecked_eqz checks if the value is zero and returns 1 if it is, 0 otherwise
        pub use {unchecked_eqz as notchecked_eqz} from dummy1::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::new();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))
        .unwrap();

    let ref_ast = context
        .parse_module(source_file!(&context, format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")))
        .unwrap();

    let (library, mut bindings) =
        context.assemble_library_with_fixture("dummy1", None, ast, [ref_ast]).unwrap();

    bind_import_reexports(&mut bindings, REF_MODULE, MODULE)?;
    let targets = imported_reexport_targets(&library, &bindings, MODULE);
    context.add_library_with_bindings(Arc::from(library), &bindings)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::checked_eqz
            exec.u256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;
    assert_imported_runtime_targets(&program, &targets, &[]);
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_reexported_custom_alias_in_same_library() -> TestResult {
    // exprted proc is in same library
    const REF_MODULE: &str = "dummy1::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        # checked_eqz checks if the value is u32 and zero and returns 1 if it is, 0 otherwise
        pub use {checked_eqz} from dummy1::math::u64 # re-export

        # unchecked_eqz checks if the value is zero and returns 1 if it is, 0 otherwise
        pub use {unchecked_eqz as notchecked_eqz} from dummy1::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::new();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))
        .unwrap();

    let ref_ast = context
        .parse_module(source_file!(&context, format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")))
        .unwrap();

    let (library, mut bindings) =
        context.assemble_library_with_fixture("dummy1", None, ast, [ref_ast]).unwrap();

    bind_import_reexports(&mut bindings, REF_MODULE, MODULE)?;
    let targets = imported_reexport_targets(&library, &bindings, MODULE);
    context.add_library_with_bindings(Arc::from(library), &bindings)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE} as myu256
        begin
            push.4 push.3
            exec.myu256::checked_eqz
            exec.myu256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;
    assert_imported_runtime_targets(&program, &targets, &[]);
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_reexported_proc_in_another_library() -> TestResult {
    // when re-exported proc is part of a different library
    const REF_MODULE: &str = "dummy2::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        pub use {checked_eqz} from dummy2::math::u64 # re-export
        pub use {unchecked_eqz as notchecked_eqz} from dummy2::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::default();
    let source_manager = context.source_manager();
    // We reference code in this module
    let ref_ast = context.parse_module(source_file!(
        &context,
        format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")
    ))?;
    // But only exports from this module are exposed by the library
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))?;

    let (dummy_library, bindings) = {
        let mut bindings = FixtureNamespace::assembly_tests();
        bindings.add_module(&ref_ast)?;
        bindings.add_module(&ast)?;
        let mut assembler =
            bindings.configure(Assembler::new(source_manager), [&*ref_ast, &*ast])?;
        assembler.compile_and_statically_link(ref_ast)?;
        let library =
            Arc::<Package>::from(assembler.assemble_library("dummy1", ast, None::<Box<Module>>)?);
        bind_import_reexports(&mut bindings, REF_MODULE, MODULE)?;
        (library, bindings)
    };
    let targets = imported_reexport_targets(&dummy_library, &bindings, MODULE);

    // Now we want to use the the library we've compiled
    context.add_library_with_bindings(dummy_library.clone(), &bindings)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::checked_eqz
            exec.u256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;

    assert_imported_runtime_targets(&program, &targets, &[]);
    insta::assert_snapshot!(program);

    // We also want to assert that exports from the referenced module do not leak
    let mut context = TestContext::default();
    context.add_library_with_bindings(dummy_library, &bindings)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {REF_MODULE}
        begin
            push.4 push.3
            exec.u64::checked_eqz
            exec.u64::notchecked_eqz
        end"#
        )
    );
    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'dummy2::math::u64'",
        regex!(r#",-\[test[\d]+:2:13\]"#),
        "1 |",
        "2 |         use dummy2::math::u64",
        "  :             ^^^^^^^^^^^^^^^^^",
        "3 |         begin",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );
    Ok(())
}

#[test]
fn module_alias() -> TestResult {
    const MODULE: &str = "dummy::math::u64";
    const PROCEDURE: &str = r#"
        pub proc checked_add
            swap
            movup.3
            u32assert2
            u32widening_add
            movup.3
            movup.3
            u32assert2
            u32widening_add3
            eq.0
            assert
        end"#;

    let mut context = TestContext::default();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))
        .unwrap();
    let (library, bindings) = context
        .assemble_library_with_fixture("dummy", None, ast, None::<Box<Module>>)
        .unwrap();

    let target = bindings.binding(Path::new("::dummy::math::u64::checked_add")).unwrap().key();
    assert_imported_procedure_root(
        &library,
        "::dummy::math::u64::checked_add",
        "0x22e4f27cc786c82bd7900fe543cd16767338914e17d57314170c06d1581a493e",
    );
    context.add_library_with_bindings(Arc::from(library), &bindings)?;

    let source = source_file!(
        &context,
        "
        use dummy::math::u64 as bigint

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
        end"
    );

    let program = context.assemble(source)?;
    assert_imported_runtime_targets(&program, &[target], &[]);
    insta::assert_snapshot!(program);

    // --- invalid module alias -----------------------------------------------
    let source = source_file!(
        &context,
        r#"
        use dummy::math::u64 as "bad name"

        begin
            push.1.0
            push.2.0
            exec."bad name"::checked_add
        end"#
    );
    let err = context
        .assemble(source)
        .expect_err("expected invalid quoted module alias to be rejected");
    assert_diagnostic!(&err, "expected an alias name after `as`");
    assert_diagnostic!(&err, "bad name");

    Ok(())
}

#[test]
//#[ignore = "disabled until unused import accuracy is improved"]
fn module_alias_unused_import() -> TestResult {
    const MODULE: &str = "dummy::math::u64";
    const PROCEDURE: &str = r#"
        pub proc checked_add
            swap
            movup.3
            u32assert2
            u32widening_add
            movup.3
            movup.3
            u32assert2
            u32widening_add3
            eq.0
            assert
        end"#;

    let mut context = TestContext::default();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))
        .unwrap();
    let (library, bindings) = context
        .assemble_library_with_fixture("dummy", None, ast, None::<Box<Module>>)
        .unwrap();

    context.add_library_with_bindings(Arc::from(library), &bindings)?;

    // --- duplicate module import --------------------------------------------
    let source = source_file!(
        &context,
        "
        use dummy::math::u64
        use dummy::math::u64 as bigint

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
        end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected unused duplicate import to be rejected");
    assert_diagnostic!(&err, "unused import");
    assert_diagnostic!(&err, "this import is never used and can be safely removed");
    assert_diagnostic!(&err, "use dummy::math::u64");
    assert_diagnostic!(&err, "use dummy::math::u64 as bigint");

    // --- duplicate module imports with different aliases --------------------
    // TODO: Do we actually want this to be a warning/error? If the imports
    // have different aliases, there might be some use for that when refactoring
    // code or something. Anyway, I'm disabling the test that expects this to
    // fail for the time being
    /*
    let source = source_file!(
    &context,
        "
        use dummy::math::u64 as bigint
        use dummy::math::u64 as bigint2

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
            exec.bigint2::checked_add
        end"
    );
    */
    Ok(())
}

#[test]
fn program_with_import_errors() {
    let context = TestContext::default();
    // --- non-existent import ------------------------------------------------
    let source = source_file!(
        &context,
        "\
        use miden::core::math::u512
        begin \
            push.4 push.3 \
            exec.u512::iszero_unsafe \
        end"
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'miden::core::math::u512'",
        regex!(r#",-\[test[\d]+:1:5\]"#),
        "1 | use miden::core::math::u512",
        "  :     ^^^^^^^^^^^^^^^^^^^^^^^",
        "2 |         begin push.4 push.3 exec.u512::iszero_unsafe end",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );

    // --- non-existent procedure in import -----------------------------------
    let source = source_file!(
        &context,
        "\
        use miden::core::math::u256
        begin \
            push.4 push.3 \
            exec.u256::foo \
        end"
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'miden::core::math::u256'",
        regex!(r#",-\[test[\d]+:1:5\]"#),
        "1 | use miden::core::math::u256",
        "  :     ^^^^^^^^^^^^^^^^^^^^^^^",
        "2 |         begin push.4 push.3 exec.u256::foo end",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );
}
