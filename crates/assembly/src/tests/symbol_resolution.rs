// SYMBOL RESOLUTION
// ================================================================================================

use miden_mast_package::arbitrary::fixture_naming;

use super::*;
use crate::testing::FixtureNamespace;

#[test]
fn test_cross_module_quoted_identifier_resolution() -> TestResult {
    let context = TestContext::default();

    // Module A defines and exports a constant
    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::"module::a"

            # Checks local path resolution
            pub proc "$item::<T>::fun"
                exec."$item::<T>::get"
            end

            # Checks absolute path resolution to a local item
            proc "$item::<T>::get"
                exec.::cycle::"module::a"::"$item::<T>::get_impl"
            end

            proc "$item::<T>::get_impl"
                push.1
            end
        "#
    ))?;

    // Module B imports Module A and defines a constant using it
    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module::b

            # Checks that import resolution with quoted path components works
            use cycle::"module::a" as a

            # Checks that link-time cross-module resolution with quoted path components works
            pub proc b_proc
                exec.a::"$item::<T>::fun"
            end
        "#
    ))?;

    let mut naming = FixtureNamespace::assembly_tests();
    naming.add_module(&module_a)?;
    naming.add_module(&module_b)?;
    let assembler =
        naming.configure(Assembler::new(context.source_manager()), [&*module_a, &*module_b])?;

    let _ = assembler.assemble_library("cycle", module_a, [module_b])?;

    Ok(())
}

#[test]
fn regression_symbol_resolution_duplicate_module_paths_are_rejected_during_linking() {
    fn try_assemble_program_with_link_order(libs: &[Arc<Package>]) -> Result<(), Report> {
        let program_source = r#"
begin
    exec.::foo::bar::add
end
"#;

        let mut assembler = Assembler::default();
        for lib in libs {
            let naming = FixtureNamespace::assembly_tests().admit_package(lib)?;
            assembler.link_package(lib.clone(), Linkage::Static, naming)?;
        }

        assembler.assemble_program("program", program_source).map(|_| ())
    }

    let context = TestContext::default();
    let legit_mod = context
        .parse_module(
            r#"
namespace ::foo::bar

pub proc add
    add.1
end
"#,
        )
        .expect("module must parse and analyse");

    let attacker_mod = context
        .parse_module(
            r##"namespace ::foo::"bar"

pub proc add add.2 end"##,
        )
        .expect("module must parse and analyse");

    let legit_lib = context
        .assemble_library("legit", None, legit_mod, None::<Box<Module>>)
        .map(Arc::<Package>::from)
        .expect("library assembly must succeed");
    let attacker_lib = context
        .assemble_library("legit", None, attacker_mod, None::<Box<Module>>)
        .map(Arc::<Package>::from)
        .expect("library assembly must succeed");

    let err = try_assemble_program_with_link_order(&[legit_lib.clone(), attacker_lib.clone()])
        .expect_err("expected duplicate canonical module namespace to be rejected");
    assert_diagnostic!(err, "duplicate definition found for module '::foo::bar'");

    let err = try_assemble_program_with_link_order(&[attacker_lib, legit_lib])
        .expect_err("expected duplicate canonical module namespace to be rejected");
    assert_diagnostic!(err, "duplicate definition found for module '::foo::bar'");
}

#[test]
fn regression_symbol_resolution_in_library_canonical_export_collision_is_rejected() {
    let context = TestContext::default();
    let legit_mod = context
        .parse_module("namespace ::foo::bar\n\npub proc add add.1 end")
        .expect("module must parse and analyse");
    let attacker_mod = context
        .parse_module(
            r##"namespace ::foo::"bar"

pub proc add add.2 end"##,
        )
        .expect("module must parse and analyse");

    let mut naming = FixtureNamespace::assembly_tests();
    naming.add_module(&legit_mod).unwrap();
    naming.add_module(&attacker_mod).unwrap();
    let err = naming
        .configure(Assembler::new(context.source_manager()), [&*legit_mod, &*attacker_mod])
        .unwrap()
        .assemble_library("lib", legit_mod, [attacker_mod])
        .expect_err("expected duplicate canonical export paths to be rejected during assembly");
    assert_diagnostic!(err, "duplicate definition found for module '::foo::bar'");
}

#[test]
fn regression_symbol_resolution_export_leaf_name_collision_should_be_rejected() {
    let context = TestContext::default();
    let module = context
        .parse_module(
            r#"
namespace lib

pub proc p
    push.1
end
"#,
        )
        .expect("base module parsing must succeed");
    let base = context
        .assemble_library("lib", None, module, None::<Box<Module>>)
        .expect("base library assembly must succeed");
    let (node, digest) = base
        .manifest
        .exports()
        .find_map(|e| e.as_procedure())
        .map(|e| (e.node, e.digest))
        .expect("expected at least one procedure export");

    let quoted = Arc::<Path>::from(Path::validate(r#"::foo::"bar""#).unwrap());
    let unquoted = Arc::<Path>::from(Path::validate("::foo::bar").unwrap());

    let exports = vec![
        PackageExport::Procedure(ProcedureExport::new(quoted, node, digest, None)),
        PackageExport::Procedure(ProcedureExport::new(unquoted, node, digest, None)),
    ];
    let naming = fixture_naming(
        FixtureNamespace::assembly_tests().namespace_plan().clone(),
        TargetType::Library,
        base.mast_forest(),
        &exports,
    );

    Package::create(
        "test".into(),
        "0.0.0".parse().unwrap(),
        TargetType::Library,
        Arc::clone(base.mast_forest()),
        exports,
        None,
        &naming,
    )
    .expect_err("duplicate export paths must be rejected");
}

#[test]
fn executable_package_main_export_points_to_entrypoint_source_root() -> TestResult {
    let context = TestContext::default();
    let lib_module = context.parse_module(
        r#"
        namespace lib::lib

        pub proc lib_proc
            push.1
        end
        "#,
    )?;
    let (lib, mut naming) =
        context.assemble_library_with_fixture("lib", None, lib_module, None::<Box<Module>>)?;
    let program = context.parse_module(
        r#"
            use lib::lib

            begin
                exec.lib::lib_proc
            end
            "#,
    )?;
    naming.add_module(&program)?;
    let lib_naming = naming.admit_package(&lib)?;
    let assembler = Assembler::new(context.source_manager()).with_package(
        Arc::from(lib),
        Linkage::Static,
        lib_naming,
    )?;
    let package = naming.configure(assembler, [&*program])?.assemble_program("program", program)?;

    let main_path = Path::exec_path().join(ProcedureName::MAIN_PROC_NAME);
    let entrypoint = package
        .get_procedure_node_by_path(&main_path)
        .expect("main procedure should have an execution node");
    let main_export = package
        .manifest
        .get_export(&main_path)
        .and_then(PackageExport::as_procedure)
        .expect("main export should exist");
    let source_node = main_export.source_node.expect("main export should retain source debug root");
    let debug_info = package
        .debug_info()
        .expect("package debug info should decode")
        .expect("package should contain source debug info");

    assert_eq!(debug_info.source_node(source_node).unwrap().exec_node, entrypoint);
    Ok(())
}

#[test]
fn regression_symbol_resolution_malformed_quoted_export_leaf_should_return_error_not_panic() {
    let context = TestContext::default();
    let module = context
        .parse_module(
            r#"
namespace test

pub proc p
    push.1
end
"#,
        )
        .expect("base module parsing must succeed");
    let base = context
        .assemble_library("test", None, module, None::<Box<Module>>)
        .expect("base library assembly must succeed");
    let (node, digest) = base
        .manifest
        .exports()
        .find_map(|e| e.as_procedure())
        .map(|e| (e.node, e.digest))
        .expect("expected at least one procedure export");

    let bad = Arc::<Path>::from(Path::validate(r#"::foo::"bad name""#).unwrap());

    let exports = vec![PackageExport::Procedure(ProcedureExport::new(bad, node, digest, None))];
    let naming = fixture_naming(
        FixtureNamespace::assembly_tests().namespace_plan().clone(),
        TargetType::Library,
        base.mast_forest(),
        &exports,
    );

    Package::create(
        "test".into(),
        "0.0.0".parse().unwrap(),
        TargetType::Library,
        Arc::clone(base.mast_forest()),
        exports,
        None,
        &naming,
    )
    .expect_err("expected malformed procedure export leaf names to be rejected");
}
