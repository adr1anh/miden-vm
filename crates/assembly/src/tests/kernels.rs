// KERNELS AND SYSCALLS
// ================================================================================================

use core::num::NonZeroU32;

use miden_core::program::{CanonicalLabel, ProcedureKey};
use miden_mast_package::{CallableProcedurePath, NamespacePlan};

use super::*;
use crate::{CallableBinding, testing::FixtureNamespace};

fn kernel_fixture_namespaces() -> (FixtureNamespace, NamespacePlan) {
    let mut home = vec![
        CanonicalLabel::text("assembly-kernel-fixtures").unwrap(),
        CanonicalLabel::revision(NonZeroU32::new(1).unwrap()),
        CanonicalLabel::text("owner").unwrap(),
    ];
    let bindings = FixtureNamespace::new(NamespacePlan::new(home.clone()));
    // This fixture explicitly names root exports as ["$kernel", name]. The authorized
    // namespace is their complete accumulated immediate parent, including every home label.
    home.push(CanonicalLabel::text("$kernel").unwrap());
    (bindings, NamespacePlan::new(home))
}

fn assemble_kernel_fixture(
    context: &TestContext,
    kernel: Box<Module>,
    support: impl IntoIterator<Item = Box<Module>>,
) -> Result<(Arc<Package>, FixtureNamespace, NamespacePlan), Report> {
    let support = support.into_iter().collect::<Vec<_>>();
    let (mut bindings, kernel_home) = kernel_fixture_namespaces();
    for module in core::iter::once(&kernel).chain(&support) {
        bindings.add_module(module)?;
    }
    let assembler = bindings.configure(
        Assembler::new(context.source_manager()).with_kernel_namespace_plan(kernel_home.clone()),
        core::iter::once(&*kernel).chain(support.iter().map(|module| &**module)),
    )?;
    let package = assembler.assemble_kernel("kernel", kernel, support)?;
    // Legacy package metadata does not carry these callable bindings or the authorized home.
    Ok((Arc::from(package), bindings, kernel_home))
}

#[test]
fn can_assemble_a_multi_module_kernel() -> Result<(), Report> {
    const KERNEL: &str = r#"
        mod helpers
        use external::helpers as h
        pub proc foo
            exec.h::get_caller
            exec.helpers::get_caller
        end"#;
    const HELPERS: &str = r#"
        namespace $kernel::helpers

        pub proc get_caller
            caller
        end"#;
    const EXTERNAL_HELPERS: &str = r#"
        namespace external::helpers

        pub proc get_caller
            caller
        end"#;
    const PROGRAM: &str = r#"
        begin
            syscall.foo
        end"#;

    let context = TestContext::new();

    let (kernel_lib, mut bindings, kernel_home) = {
        let helpers = context.parse_module(HELPERS)?;
        let external_helpers = context.parse_module(EXTERNAL_HELPERS)?;
        let kernel = context.parse_kernel(source_file!(&context, KERNEL)).unwrap();

        let (mut bindings, kernel_home) = kernel_fixture_namespaces();
        for module in [&*kernel, &*helpers, &*external_helpers] {
            bindings.add_module(module)?;
        }
        let mut assembler = bindings.configure(
            Assembler::new(context.source_manager()),
            [&*kernel, &*helpers, &*external_helpers],
        )?;
        assembler.compile_and_statically_link(external_helpers)?;
        let package = assembler.assemble_kernel("kernel", kernel, [helpers])?;
        (Arc::<Package>::from(package), bindings, kernel_home)
    };

    assert_eq!(kernel_lib.to_kernel_descriptor().ok().map(|k| k.proc_hashes().len()), Some(1));

    let program = context.parse_program(source_file!(&context, PROGRAM))?;
    bindings.add_module(&program)?;
    bindings
        .configure(
            Assembler::with_kernel(context.source_manager(), kernel_lib)?
                .with_kernel_namespace_plan(kernel_home),
            [&*program],
        )?
        .assemble_program("program", program)?;

    Ok(())
}

#[test]
fn regression_empty_kernel_is_rejected() {
    let context = TestContext::default();
    // A code candidate with no actual callable roots is rejected for every target kind.
    let kernel_masm = "pub const FOO = 1\n";
    let err = assemble_kernel_fixture(
        &context,
        context.parse_kernel(source_file!(&context, kernel_masm)).unwrap(),
        vec![],
    )
    .expect_err("expected empty kernel to be rejected");
    assert_diagnostic_lines!(err, "package must contain at least one callable procedure root");
}

#[test]
fn kernel_candidate_with_private_submodule_code_cannot_become_a_runnable_kernel() {
    let context = TestContext::default();

    // Generic code candidates may retain real private code without inventing public exports.
    // Conversion to a runnable kernel still requires a nonempty root kernel surface.
    let kernel_masm = "mod sub\n\npub const FOO = 1\n";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo push.1 end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let (candidate, ..) = assemble_kernel_fixture(&context, kernel_module, vec![submodule])
        .expect("real submodule code is a valid code candidate");
    let forest = candidate.mast_forest();
    assert_eq!(forest.procedure_roots().len(), 1);
    let root = forest.procedure_roots()[0];
    let MastNode::Block(block) = &forest[root] else {
        panic!("the retained private procedure must contain its actual local body");
    };
    // The unchanged push.1 source lowers to PAD INCR, followed only by block padding.
    let operations = block.operations().copied().collect::<Vec<_>>();
    assert!(operations.starts_with(&[Operation::Pad, Operation::Incr]));
    assert!(operations.iter().skip(2).all(|op| *op == Operation::Noop));
    assert!(candidate.manifest.exports().all(|export| export.as_procedure().is_none()));

    let error = candidate
        .to_kernel_descriptor()
        .expect_err("private code cannot manufacture a runnable root kernel surface");
    assert_diagnostic!(error, "invalid kernel package: does not export any kernel procedures");
    let error = Assembler::with_kernel(context.source_manager(), candidate)
        .err()
        .expect("a code candidate with no root kernel exports cannot be attached as a kernel");
    assert_diagnostic!(error, "invalid kernel package: does not export any kernel procedures");
}

#[test]
fn regression_empty_kernel_with_nonempty_submodule_is_rejected() {
    let context = TestContext::default();

    // Preserve the source-language restriction on re-exporting procedures from a kernel module.
    let kernel_masm = "mod sub\n\npub use {foo} from self::sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let err = context
        .parse_kernel(source_file!(&context, kernel_masm))
        .expect_err("expected sema to reject re-export from kernel module");
    assert_diagnostic!(err, "invalid re-exported procedure");
}

#[test]
fn regression_reexport_of_kernel_procedure_from_kernel_submodule_is_rejected() {
    let context = TestContext::default();

    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let submodule_masm =
        "namespace $kernel::sub\n\npub use {root} from $kernel\n\npub proc foo push.1 end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let err = assemble_kernel_fixture(&context, kernel_module, vec![submodule])
        .expect_err("expected kernel submodule re-exporting kernel syscall to be rejected");
    assert_diagnostic!(err, "invalid re-export of kernel syscall");
}

#[test]
fn kernel_submodules_may_exec_root_kernel_exports() {
    let context = TestContext::default();

    // Ordinary invocation may use the same exports as SYS; only actual SYS checks N_kernel.
    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n\npub proc other exec.root end";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo exec.$kernel::root end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let (kernel, bindings, _) = assemble_kernel_fixture(&context, kernel_module, vec![submodule])
        .expect("ordinary EXEC of a root kernel export must compile");
    let root_key = bindings.binding(Path::new("::$kernel::root")).unwrap().key();
    assert!(
        kernel
            .mast_forest()
            .nodes()
            .iter()
            .any(|node| { matches!(node, MastNode::Exec(exec) if exec.target() == root_key) })
    );
    assert_ne!(
        bindings.binding(Path::new("::$kernel::other")).unwrap().key(),
        bindings.binding(Path::new("::$kernel::sub::foo")).unwrap().key(),
    );
    // Both EXEC bodies can share D while their callable keys remain distinct.
    assert_eq!(kernel.mast_forest().procedure_roots().len(), 2);
}

#[test]
fn regression_syscall_of_kernel_submodule_procedure_is_rejected() {
    let context = TestContext::default();

    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo syscall.root end\n";
    let program_masm = "begin syscall.::$kernel::sub::foo end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let (kernel, mut bindings, kernel_home) =
        assemble_kernel_fixture(&context, kernel_module, vec![submodule])
            .expect("expected valid kernel");
    assert_ne!(
        bindings.binding(Path::new("::$kernel::sub::foo")).unwrap().parent_namespace(),
        kernel_home.namespace(),
    );
    let program = context
        .parse_module(source_file!(&context, program_masm))
        .expect("source spelling does not determine syscall authority");
    bindings.add_module(&program).unwrap();
    let assembler = bindings
        .configure(
            Assembler::with_kernel(context.source_manager(), kernel)
                .unwrap()
                .with_kernel_namespace_plan(kernel_home),
            [&*program],
        )
        .unwrap();
    let err = assembler
        .assemble_program("program", program)
        .expect_err("a descendant namespace is not the authorized immediate parent");
    assert_diagnostic!(err, "outside the configured full kernel namespace");
    // Runtime witness rejection is covered by processor/tests/keyed_execution.rs::
    // syscall_requires_exact_full_namespace_before_code_lookup.
}

#[test]
fn test_kernel_linking_against_its_own_library() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub mod lib

        proc internal_proc
            caller
            drop
            exec.$kernel::lib::lib_proc
        end

        pub proc kernel_proc
            exec.internal_proc
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace $kernel::lib

            pub proc lib_proc
                swap
            end
            "#
    ))?;

    let (kernel, bindings, _) = assemble_kernel_fixture(&context, kernel, vec![lib])?;
    let internal_key = bindings.binding(Path::new("::$kernel::internal_proc")).unwrap().key();
    let library_key = bindings.binding(Path::new("::$kernel::lib::lib_proc")).unwrap().key();
    for key in [internal_key, library_key] {
        assert!(
            kernel
                .mast_forest()
                .nodes()
                .iter()
                .any(|node| { matches!(node, MastNode::Exec(exec) if exec.target() == key) })
        );
    }
    assert_eq!(kernel.mast_forest().procedure_roots().len(), 3);
    assert_all_nodes_reachable_from_roots(kernel.mast_forest());

    Ok(())
}

#[test]
fn test_syscall_resolution_uses_kernel_module() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub proc foo
            caller
            drop
            push.1
        end

        pub proc bar
            caller
            drop
            push.2
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace userspace

            pub proc bar
                push.0
            end
            "#
    ))?;

    let source = source_file!(
        &context,
        r#"
        use {bar} from userspace

        proc foo
            push.0
        end

        begin
            syscall.foo
            syscall.bar
        end
        "#
    );

    let (kernel, mut bindings, kernel_home) = assemble_kernel_fixture(&context, kernel, vec![])?;
    let kernel_bar_key = bindings.binding(Path::new("::$kernel::bar")).unwrap().key();
    let kernel_foo_key = bindings.binding(Path::new("::$kernel::foo")).unwrap().key();
    let program = context.parse_program(source)?;
    bindings.add_module(&lib)?;
    bindings.add_module(&program)?;

    let mut assembler = Assembler::with_kernel(context.source_manager(), kernel)?
        .with_kernel_namespace_plan(kernel_home);
    assembler.compile_and_statically_link(lib)?;
    let assembler = bindings.configure(assembler, [&*program])?;
    let program = assembler.assemble_program("program", program)?.unwrap_program();

    let mast = {
        let entry = program.get_node_by_id(program.entrypoint()).unwrap();
        format!("{}", entry.to_display(program.mast_forest()))
    };

    let expected = format!(
        r#"join
    join
        basic_block push(2147483648) push(4294967294) mstore drop noop end
        syscall.{kernel_foo_key}
    end
    syscall.{kernel_bar_key}
end"#,
        kernel_foo_key = kernel_foo_key.as_word().to_hex(),
        kernel_bar_key = kernel_bar_key.as_word().to_hex(),
    );
    assert_eq!(mast, expected);

    Ok(())
}

#[test]
fn test_syscall_resolution_to_non_kernel_path_is_checked() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub proc foo
            caller
            drop
            push.1
        end
        "#
    ))?;

    let lib_source = r#"
            namespace userspace

            pub proc bar
                push.0
            end
        "#;

    let unimported_source = r#"
        begin
            syscall.userspace::bar
        end
        "#;
    let imported_source = r#"
        use userspace
        begin
            syscall.userspace::bar
        end
        "#;

    let (kernel, kernel_bindings, kernel_home) = assemble_kernel_fixture(&context, kernel, vec![])?;
    for authorized in [false, true] {
        let lib = context.parse_module(lib_source)?;
        let lib_bindings = if authorized {
            // The owner explicitly places this source definition directly under N_kernel.
            // Its userspace spelling neither grants nor prevents syscall authorization.
            let mut bindings = FixtureNamespace::new(kernel_home.clone());
            let canonical =
                CallableProcedurePath::from_semantic_components(vec!["bar".into()]).unwrap();
            bindings.add_binding(
                lib.path().join("bar").into(),
                CallableBinding::new(kernel_home.clone(), canonical).unwrap(),
            )?;
            bindings
        } else {
            let (mut bindings, _) = kernel_fixture_namespaces();
            bindings.add_module(&lib)?;
            bindings
        };
        let target = lib_bindings.binding(&lib.path().join("bar")).unwrap().clone();
        assert_eq!(target.parent_namespace() == kernel_home.namespace(), authorized);
        let package: Arc<Package> = lib_bindings
            .configure(Assembler::new(context.source_manager()), [&*lib])?
            .assemble_library("lib", lib, None::<Box<Module>>)?
            .into();

        for (source, imported) in [(unimported_source, false), (imported_source, true)] {
            let program = context.parse_program(source_file!(&context, source))?;
            let mut bindings = kernel_bindings.clone();
            bindings.add_module(&program)?;
            bindings.add_binding(Arc::from(Path::new("::userspace::bar")), target.clone())?;
            let assembler = Assembler::with_kernel(context.source_manager(), kernel.clone())?
                .with_kernel_namespace_plan(kernel_home.clone())
                .with_package(package.clone(), Linkage::Static)?;
            let result =
                bindings.configure(assembler, [&*program])?.assemble_program("program", program);

            if !imported {
                let error = result.expect_err("a relative target must resolve through an import");
                assert_diagnostic!(&error, "invalid relative item path 'userspace::bar'");
                assert_diagnostic!(&error, "syscall.userspace::bar");
            } else if authorized {
                let package =
                    result.expect("an explicitly authorized parent accepts any source alias");
                assert!(package.mast_forest().nodes().iter().any(|node| {
                    matches!(node, MastNode::Call(call)
                        if call.is_syscall() && call.target() == target.key())
                }));
            } else {
                let error = result.expect_err("a different immediate parent must reject syscall");
                assert_diagnostic!(&error, "outside the configured full kernel namespace");
                assert_diagnostic!(&error, "userspace::bar");
            }
        }
    }
    // Runtime authentication is covered by processor/tests/keyed_execution.rs::
    // syscall_requires_exact_full_namespace_before_code_lookup.

    Ok(())
}

#[test]
fn syscall_validation_does_not_panic_on_same_digest_userspace_procedure() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::default();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let (kernel_lib, mut bindings, kernel_home) = assemble_kernel_fixture(
        &context,
        context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
        vec![],
    )
    .expect("kernel assembly must succeed");
    let kernel_root = kernel_lib.get_procedure_root_by_path("::$kernel::k1").unwrap();
    let kernel_key = bindings.binding(Path::new("::$kernel::k1")).unwrap().key();

    let program_src = r#"
proc dup
    push.1
end

begin
    exec.dup
    syscall.k1
end
"#;

    let program = context.parse_program(source_file!(&context, program_src)).unwrap();
    bindings.add_module(&program).unwrap();
    let duplicate_key = bindings.binding(&program.path().join("dup")).unwrap().key();
    assert_ne!(duplicate_key, kernel_key, "equal bodies do not merge callable identities");
    let assembler = bindings
        .configure(
            Assembler::with_kernel(context.source_manager(), kernel_lib)
                .expect("test package should be valid")
                .with_kernel_namespace_plan(kernel_home),
            [&*program],
        )
        .unwrap();
    let assembled =
        catch_unwind(AssertUnwindSafe(|| assembler.assemble_program("program", program)));
    assert!(assembled.is_ok(), "assembler panicked while assembling a valid program");
    let package = assembled.unwrap().expect("expected program assembly to succeed");
    assert!(package.mast_forest().procedure_roots().iter().any(|root| {
        let node = &package.mast_forest()[*root];
        matches!(node, MastNode::Block(_)) && node.digest() == kernel_root
    }));
    assert!(
        package
            .mast_forest()
            .nodes()
            .iter()
            .any(|node| { matches!(node, MastNode::Exec(exec) if exec.target() == duplicate_key) })
    );
    assert!(package.mast_forest().nodes().iter().any(|node| {
        matches!(node, MastNode::Call(call)
            if call.is_syscall() && call.target() == kernel_key)
    }));
}

#[test]
fn syscall_literal_unknown_key_is_retained_when_the_full_kernel_home_is_supplied() {
    let context = TestContext::default();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let (kernel_lib, mut bindings, kernel_home) = assemble_kernel_fixture(
        &context,
        context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
        vec![],
    )
    .expect("kernel assembly must succeed");

    let program_src = r#"
begin
    syscall.0x0000000000000000000000000000000000000000000000000000000000000000
end
"#;

    let program = context.parse_program(source_file!(&context, program_src)).unwrap();
    bindings.add_module(&program).unwrap();
    let assembler = bindings
        .configure(
            Assembler::with_kernel(context.source_manager(), kernel_lib)
                .expect("test kernel should be valid")
                .with_kernel_namespace_plan(kernel_home),
            [&*program],
        )
        .unwrap();
    let package = assembler
        .assemble_program("program", program)
        .expect("literal targets are keys and need no reverse implementation-root lookup");
    let literal = ProcedureKey::new(Word::default());
    let syscalls = package
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Call(call) if call.is_syscall() => Some(call.target()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(syscalls, vec![literal]);
    // Assembly has not authenticated this literal. The actual witness gates are exercised by
    // processor/tests/keyed_execution.rs::{
    // entry_authenticates_fixed_root_and_key_before_loading_authenticated_body,
    // syscall_requires_exact_full_namespace_before_code_lookup}.
}

#[test]
fn syscall_without_an_explicit_full_kernel_home_is_rejected_at_assembly_time() {
    let context = TestContext::default();

    let program_src = r#"
begin
    syscall.0x0000000000000000000000000000000000000000000000000000000000000000
end
"#;

    let program = context.parse_program(source_file!(&context, program_src)).unwrap();
    let (mut bindings, _) = kernel_fixture_namespaces();
    bindings.add_module(&program).unwrap();
    let assembler = bindings
        .configure(Assembler::new(context.source_manager()), [&*program])
        .unwrap();
    let err = assembler
        .assemble_program("program", program)
        .expect_err("expected syscall without the explicit full kernel home to be rejected");
    assert_diagnostic!(err, "syscall requires an explicit complete kernel NamespacePlan");
}

#[test]
fn kernel_exports_are_available_to_ordinary_exec_call_and_procref() {
    let context = TestContext::default();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let (kernel, kernel_bindings, _) = assemble_kernel_fixture(
        &context,
        context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
        vec![],
    )
    .expect("kernel assembly must succeed");
    let kernel_key = kernel_bindings.binding(Path::new("::$kernel::k1")).unwrap().key();

    let cases = vec![
        (
            "exec",
            "proc user\n    exec.::$kernel::k1\nend\n\nbegin\n    call.user\nend\n".to_string(),
        ),
        (
            "call",
            "proc user\n    call.::$kernel::k1\nend\n\nbegin\n    call.user\nend\n".to_string(),
        ),
        (
            "procref",
            "proc user\n    procref.::$kernel::k1\n    dropw\nend\n\nbegin\n    call.user\nend\n"
                .to_string(),
        ),
    ];

    for (kind, program_src) in cases {
        let program = context.parse_program(source_file!(&context, program_src)).unwrap();
        let mut bindings = kernel_bindings.clone();
        bindings.add_module(&program).unwrap();
        // Ordinary invocation needs the callable binding, without any SYS authorization plan.
        let assembler = bindings
            .configure(
                Assembler::with_kernel(context.source_manager(), Arc::clone(&kernel))
                    .expect("test kernel should be valid"),
                [&*program],
            )
            .unwrap();
        let package = assembler
            .assemble_program("program", program)
            .unwrap_or_else(|error| panic!("ordinary {kind} must accept a kernel export: {error}"));
        let forest = package.mast_forest();
        match kind {
            "exec" => assert!(forest.nodes().iter().any(|node| {
                matches!(node, MastNode::Exec(exec) if exec.target() == kernel_key)
            })),
            "call" => assert!(forest.nodes().iter().any(|node| {
                matches!(node, MastNode::Call(call)
                    if !call.is_syscall() && call.target() == kernel_key)
            })),
            "procref" => {
                let expected = kernel_key
                    .as_word()
                    .iter()
                    .rev()
                    .copied()
                    .map(Operation::Push)
                    .collect::<Vec<_>>();
                assert!(
                    forest.nodes().iter().any(|node| match node {
                        MastNode::Block(block) => block
                            .operations()
                            .copied()
                            .collect::<Vec<_>>()
                            .windows(expected.len())
                            .any(|window| window == expected.as_slice()),
                        _ => false,
                    }),
                    "procref must retain the key in its established stack order",
                );
            },
            _ => unreachable!("all ordinary reference cases are checked"),
        }
        assert!(
            !forest
                .nodes()
                .iter()
                .any(|node| { matches!(node, MastNode::Call(call) if call.is_syscall()) })
        );
        assert_all_nodes_reachable_from_roots(forest);
    }
    // Execution of these exports, including dynamic modes, is covered separately by
    // processor/tests/keyed_execution.rs::{
    // entry_and_ordinary_call_may_use_exports_in_the_authorized_kernel_namespace,
    // native_modes_cover_local_and_host_code_with_all_public_step_apis}.
}
