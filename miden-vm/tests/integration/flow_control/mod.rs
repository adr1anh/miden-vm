use alloc::sync::Arc;

use miden_assembly::{
    Assembler, DefaultSourceManager, Parse, PathBuf, Report, ast::ModuleKind,
    testing::FixtureNamespace,
};
use miden_core::program::ProcedureKey;
use miden_core_lib::CoreLibrary;
use miden_mast_package::{CallableProcedurePath, TargetType};
use miden_processor::{
    ExecutionError,
    operation::{BinaryValueErrorContext, OperationError},
};
use miden_utils_testing::{
    Test, build_debug_test, build_test, expect_exec_error_matches,
    librarytree::assemble_fixture_program, push_inputs,
};
use miden_vm::Module;

/// Derives the expected identity from the fixture owner's declared home/path, independently of
/// code digests, forest ordering, or the processor's observed stack outputs.
fn fixture_procedure_key(test: &Test, procedure: &str) -> ProcedureKey {
    let module = test
        .source
        .clone()
        .parse(false, test.source_manager.clone())
        .expect("test source must parse in its original source manager");
    let mut fixture = FixtureNamespace::assembly_tests();
    fixture
        .add_module(&module)
        .expect("test procedures must have canonical local bindings");
    fixture
        .binding(&module.path().join(procedure))
        .expect("expected local procedure must have a fixture binding")
        .key()
}

// SIMPLE FLOW CONTROL TESTS
// ================================================================================================

#[test]
fn conditional_execution() {
    // --- if without else ------------------------------------------------------------------------
    let source = "begin dup.1 dup.1 eq if.true add end end";

    // Stack [2, 1] with 2 on top - different values, no add
    let test = build_test!(source, &[2, 1]);
    test.expect_stack(&[2, 1]);

    let test = build_test!(source, &[3, 3]);
    test.expect_stack(&[6]);

    // --- if with else ------------------------------------------------------------------------
    let source = "begin dup.1 dup.1 eq if.true add else mul end end";

    let test = build_test!(source, &[2, 3]);
    test.expect_stack(&[6]);

    let test = build_test!(source, &[3, 3]);
    test.expect_stack(&[6]);
}

#[test]
fn conditional_loop() {
    // --- entering the loop ----------------------------------------------------------------------
    // computes sum of values from 0 to the value at the top of the stack
    let source = "
        begin
            dup push.0 movdn.2 neq.0
            while.true
                dup movup.2 add swap push.1 sub dup neq.0
            end
            drop
        end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[55]);

    // --- skipping the loop ----------------------------------------------------------------------
    let source = "begin dup eq.0 while.true add end end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[10]);
}

#[test]
fn unentered_loop_with_following_block() {
    let source = "
        begin
            push.2 push.1 push.0
            while.true
                push.3 drop
            end
            drop drop
        end";

    let test = build_test!(source);
    test.check_constraints();
}

#[test]
fn faulty_condition_from_loop() {
    let source = "
        begin
            push.1
            while.true
                push.100
            end
            drop
        end";

    let test = build_test!(source, &[10]);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::NotBinaryValue {
                context: BinaryValueErrorContext::Loop,
                value: _,
            },
            ..
        }
    );
}

#[test]
fn tail_controlled_loop() {
    // --- multiple iterations --------------------------------------------------------------------
    // Count down from the top of the stack to 0; the body runs `n` times.
    let source = "
        begin
            do
                push.1 sub
            while
                dup neq.0
            end
        end";

    let test = build_test!(source, &[3]);
    test.expect_stack(&[0]);

    // --- body always runs at least once ---------------------------------------------------------
    // Unlike `while.true`, a `do`..`while` executes its body before evaluating the condition, so
    // the `add` runs once even though the condition is immediately false.
    let source = "
        begin
            do
                add
            while
                push.0
            end
        end";

    let test = build_test!(source, &[5, 3]);
    test.expect_stack(&[8]);
}

#[test]
fn faulty_condition_from_tail_controlled_loop() {
    // A non-binary loop condition fails directly in the LOOP's tail check (no SPLIT wrapper).
    let source = "
        begin
            do
                push.100
            while
                push.2
            end
        end";

    let test = build_test!(source, &[10]);
    expect_exec_error_matches!(
        test,
        ExecutionError::OperationError {
            err: OperationError::NotBinaryValue { .. },
            ..
        }
    );
}

#[test]
fn counter_controlled_loop() {
    // --- entering the loop ----------------------------------------------------------------------
    // compute 2^10
    let source = "
        begin
            push.2
            push.1
            repeat.10
                dup.1 mul
            end
            movdn.2 drop drop
        end";

    let test = build_test!(source);
    test.expect_stack(&[1024]);
}

// NESTED CONTROL FLOW
// ================================================================================================

#[test]
fn if_in_loop() {
    let source = "
        begin
            dup push.0 movdn.2 neq.0
            while.true
                dup movup.2 dup.1 eq.5
                if.true
                    mul
                else
                    add
                end
                swap push.1 sub dup neq.0
            end
            drop
        end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[210]);
}

#[test]
fn if_in_loop_in_if() {
    let source = "
        begin
            dup eq.10
            if.true
                dup push.0 movdn.2 neq.0
                while.true
                    dup movup.2 dup.1 eq.5
                    if.true
                        mul
                    else
                        add
                    end
                    swap push.1 sub dup neq.0
                end
                drop
            else
                dup mul
            end
        end";

    let test = build_test!(source, &[10]);
    test.expect_stack(&[210]);

    let test = build_test!(source, &[11]);
    test.expect_stack(&[121]);
}

// FUNCTION CALLS
// ================================================================================================

#[test]
fn local_fn_call() {
    // returning from a function with non-empty overflow table should result in an error
    let source = "
        proc foo
            push.1
        end

        begin
            call.foo
        end";

    let build_test = build_test!(source, &[1, 2]);
    expect_exec_error_matches!(
        build_test,
        ExecutionError::OperationError {
            err: OperationError::InvalidStackDepthOnReturn { depth: 17 },
            ..
        }
    );

    let inputs = (1_u64..18).collect::<Vec<_>>();

    // dropping values from the stack in the current execution context should not affect values
    // in the overflow table from the parent execution context
    let source = format!(
        "
        proc foo
            repeat.20
                drop
            end
        end

        begin
            {inputs}
            push.18
            call.foo
            repeat.16
                drop
            end

            swapw dropw
        end",
        inputs = push_inputs(&inputs)
    );

    let test = build_test!(source, &[]);
    test.expect_stack(&[2, 1]);

    test.check_constraints();
}

#[test]
fn local_fn_call_with_mem_access() {
    // foo should be executed in a different memory context; thus, when we read from memory after
    // calling foo, the value saved into memory[0] before calling foo should still be there.
    let source = "
        proc foo
            mem_store.0
        end

        begin
            mem_store.0
            call.foo
            mem_load.0
            eq.7

            swap drop
        end";

    // Stack [7, 3] with 7 on top - stores 7 in outer context, 3 in foo's context
    let test = build_test!(source, &[7, 3]);
    test.expect_stack(&[1]);

    test.check_constraints();
}

#[test]
fn simple_syscall() {
    let kernel_source = "
        pub proc foo
            add
        end
    ";

    let program_source = "
        begin
            syscall.foo
        end";

    let test = build_test!(program_source, &[1, 2]).with_kernel(kernel_source);
    test.expect_stack(&[3]);

    test.check_constraints();
}

#[test]
fn simple_syscall_2() {
    let kernel_source = "
        pub proc foo
            add
        end
        pub proc bar
            mul
        end
    ";

    // Note: we call each twice to ensure that the multiset check handles it correctly
    let program_source = "
        begin
            syscall.foo
            syscall.foo
            syscall.bar
            syscall.bar
        end";

    // Stack [1, 2, 3, 2, 2] with 1 on top
    // foo(1+2=3), foo(3+3=6), bar(6*2=12), bar(12*2=24) => 24
    let test = build_test!(program_source, &[1, 2, 3, 2, 2]).with_kernel(kernel_source);
    test.expect_stack(&[24]);

    test.check_constraints();
}

/// Tests that `CALL`ing from a syscall context works correctly, especially in terms of properly
/// handling the fmp (through procedure locals).
///
/// The flow is as follows:
/// new_ctx (program) -> first_kernel_entry (syscall) -> userland (call) -> second_kernel_entry
/// (syscall)
#[test]
fn call_in_syscall() {
    let kernel_source = "
        # USER CONTEXT FUNCTIONS (i.e. not 0)
        # ====================================================================================

        @locals(4)
        proc userland
            # Ensure that the memory locals are fresh before we write to them
            loc_loadw_be.0 assertz assertz assertz assertz

            # Write to memory locals, which should not affect context 0 memory
            push.5.6.7.8 loc_storew_be.0 dropw

            # Syscall back into context 0
            syscall.second_kernel_entry

            # Ensure that procedure locals were untouched
            loc_loadw_be.0 push.5.6.7.8 assert_eqw
        end

        # CONTEXT 0 FUNCTIONS
        # ====================================================================================

        @locals(4)
        pub proc second_kernel_entry
            # Ensure that the memory locals are fresh before we write to them
            loc_loadw_be.0 assertz assertz assertz assertz

            # Write to procedure locals. We will later ensure that this write didn't affect procedure locals
            # in first_kernel_entry.
            push.9.10.11.12 loc_storew_be.0 dropw
        end

        @locals(4)
        pub proc first_kernel_entry
            # Ensure that the memory locals are fresh before we write to them
            loc_loadw_be.0 assertz assertz assertz assertz

            # Write to memory locals. We will ensure at the end that these values are still present
            push.1.2.3.4 loc_storew_be.0 dropw

            # Call userland, which will syscall back into context 0
            call.userland

            # Ensure that procedure locals were untouched
            loc_loadw_be.0 push.1.2.3.4 assert_eqw
        end
    ";

    let program_source = "
        proc new_ctx
            syscall.first_kernel_entry
        end

        begin
            # Call into a new context which will syscall back into context 0.
            call.new_ctx
        end";

    let test = build_test!(program_source).with_kernel(kernel_source);
    test.expect_stack(&[]);

    test.check_constraints();
}

/// Tests that syscalling back into context 0 uses a different overflow table with each call.
#[test]
fn root_context_separate_overflows() {
    let kernel_source = "
    pub proc foo
        # Drop an element, which in the failing case removes the `100` from the overflow table
        drop
    end
    ";

    let program_source = "
    proc bar
        syscall.foo
    end

    begin
        # => [100]

        # push `100` on overflow stack
        swap.15 push.0

        # Call `bar`, which will syscall back into this context
        call.bar

        # Place back the 100 on top of the stack
        drop swap.15
    end";

    let test = build_test!(program_source, &[100]).with_kernel(kernel_source);
    test.expect_stack(&[100]);
    test.check_constraints();
}

// DYNAMIC CODE EXECUTION
// ================================================================================================

#[test]
fn simple_dyn_exec() {
    let program_source = "
        proc foo
            add
        end

        begin
            # call foo directly
            call.foo

            # move the first result of foo out of the way
            movdn.4

            # use dynexec to call foo again via its key, which is stored at memory location 40
            mem_storew_le.40 dropw
            push.40
            dynexec
        end";

    let test = build_debug_test!(program_source);
    let foo_key = fixture_procedure_key(&test, "foo").into_word();

    // Build stack inputs with foo's independently derived callable key.
    // We want the stack after call.foo + movdn.4 to be:
    //   [key[0], key[1], key[2], key[3], 3, 3, ...]
    // where key[0] is on top.
    let stack_init: [u64; 7] = [
        2,
        1,
        foo_key[0].as_canonical_u64(),
        foo_key[1].as_canonical_u64(),
        foo_key[2].as_canonical_u64(),
        foo_key[3].as_canonical_u64(),
        3,
    ];

    let test = test.with_stack_inputs(stack_init);

    test.expect_stack(&[6]);

    test.check_constraints();
}

#[test]
fn dynexec_with_procref() {
    let program_source = "
    use external::module

    proc foo
        push.1.2
        u32wrapping_add
    end

    begin
        procref.foo mem_storew_le.40 dropw push.40
        dynexec

        procref.module::func mem_storew_le.40 dropw push.40
        dynexec

        dup
        push.4
        assert_eq.err=\"101\"

        swap drop
    end";

    let core_lib = CoreLibrary::default();
    let test = build_test!(program_source, &[])
        .with_library_and_naming(core_lib.package(), core_lib.naming().clone())
        .with_module(
            "external::module",
            "\
            namespace external::module

            pub proc func
                u32wrapping_add.1
            end
            ",
        );

    test.expect_stack(&[4]);
}

#[test]
fn simple_dyncall() {
    let program_source = "
        proc foo
            # test that the execution context has changed
            mem_load.0 assertz

            # add the two values on top of the stack
            add
        end

        begin
            # write to memory so we can test that `call` and `dyncall` change the execution context
            push.5 mem_store.0

            # call foo directly
            call.foo

            # move the first result of foo out of the way
            movdn.4

            # use dyncall to call foo again via its key, which is on the stack
            mem_storew_le.40 dropw
            push.40
            dyncall

            swapw dropw
        end";

    let test = build_test!(program_source);
    let foo_key = fixture_procedure_key(&test, "foo").into_word();

    let stack_init: [u64; 7] = [
        2,
        1,
        foo_key[0].as_canonical_u64(),
        foo_key[1].as_canonical_u64(),
        foo_key[2].as_canonical_u64(),
        foo_key[3].as_canonical_u64(),
        3,
    ];

    let core_lib = CoreLibrary::default();
    let test = test
        .with_stack_inputs(stack_init)
        .with_library_and_naming(core_lib.package(), core_lib.naming().clone())
        .with_event_handlers(core_lib.handlers());

    test.expect_stack(&[6]);

    test.check_constraints();
}

/// Calls `bar` dynamically, which issues a syscall. We ensure that the `caller` instruction in the
/// kernel procedure correctly returns the requested callable key of `bar`.
///
/// We also populate the stack before `dyncall` to ensure that stack depth is properly restored
/// after `dyncall`.
#[test]
fn dyncall_with_syscall_and_caller() {
    let kernel_source = "
        pub proc foo
            caller
        end
    ";

    let program_source = "
        proc bar
            syscall.foo
        end

        begin
            # Populate stack before call
            push.1 push.2 push.3 push.4 padw

            # Prepare dyncall
            procref.bar mem_storew_le.40 dropw push.40
            dyncall

            # Truncate stack
            movupw.3 dropw movupw.3 dropw
        end";

    let test = build_debug_test!(program_source).with_kernel(kernel_source);

    let bar_key = fixture_procedure_key(&test, "bar").into_word();

    // SYSCALL preserves the principal established by the dynamic call to bar. CALLER pushes
    // that requested key with element[0] on top, followed by the caller's original stack.
    test.expect_stack(&[
        bar_key[0].as_canonical_u64(),
        bar_key[1].as_canonical_u64(),
        bar_key[2].as_canonical_u64(),
        bar_key[3].as_canonical_u64(),
        4,
        3,
        2,
        1,
    ]);

    test.check_constraints();
}

// PROCREF INSTRUCTION
// ================================================================================================

#[test]
fn procref() -> Result<(), Report> {
    let module_source = "
    namespace test::foo

    pub use {overflowing_add} from miden::core::math::u64

    @locals(4)
    pub proc foo
        push.3.4
    end
    ";

    let core_lib = CoreLibrary::default();
    let (library, library_naming, module_foo_key) = {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let module_path = PathBuf::new("test::foo").unwrap();
        let mut parser = Module::parser(Some(ModuleKind::Library));
        let module =
            parser.parse_str(Some(module_path.as_path()), module_source, source_manager.clone())?;
        let mut fixture = FixtureNamespace::assembly_tests();
        fixture.add_module(&module)?;
        let module_foo_key = fixture.binding(&module.path().join("foo")).unwrap().key();
        let assembler = fixture.configure(Assembler::new(source_manager), [&*module])?;
        let product = assembler
            .with_package(core_lib.code_package().clone(), miden_assembly::Linkage::Dynamic)
            .unwrap()
            .assemble_library_modules("test".into(), module, [], TargetType::Library)?;
        let naming = Arc::new(product.naming().clone());
        let package: Arc<miden_mast_package::Package> = Arc::from(product.into_artifact(true)?);
        (package, naming, module_foo_key)
    };

    let source = "
    use miden::core::math::u64
    use miden::core::sys
    use test::foo as reexported

    @locals(4)
    proc foo
        push.3.4
    end

    begin
        # A public reexport preserves the exact Core defining key.
        procref.u64::overflowing_add
        procref.reexported::overflowing_add
        assert_eqw

        procref.reexported::overflowing_add
        procref.reexported::foo
        push.0
        procref.foo

        exec.sys::truncate_stack
    end";

    let test = build_test!(source, &[])
        .with_library_and_naming(core_lib.package(), core_lib.naming().clone())
        .with_library_and_naming(library.clone(), library_naming.clone())
        .with_event_handlers(core_lib.handlers());

    let local_foo_key = fixture_procedure_key(&test, "foo");
    let core_path = CallableProcedurePath::from_semantic_components(
        ["miden", "core", "math", "u64", "overflowing_add"]
            .into_iter()
            .map(String::from)
            .collect(),
    )
    .unwrap();
    let core_key = core_lib.naming().callables().key_for_visible_path(&core_path).unwrap();
    let reexport_path = CallableProcedurePath::from_semantic_components(
        ["test", "foo", "overflowing_add"].into_iter().map(String::from).collect(),
    )
    .unwrap();
    assert_eq!(library_naming.callables().key_for_visible_path(&reexport_path), Some(core_key));
    assert_ne!(
        module_foo_key, local_foo_key,
        "distinct defining paths must retain distinct keys"
    );

    // Equal bodies do not merge the independently declared module and program identities.
    let named = assemble_fixture_program(
        Assembler::new(test.source_manager.clone())
            .with_package(core_lib.code_package().clone(), miden_assembly::Linkage::Dynamic)?
            .with_package(
                miden_assembly::CodePackage::new(library, library_naming.clone())
                    .map_err(Report::msg)?,
                miden_assembly::Linkage::Dynamic,
            )?,
        "procref_identities",
        test.source.clone(),
        &[core_lib.naming().as_ref(), library_naming.as_ref()],
    );
    assert_eq!(
        named
            .0
            .symbols()
            .callables()
            .selected_implementation(local_foo_key)
            .expect("local foo must retain its implementation"),
        library_naming
            .callables()
            .selected_implementation(module_foo_key)
            .expect("module foo must retain its implementation"),
    );

    let local_foo = local_foo_key.into_word();
    let module_foo = module_foo_key.into_word();
    let core = core_key.into_word();
    // PROCREF pushes key element[0] on top. Check both equal-body identities and the reexport.
    test.expect_stack(&[
        local_foo[0].as_canonical_u64(),
        local_foo[1].as_canonical_u64(),
        local_foo[2].as_canonical_u64(),
        local_foo[3].as_canonical_u64(),
        0,
        module_foo[0].as_canonical_u64(),
        module_foo[1].as_canonical_u64(),
        module_foo[2].as_canonical_u64(),
        module_foo[3].as_canonical_u64(),
        core[0].as_canonical_u64(),
        core[1].as_canonical_u64(),
        core[2].as_canonical_u64(),
        core[3].as_canonical_u64(),
    ]);

    test.check_constraints();
    Ok(())
}
