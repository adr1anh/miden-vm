// MAST TESTS
// ================================================================================================

use core::num::NonZeroU32;

use miden_core::{
    mast::BasicBlockNodeBuilder,
    program::{CanonicalLabel, ProcedureKey},
};
use miden_mast_package::{CallableProcedurePath, NamespacePlan};

use super::*;
use crate::CallableBinding;

#[test]
fn nested_blocks() -> Result<(), Report> {
    const KERNEL: &str = r#"
        pub proc foo
            add
        end"#;
    const MODULE_PROCEDURE: &str = r#"
        namespace libs::helpers

        pub proc help
            push.29
        end"#;

    let callable_path = |components: &[&str]| {
        CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| (*component).to_string()).collect(),
        )
        .unwrap()
    };
    let program_home = NamespacePlan::new(vec![
        CanonicalLabel::text("nested-blocks").unwrap(),
        CanonicalLabel::text("program").unwrap(),
    ]);
    let kernel_home = NamespacePlan::new(vec![
        CanonicalLabel::text("nested-blocks").unwrap(),
        CanonicalLabel::revision(NonZeroU32::new(1).unwrap()),
        CanonicalLabel::text("kernel").unwrap(),
        CanonicalLabel::text("syscalls").unwrap(),
    ]);
    let helper_home = NamespacePlan::new(vec![
        CanonicalLabel::text("nested-blocks").unwrap(),
        CanonicalLabel::text("dependency").unwrap(),
    ]);
    let entry_path = callable_path(&["entry", "$main"]);
    let foo_path = callable_path(&["private", "foo"]);
    let bar_path = callable_path(&["private", "bar"]);
    let kernel_foo_path = callable_path(&["foo"]);
    let helper_path = callable_path(&["helpers", "help"]);

    // Callable identities come only from the explicit homes and paths, before any body is built.
    let foo_key: ProcedureKey = program_home.callable_procedure_key(&foo_path).unwrap();
    let bar_key: ProcedureKey = program_home.callable_procedure_key(&bar_path).unwrap();
    let kernel_foo_key: ProcedureKey =
        kernel_home.callable_procedure_key(&kernel_foo_path).unwrap();
    let helper_key: ProcedureKey = helper_home.callable_procedure_key(&helper_path).unwrap();
    assert_ne!(foo_key, kernel_foo_key);

    let context = TestContext::new();
    let assembler = {
        let kernel_lib = Assembler::new(context.source_manager())
            .with_namespace_plan(kernel_home.clone())
            .with_callable_path(Path::kernel_path().join("foo").into(), kernel_foo_path.clone())
            .unwrap()
            .assemble_kernel("kernel", context.parse_kernel(source_file!(&context, KERNEL))?, None)
            .map(Arc::<Package>::from)
            .unwrap();

        let dummy_module = context.parse_module(MODULE_PROCEDURE)?;
        let dummy_library = Assembler::new(context.source_manager())
            .with_namespace_plan(helper_home.clone())
            .with_callable_path(Arc::from(Path::new("::libs::helpers::help")), helper_path.clone())
            .unwrap()
            .assemble_library("dummy", dummy_module, None::<Box<Module>>)
            .unwrap();

        let mut assembler = Assembler::with_kernel(context.source_manager(), kernel_lib)?
            .with_namespace_plan(program_home)
            .with_kernel_namespace_plan(kernel_home.clone())
            .with_callable_path(Path::exec_path().join("$main").into(), entry_path)
            .unwrap()
            .with_callable_path(Path::exec_path().join("foo").into(), foo_path)
            .unwrap()
            .with_callable_path(Path::exec_path().join("bar").into(), bar_path)
            .unwrap()
            .with_callable_binding(
                Path::kernel_path().join("foo").into(),
                CallableBinding::new(kernel_home, kernel_foo_path).unwrap(),
            )
            .unwrap()
            .with_callable_binding(
                Arc::from(Path::new("::libs::helpers::help")),
                CallableBinding::new(helper_home, helper_path).unwrap(),
            )
            .unwrap();
        assembler.link_package(Arc::from(dummy_library), Linkage::Dynamic).unwrap();

        assembler
    };

    // The expected `MastForest` for the program (that we will build by hand)
    let mut expected_mast_forest_builder = MastForestBuilder::default();

    // Keep selected kernel code as an independent external root; the syscall commits to its key.
    let syscall_foo_node_id = {
        let kernel_foo_digest =
            BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap().digest();
        let kernel_foo_external = expected_mast_forest_builder
            .ensure_external_link_with_source_ref(kernel_foo_digest, None, None, None)
            .unwrap();
        expected_mast_forest_builder.record_procedure_root_ref(kernel_foo_external);

        expected_mast_forest_builder
            .ensure_call_node_ref(
                kernel_foo_key,
                true,
                AssemblyOp::new(None, "test", 1, "syscall.foo"),
                vec![],
            )
            .unwrap()
    };

    let program = r#"
    use libs::helpers

    proc foo
        push.19
    end

    proc bar
        push.17
        exec.foo
    end

    begin
        push.2
        if.true
            push.3
        else
            push.5
        end
        if.true
            if.true
                push.7
            else
                push.11
            end
        else
            push.13
            while.true
                exec.bar
                push.23
            end
        end
        exec.helpers::help
        syscall.foo
    end"#;

    let program = assembler.assemble_program("program", program).unwrap().unwrap_program();

    // Dynamic code supply also retains D separately from the helper's keyed EXEC.
    let helper_digest = BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(29))])
        .build()
        .unwrap()
        .digest();
    let helper_external = expected_mast_forest_builder
        .ensure_external_link_with_source_ref(helper_digest, None, None, None)
        .unwrap();
    expected_mast_forest_builder.record_procedure_root_ref(helper_external);
    let exec_helper = expected_mast_forest_builder
        .ensure_exec_node_use(
            helper_key,
            AssemblyOp::new(None, "test", 1, "exec.helpers::help"),
            vec![],
        )
        .unwrap()
        .node_ref();

    // Private helpers remain independently callable roots instead of being inlined into callers.
    let foo_body = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(19))], vec![], vec![], vec![], vec![])
        .unwrap();
    expected_mast_forest_builder.record_procedure_root_ref(foo_body);
    let exec_foo = expected_mast_forest_builder
        .ensure_exec_node_use(foo_key, AssemblyOp::new(None, "test", 1, "exec.foo"), vec![])
        .unwrap()
        .node_ref();
    let push_17 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(17))], vec![], vec![], vec![], vec![])
        .unwrap();
    let bar_body = expected_mast_forest_builder
        .join_node_refs(vec![push_17, exec_foo], None)
        .unwrap();
    expected_mast_forest_builder.record_procedure_root_ref(bar_body);

    let fmp_initialization = expected_mast_forest_builder
        .ensure_block_ref(fmp_initialization_sequence(), vec![], vec![], vec![], vec![])
        .unwrap();

    let before = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(2))], vec![], vec![], vec![], vec![])
        .unwrap();

    let r#true1 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(3))], vec![], vec![], vec![], vec![])
        .unwrap();
    let r#false1 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(5))], vec![], vec![], vec![], vec![])
        .unwrap();
    let r#if1 = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true1, r#false1],
            AssemblyOp::new(None, "test", 1, "if.true"),
            vec![],
        )
        .unwrap();

    let r#true3 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(7))], vec![], vec![], vec![], vec![])
        .unwrap();
    let r#false3 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(11))], vec![], vec![], vec![], vec![])
        .unwrap();
    let r#true2 = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true3, r#false3],
            AssemblyOp::new(None, "test", 1, "if.true"),
            vec![],
        )
        .unwrap();

    let r#while = {
        let exec_bar = expected_mast_forest_builder
            .ensure_exec_node_use(bar_key, AssemblyOp::new(None, "test", 1, "exec.bar"), vec![])
            .unwrap()
            .node_ref();
        let push_23 = expected_mast_forest_builder
            .ensure_block_ref(
                vec![Operation::Push(Felt::from_u32(23))],
                vec![],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let body_node_ref = expected_mast_forest_builder
            .join_node_refs(vec![exec_bar, push_23], None)
            .unwrap();

        let asm_op = AssemblyOp::new(None, "test", 1, "while.true");
        let loop_node_ref = expected_mast_forest_builder
            .ensure_loop_node_ref(body_node_ref, asm_op.clone(), vec![])
            .unwrap();
        let noop_node_ref = expected_mast_forest_builder
            .ensure_block_ref(vec![Operation::Noop], vec![], vec![], vec![], vec![])
            .unwrap();

        expected_mast_forest_builder
            .ensure_split_node_ref([loop_node_ref, noop_node_ref], asm_op, vec![])
            .unwrap()
    };
    let push_13_basic_block_ref = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(13))], vec![], vec![], vec![], vec![])
        .unwrap();

    let r#false2 = expected_mast_forest_builder
        .join_node_refs(vec![push_13_basic_block_ref, r#while], None)
        .unwrap();
    let nested = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true2, r#false2],
            AssemblyOp::new(None, "test", 1, "if.true"),
            vec![],
        )
        .unwrap();

    let combined_node_ref = expected_mast_forest_builder
        .join_node_refs(
            vec![fmp_initialization, before, r#if1, nested, exec_helper, syscall_foo_node_id],
            None,
        )
        .unwrap();

    expected_mast_forest_builder.record_procedure_root_ref(combined_node_ref);
    let (mut expected_mast_forest, node_remapping) =
        expected_mast_forest_builder.build().unwrap().into_parts();
    expected_mast_forest.make_root(node_remapping[&combined_node_ref]);
    let expected_program =
        Program::new(expected_mast_forest.into(), node_remapping[&combined_node_ref]);
    assert_eq!(expected_program.hash(), program.hash());

    // Compare complete rooted structure without relying on final dense node numbering.
    let canonical_roots = |forest: &MastForest| {
        let mut roots = forest
            .procedure_roots()
            .iter()
            .map(|&root| {
                let node = &forest[root];
                (node.digest(), node.to_display(forest).to_string())
            })
            .collect::<Vec<_>>();
        roots.sort();
        roots
    };
    assert_eq!(
        canonical_roots(expected_program.mast_forest()),
        canonical_roots(program.mast_forest()),
    );
    assert_all_nodes_reachable_from_roots(program.mast_forest());

    let forest = program.mast_forest();
    let exec_targets = forest
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Exec(exec) => {
                assert!(!node.has_children());
                Some(exec.target())
            },
            _ => None,
        })
        .collect::<Vec<ProcedureKey>>();
    assert_eq!(exec_targets.len(), 3);
    assert_eq!(
        exec_targets.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([foo_key, bar_key, helper_key]),
    );
    let calls = forest
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Call(call) => {
                assert!(!node.has_children());
                Some((call.target(), call.is_syscall()))
            },
            _ => None,
        })
        .collect::<Vec<(ProcedureKey, bool)>>();
    assert_eq!(calls, vec![(kernel_foo_key, true)]);

    // Three local implementations plus the two selected external implementations remain roots.
    assert_eq!(program.num_procedures(), 5);
    assert_eq!(
        forest
            .procedure_roots()
            .iter()
            .filter(|&&root| forest[root].is_external())
            .count(),
        2,
    );
    for body in [foo_body, bar_body] {
        let digest = expected_program.mast_forest()[node_remapping[&body]].digest();
        assert!(program.find_procedure_root(digest).is_some());
    }

    Ok(())
}

/// Ensures that the arguments of `emit` do indeed modify the digest of a basic block
#[test]
fn emit_instruction_digest() {
    let context = TestContext::new();

    let program_source = r#"
        const EVT1 = event("miden::test::event_one")
        const EVT2 = event("miden::test::event_two")

        proc foo
            emit.EVT1
        end

        proc bar
            emit.EVT2
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();

    let procedure_digests: Vec<Word> = program.mast_forest().procedure_digests().collect();

    // foo, bar and entrypoint
    assert_eq!(3, procedure_digests.len());

    // Ensure that foo, bar and entrypoint all have different digests
    assert_ne!(procedure_digests[0], procedure_digests[1]);
    assert_ne!(procedure_digests[0], procedure_digests[2]);
    assert_ne!(procedure_digests[1], procedure_digests[2]);
}

/// Ensures that the arguments of `trace` do indeed modify the digest of a basic block.
#[test]
fn trace_instruction_digest() {
    let context = TestContext::new();

    let program_source = r#"
        const EVT1 = event("miden::test::trace_one")
        const EVT2 = event("miden::test::trace_two")

        proc foo
            trace.EVT1
        end

        proc bar
            trace.EVT2
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();

    let procedure_digests: Vec<Word> = program.mast_forest().procedure_digests().collect();

    // foo, bar and entrypoint
    assert_eq!(3, procedure_digests.len());

    // Ensure that foo, bar and entrypoint all have different digests
    assert_ne!(procedure_digests[0], procedure_digests[1]);
    assert_ne!(procedure_digests[0], procedure_digests[2]);
    assert_ne!(procedure_digests[1], procedure_digests[2]);
}

/// Tests that emitting events with immediate values has the same MAST representation
/// regardless of whether using emit.value or push.value emit syntax
#[test]
fn emit_syntax_equivalence() {
    let context = TestContext::new();

    // First program uses a constant
    let program1_source = r#"
        const EVT = event("miden::test::equiv")
        begin
            emit.EVT
        end
    "#;

    // Second program uses inline emit.event("...")
    let program2_source = r#"
        begin
            emit.event("miden::test::equiv")
        end
    "#;

    // Third program uses manual emit with constant event name
    let program3_source = r#"
        const EVT = event("miden::test::equiv")
        begin
            push.EVT
            emit
            drop
        end
    "#;

    let program1 = context.assemble(program1_source).unwrap();
    let program2 = context.assemble(program2_source).unwrap();
    let program3 = context.assemble(program3_source).unwrap();

    // Get the MAST forest digests for both programs
    let digest1 = program1.hash();
    let digest2 = program2.hash();
    let digest3 = program3.hash();

    // Both programs should have identical MAST representations
    assert_eq!(digest1, digest2, "MAST digests differ between programs 1 and 2");
    assert_eq!(digest1, digest3, "MAST digests differ between programs 1 and 3");

    // Verify the procedure count is 1 (just the entrypoint) for both programs
    assert_eq!(program1.num_procedures(), 1);
    assert_eq!(program2.num_procedures(), 1);
    assert_eq!(program3.num_procedures(), 1);
}

/// Tests that trace events have the same MAST representation regardless of whether the trace ID
/// is provided as a constant, inline event name, stack value, or fully expanded event sequence.
#[test]
fn trace_syntax_equivalence() {
    let context = TestContext::new();

    // First program uses a constant.
    let program1_source = r#"
        const EVT = event("miden::test::trace_equiv")
        begin
            trace.EVT
        end
    "#;

    // Second program uses inline trace.event("...").
    let program2_source = r#"
        begin
            trace.event("miden::test::trace_equiv")
        end
    "#;

    // Third program provides the trace ID on the stack.
    let program3_source = r#"
        const EVT = event("miden::test::trace_equiv")
        begin
            push.EVT
            trace
            drop
        end
    "#;

    // Fourth program uses the fully expanded trace event sequence.
    let program4_source = r#"
        const EVT = event("miden::test::trace_equiv")
        const SYS_TRACE = event("sys::trace_event")
        begin
            push.EVT
            push.SYS_TRACE
            emit
            drop
            drop
        end
    "#;

    let program1 = context.assemble(program1_source).unwrap();
    let program2 = context.assemble(program2_source).unwrap();
    let program3 = context.assemble(program3_source).unwrap();
    let program4 = context.assemble(program4_source).unwrap();

    let digest1 = program1.hash();
    assert_eq!(digest1, program2.hash(), "constant and inline trace forms differ");
    assert_eq!(digest1, program3.hash(), "immediate and stack trace forms differ");
    assert_eq!(digest1, program4.hash(), "trace and expanded emit forms differ");

    assert_eq!(program1.num_procedures(), 1);
    assert_eq!(program2.num_procedures(), 1);
    assert_eq!(program3.num_procedures(), 1);
    assert_eq!(program4.num_procedures(), 1);
}

/// Since `foo` and `bar` have the same body, we only expect them to be added once to the program.
#[test]
fn duplicate_procedure() {
    let context = TestContext::new();

    let program_source = r#"
        proc foo
            add
            mul
        end

        proc bar
            add
            mul
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();
    // `foo` and `bar` have the same body, so they are deduplicated. The entrypoint is the second
    // procedure.
    assert_eq!(program.num_procedures(), 2);
}

#[test]
fn distinguish_grandchildren_correctly() {
    let context = TestContext::new();

    let program_source = r#"
    begin
        if.true
            while.true
                push.2
                drop
                push.1
            end
        end

        if.true
            while.true
                push.1
            end
        end
    end
    "#;

    let program = context.assemble(program_source).unwrap();

    let join_node = &program.mast_forest()[program.entrypoint()].unwrap_join();

    // Make sure that both `if.true` blocks compile down to a different MAST node.
    assert_ne!(join_node.first(), join_node.second());
}

#[test]
fn explicit_fully_qualified_procedure_references() -> Result<(), Report> {
    const ROOT: &str = r#"
        namespace foo

        pub mod bar
        pub mod baz
    "#;
    const BAR: &str = r#"
        namespace foo::bar

        pub proc bar
            add
        end"#;
    const BAZ: &str = r#"
        namespace foo::baz

        pub proc baz
            exec.::foo::bar::bar
        end"#;

    let context = TestContext::default();
    let root = context.parse_module(ROOT)?;
    let bar = context.parse_module(BAR)?;
    let baz = context.parse_module(BAZ)?;
    let library = context.assemble_library("foo", None, root, [bar, baz]).unwrap();

    let assembler = Assembler::new(context.source_manager())
        .with_package(library.into(), Linkage::Dynamic)
        .unwrap();

    let program = r#"
    begin
        exec.::foo::baz::baz
    end"#;

    assert_matches!(assembler.assemble_program("program", program), Ok(_));
    Ok(())
}

#[test]
fn re_exports() -> Result<(), Report> {
    const BAR: &str = r#"
        namespace foo::bar

        pub proc baz
            add
        end"#;

    const BAZ: &str = r#"
        namespace foo::baz

        pub use {baz} from foo::bar

        pub proc qux
            push.1 push.2 add
        end"#;

    let context = TestContext::new();
    let bar = context.parse_module(BAR)?;
    let baz = context.parse_module(BAZ)?;
    let library = context.assemble_library("foo", None, baz, [bar]).unwrap();

    let assembler = Assembler::new(context.source_manager())
        .with_package(library.into(), Linkage::Dynamic)
        .unwrap();

    let program = r#"
    use foo::baz

    begin
        push.1 push.2
        exec.baz::baz
        push.3 push.4
        exec.baz::qux
    end"#;

    assert_matches!(assembler.assemble_program("test", program), Ok(_));
    Ok(())
}

#[test]
fn module_ordering_can_be_arbitrary() -> Result<(), Report> {
    const A: &str = r#"
        namespace a

        pub proc foo
            add
        end"#;

    const B: &str = r#"
        namespace b

        pub proc bar
            push.1 push.2 exec.::a::foo
        end"#;

    const C: &str = r#"
        namespace c

        pub proc baz
            exec.::b::bar
        end"#;

    let context = TestContext::new();
    let a = context.parse_module(A)?;
    let b = context.parse_module(B)?;
    let c = context.parse_module(C)?;

    let mut assembler = Assembler::new(context.source_manager());
    assembler.compile_and_statically_link(b)?.compile_and_statically_link(a)?;
    assembler.assemble_library("lib", c, None::<Box<Module>>)?;

    Ok(())
}
