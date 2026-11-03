use miden_core::{
    mast::{MastForest, MastNode},
    program::CanonicalLabel,
};

use super::*;
use crate::testing::TestContext;

fn home(name: &str) -> NamespacePlan {
    NamespacePlan::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn canonical(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_string()).collect(),
    )
    .unwrap()
}

fn target_binding() -> CallableBinding {
    CallableBinding::new(home("published-home"), canonical(&["run"])).unwrap()
}

fn root_binding() -> CallableBinding {
    CallableBinding::new(NamespacePlan::new(vec![]), canonical(&["run"])).unwrap()
}

fn lower_caller(body: Option<&str>) -> (Assembler, GlobalItemIndex, MastForest, Word) {
    let context = TestContext::default();
    let caller = context.parse_module(
        "namespace client\nuse dep as chosen\npub proc caller exec.chosen::run procref.chosen::run end",
    ).unwrap();
    let mut assembler = Assembler::new(context.source_manager())
        .with_namespace_plan(home("caller-home"))
        .with_callable_path(Arc::from(Path::new("::client::caller")), canonical(&["entry"]))
        .unwrap();
    let binding = target_binding();
    let support = match body {
        Some(body) => {
            assembler = assembler
                .with_callable_binding(Arc::from(Path::new("::dep::run")), binding)
                .unwrap();
            vec![context.parse_module(format!("namespace dep\npub proc run {body} end")).unwrap()]
        },
        None => {
            assembler
                .link_callable_declarations(
                    Arc::from(Path::new("::dep")),
                    [CallableDeclaration::new(Ident::new("run").unwrap(), binding)],
                )
                .unwrap();
            vec![]
        },
    };
    let modules = assembler.linker.link([caller], support).unwrap();
    assembler.prebind_callables().unwrap();
    let caller_module = modules
        .into_iter()
        .find(|&module| assembler.linker[module].path().as_ref() == Path::new("::client"))
        .unwrap();
    let gid = caller_module + ItemIndex::new(0);
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    assembler
        .compile_subgraph(SubgraphRoot::not_as_entrypoint(gid), &mut builder)
        .unwrap();
    let digest = builder.get_procedure(gid).unwrap().mast_root();
    let (forest, _) = builder.build().unwrap().into_parts();
    (assembler, gid, forest, digest)
}

#[test]
fn latest_without_code_and_selected_bodies_preserve_caller_identity() {
    let key = target_binding().key();
    let mut caller_digests = Vec::new();
    for body in [None, Some("push.1"), Some("push.2")] {
        let (_, _, forest, digest) = lower_caller(body);
        caller_digests.push(digest);
        let execs = forest
            .nodes()
            .iter()
            .filter_map(|node| match node {
                MastNode::Exec(exec) => Some(exec),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(execs.len(), 1);
        assert_eq!(execs[0].target(), key);
        let expected = key.into_word().iter().rev().copied().collect::<Vec<_>>();
        assert!(
            forest.nodes().iter().any(|node| match node {
                MastNode::Block(block) =>
                    block
                        .operations()
                        .filter_map(|op| match op {
                            Operation::Push(value) => Some(*value),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        == expected,
                _ => false,
            }),
            "procref must push K in the existing stack order"
        );
        assert_eq!(forest.procedure_roots().len(), if body.is_some() { 2 } else { 1 });
    }
    assert!(caller_digests.iter().all(|digest| *digest == caller_digests[0]));
}

#[test]
fn literal_words_are_keys_even_when_the_word_is_a_known_implementation_root() {
    let (assembler, caller, forest, _) = lower_caller(Some("push.1"));
    let body_root = forest
        .procedure_roots()
        .iter()
        .map(|&id| forest[id].digest())
        .find(|root| {
            assembler
                .linker
                .get_procedure_index_by_digest(root)
                .is_some_and(|gid| gid != caller)
        })
        .unwrap();
    let literal = InvocationTarget::MastRoot(miden_assembly_syntax::debuginfo::Span::new(
        SourceSpan::UNKNOWN,
        body_root,
    ));
    let resolved = assembler.resolve_target(InvokeKind::Exec, &literal, caller.module).unwrap();
    assert_eq!(resolved.key, ProcedureKey::new(body_root));
    assert_ne!(resolved.key, target_binding().key());
}

#[test]
fn caller_home_and_reachable_declaration_binding_are_required() {
    let context = TestContext::default();
    let source = "namespace client\npub proc caller push.1 end";
    let mut assembler = Assembler::new(context.source_manager());
    let modules = assembler.linker.link([context.parse_module(source).unwrap()], []).unwrap();
    assert!(
        assembler
            .prebind_callables()
            .unwrap_err()
            .to_string()
            .contains("explicit caller")
    );
    assembler = assembler.with_namespace_plan(home("caller-home"));
    assembler.prebind_callables().unwrap();
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    let result = assembler.compile_subgraph(
        SubgraphRoot::not_as_entrypoint(modules[0] + ItemIndex::new(0)),
        &mut builder,
    );
    assert!(result.unwrap_err().to_string().contains("missing canonical callable binding"));
}

#[test]
fn syscall_accepts_fixed_root_declarations_and_defers_literal_keys_to_runtime() {
    let (assembler, caller) = link_declared_caller(
        "namespace client\nuse dep as chosen\npub proc caller exec.chosen::run end",
        root_binding(),
    );
    let target = InvocationTarget::Path(miden_assembly_syntax::debuginfo::Span::new(
        SourceSpan::UNKNOWN,
        Arc::from(Path::new("::dep::run")),
    ));
    for kind in [InvokeKind::SysCall, InvokeKind::Exec, InvokeKind::Call, InvokeKind::ProcRef] {
        assert_eq!(
            assembler.resolve_target(kind, &target, caller.module).unwrap().key,
            root_binding().key(),
        );
    }

    // A literal key carries no authenticated parent at assembly time, even when the same word
    // names a known child export. Runtime resolution must enforce the fixed-root syscall rule.
    let (assembler, caller, ..) = lower_caller(None);
    let literal = InvocationTarget::MastRoot(miden_assembly_syntax::debuginfo::Span::new(
        SourceSpan::UNKNOWN,
        target_binding().key().into_word(),
    ));
    assert_eq!(
        assembler
            .resolve_target(InvokeKind::SysCall, &literal, caller.module)
            .unwrap()
            .key,
        target_binding().key(),
    );
}

fn caller_id(assembler: &Assembler) -> GlobalItemIndex {
    let module = assembler.linker.find_module_index(Path::new("::client")).unwrap();
    let index = assembler.linker[module]
        .symbols()
        .position(|symbol| symbol.name().as_str() == "caller")
        .unwrap();
    module + ItemIndex::new(index)
}

fn link_declared_caller(source: &str, binding: CallableBinding) -> (Assembler, GlobalItemIndex) {
    let context = TestContext::default();
    let caller = context.parse_module(source).unwrap();
    let mut assembler = Assembler::new(context.source_manager())
        .with_namespace_plan(home("caller-home"))
        .with_callable_path(Arc::from(Path::new("::client::caller")), canonical(&["entry"]))
        .unwrap();
    assembler
        .link_callable_declarations(
            Arc::from(Path::new("::dep")),
            [CallableDeclaration::new(Ident::new("run").unwrap(), binding)],
        )
        .unwrap();
    assembler.linker.link([caller], []).unwrap();
    assembler.prebind_callables().unwrap();
    let caller = caller_id(&assembler);
    (assembler, caller)
}

fn attached_kernel(context: &TestContext) -> Assembler {
    let mut parser = ast::Module::parser(Some(ast::ModuleKind::Kernel));
    let kernel = parser
        .parse_str(Some(Path::KERNEL), "pub proc run push.1 end", context.source_manager())
        .unwrap();
    let mut assembler = Assembler::new(context.source_manager())
        .with_namespace_plan(home("caller-home"))
        .with_callable_binding(Path::kernel_path().join("run").into(), root_binding())
        .unwrap()
        .with_callable_path(Arc::from(Path::new("::client::caller")), canonical(&["entry"]))
        .unwrap();
    assembler.linker.link_kernel(kernel, []).unwrap();
    assembler
}

#[test]
fn reexport_chains_keep_the_defining_declarations_key() {
    let context = TestContext::default();
    let caller = context.parse_module(
        "namespace client\nuse api as chosen\npub proc caller exec.chosen::exported procref.chosen::exported end",
    ).unwrap();
    let bridge = context
        .parse_module("namespace bridge\npub use {run as first} from dep")
        .unwrap();
    let api = context
        .parse_module("namespace api\npub use {first as exported} from bridge")
        .unwrap();
    let mut assembler = Assembler::new(context.source_manager())
        .with_namespace_plan(home("caller-home"))
        .with_callable_path(Arc::from(Path::new("::client::caller")), canonical(&["entry"]))
        .unwrap();
    assembler
        .link_callable_declarations(
            Arc::from(Path::new("::dep")),
            [CallableDeclaration::new(Ident::new("run").unwrap(), target_binding())],
        )
        .unwrap();
    assembler.linker.link([caller], [bridge, api]).unwrap();
    assembler.prebind_callables().unwrap();
    let caller = caller_id(&assembler);
    let target = InvocationTarget::Path(miden_assembly_syntax::debuginfo::Span::new(
        SourceSpan::UNKNOWN,
        Arc::from(Path::new("::api::exported")),
    ));
    assert_eq!(
        assembler.resolve_target(InvokeKind::Exec, &target, caller.module).unwrap().key,
        target_binding().key()
    );
    assert_eq!(
        assembler
            .resolve_target(InvokeKind::ProcRef, &target, caller.module)
            .unwrap()
            .key,
        target_binding().key()
    );
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    assembler
        .compile_subgraph(SubgraphRoot::not_as_entrypoint(caller), &mut builder)
        .unwrap();
    let (forest, _) = builder.build().unwrap().into_parts();
    assert!(forest.nodes().iter().any(|node| matches!(node,
        MastNode::Exec(exec) if exec.target() == target_binding().key()
    )));
    assert_eq!(
        forest.procedure_roots().len(),
        1,
        "re-export aliases must not fabricate callable implementation roots"
    );
}

#[test]
fn canonical_metadata_must_name_a_definition_instead_of_a_reexport_alias() {
    let context = TestContext::default();
    let bridge = context
        .parse_module("namespace bridge\npub use {run as alias} from dep")
        .unwrap();
    let mut assembler = Assembler::new(context.source_manager())
        .with_namespace_plan(home("caller-home"))
        .with_callable_path(Arc::from(Path::new("::bridge::alias")), canonical(&["renamed"]))
        .unwrap();
    assembler
        .link_callable_declarations(
            Arc::from(Path::new("::dep")),
            [CallableDeclaration::new(Ident::new("run").unwrap(), target_binding())],
        )
        .unwrap();
    assembler.linker.link([bridge], []).unwrap();
    let error = assembler.prebind_callables().unwrap_err();
    assert!(error.to_string().contains("does not name a concrete declaration"));
    let dep = assembler.linker.find_module_index(Path::new("::dep")).unwrap();
    assert_eq!(
        assembler.linker[dep + ItemIndex::new(0)].callable_binding().unwrap(),
        &target_binding(),
        "a source alias must not replace its defining declaration's binding"
    );
}

#[test]
fn callable_symbols_reject_conflicting_rebinding() {
    let (assembler, _) = link_declared_caller(
        "namespace client\nuse dep as chosen\npub proc caller exec.chosen::run end",
        target_binding(),
    );
    let dep = assembler.linker.find_module_index(Path::new("::dep")).unwrap();
    let symbol = &assembler.linker[dep + ItemIndex::new(0)];
    assert!(symbol.bind_callable(target_binding()).is_ok());
    let changed = CallableBinding::new(home("different-publisher"), canonical(&["run"])).unwrap();
    assert_ne!(changed.key(), target_binding().key());
    assert_eq!(symbol.bind_callable(changed.clone()).unwrap_err(), changed);
    assert_eq!(symbol.callable_binding(), Some(&target_binding()));
    let assembler = assembler
        .with_callable_binding(Arc::from(Path::new("::dep::run")), changed)
        .unwrap();
    let error = assembler.prebind_callables().unwrap_err();
    assert!(error.to_string().contains("conflicting callable metadata"));
    assert_eq!(
        assembler.linker[dep + ItemIndex::new(0)].callable_binding(),
        Some(&target_binding()),
        "failed frontend rebinding must preserve the original key"
    );
}

#[test]
fn unqualified_syscall_preserves_the_attached_kernel_alias_over_a_local_name() {
    let context = TestContext::default();
    let local_binding =
        CallableBinding::new(home("caller-home"), canonical(&["private", "run"])).unwrap();
    assert_ne!(local_binding.key(), root_binding().key());
    let mut assembler = attached_kernel(&context)
        .with_callable_path(Arc::from(Path::new("::client::run")), canonical(&["private", "run"]))
        .unwrap();
    let caller = context
        .parse_module(
            "namespace client\nproc run push.2 end\npub proc caller syscall.run exec.run end",
        )
        .unwrap();
    assembler.linker.link([caller], []).unwrap();
    assembler.prebind_callables().unwrap();
    let caller = caller_id(&assembler);
    let target = InvocationTarget::Symbol(Ident::new("run").unwrap());
    assert_eq!(
        assembler
            .resolve_target(InvokeKind::SysCall, &target, caller.module)
            .unwrap()
            .key,
        root_binding().key(),
        "syscall.run retains the established attached-kernel alias"
    );
    assert_eq!(
        assembler.resolve_target(InvokeKind::Exec, &target, caller.module).unwrap().key,
        local_binding.key(),
        "exec.run still resolves the caller's local procedure"
    );
    let local = caller.module + ItemIndex::new(0);
    let kernel = assembler.linker.find_module_index(Path::KERNEL).unwrap() + ItemIndex::new(0);
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    assembler
        .compile_subgraph(SubgraphRoot::not_as_entrypoint(caller), &mut builder)
        .unwrap();
    let local_body = builder.get_procedure(local).unwrap().body_node_ref();
    let kernel_body = builder.get_procedure(kernel).unwrap().body_node_ref();
    let (forest, remapping) = builder.build().unwrap().into_parts();
    assert!(forest.procedure_roots().contains(&remapping[&local_body]));
    assert!(forest.procedure_roots().contains(&remapping[&kernel_body]));
    assert!(forest.nodes().iter().any(|node| matches!(node,
        MastNode::Exec(exec) if exec.target() == local_binding.key()
    )));
    assert!(forest.nodes().iter().any(|node| matches!(node,
        MastNode::Call(call) if call.is_syscall() && call.target() == root_binding().key()
    )));
}

#[test]
fn unqualified_syscall_accepts_a_caller_alias_to_the_same_defining_symbol() {
    let context = TestContext::default();
    let mut assembler = attached_kernel(&context);
    let caller = context
        .parse_module("namespace client\nuse {run} from $kernel\npub proc caller syscall.run end")
        .unwrap();
    assembler.linker.link([caller], []).unwrap();
    assembler.prebind_callables().unwrap();
    let caller = caller_id(&assembler);
    let target = InvocationTarget::Symbol(Ident::new("run").unwrap());
    assert_eq!(
        assembler
            .resolve_target(InvokeKind::SysCall, &target, caller.module)
            .unwrap()
            .key,
        root_binding().key()
    );
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    assembler
        .compile_subgraph(SubgraphRoot::not_as_entrypoint(caller), &mut builder)
        .unwrap();
    let (forest, _) = builder.build().unwrap().into_parts();
    assert!(forest.nodes().iter().any(|node| matches!(node,
        MastNode::Call(call) if call.is_syscall() && call.target() == root_binding().key()
    )));
}

#[test]
fn unqualified_syscall_uses_a_caller_import_when_the_attached_kernel_has_no_candidate() {
    let context = TestContext::default();
    let binding =
        CallableBinding::new(root_binding().namespace_plan().clone(), canonical(&["other"]))
            .unwrap();
    let mut assembler = attached_kernel(&context);
    assembler
        .link_callable_declarations(
            Arc::from(Path::new("::dep")),
            [CallableDeclaration::new(Ident::new("other").unwrap(), binding.clone())],
        )
        .unwrap();
    let caller = context
        .parse_module("namespace client\nuse {other} from dep\npub proc caller syscall.other end")
        .unwrap();
    assembler.linker.link([caller], []).unwrap();
    assembler.prebind_callables().unwrap();
    let caller = caller_id(&assembler);
    let target = InvocationTarget::Symbol(Ident::new("other").unwrap());
    assert_eq!(
        assembler
            .resolve_target(InvokeKind::SysCall, &target, caller.module)
            .unwrap()
            .key,
        binding.key()
    );
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    assembler
        .compile_subgraph(SubgraphRoot::not_as_entrypoint(caller), &mut builder)
        .unwrap();
    let (forest, _) = builder.build().unwrap().into_parts();
    assert!(forest.nodes().iter().any(|node| matches!(node,
        MastNode::Call(call) if call.is_syscall() && call.target() == binding.key()
    )));
}

#[test]
fn syscall_rejects_child_exports_including_textual_kernel_homes() {
    let bindings = [
        target_binding(),
        CallableBinding::new(home("kernel"), canonical(&["run"])).unwrap(),
        CallableBinding::new(NamespacePlan::new(vec![]), canonical(&["child", "run"])).unwrap(),
        CallableBinding::new(
            NamespacePlan::new(vec![
                CanonicalLabel::text("publisher").unwrap(),
                CanonicalLabel::text("kernel").unwrap(),
            ]),
            canonical(&["run"]),
        )
        .unwrap(),
    ];
    for binding in bindings {
        let (assembler, caller) = link_declared_caller(
            "namespace client\nuse dep as chosen\npub proc caller exec.chosen::run end",
            binding.clone(),
        );
        let target = InvocationTarget::Path(miden_assembly_syntax::debuginfo::Span::new(
            SourceSpan::UNKNOWN,
            Arc::from(Path::new("::dep::run")),
        ));
        for kind in [InvokeKind::Exec, InvokeKind::Call, InvokeKind::ProcRef] {
            assert_eq!(
                assembler.resolve_target(kind, &target, caller.module).unwrap().key,
                binding.key(),
                "ordinary invocation remains available for child exports",
            );
        }
        let error = assembler
            .resolve_target(InvokeKind::SysCall, &target, caller.module)
            .err()
            .expect("only the fixed initial parent authorizes a known syscall target");
        assert!(error.to_string().contains("outside the fixed root syscall namespace"));
    }
}

#[test]
fn call_and_syscall_nodes_retain_keys_and_source_operations_without_code() {
    let (mut assembler, caller) = link_declared_caller(
        "namespace client\nuse dep as chosen\npub proc caller call.chosen::run syscall.chosen::run end",
        root_binding(),
    );
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    assembler
        .compile_subgraph(SubgraphRoot::not_as_entrypoint(caller), &mut builder)
        .unwrap();
    let (forest, _, debug, _) = builder.build().unwrap().into_parts_with_debug_info();
    let calls = forest
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Call(call) => Some(call),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|call| call.target() == root_binding().key()));
    assert_eq!(calls.iter().filter(|call| call.is_syscall()).count(), 1);
    let sources = debug
        .nodes()
        .iter()
        .filter(|source| matches!(&forest[source.exec_node], MastNode::Call(_)))
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 2);
    for source in sources {
        assert!(source.children.is_empty(), "keyed calls have no callee source child");
        assert!(source.inline_calls.is_empty(), "runtime calls must not invent inline call rows");
        assert_eq!(source.asm_ops.len(), 1);
        assert_eq!(source.asm_ops[0].num_cycles, 1);
        let op = debug[source.asm_ops[0].op_name_idx].as_ref();
        let MastNode::Call(call) = &forest[source.exec_node] else {
            unreachable!("source selection contains only keyed calls")
        };
        assert_eq!(
            op,
            if call.is_syscall() {
                "syscall.chosen::run"
            } else {
                "call.chosen::run"
            }
        );
    }
    assert_eq!(
        forest.procedure_roots().len(),
        1,
        "declaration-only calls must not fabricate an implementation root"
    );
}
