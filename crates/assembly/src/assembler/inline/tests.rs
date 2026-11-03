use alloc::string::ToString;

use miden_core::{
    Felt, Word,
    mast::{MastNode, MastNodeExt, MastNodeId},
    operations::Operation,
    program::CanonicalLabel,
};
use miden_mast_package::{CallableProcedurePath, NamespacePlan, Package};
use miden_project::Linkage;

use super::*;
use crate::{
    CallableBinding, CallableDeclaration,
    ast::{Ident, Instruction, ItemIndex, Op},
    debuginfo::Span,
    linker::{Linker, LinkerError},
    testing::TestContext,
};

fn home(name: &str) -> NamespacePlan {
    NamespacePlan::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn binding(name: &str) -> CallableBinding {
    CallableBinding::new(
        home("foreign-canonical-home"),
        CallableProcedurePath::from_semantic_components(vec![name.to_string()]).unwrap(),
    )
    .unwrap()
}

fn assembler(context: &TestContext, definitions: &[(&str, &str)]) -> Assembler {
    let mut assembler =
        Assembler::new(context.source_manager()).with_namespace_plan(home("inline-tests"));
    for &(definition, name) in definitions {
        // Locality deliberately does not depend on choosing `with_callable_path`.
        assembler = assembler
            .with_callable_binding(Arc::from(Path::new(definition)), binding(name))
            .unwrap();
    }
    assembler
}

fn no_support() -> [alloc::boxed::Box<crate::ast::Module>; 0] {
    []
}

fn dependency(context: &TestContext) -> Arc<Package> {
    let module = context.parse_module("namespace dep\npub proc run push.7 end").unwrap();
    assembler(context, &[("::dep::run", "run")])
        .assemble_library("dep", module, no_support())
        .unwrap()
        .into()
}

fn implementation(package: &Package, path: &str) -> ImplementationRoot {
    ImplementationRoot::new(package.mast_forest()[package.get_export_node_id(path)].digest())
}

fn nodes_from(package: &Package, root: MastNodeId) -> Vec<MastNodeId> {
    let mut nodes = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        nodes.push(node);
        let mut children = Vec::new();
        package.mast_forest()[node].append_children_to(&mut children);
        pending.extend(children.into_iter().rev());
    }
    nodes
}

fn operations_from(package: &Package, root: MastNodeId) -> Vec<Operation> {
    nodes_from(package, root)
        .into_iter()
        .flat_map(|node| match &package.mast_forest()[node] {
            MastNode::Block(block) => block.operations().copied().collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .filter(|operation| *operation != Operation::Noop)
        .collect()
}

#[test]
fn local_inline_preserves_inner_runtime_keys_and_address_taken_roots() {
    let context = TestContext::default();
    let source = "\
        namespace local
        pub proc caller inline.fixed end
        proc fixed exec.callback procref.callback end
        proc callback push.9 end
        pub proc independent push.8 end
    ";
    let module = context.parse_module(source).unwrap();
    let package = assembler(
        &context,
        &[
            ("::local::caller", "caller"),
            ("::local::fixed", "fixed"),
            ("::local::callback", "callback"),
            ("::local::independent", "independent"),
        ],
    )
    .assemble_library("local", module, no_support())
    .unwrap();
    let forest = package.mast_forest();
    let caller = package.get_export_node_id("local::caller");
    let reachable = nodes_from(&package, caller);
    let execs = reachable
        .iter()
        .filter_map(|node| match &forest[*node] {
            MastNode::Exec(exec) => Some(exec.target()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(execs, vec![binding("callback").key()]);
    let expected_key = binding("callback").key().into_word();
    let pushes = operations_from(&package, caller)
        .into_iter()
        .filter_map(|op| match op {
            Operation::Push(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(pushes, expected_key.iter().rev().copied().collect::<Vec<_>>());
    assert_eq!(forest.procedure_roots().len(), 3, "caller and fixed share one structural root");
    assert!(forest.procedure_roots().iter().any(|node| {
        operations_from(&package, *node).contains(&Operation::Push(Felt::from_u32(9)))
    }));
}

#[test]
fn local_source_aliases_and_published_wrappers_keep_the_defining_keys() {
    let context = TestContext::default();
    let root = context
        .parse_module(
            "namespace local\nmod support\nuse {fixed as chosen} from local::support\n\
         pub proc caller inline.chosen end\n\
         pub proc wrapper exec.chosen end",
        )
        .unwrap();
    let support = context
        .parse_module(
            "namespace local::support\npub proc fixed exec.callback end\nproc callback push.1 end",
        )
        .unwrap();
    let package = assembler(
        &context,
        &[
            ("::local::caller", "caller"),
            ("::local::wrapper", "wrapper"),
            ("::local::support::fixed", "fixed"),
            ("::local::support::callback", "callback"),
        ],
    )
    .assemble_library("local", root, [support])
    .unwrap();
    for (name, key) in [("caller", binding("callback").key()), ("wrapper", binding("fixed").key())]
    {
        let path = format!("local::{name}");
        let root = package.get_export_node_id(path.as_str());
        let targets = nodes_from(&package, root)
            .into_iter()
            .filter_map(|node| match &package.mast_forest()[node] {
                MastNode::Exec(exec) => Some(exec.target()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(targets, vec![key]);
    }
}

#[test]
fn runtime_recursion_across_an_inline_boundary_is_allowed() {
    let context = TestContext::default();
    let module = context
        .parse_module("namespace recursive\npub proc a inline.b end\nproc b exec.a end")
        .unwrap();
    let package = assembler(&context, &[("::recursive::a", "a"), ("::recursive::b", "b")])
        .assemble_library("recursive", module, no_support())
        .unwrap();
    let forest = package.mast_forest();
    assert!(forest.nodes().iter().any(|node| matches!(node,
        MastNode::Exec(exec) if exec.target() == binding("a").key()
    )));
    assert_eq!(forest.procedure_roots().len(), 1, "equal structural roots may be interned");
}

#[test]
fn structural_inline_cycles_reject_and_link_state_rolls_back() {
    let context = TestContext::default();
    for body in [
        "namespace cyclic\npub proc a inline.a end",
        "namespace cyclic\npub proc a inline.b end\nproc b inline.a end",
        "namespace cyclic\nuse {a as alias} from cyclic\npub proc a inline.alias end",
    ] {
        let module = context.parse_module(body).unwrap();
        let mut linker = Linker::new(context.source_manager());
        let error = linker.link([module], []).unwrap_err();
        assert!(matches!(error, LinkerError::InlineCycle { .. }));
        let gid = ModuleIndex::new(0) + ItemIndex::new(0);
        assert_eq!(linker.runtime_reachable_from([gid]), vec![gid]);
        assert!(linker[ModuleIndex::new(0)].is_unlinked());
        let repeated = linker.link([], []).unwrap_err();
        assert!(matches!(repeated, LinkerError::InlineCycle { .. }));
    }
}

#[test]
fn latest_imports_reject_even_with_source_or_static_code_supply() {
    let context = TestContext::default();
    let source = "use dep\nbegin inline.dep::run end";
    for linkage in [Linkage::Dynamic, Linkage::Static] {
        let package = dependency(&context);
        let error = assembler(&context, &[("::$exec::$main", "entry"), ("::dep::run", "run")])
            .with_package(package, linkage)
            .unwrap()
            .assemble_program("caller", source)
            .unwrap_err();
        assert!(error.to_string().contains("Latest imports cannot be inlined"));
    }
    let mut assembler = assembler(&context, &[("::$exec::$main", "entry")])
        // Explicitly local naming metadata still grants no ownership of preloaded source.
        .with_callable_path(Arc::from(Path::new("::dep::run")), binding("run").path().clone())
        .unwrap();
    assembler
        .compile_and_statically_link("namespace dep\npub proc run push.7 end")
        .unwrap();
    let error = assembler.assemble_program("caller", source).unwrap_err();
    assert!(error.to_string().contains("Latest imports cannot be inlined"));
}

#[test]
fn declaration_only_latest_and_pinned_imports_have_no_inline_body() {
    let context = TestContext::default();
    for pinned in [false, true] {
        let mut assembler = assembler(&context, &[("::$exec::$main", "entry")]);
        assembler
            .link_callable_declarations(
                Arc::from(Path::new("::dep")),
                [CallableDeclaration::new(Ident::new("run").unwrap(), binding("run"))],
            )
            .unwrap();
        if pinned {
            assembler = assembler
                .with_pinned_callable(
                    Arc::from(Path::new("::dep::run")),
                    ImplementationRoot::new(Word::default()),
                )
                .unwrap();
        }
        let error = assembler
            .assemble_program("caller", "use dep\nbegin inline.dep::run end")
            .unwrap_err();
        assert!(error.to_string().contains(if pinned {
            "has no selected implementation body"
        } else {
            "Latest imports cannot be inlined"
        }));
    }
}

#[test]
fn explicit_import_pins_match_selected_code_and_survive_aliases() {
    let context = TestContext::default();
    for linkage in [Linkage::Dynamic, Linkage::Static] {
        let dependency = dependency(&context);
        let expected = implementation(&dependency, "dep::run");
        let mut assembler =
            assembler(&context, &[("::$exec::$main", "entry"), ("::dep::run", "run")])
                .with_package(dependency, linkage)
                .unwrap()
                .with_pinned_callable(Arc::from(Path::new("::dep::run")), expected)
                .unwrap();
        assembler
            .compile_and_statically_link("namespace bridge\npub use {run as chosen} from dep")
            .unwrap();
        let package = assembler
            .assemble_program("caller", "use bridge\nbegin inline.bridge::chosen end")
            .unwrap();
        assert!(
            package
                .mast_forest()
                .nodes()
                .iter()
                .all(|node| !matches!(node, MastNode::Exec(_)))
        );
    }
    let dependency = dependency(&context);
    let expected = implementation(&dependency, "dep::run");
    let mut assembler = assembler(&context, &[("::$exec::$main", "entry"), ("::dep::run", "run")])
        .with_pinned_callable(Arc::from(Path::new("::dep::run")), expected)
        .unwrap();
    assembler
        .compile_and_statically_link("namespace dep\npub proc run push.7 end")
        .unwrap();
    assembler
        .assemble_program("caller", "use dep\nbegin inline.dep::run end")
        .unwrap();
}

#[test]
fn pins_reject_wrong_roots_alias_names_and_duplicate_configuration() {
    let context = TestContext::default();
    let declaration: Arc<Path> = Arc::from(Path::new("::dep::run"));
    let wrong = ImplementationRoot::new(Word::default());
    let error = assembler(&context, &[("::$exec::$main", "entry"), ("::dep::run", "run")])
        .with_package(dependency(&context), Linkage::Static)
        .unwrap()
        .with_pinned_callable(declaration.clone(), wrong)
        .unwrap()
        .assemble_program("caller", "use dep\nbegin inline.dep::run end")
        .unwrap_err();
    assert!(error.to_string().contains("selected body has"));
    let error = assembler(&context, &[("::$exec::$main", "entry"), ("::dep::run", "run")])
        .with_package(dependency(&context), Linkage::Static)
        .unwrap()
        .with_pinned_callable(Arc::from(Path::new("::$exec::chosen")), wrong)
        .unwrap()
        .assemble_program("caller", "use {run as chosen} from dep\nbegin inline.chosen end")
        .unwrap_err();
    assert!(error.to_string().contains("does not name a concrete declaration"));
    let duplicate = assembler(&context, &[])
        .with_pinned_callable(declaration.clone(), wrong)
        .unwrap()
        .with_pinned_callable(declaration, wrong);
    assert!(
        duplicate
            .err()
            .unwrap()
            .to_string()
            .contains("duplicate inline implementation pin")
    );
}

#[test]
fn inline_key_literals_never_reverse_resolve_to_a_body() {
    let context = TestContext::default();
    let dependency = dependency(&context);
    let known_body = implementation(&dependency, "dep::run");
    let source = format!("begin inline.{} end", known_body.as_word().to_hex());
    let error = assembler(&context, &[("::$exec::$main", "entry")])
        .with_package(dependency, Linkage::Static)
        .unwrap()
        .with_pinned_callable(Arc::from(Path::new("::dep::run")), known_body)
        .unwrap()
        .assemble_program("caller", source.as_str())
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("a procedure key does not select a fixed implementation")
    );
}

#[test]
fn inline_preserves_local_frame_wrappers_on_each_expansion() {
    let context = TestContext::default();
    let source = "\
        begin inline.frame inline.frame end
        @locals(4)
        proc frame push.7 loc_store.0 loc_load.0 drop end
    ";
    let package = assembler(&context, &[("::$exec::$main", "entry"), ("::$exec::frame", "frame")])
        .assemble_program("caller", source)
        .unwrap();
    let entry = package.get_export_node_id(package.entrypoint().unwrap());
    let helper = package
        .mast_forest()
        .procedure_roots()
        .iter()
        .copied()
        .find(|node| *node != entry)
        .unwrap();
    let helper_operations = operations_from(&package, helper);
    let entry_operations = operations_from(&package, entry);
    let mut expected = crate::fmp::fmp_initialization_sequence();
    expected.extend_from_slice(&helper_operations);
    expected.extend_from_slice(&helper_operations);
    assert_eq!(entry_operations, expected);
}

#[test]
fn missing_call_site_still_clones_definition_source_occurrences() {
    let context = TestContext::default();
    let mut module = context
        .parse_module(
            "namespace local\npub proc leaf push.42 end\npub proc wrapper inline.leaf end",
        )
        .unwrap();
    for procedure in module.procedures_mut() {
        for op in procedure.body_mut().iter_mut() {
            if let Op::Inst(instruction) = op
                && matches!(instruction.inner(), Instruction::Inline(_))
            {
                *instruction = Span::new(SourceSpan::UNKNOWN, instruction.inner().clone());
            }
        }
    }
    let base = assembler(&context, &[("::local::leaf", "leaf"), ("::local::wrapper", "wrapper")]);
    let mut internal = base.clone();
    internal.emit_debug_info = false;
    let modules = internal.linker.link([module.clone()], []).unwrap();
    internal.record_assembly_modules(0);
    internal.prebind_callables().unwrap();
    let leaf = modules[0] + ItemIndex::new(0);
    let wrapper = modules[0] + ItemIndex::new(1);
    let mut builder = MastForestBuilder::new_with_static_libraries([]).unwrap();
    internal
        .compile_subgraph(crate::assembler::SubgraphRoot::not_as_entrypoint(wrapper), &mut builder)
        .unwrap();
    assert_eq!(
        builder.get_procedure(leaf).unwrap().mast_root(),
        builder.get_procedure(wrapper).unwrap().mast_root()
    );
    assert_ne!(
        builder.get_procedure(leaf).unwrap().body_source_ref(),
        builder.get_procedure(wrapper).unwrap().body_source_ref()
    );
    let with_debug = base.clone().assemble_library("local", module.clone(), no_support()).unwrap();
    let mut without_debug = base;
    without_debug.emit_debug_info = false;
    let without_debug = without_debug.assemble_library("local", module, no_support()).unwrap();
    assert!(without_debug.debug_info().unwrap().is_none());
    assert_eq!(with_debug.mast_forest().commitment(), without_debug.mast_forest().commitment());
    let debug = with_debug.debug_info().unwrap().unwrap();
    let source = |name: &str| {
        debug
            .functions()
            .iter()
            .find_map(|function| {
                let index = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
                (debug[index].as_ref() == name).then(|| function.source_node.into_option().unwrap())
            })
            .unwrap()
    };
    let leaf = source("::local::leaf");
    let wrapper = source("::local::wrapper");
    assert_ne!(leaf, wrapper);
    assert!(debug[leaf].inline_calls.is_empty());
    assert!(debug[wrapper].inline_calls.is_empty());
}

#[test]
fn nested_repeated_inline_sites_keep_same_root_definitions_distinct() {
    let context = TestContext::default();
    let module = context
        .parse_module(
            "namespace local\n\
         pub proc left push.42 end\n\
         pub proc right push.42 end\n\
         proc inner inline.left end\n\
         pub proc wrapper inline.inner inline.right inline.inner end",
        )
        .unwrap();
    let package = assembler(
        &context,
        &[
            ("::local::left", "left"),
            ("::local::right", "right"),
            ("::local::inner", "inner"),
            ("::local::wrapper", "wrapper"),
        ],
    )
    .assemble_library("local", module, no_support())
    .unwrap();
    let debug = package.debug_info().unwrap().unwrap();
    let function = |name: &str| {
        debug
            .functions()
            .iter()
            .find(|function| {
                let name_idx = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
                debug[name_idx].as_ref() == name
            })
            .unwrap()
    };
    let left = function("::local::left");
    let right = function("::local::right");
    assert_eq!(left.mast_root, right.mast_root);
    let left_source = left.source_node.into_option().unwrap();
    let right_source = right.source_node.into_option().unwrap();
    assert_ne!(left_source, right_source);
    assert!(debug[left_source].inline_calls.is_empty());
    assert!(debug[right_source].inline_calls.is_empty());
    let wrapper = function("::local::wrapper").source_node.into_option().unwrap();
    let names = debug[wrapper]
        .inline_calls
        .iter()
        .map(|row| {
            let callee = debug.get_function(row.callee_idx).unwrap();
            debug[callee.linkage_name_idx.into_option().unwrap_or(callee.name_idx)].as_ref()
        })
        .collect::<Vec<_>>();
    assert_eq!(names.iter().filter(|name| **name == "::local::left").count(), 2);
    assert_eq!(names.iter().filter(|name| **name == "::local::right").count(), 1);
    assert_eq!(names.iter().filter(|name| **name == "::local::inner").count(), 2);
}

#[test]
fn pinned_static_inline_keeps_selected_export_source_after_inventory_retention() {
    let context = TestContext::default();
    let module = context
        .parse_module(
            "namespace dep\n\
         pub proc leaf exec.callback end\n\
         pub proc wrapper push.1 inline.leaf end\n\
         proc callback push.9 end",
        )
        .unwrap();
    let dependency: Arc<Package> = assembler(
        &context,
        &[
            ("::dep::leaf", "leaf"),
            ("::dep::wrapper", "wrapper"),
            ("::dep::callback", "callback"),
        ],
    )
    .assemble_library("dep", module, no_support())
    .unwrap()
    .into();
    let expected = implementation(&dependency, "dep::leaf");
    let caller = context.parse_module("use dep\nbegin inline.dep::leaf end").unwrap();
    let call_site = caller
        .procedures()
        .flat_map(|procedure| procedure.iter())
        .find_map(|op| match op {
            Op::Inst(instruction) if matches!(instruction.inner(), Instruction::Inline(_)) => {
                Some(instruction.span())
            },
            _ => None,
        })
        .unwrap();
    let expected_location = context.source_manager().location(call_site).unwrap();
    let package = assembler(&context, &[("::$exec::$main", "entry"), ("::dep::leaf", "leaf")])
        .with_package(dependency, Linkage::Static)
        .unwrap()
        .with_pinned_callable(Arc::from(Path::new("::dep::leaf")), expected)
        .unwrap()
        .assemble_program("caller", caller)
        .unwrap();
    let entry = package.get_export_node_id(package.entrypoint().unwrap());
    let inner_keys = nodes_from(&package, entry)
        .into_iter()
        .filter_map(|node| match &package.mast_forest()[node] {
            MastNode::Exec(exec) => Some(exec.target()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(inner_keys, vec![binding("callback").key()]);
    assert!(
        package.mast_forest().procedure_roots().iter().any(|node| {
            operations_from(&package, *node).contains(&Operation::Push(Felt::from_u32(9)))
        }),
        "private runtime callback code remains available"
    );
    let debug = package.debug_info().unwrap().unwrap();
    let leaf = debug
        .functions()
        .iter()
        .find(|function| {
            let name = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
            debug[name].as_ref() == "::dep::leaf"
        })
        .unwrap();
    assert!(debug[leaf.source_node.into_option().unwrap()].inline_calls.is_empty());
    let mut pending = vec![package.entrypoint_source_node().unwrap()];
    let mut calls: Vec<&DebugSourceInlineCall> = Vec::new();
    while let Some(source) = pending.pop() {
        pending.extend(debug[source].children.iter().copied());
        calls.extend(debug[source].inline_calls.iter());
    }
    assert_eq!(
        calls.len(),
        1,
        "the dependency wrapper's inline frame must not leak into the caller"
    );
    let callee = debug.get_function(calls[0].callee_idx).unwrap();
    let name = callee.linkage_name_idx.into_option().unwrap_or(callee.name_idx);
    assert_eq!(debug[name].as_ref(), "::dep::leaf");
    assert_eq!(debug.get_location(calls[0].loc_idx).unwrap(), expected_location);
}
