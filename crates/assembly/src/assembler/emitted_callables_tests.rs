use miden_core::{mast::MastNode, program::CanonicalLabel};

use super::*;
use crate::testing::{FixtureNamespace, TestContext};

fn home(name: &str) -> NamespacePath {
    NamespacePath::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn canonical(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_string()).collect(),
    )
    .unwrap()
}

#[test]
fn emitted_inventory_retains_private_roots_aliases_and_distinct_wrappers() {
    let context = TestContext::default();
    let root = context
        .parse_module(
            "namespace api\npub use {run as original, run as alias, wrapper} from implementation",
        )
        .unwrap();
    let definitions = context
        .parse_module(
            "namespace implementation\n\
             proc callback push.7 end\n\
             proc hidden push.7 end\n\
             pub proc run procref.callback end\n\
             pub proc wrapper exec.run end",
        )
        .unwrap();
    let mut names = FixtureNamespace::assembly_tests();
    names.add_module(&definitions).unwrap();
    let expected =
        |name: &str| names.binding(&Path::new("::implementation").join(name)).unwrap().clone();
    let callback = expected("callback");
    let hidden = expected("hidden");
    let run = expected("run");
    let wrapper = expected("wrapper");
    let product = names
        .configure(Assembler::new(context.source_manager()), [&*root, &*definitions])
        .unwrap()
        .assemble_library_modules("test".into(), root, [definitions], TargetType::Library)
        .unwrap();

    assert_eq!(product.callables().bindings().len(), 4);
    assert_eq!(product.callables().selected_implementations().len(), 4);
    for binding in [&callback, &hidden, &run, &wrapper] {
        assert_eq!(product.callables().binding(binding.key()), Some(binding));
    }
    assert_eq!(
        product.callables().key_for_visible_path(&canonical(&["api", "original"])),
        Some(run.key()),
    );
    assert_eq!(
        product.callables().key_for_visible_path(&canonical(&["api", "alias"])),
        Some(run.key()),
    );
    assert_eq!(
        product.callables().key_for_visible_path(&canonical(&["api", "wrapper"])),
        Some(wrapper.key()),
    );
    assert_ne!(run.key(), wrapper.key());
    assert_ne!(callback.key(), hidden.key());
    assert_eq!(
        product.callables().selected_implementation(callback.key()),
        product.callables().selected_implementation(hidden.key()),
        "equal bodies must retain both distinct callable identities",
    );
    assert_eq!(
        product.callable_key_for_definition(Path::new("::implementation::run")),
        Some(run.key()),
    );
    assert_eq!(product.callable_key_for_definition(Path::new("::api::alias")), None);
    let callback_source = product
        .callable_source_for_definition(Path::new("::implementation::callback"))
        .unwrap();
    let hidden_source = product
        .callable_source_for_definition(Path::new("::implementation::hidden"))
        .unwrap();
    assert_ne!(callback_source.1, hidden_source.1);
    let wrapper_source = product
        .callable_source_for_definition(Path::new("::implementation::wrapper"))
        .unwrap();
    let selected_wrapper = product.callables().selected_implementation(wrapper.key()).unwrap();
    assert_eq!(product.entry_key(), None);

    let package = product.into_artifact(true).unwrap();
    assert_eq!(
        ImplementationRoot::new(package.mast_forest()[wrapper_source.0].digest()),
        selected_wrapper,
    );
    assert!(matches!(
        &package.mast_forest()[wrapper_source.0],
        MastNode::Exec(exec) if exec.target() == run.key()
    ));
    assert!(package.mast_forest().procedure_roots().contains(&callback_source.0));
    assert!(package.mast_forest().procedure_roots().contains(&hidden_source.0));
    let debug = package.debug_info().unwrap().unwrap();
    assert_eq!(debug[callback_source.1].exec_node, callback_source.0);
    assert_eq!(debug[hidden_source.1].exec_node, hidden_source.0);
}

#[test]
fn emitted_inventory_coalesces_declaration_aliases_without_selected_code() {
    let context = TestContext::default();
    let root = context
        .parse_module("namespace client\nuse left\nuse right\npub proc caller exec.left::run exec.right::run end")
        .unwrap();
    let caller = ProcedureName::new(home("caller"), canonical(&["public", "caller"])).unwrap();
    let dependency = ProcedureName::new(home("dependency"), canonical(&["run"])).unwrap();
    let mut assembler = Assembler::new(context.source_manager())
        .with_namespace_plan(caller.namespace_plan().clone())
        .with_callable_path(Arc::from(Path::new("::client::caller")), caller.path().clone())
        .unwrap();
    for path in ["::left", "::right"] {
        assembler
            .link_callable_declarations(
                Arc::from(Path::new(path)),
                [CallableDeclaration::new(Ident::new("run").unwrap(), dependency.clone())],
            )
            .unwrap();
    }
    let product = assembler
        .assemble_library_modules("test".into(), root, [], TargetType::Library)
        .unwrap();

    assert_eq!(product.callables().bindings().len(), 2);
    assert_eq!(product.callables().binding(dependency.key()), Some(&dependency));
    assert_eq!(product.callables().selected_implementation(dependency.key()), None);
    assert_eq!(product.callables().selected_implementations().len(), 1);
    for path in ["::left::run", "::right::run"] {
        assert_eq!(product.callable_key_for_definition(Path::new(path)), Some(dependency.key()));
        assert_eq!(product.callable_source_for_definition(Path::new(path)), None);
    }
    assert_eq!(
        product.callables().key_for_visible_path(&canonical(&["client", "caller"])),
        Some(caller.key()),
    );
}

#[test]
fn emitted_inventory_coalesces_imported_compiled_reexport_aliases() {
    let context = TestContext::default();
    let root = context
        .parse_module("namespace api\npub use {run as first, run as second} from implementation")
        .unwrap();
    let implementation = context
        .parse_module("namespace implementation\npub proc run push.7 end")
        .unwrap();
    let mut names = FixtureNamespace::new(home("published-home"));
    names.add_module(&implementation).unwrap();
    let target = names.binding(Path::new("::implementation::run")).unwrap().clone();
    let package = names
        .configure(Assembler::new(context.source_manager()), [&*root, &*implementation])
        .unwrap()
        .assemble_library_modules("published".into(), root, [implementation], TargetType::Library)
        .unwrap();
    let package = package.into_code_package(true).unwrap();
    let caller = context
        .parse_module(
            "namespace client\nuse api\npub proc caller exec.api::first exec.api::second end",
        )
        .unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_plan(home("caller-home"))
        .with_callable_path(Arc::from(Path::new("::client::caller")), canonical(&["caller"]))
        .unwrap()
        .with_package(package, Linkage::Static)
        .unwrap()
        .with_callable_binding(Arc::from(Path::new("::api::first")), target.clone())
        .unwrap()
        .with_callable_binding(Arc::from(Path::new("::api::second")), target.clone())
        .unwrap()
        .assemble_library_modules("caller".into(), caller, [], TargetType::Library)
        .unwrap();

    assert_eq!(product.callables().bindings().len(), 2);
    assert_eq!(product.callables().selected_implementations().len(), 2);
    assert_eq!(product.callables().binding(target.key()), Some(&target));
    let first = product.callable_source_for_definition(Path::new("::api::first")).unwrap();
    let second = product.callable_source_for_definition(Path::new("::api::second")).unwrap();
    for path in ["::api::first", "::api::second"] {
        assert_eq!(product.callable_key_for_definition(Path::new(path)), Some(target.key()));
    }
    let selected = product.callables().selected_implementation(target.key()).unwrap();
    let package = product.into_artifact(true).unwrap();
    assert_eq!(ImplementationRoot::new(package.mast_forest()[first.0].digest()), selected);
    assert_eq!(ImplementationRoot::new(package.mast_forest()[second.0].digest()), selected);
    let debug = package.debug_info().unwrap().unwrap();
    assert_eq!(debug[first.1].exec_node, first.0);
    assert_eq!(debug[second.1].exec_node, second.0);
}

#[test]
fn emitted_program_retains_entry_key_and_explicit_home_inputs_without_debug_emission() {
    let context = TestContext::default();
    let root = context
        .parse_module("proc callback push.7 end\nbegin procref.callback end")
        .unwrap();
    let mut names = FixtureNamespace::assembly_tests();
    names.add_module(&root).unwrap();
    let entry_path = root.path().join(ast::ProcedureName::MAIN_PROC_NAME);
    let entry = names.binding(&entry_path).unwrap().clone();
    let product = names
        .configure(Assembler::new(context.source_manager()), [&*root])
        .unwrap()
        .assemble_executable_modules("test".into(), root, [])
        .unwrap();

    assert_eq!(product.entry_key(), Some(entry.key()));
    assert_eq!(product.namespace_plan(), names.namespace_plan());
    assert_eq!(product.callables().binding(entry.key()), Some(&entry));
    assert_eq!(product.callable_key_for_definition(&entry_path), Some(entry.key()));
    let selected = product.callables().selected_implementation(entry.key()).unwrap();
    let source = product.callable_source_for_definition(&entry_path).unwrap();
    let package = product.into_artifact(false).unwrap();
    assert_eq!(ImplementationRoot::new(package.mast_forest()[source.0].digest()), selected);
    assert!(package.debug_info().unwrap().is_none());
}

#[test]
fn emitted_inventory_rejects_distinct_definitions_assigned_the_same_key() {
    let context = TestContext::default();
    for prelinked_count in [0, 1, 2] {
        let root = context.parse_module("namespace client\npub proc caller push.1 end").unwrap();
        let first = context.parse_module("namespace left\npub proc run push.7 end").unwrap();
        let second = context.parse_module("namespace right\npub proc run push.7 end").unwrap();
        let mut assembler = Assembler::new(context.source_manager())
            .with_namespace_plan(home("explicit-home"))
            .with_callable_path(Arc::from(Path::new("::client::caller")), canonical(&["caller"]))
            .unwrap()
            .with_callable_path(Arc::from(Path::new("::left::run")), canonical(&["same"]))
            .unwrap()
            .with_callable_path(Arc::from(Path::new("::right::run")), canonical(&["same"]))
            .unwrap();
        let mut support = vec![first, second];
        let prelinked = support.drain(..prelinked_count).collect::<Vec<_>>();
        assembler.compile_and_statically_link_all(prelinked).unwrap();
        let error = assembler
            .assemble_library_modules("test".into(), root, support, TargetType::Library)
            .err()
            .expect("distinct definitions cannot claim the same executable path");
        assert!(error.to_string().contains("duplicate callable binding"), "{error}");
    }
}

#[test]
fn module_cohort_producers_reject_mismatched_target_kinds() {
    let context = TestContext::default();
    for kind in [TargetType::Executable, TargetType::Kernel] {
        let root = context.parse_module("namespace library\npub proc run push.1 end").unwrap();
        let error = Assembler::new(context.source_manager())
            .assemble_library_modules("test".into(), root, [], kind)
            .err()
            .expect("a library root cannot be assembled as an executable or kernel target");
        assert!(
            error.to_string().contains(if kind.is_executable() {
                "executable targets require"
            } else {
                "root module kind"
            }),
            "{error}",
        );
    }
    let root = context.parse_module("begin push.1 end").unwrap();
    let error = Assembler::new(context.source_manager())
        .assemble_library_modules("test".into(), root, [], TargetType::Library)
        .err()
        .expect("an executable root requires the executable producer");
    assert!(error.to_string().contains("root module kind"), "{error}");
    let root = context.parse_module("namespace library\npub proc run push.1 end").unwrap();
    let error = Assembler::new(context.source_manager())
        .assemble_executable_modules("test".into(), root, [])
        .err()
        .expect("the executable producer requires an executable root");
    assert!(error.to_string().contains("requires an executable root"), "{error}");
}
