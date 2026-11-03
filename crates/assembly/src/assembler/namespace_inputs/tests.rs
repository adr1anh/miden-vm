use alloc::{string::ToString, sync::Arc};

use miden_core::program::{CanonicalLabel, ImplementationRoot, Namespace};
use miden_mast_package::{CallableProcedurePath, NamespacePlan};
use miden_project::TargetType;

use crate::{
    Assembler, AssemblyProduct, CallableBinding, CallableDeclaration, NamespaceInputs, Path,
    Report,
    ast::{self, Ident, ItemIndex},
    testing::{FixtureNamespace, TestContext},
};

fn home(name: &str) -> NamespacePlan {
    NamespacePlan::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn canonical(name: &str) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(vec![name.to_string()]).unwrap()
}

fn declaration(path: &str) -> Arc<Path> {
    Arc::from(Path::new(path))
}

fn binding(home_name: &str, name: &str) -> CallableBinding {
    CallableBinding::new(home(home_name), canonical(name)).unwrap()
}

fn source_binding(home_name: &str, components: &[&str]) -> CallableBinding {
    let path = CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).to_string()).collect(),
    )
    .unwrap();
    CallableBinding::new(home(home_name), path).unwrap()
}

fn inputs(home_name: &str) -> NamespaceInputs {
    NamespaceInputs::new()
        .with_namespace_plan(home(home_name))
        .with_callable_path(declaration("::client::run"), canonical("entry"))
        .unwrap()
}

fn library(
    context: &TestContext,
    assembler: Assembler,
    source: &str,
) -> Result<AssemblyProduct, Report> {
    assembler.assemble_library_modules(
        "namespace-inputs".into(),
        context.parse_module(source).unwrap(),
        [],
        TargetType::Library,
    )
}

#[test]
fn replacement_removes_previous_home_and_both_forms_of_declaration_metadata() {
    let context = TestContext::default();
    let previous = NamespaceInputs::new()
        .with_namespace_plan(home("previous-caller"))
        .with_callable_path(declaration("::absent::local"), canonical("old-local"))
        .unwrap()
        .with_callable_binding(declaration("::absent::foreign"), binding("foreign", "old"))
        .unwrap();
    let replacement = inputs("current-caller");
    let assembler = Assembler::new(context.source_manager())
        .with_namespace_inputs(previous)
        .with_namespace_inputs(replacement.clone());
    assert_eq!(assembler.namespace_inputs(), &replacement);
    let product =
        library(&context, assembler, "namespace client\npub proc run push.1 end").unwrap();
    assert_eq!(product.namespace_plan(), &home("current-caller"));
    assert_eq!(
        product.callable_key_for_definition(Path::new("::client::run")),
        Some(binding("current-caller", "entry").key())
    );
    assert_eq!(product.callables().bindings().len(), 1);
}

#[test]
fn empty_replacement_clears_the_previous_caller_home() {
    let context = TestContext::default();
    let assembler = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs("previous-caller"))
        .with_namespace_inputs(NamespaceInputs::default());
    let error = library(&context, assembler, "namespace client\npub proc run push.1 end")
        .err()
        .expect("an empty replacement must not inherit the previous caller home");
    assert!(error.to_string().contains("explicit caller NamespacePlan"));
}

#[test]
fn replacement_does_not_retain_a_previous_local_binding() {
    let context = TestContext::default();
    let assembler = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs("previous-caller"))
        .with_namespace_inputs(NamespaceInputs::new().with_namespace_plan(home("current-caller")));
    let error = library(&context, assembler, "namespace client\npub proc run push.1 end")
        .err()
        .expect("a callable still requires explicit canonical metadata after replacement");
    assert!(error.to_string().contains("missing canonical callable binding"));
}

#[test]
fn prelinked_assembler_clones_compile_with_independent_target_homes() {
    let context = TestContext::default();
    let original_inputs = inputs("original")
        .with_callable_path(declaration("::dep::helper"), canonical("helper"))
        .unwrap();
    let mut base =
        Assembler::new(context.source_manager()).with_namespace_inputs(original_inputs.clone());
    base.compile_and_statically_link(
        context.parse_module("namespace dep\npub proc helper push.7 end").unwrap(),
    )
    .unwrap();
    let first_inputs = base.namespace_inputs().clone().with_namespace_plan(home("first"));
    let second_inputs = base.namespace_inputs().clone().with_namespace_plan(home("second"));
    assert_ne!(first_inputs, second_inputs);
    let source = "namespace client\nuse dep\npub proc run exec.dep::helper end";
    let first =
        library(&context, base.clone().with_namespace_inputs(first_inputs), source).unwrap();
    let second =
        library(&context, base.clone().with_namespace_inputs(second_inputs), source).unwrap();
    assert_eq!(base.namespace_inputs(), &original_inputs);
    let original = library(&context, base, source).unwrap();
    for (product, home_name) in [(&first, "first"), (&second, "second"), (&original, "original")] {
        assert_eq!(product.namespace_plan(), &home(home_name));
        assert_eq!(
            product.callable_key_for_definition(Path::new("::client::run")),
            Some(binding(home_name, "entry").key())
        );
        assert_eq!(
            product.callable_key_for_definition(Path::new("::dep::helper")),
            Some(binding(home_name, "helper").key())
        );
    }
}

#[test]
fn local_paths_use_the_final_explicit_home_independently_of_builder_order() {
    let context = TestContext::default();
    let early_path = Assembler::new(context.source_manager())
        .with_callable_path(declaration("::client::run"), canonical("entry"))
        .unwrap()
        .with_namespace_plan(home("previous"))
        .with_namespace_plan(home("current"));
    let late_path = Assembler::new(context.source_manager())
        .with_namespace_plan(home("current"))
        .with_callable_path(declaration("::client::run"), canonical("entry"))
        .unwrap();
    assert_eq!(early_path.namespace_inputs(), late_path.namespace_inputs());
    for assembler in [early_path, late_path] {
        let product =
            library(&context, assembler, "namespace client\npub proc run push.1 end").unwrap();
        assert_eq!(
            product.callable_key_for_definition(Path::new("::client::run")),
            Some(binding("current", "entry").key())
        );
    }
}

#[test]
fn changing_the_local_home_preserves_a_complete_foreign_binding() {
    let context = TestContext::default();
    let foreign = binding("foreign-publisher", "foreign-export");
    let previous = inputs("previous");
    let replacement = previous
        .clone()
        .with_namespace_plan(home("current"))
        .with_callable_binding(declaration("::client::foreign"), foreign.clone())
        .unwrap();
    let product = library(
        &context,
        Assembler::new(context.source_manager()).with_namespace_inputs(replacement),
        "namespace client\nproc foreign push.7 end\npub proc run exec.foreign end",
    )
    .unwrap();
    assert_eq!(
        product.callable_key_for_definition(Path::new("::client::run")),
        Some(binding("current", "entry").key())
    );
    assert_eq!(
        product.callable_key_for_definition(Path::new("::client::foreign")),
        Some(foreign.key())
    );
    assert_eq!(product.callables().binding(foreign.key()), Some(&foreign));
    let original = library(
        &context,
        Assembler::new(context.source_manager()).with_namespace_inputs(previous),
        "namespace client\npub proc run push.1 end",
    )
    .unwrap();
    assert_eq!(
        original.callable_key_for_definition(Path::new("::client::run")),
        Some(binding("previous", "entry").key())
    );
}

#[test]
fn duplicate_declarations_reject_both_local_path_and_complete_binding_orders() {
    let context = TestContext::default();
    for bound_first in [false, true] {
        let declaration = declaration("::client::run");
        let binding = binding("foreign", "run");
        let raw = if bound_first {
            NamespaceInputs::new()
                .with_callable_binding(declaration.clone(), binding.clone())
                .unwrap()
                .with_callable_path(declaration.clone(), canonical("entry"))
        } else {
            NamespaceInputs::new()
                .with_callable_path(declaration.clone(), canonical("entry"))
                .unwrap()
                .with_callable_binding(declaration.clone(), binding.clone())
        };
        assert!(raw.unwrap_err().to_string().contains("duplicate callable metadata"));
        let assembler = Assembler::new(context.source_manager());
        let incremental = if bound_first {
            assembler
                .with_callable_binding(declaration.clone(), binding)
                .unwrap()
                .with_callable_path(declaration, canonical("entry"))
        } else {
            assembler
                .with_callable_path(declaration.clone(), canonical("entry"))
                .unwrap()
                .with_callable_binding(declaration, binding)
        };
        assert!(
            incremental
                .err()
                .expect("incremental configuration must share duplicate validation")
                .to_string()
                .contains("duplicate callable metadata")
        );
    }
}

#[test]
fn replacement_cannot_change_an_already_bound_linker_declaration() {
    let context = TestContext::default();
    let original = binding("foreign-publisher", "run");
    let mut base = Assembler::new(context.source_manager()).with_namespace_inputs(inputs("caller"));
    base.link_callable_declarations(
        declaration("::dep"),
        [CallableDeclaration::new(Ident::new("run").unwrap(), original.clone())],
    )
    .unwrap();
    let conflicting = base
        .namespace_inputs()
        .clone()
        .with_callable_binding(declaration("::dep::run"), binding("different-publisher", "run"))
        .unwrap();
    let rejected = base.clone().with_namespace_inputs(conflicting);
    let source = "namespace client\nuse dep\npub proc run exec.dep::run end";
    let error = library(&context, rejected.clone(), source)
        .err()
        .expect("replacement must reject an identity conflict during compilation");
    assert!(error.to_string().contains("conflicting callable metadata"));
    let module = rejected.linker().find_module_index(Path::new("::dep")).unwrap();
    assert!(rejected.prebind_callables().is_err());
    assert_eq!(
        rejected.linker()[module + ItemIndex::new(0)].callable_binding(),
        Some(&original),
        "a rejected prebind must preserve the symbol's original canonical binding"
    );
    let retained = rejected.with_namespace_inputs(base.namespace_inputs().clone());
    let product = library(&context, retained, source).unwrap();
    assert_eq!(product.callables().binding(original.key()), Some(&original));
}

#[test]
fn either_input_form_must_name_a_concrete_declaration() {
    let context = TestContext::default();
    for bound in [false, true] {
        let inputs = inputs("caller");
        let inputs = if bound {
            inputs.with_callable_binding(declaration("::absent::run"), binding("foreign", "run"))
        } else {
            inputs.with_callable_path(declaration("::absent::run"), canonical("absent"))
        }
        .unwrap();
        let error = library(
            &context,
            Assembler::new(context.source_manager()).with_namespace_inputs(inputs),
            "namespace client\npub proc run push.1 end",
        )
        .err()
        .expect("raw metadata cannot create an absent declaration");
        assert!(error.to_string().contains("does not name a concrete declaration"));
    }
}

#[test]
fn executable_product_retains_the_explicit_home_and_entry_key() {
    let context = TestContext::default();
    let program = context.parse_module("begin push.1 end").unwrap();
    let entry = program.path().join(ast::ProcedureName::MAIN_PROC_NAME);
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("entry-caller"))
        .with_callable_path(entry.clone().into(), canonical("entry"))
        .unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs)
        .assemble_executable_modules("entry".into(), program, [])
        .unwrap();
    assert_eq!(product.namespace_plan(), &home("entry-caller"));
    assert_eq!(product.entry_key(), Some(binding("entry-caller", "entry").key()));
    assert_eq!(product.callable_key_for_definition(&entry), product.entry_key());
}

#[test]
fn default_source_paths_require_an_explicit_home_even_with_complete_bindings() {
    let context = TestContext::default();
    let module = context.parse_module("namespace client\npub proc run push.1 end").unwrap();
    let missing = NamespaceInputs::new();
    let bound = missing
        .clone()
        .with_callable_binding(declaration("::client::run"), binding("foreign", "entry"))
        .unwrap();
    for inputs in [missing, bound] {
        let error = inputs.with_default_callable_paths([&*module]).unwrap_err();
        assert!(error.to_string().contains("explicit caller NamespacePlan"));
    }
    let explicit_root = NamespaceInputs::new()
        .with_namespace_plan(NamespacePlan::new(vec![]))
        .with_default_callable_paths([&*module])
        .unwrap();
    assert_eq!(explicit_root.namespace_plan(), Some(&NamespacePlan::new(vec![])));
}

#[test]
fn default_source_paths_retain_private_callbacks_unused_helpers_and_entrypoints() {
    let context = TestContext::default();
    let program = context
        .parse_module(
            "proc unused push.9 end\nproc callback push.7 end\nbegin procref.callback dropw end",
        )
        .unwrap();
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("application"))
        .with_default_callable_paths([&*program])
        .unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs)
        .assemble_executable_modules("application".into(), program, [])
        .unwrap();
    let entry = source_binding("application", &["$exec", "$main"]);
    assert_eq!(product.entry_key(), Some(entry.key()));
    assert_eq!(product.callables().bindings().len(), 3);
    for name in ["unused", "callback", "$main"] {
        let expected = source_binding("application", &["$exec", name]);
        assert_eq!(
            product.callable_key_for_definition(&Path::EXEC.join(name)),
            Some(expected.key())
        );
    }
}

#[test]
fn default_source_paths_preserve_local_overrides_and_foreign_complete_bindings() {
    let context = TestContext::default();
    let module = context
        .parse_module(
            "namespace client\npub proc run exec.foreign exec.helper end\nproc foreign push.7 end\nproc helper push.1 end",
        )
        .unwrap();
    let foreign = binding("foreign-publisher", "foreign-export");
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("previous"))
        .with_callable_path(declaration("::client::run"), canonical("custom-entry"))
        .unwrap()
        .with_callable_binding(declaration("::client::foreign"), foreign.clone())
        .unwrap()
        .with_default_callable_paths([&*module])
        .unwrap()
        .with_namespace_plan(home("current"));
    let product = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs)
        .assemble_library_modules("overrides".into(), module, [], TargetType::Library)
        .unwrap();
    for (path, expected) in [
        ("::client::run", binding("current", "custom-entry")),
        ("::client::foreign", foreign),
        ("::client::helper", source_binding("current", &["client", "helper"])),
    ] {
        assert_eq!(product.callable_key_for_definition(Path::new(path)), Some(expected.key()));
    }
}

#[test]
fn default_source_paths_preserve_quoted_components_and_defining_keys_through_aliases() {
    let context = TestContext::default();
    let client = context
        .parse_module("namespace client\nuse bridge\npub proc caller exec.bridge::alias end")
        .unwrap();
    let dependency = context
        .parse_module("namespace dep::\"math::wide\"\npub proc run push.7 end")
        .unwrap();
    let bridge = context
        .parse_module("namespace bridge\npub use {run as alias} from dep::\"math::wide\"")
        .unwrap();
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("caller"))
        .with_default_callable_paths([&*client, &*dependency, &*bridge])
        .unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs)
        .assemble_library_modules(
            "aliases".into(),
            client,
            [dependency, bridge],
            TargetType::Library,
        )
        .unwrap();
    let defining = source_binding("caller", &["dep", "math::wide", "run"]);
    assert_eq!(
        product.callable_key_for_definition(Path::new("::dep::\"math::wide\"::run")),
        Some(defining.key())
    );
    assert_eq!(product.callable_key_for_definition(Path::new("::bridge::alias")), None);
    assert_eq!(product.callables().bindings().len(), 2);
    let artifact = product.into_artifact(false).unwrap();
    assert!(artifact.mast_forest().nodes().iter().any(|node| {
        matches!(node, miden_core::mast::MastNode::Exec(exec) if exec.target() == defining.key())
    }));
}

#[test]
fn default_source_paths_reject_duplicate_cohort_modules_even_without_procedures() {
    let first = ast::Module::new(ast::ModuleKind::Library, Path::new("::duplicate"));
    let second = first.clone();
    for modules in [[&first, &first], [&first, &second]] {
        let error = NamespaceInputs::new()
            .with_namespace_plan(home("caller"))
            .with_default_callable_paths(modules)
            .unwrap_err();
        assert!(error.to_string().contains("duplicate source module"));
    }
}

#[test]
fn default_source_paths_reject_duplicate_declarations_even_when_an_override_exists() {
    let context = TestContext::default();
    let mut module = context
        .parse_module("namespace client\npub proc run push.1 end\nproc helper push.2 end")
        .unwrap();
    let duplicate = module.items()[0].clone();
    *module.items_mut().nth(1).unwrap() = duplicate;
    let error = NamespaceInputs::new()
        .with_namespace_plan(home("caller"))
        .with_callable_binding(declaration("::client::run"), binding("foreign", "run"))
        .unwrap()
        .with_default_callable_paths([&*module])
        .unwrap_err();
    assert!(error.to_string().contains("duplicate source callable declaration"));
}

#[test]
fn default_source_paths_require_separate_kernel_placement_at_any_source_path() {
    for path in [Path::KERNEL, Path::new("::ordinary_name")] {
        let kernel = ast::Module::new(ast::ModuleKind::Kernel, path);
        let error = NamespaceInputs::new()
            .with_namespace_plan(home("private-helpers"))
            .with_default_callable_paths([&kernel])
            .unwrap_err();
        assert!(error.to_string().contains("explicit root-export and private-helper placement"));
    }
}

fn root_binding(name: &str) -> CallableBinding {
    CallableBinding::new(NamespacePlan::new(vec![]), canonical(name)).unwrap()
}

#[test]
fn kernel_root_exports_require_a_chosen_home_and_nonempty_cohort() {
    let context = TestContext::default();
    let base = Assembler::new(context.source_manager());
    let root = ast::Module::new(ast::ModuleKind::Kernel, Path::KERNEL);
    let error = NamespaceInputs::new().with_kernel_root_exports(&base, &[&root]).unwrap_err();
    assert!(error.to_string().contains("explicit caller NamespacePlan"));
    let error = NamespaceInputs::new()
        .with_namespace_plan(home("helpers"))
        .with_kernel_root_exports(&base, &[])
        .unwrap_err();
    assert!(error.to_string().contains("requires a root module"));
}

#[test]
fn kernel_root_exports_follow_public_submodules_and_keep_private_helpers_in_children() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub mod api\nmod hidden\npub proc run exec.helper end\nproc helper push.1 end"
        ))
        .unwrap();
    let api = context
        .parse_module("namespace $kernel::api\npub proc child push.2 end\nproc callback push.3 end")
        .unwrap();
    let hidden = context
        .parse_module("namespace $kernel::hidden\npub proc internal push.4 end")
        .unwrap();
    let base = Assembler::new(context.source_manager());
    // Empty homes remain explicit: a helper's defining path still creates a child parent.
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(NamespacePlan::new(vec![]))
        .with_kernel_root_exports(&base, &[&root, &api, &hidden])
        .unwrap();
    let product = base
        .with_namespace_inputs(inputs)
        .assemble_library_modules("kernel".into(), root, [api, hidden], TargetType::Kernel)
        .unwrap();
    for (path, name) in [("::$kernel::run", "run"), ("::$kernel::api::child", "child")] {
        let expected = root_binding(name);
        assert_eq!(product.callable_key_for_definition(Path::new(path)), Some(expected.key()));
        assert_eq!(expected.parent_namespace(), Namespace::initial());
    }
    for components in [
        vec!["$kernel", "helper"],
        vec!["$kernel", "api", "callback"],
        vec!["$kernel", "hidden", "internal"],
    ] {
        let canonical = CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| (*component).to_string()).collect(),
        )
        .unwrap();
        let expected = CallableBinding::new(NamespacePlan::new(vec![]), canonical).unwrap();
        assert_ne!(expected.parent_namespace(), Namespace::initial());
        let declaration = format!("::{}", components.join("::"));
        assert_eq!(
            product.callable_key_for_definition(Path::new(&declaration)),
            Some(expected.key())
        );
    }
    assert_eq!(product.callables().bindings().len(), 5);
}

#[test]
fn kernel_root_reexports_use_the_defining_leaf_and_never_name_aliases() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "mod hidden\npub use {original as alias} from self::hidden\npub proc run push.1 end"
        ))
        .unwrap();
    let hidden = context
        .parse_module("namespace $kernel::hidden\npub proc original push.1 end")
        .unwrap();
    let base = Assembler::new(context.source_manager());
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("helpers"))
        .with_kernel_root_exports(&base, &[&root, &hidden])
        .unwrap();
    assert!(!inputs.resolved_bindings().unwrap().contains_key(Path::new("::$kernel::alias")));
    let product = base
        .with_namespace_inputs(inputs)
        .assemble_library_modules("kernel".into(), root, [hidden], TargetType::Kernel)
        .unwrap();
    let expected = root_binding("original");
    let visible =
        CallableProcedurePath::from_semantic_components(vec!["$kernel".into(), "alias".into()])
            .unwrap();
    assert_eq!(product.callables().key_for_visible_path(&visible), Some(expected.key()));
    assert_eq!(product.callable_key_for_definition(Path::new("::$kernel::alias")), None);
    assert_eq!(
        product.callable_key_for_definition(Path::new("::$kernel::hidden::original")),
        Some(expected.key())
    );
    assert_eq!(product.callables().bindings().len(), 2);
}

#[test]
fn kernel_imported_reexports_preserve_the_actual_root_binding() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub use {original as first, original as second} from imported"
        ))
        .unwrap();
    let actual = root_binding("actual-canonical-export");
    let helper = binding("imported-private-home", "actual-helper");
    let unused = binding("imported-private-home", "unused-helper");
    let inherited = NamespaceInputs::new()
        .with_namespace_plan(home("imported-default"))
        .with_callable_binding(declaration("::imported::original"), actual.clone())
        .unwrap()
        .with_callable_binding(declaration("::imported::helper"), helper.clone())
        .unwrap()
        .with_callable_binding(declaration("::imported::unused"), unused.clone())
        .unwrap();
    let mut base = Assembler::new(context.source_manager()).with_namespace_inputs(inherited);
    base.compile_and_statically_link(
        context
            .parse_module(
                "namespace imported\npub proc original exec.helper end\nproc helper push.7 end\nproc unused push.9 end",
            )
            .unwrap(),
    )
    .unwrap();
    let imported_module = base.linker().find_module(Path::new("::imported")).unwrap();
    assert!(imported_module.symbols().all(|symbol| symbol.callable_binding().is_none()));
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("helpers"))
        .with_kernel_root_exports(&base, &[&root])
        .unwrap();
    let preserved = inputs.resolved_bindings().unwrap();
    for (path, binding) in [
        ("::imported::original", &actual),
        ("::imported::helper", &helper),
        ("::imported::unused", &unused),
    ] {
        assert_eq!(preserved.get(Path::new(path)), Some(binding));
    }
    assert_eq!(preserved.len(), 3);
    let changed = inputs.clone().with_namespace_plan(home("different-kernel-home"));
    assert_eq!(changed.resolved_bindings().unwrap(), preserved);
    let product = base
        .with_namespace_inputs(inputs)
        .assemble_library_modules("kernel".into(), root, [], TargetType::Kernel)
        .unwrap();
    for alias in ["first", "second"] {
        let visible =
            CallableProcedurePath::from_semantic_components(vec!["$kernel".into(), alias.into()])
                .unwrap();
        assert_eq!(product.callables().key_for_visible_path(&visible), Some(actual.key()));
        assert_eq!(product.callable_key_for_definition(&Path::KERNEL.join(alias)), None);
    }
    assert_eq!(product.callables().bindings().len(), 3);
    assert_eq!(product.callables().binding(actual.key()), Some(&actual));
    assert_eq!(product.callables().binding(helper.key()), Some(&helper));
    assert_eq!(product.callables().binding(unused.key()), Some(&unused));
    let artifact = product.into_artifact(false).unwrap();
    assert!(artifact.mast_forest().nodes().iter().any(|node| {
        matches!(node, miden_core::mast::MastNode::Exec(exec) if exec.target() == helper.key())
    }));
}

#[test]
fn kernel_imported_reexports_reject_child_bindings_and_rebinding_attempts() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub use {run as alias} from imported"
        ))
        .unwrap();
    for actual in [binding("foreign", "run"), root_binding("actual")] {
        let mut base = Assembler::new(context.source_manager());
        base.link_callable_declarations(
            declaration("::imported"),
            [CallableDeclaration::new(Ident::new("run").unwrap(), actual.clone())],
        )
        .unwrap();
        let mut inputs = NamespaceInputs::new().with_namespace_plan(home("helpers"));
        if actual.parent_namespace() == Namespace::initial() {
            inputs = inputs
                .with_callable_binding(declaration("::imported::run"), root_binding("replacement"))
                .unwrap();
        }
        let error = inputs.with_kernel_root_exports(&base, &[&root]).unwrap_err();
        assert!(
            error.to_string().contains("fixed root syscall namespace")
                || error.to_string().contains("conflicting callable metadata"),
            "{error:?}"
        );
    }
}

#[test]
fn kernel_reexport_lowering_keeps_linker_import_errors() {
    let context = TestContext::default();
    let missing = context
        .parse_kernel(crate::testing::source_file!(&context, "pub use {absent} from missing"))
        .unwrap();
    let base = Assembler::new(context.source_manager());
    let inputs = NamespaceInputs::new().with_namespace_plan(home("helpers"));
    assert!(inputs.clone().with_kernel_root_exports(&base, &[&missing]).is_err());

    let root = context
        .parse_kernel(crate::testing::source_file!(&context, "pub use {cycle} from bridge"))
        .unwrap();
    let bridge = context.parse_module("namespace bridge\npub use {cycle} from $kernel").unwrap();
    assert!(inputs.with_kernel_root_exports(&base, &[&root, &bridge]).is_err());
}

#[test]
fn kernel_root_export_overrides_preserve_compatible_local_and_complete_bindings() {
    let context = TestContext::default();
    let mut root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub proc run exec.local exec.foreign end\nproc local push.1 end\nproc foreign push.2 end"
        ))
        .unwrap();
    // Kernel placement follows the selected cohort, independently of its source spelling.
    root.set_path(Path::new("::unprivileged_name"));
    let base = Assembler::new(context.source_manager());
    let exported = root_binding("custom-export");
    let foreign = binding("foreign-helper-home", "custom-helper");
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("helpers"))
        .with_callable_binding(declaration("::unprivileged_name::run"), exported.clone())
        .unwrap()
        .with_callable_path(declaration("::unprivileged_name::local"), canonical("local-override"))
        .unwrap()
        .with_callable_binding(declaration("::unprivileged_name::foreign"), foreign.clone())
        .unwrap()
        .with_kernel_root_exports(&base, &[&root])
        .unwrap();
    let product = base
        .with_namespace_inputs(inputs)
        .assemble_library_modules("kernel".into(), root, [], TargetType::Kernel)
        .unwrap();
    for (name, expected) in [
        ("run", exported),
        ("local", binding("helpers", "local-override")),
        ("foreign", foreign),
    ] {
        assert_eq!(
            product.callable_key_for_definition(&Path::new("::unprivileged_name").join(name)),
            Some(expected.key())
        );
    }
}

#[test]
fn kernel_local_root_overrides_and_empty_home_child_paths_are_compatible() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub proc run exec.helper end\nproc helper push.1 end"
        ))
        .unwrap();
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(NamespacePlan::new(vec![]))
        .with_callable_path(declaration("::$kernel::run"), canonical("root-override"))
        .unwrap()
        .with_callable_path(
            declaration("::$kernel::helper"),
            CallableProcedurePath::from_semantic_components(vec!["child".into(), "helper".into()])
                .unwrap(),
        )
        .unwrap();
    let expected = inputs.clone();
    assert_eq!(
        inputs
            .with_kernel_root_exports(&Assembler::new(context.source_manager()), &[&root])
            .unwrap(),
        expected
    );
}

#[test]
fn kernel_root_exports_reject_overrides_with_incompatible_actual_parents() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub proc run push.1 end\nproc helper push.2 end"
        ))
        .unwrap();
    let base = Assembler::new(context.source_manager());
    for inputs in [
        NamespaceInputs::new()
            .with_namespace_plan(home("helpers"))
            .with_callable_path(declaration("::$kernel::run"), canonical("root-override"))
            .unwrap(),
        NamespaceInputs::new()
            .with_namespace_plan(home("helpers"))
            .with_callable_binding(declaration("::$kernel::run"), binding("child", "run"))
            .unwrap(),
        NamespaceInputs::new()
            .with_namespace_plan(home("helpers"))
            .with_callable_binding(declaration("::$kernel::helper"), root_binding("helper"))
            .unwrap(),
        NamespaceInputs::new()
            .with_namespace_plan(NamespacePlan::new(vec![]))
            .with_callable_path(declaration("::$kernel::helper"), canonical("helper"))
            .unwrap(),
    ] {
        let error = inputs.with_kernel_root_exports(&base, &[&root]).unwrap_err();
        assert!(
            error.to_string().contains("fixed root syscall namespace")
                || error.to_string().contains("beneath a child Env namespace"),
            "{error:?}"
        );
    }
}

#[test]
fn kernel_root_exports_reject_default_and_explicit_canonical_collisions() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub mod api\npub proc same push.1 end"
        ))
        .unwrap();
    let api = context
        .parse_module("namespace $kernel::api\npub proc same push.2 end")
        .unwrap();
    let base = Assembler::new(context.source_manager());
    let inputs = NamespaceInputs::new().with_namespace_plan(home("helpers"));
    assert!(
        inputs
            .clone()
            .with_kernel_root_exports(&base, &[&root, &api])
            .unwrap_err()
            .to_string()
            .contains("conflicting canonical bindings")
    );
    let renamed = inputs
        .with_callable_binding(
            declaration("::$kernel::api::same"),
            root_binding("explicit-distinct"),
        )
        .unwrap()
        .with_kernel_root_exports(&base, &[&root, &api])
        .unwrap();
    assert_eq!(renamed.resolved_bindings().unwrap().len(), 2);

    let mut imported = Assembler::new(context.source_manager());
    imported
        .link_callable_declarations(
            declaration("::another_fragment"),
            [CallableDeclaration::new(Ident::new("alias").unwrap(), root_binding("same"))],
        )
        .unwrap();
    let error = NamespaceInputs::new()
        .with_namespace_plan(home("helpers"))
        .with_callable_binding(
            declaration("::$kernel::api::same"),
            root_binding("explicit-distinct"),
        )
        .unwrap()
        .with_kernel_root_exports(&imported, &[&root, &api])
        .unwrap_err();
    assert!(error.to_string().contains("conflicting canonical bindings"));
}

#[test]
fn kernel_root_exports_reject_duplicate_cohort_declarations_before_defaults() {
    let context = TestContext::default();
    let mut root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub proc run push.1 end\nproc other push.2 end"
        ))
        .unwrap();
    let base = Assembler::new(context.source_manager());
    let inputs = NamespaceInputs::new().with_namespace_plan(home("helpers"));
    let error = inputs.clone().with_kernel_root_exports(&base, &[&root, &root]).unwrap_err();
    assert!(error.to_string().contains("duplicate source module"));
    let duplicate = root.items()[0].clone();
    *root.items_mut().nth(1).unwrap() = duplicate;
    let error = inputs
        .with_callable_binding(declaration("::$kernel::run"), root_binding("override"))
        .unwrap()
        .with_kernel_root_exports(&base, &[&root])
        .unwrap_err();
    assert!(error.to_string().contains("duplicate source callable declaration"));
}

#[test]
fn kernel_fixture_shared_lowering_preserves_repeats_conflicts_and_imported_metadata() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub proc run push.1 end\nproc helper push.2 end"
        ))
        .unwrap();
    let base = Assembler::new(context.source_manager());
    let foreign = binding("foreign", "actual");
    let mut fixture = FixtureNamespace::new(home("helpers"));
    fixture.add_binding(declaration("::imported::alias"), foreign.clone()).unwrap();
    fixture.add_kernel_modules(&base, &[&root]).unwrap();
    fixture.add_kernel_modules(&base, &[&root]).unwrap();
    assert_eq!(fixture.binding(Path::new("::$kernel::run")), Some(&root_binding("run")));
    assert_eq!(fixture.binding(Path::new("::imported::alias")), Some(&foreign));
    let mut conflicting = FixtureNamespace::new(home("helpers"));
    conflicting
        .add_binding(declaration("::$kernel::run"), root_binding("override"))
        .unwrap();
    let error = conflicting.add_kernel_modules(&base, &[&root]).unwrap_err();
    assert!(error.to_string().contains("conflicting fixture callable metadata"));
}

#[test]
fn kernel_fixture_reexports_consume_exact_sidecar_bindings_for_inherited_ast() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub use {original as alias} from imported"
        ))
        .unwrap();
    let mut base = Assembler::new(context.source_manager());
    base.compile_and_statically_link(
        context
            .parse_module(
                "namespace imported\npub proc original exec.helper end\nproc helper push.7 end",
            )
            .unwrap(),
    )
    .unwrap();
    let actual = root_binding("actual-export");
    let helper = binding("foreign-helper-home", "actual-helper");
    let mut fixture = FixtureNamespace::new(home("helpers"));
    fixture
        .add_binding(declaration("::imported::original"), actual.clone())
        .unwrap();
    fixture.add_binding(declaration("::imported::helper"), helper.clone()).unwrap();
    fixture.add_kernel_modules(&base, &[&root]).unwrap();
    fixture.add_kernel_modules(&base, &[&root]).unwrap();
    assert!(base.namespace_plan().is_none());
    assert!(
        base.linker()
            .modules()
            .iter()
            .all(|module| { module.symbols().all(|symbol| symbol.callable_binding().is_none()) })
    );
    assert_eq!(fixture.binding(Path::new("::imported::original")), Some(&actual));
    assert_eq!(fixture.binding(Path::new("::imported::helper")), Some(&helper));
    let product = fixture
        .configure(base, [&*root])
        .unwrap()
        .assemble_library_modules("kernel".into(), root, [], TargetType::Kernel)
        .unwrap();
    let alias =
        CallableProcedurePath::from_semantic_components(vec!["$kernel".into(), "alias".into()])
            .unwrap();
    assert_eq!(product.callables().key_for_visible_path(&alias), Some(actual.key()));
    assert_eq!(product.callable_key_for_definition(Path::new("::$kernel::alias")), None);
    assert_eq!(
        product.callable_key_for_definition(Path::new("::imported::original")),
        Some(actual.key())
    );
    assert_eq!(product.callables().binding(helper.key()), Some(&helper));
    assert_eq!(product.callables().bindings().len(), 2);
}

#[test]
fn kernel_fixture_inherited_sidecar_bindings_reject_existing_metadata_conflicts() {
    let context = TestContext::default();
    let root = context
        .parse_kernel(crate::testing::source_file!(
            &context,
            "pub use {original as alias} from imported"
        ))
        .unwrap();
    let mut fixture = FixtureNamespace::new(home("helpers"));
    fixture
        .add_binding(declaration("::imported::original"), root_binding("sidecar-export"))
        .unwrap();
    for bound_symbol in [false, true] {
        let actual = root_binding("base-export");
        let mut base = Assembler::new(context.source_manager());
        if bound_symbol {
            base.link_callable_declarations(
                declaration("::imported"),
                [CallableDeclaration::new(Ident::new("original").unwrap(), actual.clone())],
            )
            .unwrap();
        } else {
            base = base
                .with_namespace_plan(home("existing-base-home"))
                .with_callable_binding(declaration("::imported::original"), actual.clone())
                .unwrap();
            base.compile_and_statically_link(
                context
                    .parse_module("namespace imported\npub proc original push.1 end")
                    .unwrap(),
            )
            .unwrap();
        }
        let error = fixture.add_kernel_modules(&base, &[&root]).unwrap_err();
        assert!(error.to_string().contains("conflicting fixture callable metadata"));
        if bound_symbol {
            let module = base.linker().find_module(Path::new("::imported")).unwrap();
            assert_eq!(module.get("original").unwrap().callable_binding(), Some(&actual));
            assert!(base.namespace_plan().is_none());
        } else {
            assert_eq!(base.namespace_plan(), Some(&home("existing-base-home")));
            assert_eq!(
                base.namespace_inputs()
                    .resolved_bindings()
                    .unwrap()
                    .get(Path::new("::imported::original")),
                Some(&actual)
            );
        }
    }
}

#[test]
fn source_fixture_lowering_preserves_identical_repeats_and_rejects_conflicts() {
    let context = TestContext::default();
    let module = context
        .parse_module("namespace fixtures::\"math::wide\"\npub proc run push.1 end")
        .unwrap();
    let path = declaration("::fixtures::\"math::wide\"::run");
    let mut fixture = FixtureNamespace::new(home("fixtures"));
    fixture.add_module(&module).unwrap();
    fixture.add_module(&module).unwrap();
    assert_eq!(
        fixture.binding(&path),
        Some(&source_binding("fixtures", &["fixtures", "math::wide", "run"]))
    );
    let mut conflicting = FixtureNamespace::new(home("fixtures"));
    conflicting.add_binding(path, binding("fixtures", "override")).unwrap();
    assert!(
        conflicting
            .add_module(&module)
            .unwrap_err()
            .to_string()
            .contains("conflicting fixture callable metadata")
    );
}

#[test]
fn namespace_replacement_keeps_separate_inline_pin_validation() {
    let context = TestContext::default();
    let assembler = Assembler::new(context.source_manager())
        .with_pinned_callable(
            declaration("::absent::inline"),
            ImplementationRoot::new(Default::default()),
        )
        .unwrap()
        .with_namespace_inputs(inputs("caller"));
    let error = library(&context, assembler, "namespace client\npub proc run push.1 end")
        .err()
        .expect("namespace replacement must not discard separately supplied inline pins");
    assert!(error.to_string().contains("inline implementation pin does not name"));
}

#[test]
fn cache_commitment_requires_a_caller_home_even_for_complete_foreign_bindings() {
    let missing = NamespaceInputs::new();
    let bound = missing
        .clone()
        .with_callable_binding(declaration("::client::run"), binding("foreign", "entry"))
        .unwrap();
    for inputs in [missing, bound] {
        assert!(
            inputs
                .cache_commitment()
                .unwrap_err()
                .to_string()
                .contains("explicit caller NamespacePlan")
        );
    }
    assert!(
        NamespaceInputs::new()
            .with_namespace_plan(NamespacePlan::new(vec![]))
            .cache_commitment()
            .is_ok(),
        "an explicitly requested root home is distinct from missing configuration"
    );
}

#[test]
fn cache_commitment_normalizes_resolved_bindings_and_builder_order() {
    let early = NamespaceInputs::new()
        .with_callable_path(declaration("::client::run"), canonical("entry"))
        .unwrap()
        .with_namespace_plan(home("previous"))
        .with_callable_binding(declaration("::dep::helper"), binding("foreign", "helper"))
        .unwrap()
        .with_namespace_plan(home("caller"));
    let late = NamespaceInputs::new()
        .with_namespace_plan(home("caller"))
        .with_callable_binding(declaration("::dep::helper"), binding("foreign", "helper"))
        .unwrap()
        .with_callable_binding(declaration("::client::run"), binding("caller", "entry"))
        .unwrap();
    assert_eq!(early.resolved_bindings().unwrap(), late.resolved_bindings().unwrap());
    assert_eq!(early.cache_commitment().unwrap(), late.cache_commitment().unwrap());
}

#[test]
fn cache_commitment_tracks_the_caller_home_with_only_foreign_bindings() {
    let foreign = NamespaceInputs::new()
        .with_namespace_plan(home("first"))
        .with_callable_binding(declaration("::client::run"), binding("foreign", "entry"))
        .unwrap();
    let changed = foreign.clone().with_namespace_plan(home("second"));
    assert_eq!(foreign.resolved_bindings().unwrap(), changed.resolved_bindings().unwrap());
    assert_ne!(foreign.cache_commitment().unwrap(), changed.cache_commitment().unwrap());
}

#[test]
fn cache_commitment_tracks_typed_home_labels_and_complete_home_paths() {
    use core::num::NonZeroU32;

    let make = |labels| {
        NamespaceInputs::new()
            .with_namespace_plan(NamespacePlan::new(labels))
            .cache_commitment()
            .unwrap()
    };
    let text = make(vec![CanonicalLabel::text("1").unwrap()]);
    let revision = make(vec![CanonicalLabel::revision(NonZeroU32::new(1).unwrap())]);
    assert_ne!(text, revision);
    assert_ne!(
        make(vec![CanonicalLabel::text("a::b").unwrap()]),
        make(vec![CanonicalLabel::text("a").unwrap(), CanonicalLabel::text("b").unwrap()])
    );
    assert_ne!(
        make(vec![CanonicalLabel::typed_id(7, b"id", |_, _| Ok(())).unwrap()]),
        make(vec![CanonicalLabel::typed_id(8, b"id", |_, _| Ok(())).unwrap()])
    );
}

#[test]
fn cache_commitment_tracks_complete_foreign_binding_homes_and_paths() {
    let make = |foreign| {
        NamespaceInputs::new()
            .with_namespace_plan(home("caller"))
            .with_callable_binding(declaration("::client::run"), foreign)
            .unwrap()
            .cache_commitment()
            .unwrap()
    };
    let original = make(binding("foreign", "entry"));
    assert_ne!(original, make(binding("other-foreign", "entry")));
    assert_ne!(original, make(binding("foreign", "other-entry")));
}

#[test]
fn cache_commitment_frames_semantic_callable_path_components() {
    let make = |components| {
        NamespaceInputs::new()
            .with_namespace_plan(home("caller"))
            .with_callable_path(
                declaration("::client::run"),
                CallableProcedurePath::from_semantic_components(components).unwrap(),
            )
            .unwrap()
            .cache_commitment()
            .unwrap()
    };
    assert_ne!(make(vec!["a::b".to_string()]), make(vec!["a".to_string(), "b".to_string()]));
    assert_ne!(
        make(vec!["ab".to_string(), "c".to_string()]),
        make(vec!["a".to_string(), "bc".to_string()])
    );
}

#[test]
fn cache_commitment_preserves_exact_defining_source_path_bytes() {
    let make = |source_path| {
        NamespaceInputs::new()
            .with_namespace_plan(home("caller"))
            .with_callable_path(declaration(source_path), canonical("entry"))
            .unwrap()
            .cache_commitment()
            .unwrap()
    };
    let original = make("::client::run");
    assert_ne!(original, make("::client::other"));
    assert_ne!(original, make("::client::\"run\""));
    assert_ne!(original, make("::client::::run"));
}

#[test]
fn cache_commitment_includes_unreferenced_declaration_metadata() {
    let original = inputs("caller");
    for with_bound in [false, true] {
        let extra = if with_bound {
            original.clone().with_callable_binding(
                declaration("::absent::helper"),
                binding("foreign", "helper"),
            )
        } else {
            original
                .clone()
                .with_callable_path(declaration("::absent::helper"), canonical("helper"))
        }
        .unwrap();
        assert_ne!(original.cache_commitment().unwrap(), extra.cache_commitment().unwrap());
    }
}

#[cfg(feature = "std")]
#[test]
fn project_cache_does_not_claim_complete_snapshots_of_inherited_ast_or_declarations() {
    let context = TestContext::default();
    let base = Assembler::new(context.source_manager()).with_namespace_inputs(inputs("caller"));
    assert!(base.project_cache_commitment("dev").unwrap().is_some());
    let mut source = base.clone();
    source
        .compile_and_statically_link(
            context.parse_module("namespace dep\npub proc helper push.7 end").unwrap(),
        )
        .unwrap();
    assert!(source.project_cache_commitment("dev").unwrap().is_none());
    let mut declared = base;
    declared
        .link_callable_declarations(
            declaration("::dep"),
            [CallableDeclaration::new(
                Ident::new("helper").unwrap(),
                binding("foreign", "helper"),
            )],
        )
        .unwrap();
    for module in declared.linker().modules() {
        assert!(module.is_mast());
    }
    assert!(
        declared.project_cache_commitment("dev").unwrap().is_none(),
        "declaration-only modules must not be mistaken for committed package inputs"
    );
}
