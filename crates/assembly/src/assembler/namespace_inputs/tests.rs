use alloc::{string::ToString, sync::Arc};

use miden_core::program::{CanonicalLabel, ImplementationRoot};
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
    assert!(declared.linker().modules().iter().all(|module| module.is_mast()));
    assert!(
        declared.project_cache_commitment("dev").unwrap().is_none(),
        "declaration-only modules must not be mistaken for committed package inputs"
    );
}
