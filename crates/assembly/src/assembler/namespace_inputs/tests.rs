use alloc::{string::ToString, sync::Arc};

use miden_core::program::{CanonicalLabel, ImplementationRoot};
use miden_mast_package::{CallableProcedurePath, NamespacePlan};
use miden_project::TargetType;

use crate::{
    Assembler, AssemblyProduct, CallableBinding, CallableDeclaration, NamespaceInputs, Path,
    Report,
    ast::{self, Ident, ItemIndex},
    testing::TestContext,
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
fn replacement_removes_previous_homes_and_both_forms_of_declaration_metadata() {
    let context = TestContext::default();
    let previous = NamespaceInputs::new()
        .with_namespace_plan(home("previous-caller"))
        .with_kernel_namespace_plan(Some(home("previous-kernel")))
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
    assert_eq!(product.kernel_namespace_plan(), None);
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
    let first_inputs = base
        .namespace_inputs()
        .clone()
        .with_namespace_plan(home("first"))
        .with_kernel_namespace_plan(Some(home("first-kernel")));
    let second_inputs = base.namespace_inputs().clone().with_namespace_plan(home("second"));
    assert_ne!(first_inputs, second_inputs);
    let source = "namespace client\nuse dep\npub proc run exec.dep::helper end";
    let first =
        library(&context, base.clone().with_namespace_inputs(first_inputs), source).unwrap();
    let second =
        library(&context, base.clone().with_namespace_inputs(second_inputs), source).unwrap();
    assert_eq!(base.namespace_inputs(), &original_inputs);
    let original = library(&context, base, source).unwrap();
    assert_eq!(first.kernel_namespace_plan(), Some(&home("first-kernel")));
    assert_eq!(second.kernel_namespace_plan(), None);
    assert_eq!(original.kernel_namespace_plan(), None);
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
fn executable_product_retains_the_replacement_homes_and_entry_key() {
    let context = TestContext::default();
    let program = context.parse_module("begin push.1 end").unwrap();
    let entry = program.path().join(ast::ProcedureName::MAIN_PROC_NAME);
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("entry-caller"))
        .with_kernel_namespace_plan(Some(home("entry-kernel")))
        .with_callable_path(entry.clone().into(), canonical("entry"))
        .unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs)
        .assemble_executable_modules("entry".into(), program, [])
        .unwrap();
    assert_eq!(product.namespace_plan(), &home("entry-caller"));
    assert_eq!(product.kernel_namespace_plan(), Some(&home("entry-kernel")));
    assert_eq!(product.entry_key(), Some(binding("entry-caller", "entry").key()));
    assert_eq!(product.callable_key_for_definition(&entry), product.entry_key());
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
