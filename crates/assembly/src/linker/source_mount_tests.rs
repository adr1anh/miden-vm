use alloc::{collections::BTreeSet, sync::Arc};
use core::num::NonZeroU32;

use miden_core::{
    Felt,
    mast::MastNode,
    program::{CanonicalLabel, ProcedureKey},
};
use miden_mast_package::{
    CallableProcedurePath, NamespacePath,
    debug_info::{DebugFunctionInfo, PackageDebugInfo},
};
use miden_project::{LibraryRef, LibrarySelection, PackageSourceMount};

use super::*;
use crate::{
    Assembler, NamespaceInputs,
    testing::{TestContext, source_file},
};

fn home(name: &str) -> NamespacePath {
    NamespacePath::new(vec![CanonicalLabel::text(name).unwrap()])
}

fn mount(package: &str, source: &str) -> PackageSourceMount {
    PackageSourceMount::new(Path::new(package), Path::new(source)).unwrap()
}

fn semantic(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    )
    .unwrap()
}

fn pinned_library(context: &TestContext, revision: u32) -> LinkLibrary {
    let module = context.parse_module("namespace lib\npub proc foo push.1 end").unwrap();
    let import = LibraryRef::new(
        home("mount-fixture"),
        Word::new([Felt::from_u32(17); 4]),
        LibrarySelection::Revision(NonZeroU32::new(revision).unwrap()),
    );
    let product = Assembler::new(context.source_manager())
        .with_namespace_plan(import.namespace_plan())
        .with_callable_binding(
            Path::new("::lib::foo").into(),
            import.callable_binding(semantic(&["lib", "foo"])).unwrap(),
        )
        .unwrap()
        .assemble_library_modules("lib".into(), module, [], miden_project::TargetType::Library)
        .unwrap();
    let naming = product.naming().clone();
    LinkLibrary::from_package(product.into_artifact(true).unwrap().into(), naming).unwrap()
}

fn imported_key(linker: &Linker, module: &str, procedure: &str) -> ProcedureKey {
    linker
        .find_module(Path::new(module))
        .unwrap()
        .get(procedure)
        .unwrap()
        .callable_binding()
        .unwrap()
        .key()
}

#[test]
fn explicit_mounts_keep_equal_bodies_at_distinct_pinned_keys() {
    let context = TestContext::default();
    let first = pinned_library(&context, 1);
    let second = pinned_library(&context, 2);
    assert_eq!(first.interface_commitment().unwrap(), second.interface_commitment().unwrap());
    assert_eq!(first.mast().commitment(), second.mast().commitment());
    assert_ne!(first.commitment(), second.commitment());
    let expected = |library: &LinkLibrary| {
        library
            .naming()
            .callables()
            .key_for_visible_path(&semantic(&["lib", "foo"]))
            .unwrap()
    };
    let mut linker = Linker::new(context.source_manager());
    linker.link_library_at(first.clone(), mount("::lib", "::left")).unwrap();
    linker.link_library_at(second.clone(), mount("::lib", "::right")).unwrap();
    assert_eq!(imported_key(&linker, "::left", "foo"), expected(&first));
    assert_eq!(imported_key(&linker, "::right", "foo"), expected(&second));
    assert_ne!(expected(&first), expected(&second));
    assert!(linker.find_module(Path::new("::lib")).is_none());
    assert_eq!(linker.libraries().count(), 2);
    assert_eq!(linker.modules().len(), 2);
    for library in [&first, &second] {
        assert_eq!(
            linker.library_by_commitment(library.commitment()).unwrap().naming(),
            library.naming(),
        );
    }
    for linkage in [Linkage::Static, Linkage::Dynamic] {
        let consumer = context
            .parse_module(
                "namespace consumer\nuse left as lib\nuse right\npub proc run exec.lib::foo exec.right::foo end",
            )
            .unwrap();
        let inputs = NamespaceInputs::new()
            .with_namespace_plan(home("caller"))
            .with_default_callable_paths([&*consumer])
            .unwrap();
        let product = Assembler::new(context.source_manager())
            .with_namespace_inputs(inputs)
            .with_package_at(
                first.package.clone(),
                linkage,
                first.naming().clone(),
                mount("::lib", "::left"),
            )
            .unwrap()
            .with_package_at(
                second.package.clone(),
                linkage,
                second.naming().clone(),
                mount("::lib", "::right"),
            )
            .unwrap()
            .assemble_library_modules(
                "consumer".into(),
                consumer,
                [],
                miden_project::TargetType::Library,
            )
            .unwrap();
        for library in [&first, &second] {
            let key = expected(library);
            assert_eq!(product.callables().binding(key), library.naming().callables().binding(key));
            if linkage == Linkage::Static {
                assert_eq!(
                    product.callables().selected_implementation(key),
                    library.naming().callables().selected_implementation(key),
                );
            }
        }
        let package = product.into_artifact(true).unwrap();
        let targets = package
            .mast_forest()
            .nodes()
            .iter()
            .filter_map(|node| match node {
                MastNode::Exec(exec) => Some(exec.target()),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(targets, BTreeSet::from([expected(&first), expected(&second)]));
        let implementation =
            first.naming().callables().selected_implementation(expected(&first)).unwrap();
        let node = package.mast_forest().find_procedure_root(implementation.into_word()).unwrap();
        assert_eq!(package.mast_forest()[node].is_external(), linkage == Linkage::Dynamic);
    }
}

#[test]
fn an_exact_artifact_can_be_mounted_twice_and_alias_renames_preserve_its_key() {
    let context = TestContext::default();
    let library = pinned_library(&context, 1);
    let original_commitment = library.package.commitment();
    let mut linker = Linker::new(context.source_manager());
    linker.link_library_at(library.clone(), mount("::lib", "::left")).unwrap();
    linker
        .link_library_at(library.clone().with_linkage(Linkage::Static), mount("::lib", "::right"))
        .unwrap();
    linker.link_library_at(library.clone(), mount("::lib", "::renamed")).unwrap();
    assert_eq!(imported_key(&linker, "::left", "foo"), imported_key(&linker, "::right", "foo"));
    assert_eq!(
        imported_key(&linker, "::left", "foo"),
        imported_key(&linker, "::renamed", "foo"),
    );
    assert_eq!(linker.libraries().count(), 1);
    assert_eq!(linker.static_libraries().count(), 1);
    assert_eq!(linker.modules().len(), 3);
    for module in linker.modules() {
        assert_eq!(module.package_path().as_ref(), Path::new("::lib"));
    }
    assert_eq!(linker.library_routes().count(), 3);
    linker.link_library_at(library.clone(), mount("::lib", "::right")).unwrap();
    assert_eq!(linker.modules().len(), 3, "repeating an exact route is idempotent");
    assert_eq!(linker.library_routes().count(), 3);
    assert_eq!(library.package.commitment(), original_commitment);
    assert_eq!(linker.libraries().next().unwrap().package.commitment(), original_commitment);
}

#[cfg(feature = "std")]
#[test]
fn quoted_mount_bases_resolve_unquoted_imports_and_share_the_normalized_cache_route() {
    let context = TestContext::default();
    let library = pinned_library(&context, 1);
    let expected = library
        .naming()
        .callables()
        .key_for_visible_path(&semantic(&["lib", "foo"]))
        .unwrap();
    let consumer = context
        .parse_module("namespace consumer\nuse left\npub proc run exec.left::foo end")
        .unwrap();
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("caller"))
        .with_default_callable_paths([&*consumer])
        .unwrap();
    let base = Assembler::new(context.source_manager()).with_namespace_inputs(inputs);
    let plain = base
        .clone()
        .with_package_at(
            library.package.clone(),
            Linkage::Dynamic,
            library.naming().clone(),
            mount("::lib", "::left"),
        )
        .unwrap();
    let mut quoted = base
        .with_package_at(
            library.package.clone(),
            Linkage::Dynamic,
            library.naming().clone(),
            mount("::\"lib\"", "::\"left\""),
        )
        .unwrap();
    let cache = plain.project_cache_commitment("release").unwrap().unwrap();
    assert_eq!(quoted.project_cache_commitment("release").unwrap(), Some(cache));
    assert_eq!(imported_key(quoted.linker(), "::left", "foo"), expected);
    quoted
        .link_package_at(
            library.package.clone(),
            Linkage::Dynamic,
            library.naming().clone(),
            mount("::lib", "::left"),
        )
        .unwrap();
    assert_eq!(quoted.linker().modules().len(), 1);
    assert_eq!(quoted.linker().library_routes().count(), 1);
    assert_eq!(quoted.project_cache_commitment("release").unwrap(), Some(cache));
    let product = quoted
        .assemble_library_modules(
            "consumer".into(),
            consumer,
            [],
            miden_project::TargetType::Library,
        )
        .unwrap();
    assert_eq!(product.callable_key_for_definition(Path::new("::left::foo")), Some(expected));
    let package = product.into_artifact(true).unwrap();
    let targets = package
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| match node {
            MastNode::Exec(exec) => Some(exec.target()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(targets, BTreeSet::from([expected]));
}

#[cfg(feature = "std")]
#[test]
fn project_cache_commits_to_route_assignment_and_is_independent_of_insertion_order() {
    let context = TestContext::default();
    let first = pinned_library(&context, 1);
    let second = pinned_library(&context, 2);
    let configured = |swapped: bool, reversed: bool| {
        let mut assembler =
            Assembler::new(context.source_manager()).with_namespace_plan(home("caller"));
        let mut inputs = [(&first, "::left"), (&second, "::right")];
        if swapped {
            inputs.swap(0, 1);
            inputs[0].1 = "::left";
            inputs[1].1 = "::right";
        }
        if reversed {
            inputs.reverse();
        }
        for (library, source) in inputs {
            assembler
                .link_package_at(
                    library.package.clone(),
                    Linkage::Dynamic,
                    library.naming().clone(),
                    mount("::lib", source),
                )
                .unwrap();
        }
        assembler.project_cache_commitment("release").unwrap().unwrap()
    };
    assert_eq!(configured(false, false), configured(false, true));
    assert_eq!(configured(true, false), configured(true, true));
    assert_ne!(configured(false, false), configured(true, false));
}

fn library_with_public_child(context: &TestContext) -> LinkLibrary {
    let root = context
        .parse_module("namespace lib\npub mod extra\npub proc foo push.1 end")
        .unwrap();
    let child = context.parse_module("namespace lib::extra\npub proc bar push.2 end").unwrap();
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("child-fixture"))
        .with_default_callable_paths([&*root, &*child])
        .unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs)
        .assemble_library_modules("lib".into(), root, [child], miden_project::TargetType::Library)
        .unwrap();
    let naming = product.naming().clone();
    LinkLibrary::from_package(product.into_artifact(true).unwrap().into(), naming).unwrap()
}

#[test]
fn invalid_or_conflicting_routes_do_not_insert_modules_artifacts_or_upgrade_linkage() {
    let context = TestContext::default();
    let library = library_with_public_child(&context);
    let mut linker = Linker::new(context.source_manager());
    linker.link_library_at(library.clone(), mount("::lib", "::right")).unwrap();
    linker
        .link_assembled_module(ModuleDescriptor::new(Path::new("::left::extra").into(), None))
        .unwrap();
    for route in [mount("::li", "::invalid"), mount("::lib", "::left")] {
        assert!(
            linker
                .link_library_at(library.clone().with_linkage(Linkage::Static), route)
                .is_err()
        );
        assert!(linker.find_module(Path::new("::left")).is_none());
        assert!(linker.find_module(Path::new("::invalid")).is_none());
        assert_eq!(linker.modules().len(), 3);
        assert_eq!(linker.libraries().count(), 1);
        assert_eq!(linker.static_libraries().count(), 0);
        assert_eq!(linker.library_routes().count(), 1);
        assert!(matches!(linker.libraries().next().unwrap().linkage, Linkage::Dynamic));
    }
    // A failed new artifact route must leave its artifact inventory absent too.
    let other = pinned_library(&context, 2).with_linkage(Linkage::Static);
    assert!(linker.link_library_at(other.clone(), mount("::lib", "::right")).is_err());
    assert!(linker.library_by_commitment(other.commitment()).is_none());
    assert_eq!(linker.libraries().count(), 1);
    assert_eq!(linker.static_libraries().count(), 0);
    assert_eq!(linker.library_routes().count(), 1);
}

#[test]
fn known_artifact_route_checks_capacity_before_static_upgrade() {
    let context = TestContext::default();
    let library = pinned_library(&context, 1);
    let mut linker = Linker::new(context.source_manager());
    linker.link_library_at(library.clone(), mount("::lib", "::left")).unwrap();
    let placeholder = linker.modules[0].clone();
    linker.modules.resize(ModuleIndex::MAX_MODULES, placeholder);
    for _ in 0..2 {
        assert!(matches!(
            linker.link_library_at(
                library.clone().with_linkage(Linkage::Static),
                mount("::lib", "::right"),
            ),
            Err(LinkerError::TooManyModules)
        ));
        assert!(linker.find_module(Path::new("::right")).is_none());
        assert_eq!(linker.libraries().count(), 1);
        assert_eq!(linker.static_libraries().count(), 0);
        assert_eq!(linker.library_routes().count(), 1);
        assert!(matches!(linker.libraries().next().unwrap().linkage, Linkage::Dynamic));
    }
}

#[test]
fn root_mount_preserves_suffixes_and_submodule_names_without_synthetic_parent() {
    let context = TestContext::default();
    let library = library_with_public_child(&context);
    let mut linker = Linker::new(context.source_manager());
    linker.link_library_at(library, mount("::", "::prefix")).unwrap();
    assert!(linker.find_module(Path::new("::prefix")).is_none());
    let root = linker.find_module(Path::new("::prefix::lib")).unwrap();
    assert_eq!(root.package_path().as_ref(), Path::new("::lib"));
    assert_eq!(
        root.submodules().map(|child| child.name.as_str()).collect::<Vec<_>>(),
        ["extra"]
    );
    assert!(linker.find_module(Path::new("::prefix::lib::extra")).is_some());
}

#[test]
fn explicit_mount_cannot_attach_a_kernel() {
    let context = TestContext::default();
    let kernel = context.parse_kernel(source_file!(&context, "pub proc foo push.1 end")).unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_plan(NamespacePath::new(vec![]))
        .with_callable_binding(
            kernel.path().join("foo").into(),
            ProcedureName::new(NamespacePath::new(vec![]), semantic(&["syscall"])).unwrap(),
        )
        .unwrap()
        .assemble_library_modules("kernel".into(), kernel, [], miden_project::TargetType::Kernel)
        .unwrap();
    let naming = product.naming().clone();
    let kernel: Arc<MastPackage> = product.into_artifact(false).unwrap().into();
    let library = LinkLibrary::from_package(kernel.clone(), naming.clone()).unwrap();
    let mut linker = Linker::new(context.source_manager());
    assert!(linker.link_library_at(library, mount("::", "::alias")).is_err());
    assert!(!linker.has_kernel());
    assert!(linker.modules().is_empty());
    assert_eq!(linker.library_routes().count(), 0);
    let mut assembler = Assembler::new(context.source_manager());
    assert!(
        assembler
            .link_package_at(
                kernel.clone(),
                Linkage::Static,
                naming.clone(),
                mount("::", "::alias"),
            )
            .is_err()
    );
    assert!(!assembler.has_kernel());
    assembler.link_package(kernel, Linkage::Dynamic, naming).unwrap();
    assert!(assembler.has_kernel());
}

fn debug_function<'a>(debug: &'a PackageDebugInfo, path: &str) -> &'a DebugFunctionInfo {
    let mut functions = debug.functions().iter().filter(|function| {
        let name = function.linkage_name_idx.into_option().unwrap_or(function.name_idx);
        debug[name].as_ref() == path
    });
    let function = functions.next().unwrap_or_else(|| panic!("missing function {path}"));
    assert!(functions.next().is_none(), "ambiguous function {path}");
    function
}

#[test]
fn mounted_private_helpers_and_dynamic_reexports_keep_keys_and_original_debug_names() {
    let context = TestContext::default();
    let dependency = context
        .parse_module(
            "namespace dep\n@source_name(\"same\")\npub proc foo() -> felt\n exec.helper\nend\nproc helper() -> felt\n push.42\nend\nproc twin() -> felt\n push.42\nend",
        )
        .unwrap();
    let inputs = NamespaceInputs::new()
        .with_namespace_plan(home("defining-home"))
        .with_callable_binding(
            Path::new("::dep::helper").into(),
            ProcedureName::new(home("private-helper-home"), semantic(&["helper"])).unwrap(),
        )
        .unwrap()
        .with_default_callable_paths([&*dependency])
        .unwrap();
    let product = Assembler::new(context.source_manager())
        .with_namespace_inputs(inputs)
        .assemble_library_modules("dep".into(), dependency, [], miden_project::TargetType::Library)
        .unwrap();
    let defining = product.naming().clone();
    let foo_key = product.callable_key_for_definition(Path::new("::dep::foo")).unwrap();
    let helper_key = product.callable_key_for_definition(Path::new("::dep::helper")).unwrap();
    let twin_key = product.callable_key_for_definition(Path::new("::dep::twin")).unwrap();
    assert_ne!(helper_key, twin_key);
    assert_eq!(
        defining.callables().selected_implementation(helper_key),
        defining.callables().selected_implementation(twin_key),
    );
    let dependency: Arc<MastPackage> = product.into_artifact(true).unwrap().into();
    let bridge = context.parse_module("namespace lib\npub use {foo as facade} from dep").unwrap();
    let bridge = Assembler::new(context.source_manager())
        .with_namespace_plan(home("bridge-home"))
        .with_package(dependency, Linkage::Dynamic, defining.clone())
        .unwrap()
        .assemble_library_modules("bridge".into(), bridge, [], miden_project::TargetType::Library)
        .unwrap();
    let naming = bridge.naming().clone();
    let bridge: Arc<MastPackage> = bridge.into_artifact(true).unwrap().into();
    let bridge_debug = bridge.debug_info().unwrap().unwrap();
    assert_eq!(debug_function(&bridge_debug, "::lib::facade").source_node.into_option(), None);
    for linkage in [Linkage::Static, Linkage::Dynamic] {
        // With run present, the compiled dependency is materialized before the reexport. Without
        // it, exporting the dependency performs its own original-package debug lookup.
        for invokes_first in [false, true] {
            let source = if invokes_first {
                "namespace consumer\nuse left\npub proc run exec.left::facade end\npub use {facade as forwarded} from ::left"
            } else {
                "namespace consumer\npub use {facade as forwarded} from ::left"
            };
            let consumer = context.parse_module(source).unwrap();
            let inputs = NamespaceInputs::new()
                .with_namespace_plan(home("caller-home"))
                .with_default_callable_paths([&*consumer])
                .unwrap();
            let assembler = Assembler::new(context.source_manager())
                .with_namespace_inputs(inputs)
                .with_package_at(bridge.clone(), linkage, naming.clone(), mount("::lib", "::left"))
                .unwrap();
            assert!(assembler.linker().find_module(Path::new("::left::helper")).is_none());
            let product = assembler
                .assemble_library_modules(
                    "consumer".into(),
                    consumer,
                    [],
                    miden_project::TargetType::Library,
                )
                .unwrap();
            assert_eq!(
                product.callables().key_for_visible_path(&semantic(&["consumer", "forwarded"])),
                Some(foo_key),
            );
            for key in [foo_key, helper_key, twin_key] {
                assert_eq!(product.callables().binding(key), defining.callables().binding(key));
            }
            assert_eq!(product.callable_key_for_definition(Path::new("::dep::helper")), None);
            let package = product.into_artifact(true).unwrap();
            let debug = package.debug_info().unwrap().unwrap();
            let forwarded = debug_function(&debug, "::consumer::forwarded");
            assert_eq!(debug[forwarded.name_idx].as_ref(), "::dep::same");
            assert!(forwarded.type_idx.into_option().is_some());
            assert_eq!(forwarded.source_node.into_option(), None);
            if invokes_first {
                let targets = package
                    .mast_forest()
                    .nodes()
                    .iter()
                    .filter_map(|node| match node {
                        MastNode::Exec(exec) => Some(exec.target()),
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>();
                assert_eq!(targets, BTreeSet::from([foo_key]));
            }
        }
    }
}
