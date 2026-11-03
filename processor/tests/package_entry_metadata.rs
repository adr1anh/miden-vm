//! Package preparation checks through the public processor API.
//!
//! These tests supply explicit fixture names, caller-selected roots and finite native policies.
//! Preparation alone does not authenticate an environment binding or execute any code.

use std::sync::Arc;

use miden_core::{
    Felt, Word,
    mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
    operations::Operation,
    program::{
        CanonicalLabel, EnvironmentRoot, ExecutionDescriptor, ImplementationRoot, ProcedureKey,
    },
};
use miden_mast_package::{
    CallableBinding, CallableProcedurePath, NamespacePlan, Package, PackageCallables, PackageId,
    PackageNaming, TargetType, Version,
};
use miden_processor::{
    ExecutionEnvironment, ExecutionError, FastProcessor, LedgerLimits, OpeningLimits,
    SessionLimits, StackInputs,
};

fn home(label: &str) -> NamespacePlan {
    NamespacePlan::new(vec![CanonicalLabel::text(label).unwrap()])
}

fn binding(name: &str) -> CallableBinding {
    CallableBinding::new(
        home("application"),
        CallableProcedurePath::from_semantic_components(vec!["private".into(), name.into()])
            .unwrap(),
    )
    .unwrap()
}

fn package_fixture(has_entry: bool) -> (Arc<Package>, PackageNaming, ProcedureKey) {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);
    let entry = binding("start");
    let key = entry.key();
    let naming = PackageNaming::new(
        home("compilation"),
        PackageCallables::new([entry], [], [(key, ImplementationRoot::new(forest[root].digest()))])
            .unwrap(),
        has_entry.then_some(key),
    )
    .unwrap();
    let package = Package::create(
        PackageId::from("private-entry-fixture"),
        Version::new(1, 0, 0),
        TargetType::Executable,
        Arc::new(forest),
        [],
        [],
        &naming,
    )
    .unwrap();
    (Arc::new(package), naming, key)
}

fn environment(entry: ProcedureKey) -> ExecutionEnvironment {
    // This opaque root is a caller input, independent of the code digest and naming inventory.
    let root = EnvironmentRoot::new(Word::new([41u32; 4].map(Felt::from_u32)));
    ExecutionEnvironment::new(
        ExecutionDescriptor::new(entry, root),
        OpeningLimits {
            max_nodes: 8,
            max_depth: 7,
            max_list_children: 8,
            max_total_list_children: 16,
            max_encoded_bytes: 4096,
            max_storage_bytes: 16_384,
        },
        LedgerLimits {
            max_occurrences: 8,
            max_total_list_children: 16,
            max_encoded_bytes: 8192,
            max_library_rows: 128,
            max_compression_requests: 128,
            max_retained_bytes: 65_536,
            max_peak_bytes: 131_072,
        },
        SessionLimits {
            max_cached_keys: 8,
            max_requests: 8,
            max_retained_bytes: 131_072,
            max_prepare_peak_bytes: 262_144,
        },
    )
}

#[test]
fn explicit_private_entry_prepares_without_a_manifest_alias() {
    let (package, naming, key) = package_fixture(true);
    assert!(package.manifest.entrypoint().is_none());
    assert_eq!(naming.callables().visible_paths().len(), 0);

    let mut processor = FastProcessor::new(StackInputs::default());
    assert!(
        processor
            .get_initial_resume_context_for_package(package, &naming, environment(key))
            .is_ok()
    );
}

#[test]
fn mismatched_descriptor_entry_is_typed_and_does_not_poison_later_preparation() {
    let (package, naming, key) = package_fixture(true);
    let other = binding("other").key();
    assert_ne!(key, other);
    let mut processor = FastProcessor::new(StackInputs::default());

    let result = processor.get_initial_resume_context_for_package(
        package.clone(),
        &naming,
        environment(other),
    );
    assert!(matches!(
        result,
        Err(ExecutionError::PackageEntryMismatch { expected, requested })
            if expected == key && requested == other,
    ));
    assert!(
        processor
            .get_initial_resume_context_for_package(package, &naming, environment(key))
            .is_ok()
    );
}

#[test]
fn identical_code_with_stale_compilation_naming_returns_a_package_error() {
    let (package, naming, key) = package_fixture(true);
    let stale = PackageNaming::new(
        home("other-compilation"),
        naming.callables().clone(),
        naming.entry_key(),
    )
    .unwrap();
    stale
        .validate_package(package.kind, package.mast_forest(), &package.manifest)
        .unwrap();
    let mut processor = FastProcessor::new(StackInputs::default());

    let result =
        processor.get_initial_resume_context_for_package(package, &stale, environment(key));
    assert!(matches!(result, Err(ExecutionError::InvalidPackageExecutable(_))));
}

#[test]
fn executable_tag_without_an_explicit_entry_returns_a_package_error() {
    let (package, naming, retained_key) = package_fixture(false);
    assert_eq!(naming.entry_key(), None);
    let mut processor = FastProcessor::new(StackInputs::default());

    let result = processor.get_initial_resume_context_for_package(
        package,
        &naming,
        environment(retained_key),
    );
    assert!(matches!(result, Err(ExecutionError::InvalidPackageExecutable(_))));
}
