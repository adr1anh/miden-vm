//! Package preparation checks through the public processor API.
//!
//! These tests supply explicit fixture names, caller-selected roots and finite native policies.
//! Preparation alone does not authenticate an environment binding or execute any code.

use std::sync::Arc;

use miden_core::{
    Felt, Word,
    mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
    operations::Operation,
    program::{CanonicalLabel, EnvironmentRoot, ExecutionTarget, ImplementationRoot, ProcedureKey},
};
use miden_mast_package::{
    CallableProcedurePath, CodePackage, NamespacePath, Package, PackageCallables, PackageId,
    PackageProcedureOccurrence, PackageSymbols, ProcedureName, TargetType, Version,
};
use miden_processor::{
    DefaultHost, ExecutionError, ExecutionOptions, FastProcessor, LedgerLimits, OpeningLimits,
    ResolutionLimits, SessionLimits, StackInputs,
};

fn home(label: &str) -> NamespacePath {
    NamespacePath::new(vec![CanonicalLabel::text(label).unwrap()])
}

fn binding(name: &str) -> ProcedureName {
    ProcedureName::new(
        home("application"),
        CallableProcedurePath::from_semantic_components(vec!["private".into(), name.into()])
            .unwrap(),
    )
    .unwrap()
}

fn package_fixture(has_entry: bool) -> (Arc<Package>, PackageSymbols, ProcedureKey) {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);
    let entry = binding("start");
    let key = entry.key();
    let naming = PackageSymbols::new(
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
    .unwrap()
    .with_procedure_occurrences([PackageProcedureOccurrence::new(key, root, None)], &naming)
    .unwrap();
    (Arc::new(package), naming, key)
}

fn target(entry: ProcedureKey) -> ExecutionTarget {
    // This opaque root is a caller input, independent of the code digest and naming inventory.
    let root = EnvironmentRoot::new(Word::new([41u32; 4].map(Felt::from_u32)));
    ExecutionTarget::new(entry, root)
}

fn resolution_limits() -> ResolutionLimits {
    ResolutionLimits::new(
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
    package.check_executable_code(&naming).unwrap();
    let code = CodePackage::new(package, Arc::new(naming)).unwrap();
    let mut host = DefaultHost::default();
    host.load_library(code).unwrap();
    let mut processor = FastProcessor::new(StackInputs::default())
        .with_options(ExecutionOptions::default().with_resolution_limits(resolution_limits()))
        .unwrap();
    let resume = processor.get_initial_resume_context(target(key)).unwrap();
    assert_eq!(*resume.target(), target(key));
    assert!(resume.current_forest().procedure_roots().is_empty());
    assert!(resume.debug_info().is_none());
}

#[test]
fn caller_target_cannot_be_replaced_by_package_entry_metadata() {
    let (package, naming, key) = package_fixture(true);
    let other = binding("other").key();
    assert_ne!(key, other);
    let code = CodePackage::new(package, Arc::new(naming)).unwrap();
    assert_eq!(code.symbols().entry_key(), Some(key));
    let mut host = DefaultHost::default();
    host.load_library(code).unwrap();
    let mut processor = FastProcessor::new(StackInputs::default())
        .with_options(ExecutionOptions::default().with_resolution_limits(resolution_limits()))
        .unwrap();
    let mut resume = processor.get_initial_resume_context(target(other)).unwrap();
    assert_eq!(*resume.target(), target(other));
    assert!(resume.current_forest().procedure_roots().is_empty());
    assert!(matches!(processor.step_sync(&mut host, &mut resume),
        Err(ExecutionError::EnvironmentWitnessUnavailable { root, key: requested })
            if root == target(other).environment_root() && requested == other));
    assert!(resume.current_forest().procedure_roots().is_empty());
    assert_eq!(resume.resolution_session().uses().count(), 0);
    assert!(matches!(
        processor.get_initial_resume_context(target(key)),
        Err(ExecutionError::InvalidExecutionState)
    ));
}

#[test]
fn identical_code_with_stale_compilation_naming_returns_a_package_error() {
    let (package, naming, _) = package_fixture(true);
    let stale = PackageSymbols::new(
        home("other-compilation"),
        naming.callables().clone(),
        naming.entry_key(),
    )
    .unwrap();
    stale
        .validate_package(package.kind, package.mast_forest(), &package.manifest)
        .unwrap();
    assert!(CodePackage::new(package, Arc::new(stale)).is_err());
}

#[test]
fn executable_tag_without_an_explicit_entry_fails_runnable_package_validation() {
    let (package, naming, _) = package_fixture(false);
    assert_eq!(naming.entry_key(), None);
    assert!(package.check_executable_code(&naming).is_err());
    // Generic host code supply does not need a package-selected execution target.
    let code = CodePackage::new(package, Arc::new(naming)).unwrap();
    let mut host = DefaultHost::default();
    host.load_library(code).unwrap();
}
