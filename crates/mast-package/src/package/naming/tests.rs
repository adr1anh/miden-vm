use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::Path;
use miden_core::{
    Felt, Word,
    mast::{BasicBlockNodeBuilder, ExecNodeBuilder, ExternalNodeBuilder},
    operations::Operation,
    program::CanonicalLabel,
};

use super::*;
use crate::{CallableBinding, PackageExport, PathBuf, ProcedureExport};

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    )
    .unwrap()
}

fn home(components: &[&str]) -> NamespacePlan {
    NamespacePlan::new(
        components
            .iter()
            .map(|component| CanonicalLabel::text(component).unwrap())
            .collect(),
    )
}

fn binding(home_components: &[&str], components: &[&str]) -> CallableBinding {
    CallableBinding::new(home(home_components), path(components)).unwrap()
}

fn body(forest: &mut MastForest, operation: Operation, root: bool) -> MastNodeId {
    let node = BasicBlockNodeBuilder::new(vec![operation]).add_to_forest(forest).unwrap();
    if root {
        forest.make_root(node);
    }
    node
}

fn implementation(forest: &MastForest, node: MastNodeId) -> ImplementationRoot {
    ImplementationRoot::new(forest[node].digest())
}

fn export(source: &str, forest: &MastForest, node: MastNodeId) -> PackageExport {
    let source = PathBuf::new(source).unwrap();
    PackageExport::Procedure(ProcedureExport::new(
        Arc::<Path>::from(source.into_boxed_path()),
        Some(node),
        forest[node].digest(),
        None,
    ))
}

fn naming(
    bindings: impl IntoIterator<Item = CallableBinding>,
    aliases: impl IntoIterator<Item = (CallableProcedurePath, ProcedureKey)>,
    selected: impl IntoIterator<Item = (ProcedureKey, ImplementationRoot)>,
    entry: Option<ProcedureKey>,
) -> PackageNaming {
    PackageNaming::new(
        home(&["compilation"]),
        PackageCallables::new(bindings, aliases, selected).unwrap(),
        entry,
    )
    .unwrap()
}

#[test]
fn private_code_and_foreign_declarations_need_no_public_exports_or_own_identity() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let helper = binding(&["private"], &["helpers", "run"]);
    let foreign = binding(&["foreign", "latest"], &["api", "callback"]);
    let metadata = naming(
        [helper.clone(), foreign.clone()],
        [],
        [(helper.key(), implementation(&forest, root))],
        None,
    );
    let manifest = PackageManifest::new([]).unwrap();

    metadata.validate_package(TargetType::Library, &forest, &manifest).unwrap();
    assert_ne!(metadata.namespace_plan(), foreign.namespace_plan());
    assert_eq!(metadata.callables().selected_implementation(foreign.key()), None);
    assert_eq!(metadata.entry_key(), None);
}

#[test]
fn private_code_candidates_without_entry_metadata_admit_under_every_usage_tag() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let private = binding(&["private"], &["helpers", "run"]);
    let metadata =
        naming([private.clone()], [], [(private.key(), implementation(&forest, root))], None);
    let manifest = PackageManifest::new([]).unwrap();
    for kind in [
        TargetType::Library,
        TargetType::Kernel,
        TargetType::Executable,
        TargetType::AccountComponent,
        TargetType::Note,
        TargetType::TransactionScript,
    ] {
        metadata.validate_package(kind, &forest, &manifest).unwrap();
    }
    assert_eq!(metadata.entry_key(), None);
    assert_eq!(metadata.callables().visible_paths().len(), 0);
}

#[test]
fn private_executable_entry_requires_its_own_selection_to_a_procedure_root() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let nonroot = body(&mut forest, Operation::Mul, false);
    let entry = binding(&["private"], &["entry"]);
    let retained = binding(&["private"], &["retained"]);
    let manifest = PackageManifest::new([]).unwrap();
    let make =
        |selected| naming([entry.clone(), retained.clone()], [], selected, Some(entry.key()));
    // Another key selecting the same code cannot substitute for the explicit entry's selection.
    let missing = make(vec![(retained.key(), implementation(&forest, root))]);
    assert!(matches!(
        missing.validate_package(TargetType::Executable, &forest, &manifest),
        Err(PackageNamingError::MissingEntryImplementation { key }) if key == entry.key(),
    ));
    let wrong_root = make(vec![
        (retained.key(), implementation(&forest, root)),
        (entry.key(), implementation(&forest, nonroot)),
    ]);
    assert!(matches!(
        wrong_root.validate_package(TargetType::Executable, &forest, &manifest),
        Err(PackageNamingError::MissingSelectedRoot { key, .. }) if key == entry.key(),
    ));
    let valid = make(vec![
        (retained.key(), implementation(&forest, root)),
        (entry.key(), implementation(&forest, root)),
    ]);
    valid.validate_package(TargetType::Executable, &forest, &manifest).unwrap();
    assert_eq!(valid.callables().visible_paths().len(), 0);
    assert_eq!(valid.entry_key(), Some(entry.key()));
    assert!(matches!(
        valid.validate_package(TargetType::Library, &forest, &manifest),
        Err(PackageNamingError::NonExecutableEntrypoint),
    ));
}

#[test]
fn aliases_share_a_key_and_equal_code_may_have_distinct_keys() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let first = binding(&["original"], &["canonical", "run"]);
    let second = binding(&["other"], &["canonical", "run"]);
    let selected = implementation(&forest, root);
    let metadata = naming(
        [first.clone(), second.clone()],
        [
            (path(&["alias", "run"]), first.key()),
            (path(&["alias", "again"]), first.key()),
            (path(&["other", "run"]), second.key()),
        ],
        [(first.key(), selected), (second.key(), selected)],
        None,
    );
    let manifest = PackageManifest::new([
        export("alias::run", &forest, root),
        export("alias::again", &forest, root),
        export("other::run", &forest, root),
    ])
    .unwrap();

    assert_ne!(first.key(), second.key());
    metadata.validate_package(TargetType::Library, &forest, &manifest).unwrap();
}

#[test]
fn external_procedure_root_is_structural_code_metadata() {
    let digest = Word::new([19u32; 4].map(Felt::from_u32));
    let mut forest = MastForest::new();
    let root = ExternalNodeBuilder::new(digest).add_to_forest(&mut forest).unwrap();
    forest.make_root(root);
    let declared = binding(&["supplied"], &["run"]);
    let metadata = naming(
        [declared.clone()],
        [],
        [(declared.key(), ImplementationRoot::new(digest))],
        None,
    );
    metadata
        .validate_package(TargetType::Library, &forest, &PackageManifest::new([]).unwrap())
        .unwrap();
}

#[test]
fn literal_invocation_keys_need_no_local_declaration() {
    let target = binding(&["external"], &["run"]);
    let local = binding(&["local"], &["entry"]);
    let mut forest = MastForest::new();
    let root = ExecNodeBuilder::new(target.key()).add_to_forest(&mut forest).unwrap();
    forest.make_root(root);
    let metadata =
        naming([local.clone()], [], [(local.key(), implementation(&forest, root))], None);
    assert!(metadata.callables().binding(target.key()).is_none());
    metadata
        .validate_package(TargetType::Library, &forest, &PackageManifest::new([]).unwrap())
        .unwrap();
}

#[test]
fn every_retained_root_requires_a_selected_binding() {
    let mut forest = MastForest::new();
    let first = body(&mut forest, Operation::Add, true);
    let unbound = body(&mut forest, Operation::Mul, true);
    let local = binding(&["local"], &["run"]);
    let metadata =
        naming([local.clone()], [], [(local.key(), implementation(&forest, first))], None);
    assert!(matches!(
        metadata.validate_package(TargetType::Library, &forest, &PackageManifest::new([]).unwrap()),
        Err(PackageNamingError::UnboundProcedureRoot { node, .. }) if node == unbound,
    ));
}

#[test]
fn selected_code_cannot_be_a_nonroot_or_an_absent_digest() {
    for nonroot in [true, false] {
        let mut forest = MastForest::new();
        let root = body(&mut forest, Operation::Add, true);
        let other = body(&mut forest, Operation::Mul, false);
        let retained = binding(&["local"], &["run"]);
        let missing = binding(&["foreign"], &["run"]);
        let invalid = if nonroot {
            implementation(&forest, other)
        } else {
            ImplementationRoot::new(Word::new([23u32; 4].map(Felt::from_u32)))
        };
        let metadata = naming(
            [retained.clone(), missing.clone()],
            [],
            [(retained.key(), implementation(&forest, root)), (missing.key(), invalid)],
            None,
        );
        assert!(matches!(
            metadata.validate_package(TargetType::Library, &forest, &PackageManifest::new([]).unwrap()),
            Err(PackageNamingError::MissingSelectedRoot { key, .. }) if key == missing.key(),
        ));
    }
}

#[test]
fn visible_aliases_must_match_all_and_only_manifest_procedures() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let local = binding(&["canonical"], &["run"]);
    let manifest = PackageManifest::new([export("visible::run", &forest, root)]).unwrap();
    for aliases in [vec![], vec![(path(&["wrong", "run"]), local.key())]] {
        let metadata =
            naming([local.clone()], aliases, [(local.key(), implementation(&forest, root))], None);
        assert!(matches!(
            metadata.validate_package(TargetType::Library, &forest, &manifest),
            Err(PackageNamingError::MissingVisibleExport { .. }),
        ));
    }
    let metadata = naming(
        [local.clone()],
        [(path(&["visible", "run"]), local.key()), (path(&["extra", "run"]), local.key())],
        [(local.key(), implementation(&forest, root))],
        None,
    );
    assert!(matches!(
        metadata.validate_package(TargetType::Library, &forest, &manifest),
        Err(PackageNamingError::UnexpectedVisiblePath { .. }),
    ));
}

#[test]
fn export_requires_its_own_matching_selection_and_exact_node_provenance() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let other = body(&mut forest, Operation::Mul, true);
    let exported = binding(&["local"], &["run"]);
    let private = binding(&["local"], &["helper"]);
    let manifest = PackageManifest::new([export("visible::run", &forest, root)]).unwrap();
    let make = |selection: Vec<_>| {
        naming(
            [exported.clone(), private.clone()],
            [(path(&["visible", "run"]), exported.key())],
            selection,
            None,
        )
    };
    let missing = make(vec![(private.key(), implementation(&forest, root))]);
    assert!(matches!(
        missing.validate_package(TargetType::Library, &forest, &manifest),
        Err(PackageNamingError::MissingExportImplementation { .. }),
    ));
    let wrong = make(vec![
        (private.key(), implementation(&forest, root)),
        (exported.key(), implementation(&forest, other)),
    ]);
    assert!(matches!(
        wrong.validate_package(TargetType::Library, &forest, &manifest),
        Err(PackageNamingError::ExportImplementationMismatch { .. }),
    ));
    let correct = make(vec![
        (exported.key(), implementation(&forest, root)),
        (private.key(), implementation(&forest, other)),
    ]);
    let mut stale = export("visible::run", &forest, root);
    let PackageExport::Procedure(procedure) = &mut stale else {
        unreachable!()
    };
    procedure.node = Some(other);
    let stale = PackageManifest::new([stale]).unwrap();
    assert!(matches!(
        correct.validate_package(TargetType::Library, &forest, &stale),
        Err(PackageNamingError::InvalidProcedureExport { .. }),
    ));
}

#[test]
fn entry_is_explicit_even_when_other_keys_select_identical_code() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let entry = binding(&["local"], &["entry"]);
    let other = binding(&["local"], &["other"]);
    let manifest = PackageManifest::new([export("visible::run", &forest, root)])
        .unwrap()
        .with_entrypoint(PathBuf::new("visible::run").unwrap().into())
        .unwrap();
    let make = |entry_key| {
        naming(
            [entry.clone(), other.clone()],
            [(path(&["visible", "run"]), entry.key())],
            [
                (entry.key(), implementation(&forest, root)),
                (other.key(), implementation(&forest, root)),
            ],
            entry_key,
        )
    };
    make(Some(entry.key()))
        .validate_package(TargetType::Executable, &forest, &manifest)
        .unwrap();
    assert!(matches!(
        make(None).validate_package(TargetType::Executable, &forest, &manifest),
        Err(PackageNamingError::MissingEntryKey),
    ));
    assert!(matches!(
        make(Some(other.key())).validate_package(TargetType::Executable, &forest, &manifest),
        Err(PackageNamingError::EntryKeyMismatch { .. }),
    ));
    assert!(matches!(
        make(Some(entry.key())).validate_package(TargetType::Library, &forest, &manifest),
        Err(PackageNamingError::NonExecutableEntrypoint),
    ));
    let no_entry = PackageManifest::new([export("visible::run", &forest, root)]).unwrap();
    make(Some(entry.key()))
        .validate_package(TargetType::Executable, &forest, &no_entry)
        .unwrap();
}

#[test]
fn constructor_rejects_undeclared_entry_and_empty_code_cannot_admit() {
    let undeclared = binding(&["unknown"], &["entry"]).key();
    assert!(matches!(
        PackageNaming::new(home(&[]), PackageCallables::new([], [], []).unwrap(), Some(undeclared)),
        Err(PackageNamingError::UnknownEntryKey { key }) if key == undeclared,
    ));
    assert!(matches!(
        naming([], [], [], None).validate_package(
            TargetType::Library,
            &MastForest::new(),
            &PackageManifest::new([]).unwrap(),
        ),
        Err(PackageNamingError::NoProcedures),
    ));
}

#[test]
fn kernel_public_aliases_preserve_root_keys_and_helpers_use_explicit_child_homes() {
    let mut forest = MastForest::new();
    let root = body(&mut forest, Operation::Add, true);
    let helper = body(&mut forest, Operation::Mul, true);
    let manifest = PackageManifest::new([export("public::nested::run", &forest, root)]).unwrap();
    let private = binding(&["kernel", "helpers"], &["helper"]);
    for canonical in [binding(&[], &["safe"]), binding(&["child"], &["safe"])] {
        let metadata = naming(
            [canonical.clone(), private.clone()],
            [(path(&["public", "nested", "run"]), canonical.key())],
            [
                (canonical.key(), implementation(&forest, root)),
                (private.key(), implementation(&forest, helper)),
            ],
            None,
        );
        let result = metadata.validate_package(TargetType::Kernel, &forest, &manifest);
        if canonical.parent_namespace() == Namespace::initial() {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(PackageNamingError::KernelExportOutsideRoot { .. })));
        }
    }
}

#[test]
fn manifest_path_lowering_preserves_quoted_separator_components() {
    let quoted = callable_path_from_manifest(Path::new(r#"::"a::b"::"run""#)).unwrap();
    assert_eq!(quoted, path(&["a::b", "run"]));
    assert_ne!(quoted, path(&["a", "b", "run"]));
}
