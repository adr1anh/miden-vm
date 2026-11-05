use alloc::vec::Vec;

use miden_core::{
    Felt, Word,
    program::{CanonicalLabel, ImplementationRoot},
};

use super::{PackageCallables, PackageCallablesError};
use crate::{CallableProcedurePath, NamespacePath, ProcedureName};

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    )
    .unwrap()
}

fn binding(home: &[&str], components: &[&str]) -> ProcedureName {
    ProcedureName::new(
        NamespacePath::new(
            home.iter().map(|component| CanonicalLabel::text(component).unwrap()).collect(),
        ),
        path(components),
    )
    .unwrap()
}

fn implementation(value: u32) -> ImplementationRoot {
    ImplementationRoot::new(Word::new([value; 4].map(Felt::from_u32)))
}

#[test]
fn unaliased_entry_helpers_and_callbacks_survive_without_selected_code() {
    let entry = binding(&["artifact"], &["$exec", "$main"]);
    let helper = binding(&["artifact"], &["helpers", "hidden"]);
    let callback = binding(&["artifact"], &["callbacks", "dispatch"]);
    let target = binding(&["artifact"], &["public", "run"]);
    let wrapper = binding(&["artifact"], &["public", "wrapper"]);
    let retained = [entry, helper, callback, target, wrapper];
    let target_key = retained[3].key();
    let wrapper_key = retained[4].key();
    let shared_code = implementation(1);

    let inventory = PackageCallables::new(
        retained.clone(),
        [(path(&["imported", "run"]), target_key)],
        [(target_key, shared_code), (wrapper_key, shared_code)],
    )
    .unwrap();

    assert_eq!(inventory.bindings().count(), retained.len());
    for declaration in &retained {
        assert_eq!(inventory.binding(declaration.key()), Some(declaration));
    }
    for declaration in &retained[..3] {
        assert_eq!(inventory.selected_implementation(declaration.key()), None);
    }
    assert_ne!(wrapper_key, target_key);
    assert_eq!(inventory.selected_implementation(target_key), Some(shared_code));
    assert_eq!(inventory.selected_implementation(wrapper_key), Some(shared_code));
    assert_eq!(inventory.visible_paths().count(), 1);
}

#[test]
fn visible_aliases_reuse_keys_without_changing_complete_canonical_homes() {
    let original = binding(&["canonical", "home"], &["math", "run"]);
    let other_home = binding(&["dependency", "home"], &["math", "run"]);
    let original_key = original.key();
    let other_key = other_home.key();
    let aliases = [path(&["renamed", "run"]), path(&["legacy", "go"])];
    let inventory = PackageCallables::new(
        [original.clone(), other_home.clone()],
        aliases.iter().cloned().map(|alias| (alias, original_key)),
        [],
    )
    .unwrap();

    assert_ne!(original_key, other_key);
    for alias in &aliases {
        assert_eq!(inventory.key_for_visible_path(alias), Some(original_key));
        assert_ne!(original.namespace_plan().callable_procedure_key(alias).unwrap(), original_key,);
    }
    assert_eq!(inventory.binding(original_key), Some(&original));
    assert_eq!(inventory.binding(other_key), Some(&other_home));
    assert_eq!(inventory.selected_implementations().count(), 0);
}

#[test]
fn input_order_does_not_change_inventory_relations() {
    let declarations = [
        binding(&["second"], &["module", "run"]),
        binding(&["first"], &["module", "run"]),
        binding(&[], &["private", "helper"]),
    ];
    let aliases = [
        (path(&["right", "run"]), declarations[0].key()),
        (path(&["left", "run"]), declarations[1].key()),
    ];
    let selections = [
        (declarations[0].key(), implementation(2)),
        (declarations[1].key(), implementation(2)),
    ];
    let forward = PackageCallables::new(declarations.clone(), aliases.clone(), selections).unwrap();
    let reversed = PackageCallables::new(
        declarations.into_iter().rev(),
        aliases.into_iter().rev(),
        selections.into_iter().rev(),
    )
    .unwrap();

    assert_eq!(forward, reversed);
    let keys = forward.bindings().map(|(key, _)| *key).collect::<Vec<_>>();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
}

#[test]
fn empty_candidate_has_no_required_artifact_kind_metadata() {
    let inventory = PackageCallables::new([], [], []).unwrap();
    assert_eq!(inventory.bindings().count(), 0);
    assert_eq!(inventory.visible_paths().count(), 0);
    assert_eq!(inventory.selected_implementations().count(), 0);
}

#[test]
fn duplicate_binding_is_rejected_even_when_identical() {
    let declaration = binding(&["home"], &["run"]);
    let key = declaration.key();
    assert_eq!(
        PackageCallables::new([declaration.clone(), declaration], [], []).unwrap_err(),
        PackageCallablesError::DuplicateBinding { key },
    );
}

#[test]
fn duplicate_visible_path_is_rejected_for_identical_or_conflicting_targets() {
    let first = binding(&["home"], &["first"]);
    let second = binding(&["home"], &["second"]);
    let visible = path(&["imported", "run"]);
    for target in [first.key(), second.key()] {
        assert_eq!(
            PackageCallables::new(
                [first.clone(), second.clone()],
                [(visible.clone(), first.key()), (visible.clone(), target)],
                [],
            )
            .unwrap_err(),
            PackageCallablesError::DuplicateVisiblePath { path: visible.clone() },
        );
    }
}

#[test]
fn visible_path_cannot_introduce_an_undeclared_key() {
    let declaration = binding(&["home"], &["run"]);
    let missing = binding(&["another_home"], &["run"]).key();
    let visible = path(&["imported", "run"]);
    assert_eq!(
        PackageCallables::new([declaration], [(visible.clone(), missing)], []).unwrap_err(),
        PackageCallablesError::UnknownVisiblePathTarget { path: visible, key: missing },
    );
}

#[test]
fn duplicate_implementation_selection_is_rejected_even_when_identical() {
    let declaration = binding(&["home"], &["run"]);
    let key = declaration.key();
    for selected in [implementation(3), implementation(4)] {
        assert_eq!(
            PackageCallables::new(
                [declaration.clone()],
                [],
                [(key, implementation(3)), (key, selected)],
            )
            .unwrap_err(),
            PackageCallablesError::DuplicateImplementation { key },
        );
    }
}

#[test]
fn implementation_selection_cannot_introduce_an_undeclared_key() {
    let declaration = binding(&["home"], &["run"]);
    let missing = binding(&["another_home"], &["run"]).key();
    assert_eq!(
        PackageCallables::new([declaration], [], [(missing, implementation(5))]).unwrap_err(),
        PackageCallablesError::UnknownImplementationTarget { key: missing },
    );
}
