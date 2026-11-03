//! Standard library homes over generic namespace labels.
//!
//! This is an opt-in toolchain convention. It neither selects a code artifact nor authenticates
//! an identity, publisher, revision or binding. Custom homes continue to use `NamespacePlan`.

use alloc::collections::{BTreeMap, btree_map::Entry};
use core::num::NonZeroU32;

use miden_core::{
    Word,
    program::{CanonicalLabel, LabelError},
};
use miden_mast_package::{CallableBinding, CallableProcedurePath, NamespacePlan, PackageNaming};

use crate::Report;

/// The caller's independently expected complete visible callable mapping for a dependency.
///
/// Every visible path names a complete defining binding, including its own home. Reexports may
/// retain foreign bindings, and private declarations need not appear here. This expectation does
/// not select implementations, supply code, admit a home/profile or authorize an environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedVisibleCallables {
    mappings: BTreeMap<CallableProcedurePath, CallableBinding>,
}

impl ExpectedVisibleCallables {
    /// Retains an exact expected public mapping, rejecting even identical duplicate paths.
    pub fn new(
        mappings: impl IntoIterator<Item = (CallableProcedurePath, CallableBinding)>,
    ) -> Result<Self, Report> {
        let mut unique = BTreeMap::new();
        for (path, binding) in mappings {
            match unique.entry(path) {
                Entry::Vacant(entry) => {
                    entry.insert(binding);
                },
                Entry::Occupied(entry) => {
                    return Err(Report::msg(format!(
                        "duplicate expected visible callable path {:?}",
                        entry.key()
                    )));
                },
            }
        }
        Ok(Self { mappings: unique })
    }

    /// Borrows the caller-supplied visible paths and complete defining bindings.
    pub fn mappings(&self) -> &BTreeMap<CallableProcedurePath, CallableBinding> {
        &self.mappings
    }

    /// Checks exact visible-path and complete-binding agreement with already admitted naming.
    ///
    /// The caller must separately admit the exact package under its selected profile and check
    /// package/code relationships. This comparison does not restrict retained private bindings,
    /// infer ownership from the package default home or validate implementation selections.
    pub fn check(&self, naming: &PackageNaming) -> Result<(), Report> {
        let callables = naming.callables();
        for (path, expected) in &self.mappings {
            let key = callables.key_for_visible_path(path).ok_or_else(|| {
                Report::msg(format!("missing expected visible callable path {path:?}"))
            })?;
            if key != expected.key() || callables.binding(key) != Some(expected) {
                return Err(Report::msg(format!(
                    "visible callable path {path:?} differs from its expected complete binding"
                )));
            }
        }
        for (path, _) in callables.visible_paths() {
            if !self.mappings.contains_key(path) {
                return Err(Report::msg(format!("unexpected visible callable path {path:?}")));
            }
        }
        Ok(())
    }
}

/// An explicitly chosen runtime dependency mode, independent of source semver/Git provenance.
///
/// There is deliberately no default: callers must choose Latest or Pinned. Pinned qualifies the
/// callable name with a nonzero revision; the authorized execution environment still selects D.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LibrarySelection {
    Latest,
    Pinned(NonZeroU32),
}

/// A standard library binding beneath the caller's complete ancestor base.
///
/// Latest appends `Text("latest") / LibraryId(I)`. Pinned appends
/// `Text("pinned") / LibraryId(I) / Revision(r)`. Module/export components are supplied separately
/// as semantic callable paths. Neither source aliases nor implementation roots enter these names.
///
/// The supplied ID is opaque. This type provides no identity derivation, publication admission,
/// relocation, freshness rule or authority to execute any selected implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryImport {
    base: NamespacePlan,
    library_id: Word,
    selection: LibrarySelection,
}

impl LibraryImport {
    /// Retains the complete base, supplied identity and explicit runtime selection.
    pub fn new(base: NamespacePlan, library_id: Word, selection: LibrarySelection) -> Self {
        Self { base, library_id, selection }
    }

    pub fn base(&self) -> &NamespacePlan {
        &self.base
    }

    pub fn library_id(&self) -> Word {
        self.library_id
    }

    pub fn selection(&self) -> LibrarySelection {
        self.selection
    }

    /// Produces a complete generic home without interpreting or discarding ancestor labels.
    ///
    /// TypedId ancestors must already have been validated by their owning codec/profile. The
    /// resulting home still needs the selected consumer's admission and authorization checks.
    pub fn namespace_plan(&self) -> NamespacePlan {
        let mut labels = self.base.home().to_vec();
        let mode = match self.selection {
            LibrarySelection::Latest => "latest",
            LibrarySelection::Pinned(_) => "pinned",
        };
        labels.push(CanonicalLabel::text(mode).expect("fixed selection text is representable"));
        labels.push(CanonicalLabel::library_id(self.library_id));
        if let LibrarySelection::Pinned(revision) = self.selection {
            labels.push(CanonicalLabel::revision(revision));
        }
        NamespacePlan::new(labels)
    }

    /// Binds an explicit semantic module/export path without requiring code or selecting a body.
    pub fn callable_binding(
        &self,
        path: CallableProcedurePath,
    ) -> Result<CallableBinding, LabelError> {
        CallableBinding::new(self.namespace_plan(), path)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use miden_core::{
        Felt,
        program::{ImplementationRoot, Namespace, ProcedureKey},
    };
    use miden_mast_package::PackageCallables;

    use super::*;

    fn id(value: u32) -> Word {
        Word::new([Felt::from_u32(value); 4])
    }

    fn path() -> CallableProcedurePath {
        CallableProcedurePath::from_semantic_components(vec!["math".into(), "add".into()]).unwrap()
    }

    fn key(import: &LibraryImport) -> ProcedureKey {
        import.callable_binding(path()).unwrap().key()
    }

    fn semantic(components: &[&str]) -> CallableProcedurePath {
        CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| (*component).into()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn expected_visible_mapping_preserves_aliases_foreign_homes_and_private_inventory() {
        let defining =
            LibraryImport::new(NamespacePlan::new(vec![]), id(1), LibrarySelection::Latest)
                .callable_binding(semantic(&["defining", "run"]))
                .unwrap();
        let foreign = LibraryImport::new(
            NamespacePlan::new(vec![]),
            id(2),
            LibrarySelection::Pinned(NonZeroU32::new(3).unwrap()),
        )
        .callable_binding(semantic(&["foreign", "helper"]))
        .unwrap();
        let private = CallableBinding::new(
            NamespacePlan::new(vec![CanonicalLabel::text("private-child").unwrap()]),
            semantic(&["hidden"]),
        )
        .unwrap();
        let alias = semantic(&["facade", "renamed"]);
        let second_alias = semantic(&["facade", "also_run"]);
        let foreign_alias = semantic(&["facade", "foreign"]);
        let expected = ExpectedVisibleCallables::new([
            (alias.clone(), defining.clone()),
            (second_alias.clone(), defining.clone()),
            (foreign_alias.clone(), foreign.clone()),
        ])
        .unwrap();
        assert_eq!(expected.mappings().len(), 3);
        for body in [id(10), id(11)] {
            let callables = PackageCallables::new(
                [defining.clone(), foreign.clone(), private.clone()],
                [
                    (alias.clone(), defining.key()),
                    (second_alias.clone(), defining.key()),
                    (foreign_alias.clone(), foreign.key()),
                ],
                [(defining.key(), ImplementationRoot::new(body))],
            )
            .unwrap();
            // Default metadata and selected bodies are separate from the expected public map.
            let naming = PackageNaming::new(
                NamespacePlan::new(vec![CanonicalLabel::text("default-only").unwrap()]),
                callables,
                None,
            )
            .unwrap();
            expected.check(&naming).unwrap();
            assert_eq!(naming.callables().binding(private.key()), Some(&private));
        }
    }

    #[test]
    fn expected_visible_mapping_rejects_duplicate_missing_extra_and_changed_bindings() {
        let visible = semantic(&["public", "run"]);
        let extra = semantic(&["public", "extra"]);
        let original =
            LibraryImport::new(NamespacePlan::new(vec![]), id(1), LibrarySelection::Latest)
                .callable_binding(semantic(&["defining", "run"]))
                .unwrap();
        let changed =
            LibraryImport::new(NamespacePlan::new(vec![]), id(2), LibrarySelection::Latest)
                .callable_binding(original.path().clone())
                .unwrap();
        let duplicate = ExpectedVisibleCallables::new([
            (visible.clone(), original.clone()),
            (visible.clone(), original.clone()),
        ])
        .unwrap_err();
        assert!(duplicate.to_string().contains("duplicate expected visible callable path"));
        let naming = PackageNaming::new(
            NamespacePlan::new(vec![]),
            PackageCallables::new([original.clone()], [(visible.clone(), original.key())], [])
                .unwrap(),
            None,
        )
        .unwrap();
        let missing = ExpectedVisibleCallables::new([
            (visible.clone(), original.clone()),
            (extra, original.clone()),
        ])
        .unwrap()
        .check(&naming)
        .unwrap_err();
        assert!(missing.to_string().contains("missing expected visible callable path"));
        let unexpected = ExpectedVisibleCallables::new([]).unwrap().check(&naming).unwrap_err();
        assert!(unexpected.to_string().contains("unexpected visible callable path"));
        let mismatch = ExpectedVisibleCallables::new([(visible, changed)])
            .unwrap()
            .check(&naming)
            .unwrap_err();
        assert!(mismatch.to_string().contains("expected complete binding"));
        let private_only = PackageNaming::new(
            NamespacePlan::new(vec![]),
            PackageCallables::new([original], [], []).unwrap(),
            None,
        )
        .unwrap();
        ExpectedVisibleCallables::new([]).unwrap().check(&private_only).unwrap();
    }

    #[test]
    fn latest_preserves_the_complete_typed_base_and_exact_label_order() {
        let base = NamespacePlan::new(vec![
            CanonicalLabel::text("tenant").unwrap(),
            CanonicalLabel::library_id(id(8)),
            CanonicalLabel::revision(NonZeroU32::new(3).unwrap()),
        ]);
        let import = LibraryImport::new(base.clone(), id(11), LibrarySelection::Latest);
        let expected = NamespacePlan::new(vec![
            CanonicalLabel::text("tenant").unwrap(),
            CanonicalLabel::library_id(id(8)),
            CanonicalLabel::revision(NonZeroU32::new(3).unwrap()),
            CanonicalLabel::text("latest").unwrap(),
            CanonicalLabel::library_id(id(11)),
        ]);
        assert_eq!(import.base(), &base);
        assert_eq!(import.library_id(), id(11));
        assert_eq!(import.selection(), LibrarySelection::Latest);
        assert_eq!(import.namespace_plan(), expected);
        assert_eq!(key(&import), expected.callable_procedure_key(&path()).unwrap());
        assert_eq!(
            import.callable_binding(path()).unwrap().parent_namespace(),
            expected.callable_parent_namespace(&path()).unwrap()
        );
    }

    #[test]
    fn pinned_revision_changes_the_key_without_naming_a_body() {
        let base = NamespacePlan::new(vec![]);
        let latest = LibraryImport::new(base.clone(), id(1), LibrarySelection::Latest);
        let pinned1 = LibraryImport::new(
            base.clone(),
            id(1),
            LibrarySelection::Pinned(NonZeroU32::new(1).unwrap()),
        );
        let pinned2 =
            LibraryImport::new(base, id(1), LibrarySelection::Pinned(NonZeroU32::new(2).unwrap()));
        assert_ne!(key(&latest), key(&pinned1));
        assert_ne!(key(&pinned1), key(&pinned2));
        assert_eq!(
            pinned1.namespace_plan().home(),
            &[
                CanonicalLabel::text("pinned").unwrap(),
                CanonicalLabel::library_id(id(1)),
                CanonicalLabel::revision(NonZeroU32::new(1).unwrap())
            ]
        );
        assert_ne!(
            pinned1.callable_binding(path()).unwrap().parent_namespace(),
            Namespace::initial()
        );
    }

    #[test]
    fn ancestor_types_boundaries_and_identity_remain_significant() {
        let import = |base, identity| LibraryImport::new(base, identity, LibrarySelection::Latest);
        let plain = import(NamespacePlan::new(vec![]), id(1));
        assert_ne!(key(&plain), key(&import(NamespacePlan::new(vec![]), id(2))));
        let typed = import(NamespacePlan::new(vec![CanonicalLabel::library_id(id(2))]), id(1));
        let text = import(
            NamespacePlan::new(vec![CanonicalLabel::text(&id(2).to_string()).unwrap()]),
            id(1),
        );
        assert_ne!(key(&typed), key(&text));
        let joined = import(NamespacePlan::new(vec![CanonicalLabel::text("a::b").unwrap()]), id(1));
        let split = import(
            NamespacePlan::new(vec![
                CanonicalLabel::text("a").unwrap(),
                CanonicalLabel::text("b").unwrap(),
            ]),
            id(1),
        );
        assert_ne!(key(&joined), key(&split));
        assert_ne!(key(&plain), key(&joined));
    }

    #[test]
    fn externally_validated_typed_ancestors_are_retained_without_revalidation_or_rewriting() {
        let ancestor = CanonicalLabel::typed_id(77, &[4, 0, 9], |kind, bytes| {
            assert_eq!(kind, 77);
            assert_eq!(bytes, &[4, 0, 9]);
            Ok(())
        })
        .unwrap();
        let import = LibraryImport::new(
            NamespacePlan::new(vec![ancestor.clone()]),
            id(1),
            LibrarySelection::Latest,
        );
        assert_eq!(import.namespace_plan().home()[0], ancestor);
        // Custom homes still name callables directly; no standard prefix is imposed on them.
        let custom = CallableBinding::new(NamespacePlan::new(vec![]), path()).unwrap();
        assert_ne!(key(&import), custom.key());
    }
}
