//! Standard library homes over generic namespace labels.
//!
//! This is an opt-in toolchain convention. It neither selects a code artifact nor authenticates
//! an identity, publisher, revision or binding. Custom homes continue to use `NamespacePlan`.

use core::num::NonZeroU32;

use miden_core::{
    Word,
    program::{CanonicalLabel, LabelError},
};
use miden_mast_package::{CallableBinding, CallableProcedurePath, NamespacePlan};

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
        program::{Namespace, ProcedureKey},
    };

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
