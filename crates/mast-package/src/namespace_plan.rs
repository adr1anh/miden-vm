//! Explicit in-memory namespace homes for declaration key derivation.
//!
//! A plan computes names; it does not authenticate bindings, authorize a home or publisher,
//! establish a kernel namespace, or select code. Protocol-specific home policies and interchange
//! formats remain the responsibility of their owning layers.

use alloc::{string::String, vec::Vec};

use miden_core::program::{CanonicalLabel, LabelError, Namespace, ProcedureKey};

use crate::{CallableProcedurePath, PublicProcedurePath};

mod serialization;

/// An explicitly supplied complete home path, independent of code and source import aliases.
///
/// Home components retain their types through [`CanonicalLabel`]: LibraryId words, nonzero
/// revisions, externally validated TypedIds, and Text labels are distinct. A supplied LibraryId
/// label is opaque; this type does not derive its identity or authenticate its publisher.
///
/// There is no default home. An explicitly supplied empty path denotes [`Namespace::initial`].
/// Generic label validity does not imply that a Protocol profile permits or authorizes the home.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacePlan {
    home: Vec<CanonicalLabel>,
}

impl NamespacePlan {
    /// Retains an explicit home made from validated canonical labels.
    ///
    /// TypedId construction/decoding must use the core label API's external codec validator.
    /// This method adds no AccountId parser or Protocol-specific home-shape policy.
    pub fn new(home: Vec<CanonicalLabel>) -> Self {
        Self { home }
    }

    /// Returns the complete typed home path supplied by the caller.
    pub fn home(&self) -> &[CanonicalLabel] {
        &self.home
    }

    /// Derives the accumulated namespace at the supplied home without authenticating it.
    pub fn namespace(&self) -> Namespace {
        self.home
            .iter()
            .fold(Namespace::initial(), |namespace, label| namespace.child(label.commitment()))
    }

    /// Derives the immediate parent namespace of a public procedure under this home.
    ///
    /// Public namespace components are Text labels; source aliases do not enter the derivation.
    pub fn parent_namespace(&self, path: &PublicProcedurePath) -> Result<Namespace, LabelError> {
        self.parent_namespace_from_components(path.components())
    }

    /// Derives the immediate parent namespace of any callable under this explicit home.
    ///
    /// Every path component is Text, including reserved source roots. The caller must supply
    /// canonical helper prefixes explicitly. This method does not resolve aliases, choose a
    /// profile, or authorize a kernel namespace.
    pub fn callable_parent_namespace(
        &self,
        path: &CallableProcedurePath,
    ) -> Result<Namespace, LabelError> {
        self.parent_namespace_from_components(path.components())
    }

    fn parent_namespace_from_components(
        &self,
        components: &[String],
    ) -> Result<Namespace, LabelError> {
        let (_, namespaces) = components.split_last().expect("validated paths are nonempty");
        let mut namespace = self.namespace();
        for component in namespaces {
            namespace = namespace.child(CanonicalLabel::text(component)?.commitment());
        }
        Ok(namespace)
    }

    /// Derives a declaration's key without an implementation root or selected release.
    ///
    /// ABI text, tooling signatures, source aliases, forests and the execution environment root
    /// do not enter the key. The result does not authenticate a callable binding.
    pub fn procedure_key(&self, path: &PublicProcedurePath) -> Result<ProcedureKey, LabelError> {
        self.procedure_key_from_components(path.components())
    }

    /// Derives a callable key without a body, implementation root, ABI, or selected release.
    ///
    /// Entry and helper paths use the same Text label derivation as public paths. Naming a
    /// callable grants no binding or publication authority and does not make it a public export.
    pub fn callable_procedure_key(
        &self,
        path: &CallableProcedurePath,
    ) -> Result<ProcedureKey, LabelError> {
        self.procedure_key_from_components(path.components())
    }

    fn procedure_key_from_components(
        &self,
        components: &[String],
    ) -> Result<ProcedureKey, LabelError> {
        let local = components.last().expect("validated paths are nonempty");
        Ok(self
            .parent_namespace_from_components(components)?
            .procedure_key(CanonicalLabel::text(local)?.commitment()))
    }
}

#[cfg(test)]
mod interface_tests;
