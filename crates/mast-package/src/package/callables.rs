//! Detached callable declarations, source-visible names, and optional implementation selections.

use alloc::collections::BTreeMap;

use miden_core::program::{ImplementationRoot, ProcedureKey};

use crate::{CallableBinding, CallableProcedurePath};

/// An in-memory inventory of named callables, independently of selected code and source aliases.
///
/// Every supplied binding is retained, including implementation-private helpers, entrypoints and
/// address-taken procedures without visible aliases. Visible semantic paths refer to existing keys;
/// they do not derive new keys or change the target's canonical home. A wrapper is a separate
/// binding, even when it selects the same implementation as another callable.
///
/// A selected implementation root is optional for each declaration. It neither establishes code
/// availability nor authenticates an environment binding. Construction validates only these three
/// relations between already-owned values; it does not admit a home, authorize a publisher or
/// kernel namespace, or establish executable-path uniqueness across composed environments.
///
/// This detached inventory is not a serialized package, interface or release artifact. Library
/// identity, executable entry selection and authorized full kernel paths remain requirements of
/// their respective artifact/configuration containers. A future admission operation must use
/// explicit caller-supplied profile, context and aggregate resource bounds; validating each home
/// with a fresh budget does not bound the complete inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageCallables {
    bindings: BTreeMap<ProcedureKey, CallableBinding>,
    visible_paths: BTreeMap<CallableProcedurePath, ProcedureKey>,
    selected_implementations: BTreeMap<ProcedureKey, ImplementationRoot>,
}

impl PackageCallables {
    /// Retains declarations, visible aliases and independently optional implementation selections.
    ///
    /// All bindings are collected before checking aliases and selections, so input order within
    /// each relation does not affect successful construction. Duplicate keys or visible paths are
    /// rejected even when their associated values are identical. Empty inventories and declarations
    /// without aliases or selected implementations are permitted.
    pub fn new(
        bindings: impl IntoIterator<Item = CallableBinding>,
        visible_paths: impl IntoIterator<Item = (CallableProcedurePath, ProcedureKey)>,
        selected_implementations: impl IntoIterator<Item = (ProcedureKey, ImplementationRoot)>,
    ) -> Result<Self, PackageCallablesError> {
        let mut unique_bindings = BTreeMap::new();
        for binding in bindings {
            let key = binding.key();
            if unique_bindings.insert(key, binding).is_some() {
                return Err(PackageCallablesError::DuplicateBinding { key });
            }
        }

        let mut unique_visible_paths = BTreeMap::new();
        for (path, key) in visible_paths {
            if !unique_bindings.contains_key(&key) {
                return Err(PackageCallablesError::UnknownVisiblePathTarget { path, key });
            }
            if unique_visible_paths.insert(path.clone(), key).is_some() {
                return Err(PackageCallablesError::DuplicateVisiblePath { path });
            }
        }

        let mut unique_implementations = BTreeMap::new();
        for (key, implementation) in selected_implementations {
            if !unique_bindings.contains_key(&key) {
                return Err(PackageCallablesError::UnknownImplementationTarget { key });
            }
            if unique_implementations.insert(key, implementation).is_some() {
                return Err(PackageCallablesError::DuplicateImplementation { key });
            }
        }

        Ok(Self {
            bindings: unique_bindings,
            visible_paths: unique_visible_paths,
            selected_implementations: unique_implementations,
        })
    }

    /// Iterates over every declaration in key order, without defining a wire encoding.
    pub fn bindings(&self) -> impl ExactSizeIterator<Item = (&ProcedureKey, &CallableBinding)> {
        self.bindings.iter()
    }

    /// Looks up a declaration independently of its visibility or selected implementation.
    pub fn binding(&self, key: ProcedureKey) -> Option<&CallableBinding> {
        self.bindings.get(&key)
    }

    /// Iterates over visible semantic paths in component-value order.
    ///
    /// The order is an in-memory lookup order, not a canonical serialization contract.
    pub fn visible_paths(
        &self,
    ) -> impl ExactSizeIterator<Item = (&CallableProcedurePath, &ProcedureKey)> {
        self.visible_paths.iter()
    }

    /// Returns the existing key named by a caller-lowered visible semantic path.
    ///
    /// This is a table lookup, without source parsing, alias expansion or home derivation.
    pub fn key_for_visible_path(&self, path: &CallableProcedurePath) -> Option<ProcedureKey> {
        self.visible_paths.get(path).copied()
    }

    /// Iterates over supplied implementation selections in key order.
    ///
    /// Declarations without a selected implementation have no entry in this relation.
    pub fn selected_implementations(
        &self,
    ) -> impl ExactSizeIterator<Item = (&ProcedureKey, &ImplementationRoot)> {
        self.selected_implementations.iter()
    }

    /// Returns the selected implementation commitment, without establishing code availability.
    pub fn selected_implementation(&self, key: ProcedureKey) -> Option<ImplementationRoot> {
        self.selected_implementations.get(&key).copied()
    }
}

/// Duplicate inventory entries or references to undeclared callable keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackageCallablesError {
    #[error("duplicate callable binding for key {key:?}")]
    DuplicateBinding { key: ProcedureKey },
    #[error("duplicate visible callable path: {path:?}")]
    DuplicateVisiblePath { path: CallableProcedurePath },
    #[error("visible callable path {path:?} refers to undeclared key {key:?}")]
    UnknownVisiblePathTarget {
        path: CallableProcedurePath,
        key: ProcedureKey,
    },
    #[error("duplicate implementation selection for callable key {key:?}")]
    DuplicateImplementation { key: ProcedureKey },
    #[error("implementation selection refers to undeclared callable key {key:?}")]
    UnknownImplementationTarget { key: ProcedureKey },
}

#[cfg(test)]
mod tests;
