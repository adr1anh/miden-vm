//! Detached callable declarations, source-visible names, and optional implementation selections.

use alloc::collections::BTreeMap;

use miden_core::program::{ImplementationRoot, ProcedureKey};

use crate::{
    CallableBinding, CallableProcedurePath,
    interface::serialization::{Budget, CodecError, CodecLimits, HomeProfile, checked_add},
};

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
/// their respective artifact/configuration containers. [`Self::validate_homes`] checks explicit
/// caller-supplied home policy and aggregate owned-data bounds. Full artifact admission, including
/// future wire-format validation, remains a separate container operation.
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

    /// Revalidates every binding home and bounds this inventory's aggregate owned logical data.
    ///
    /// Every invocation uses the supplied profile and context afresh, including for empty N0
    /// homes and bindings without visible aliases or selected implementations. The context owns
    /// the evidence associating each complete home with the caller; no default policy is used.
    /// Repeated owned homes are counted and checked separately.
    ///
    /// All three relations share the caller's finite [`CodecLimits`]:
    /// - `max_bytes` counts one 32-byte K per binding and visible alias, 32-byte K plus 32-byte D
    ///   per implementation selection, complete stored home-label envelopes, and exact UTF-8 bytes
    ///   of every canonical and visible path component, including final procedure names.
    /// - `max_records` counts bindings, visible aliases, implementation selections and home labels.
    /// - `max_components` counts home labels and every canonical and visible path component.
    /// - `max_blob_bytes` counts home-label payloads, including TypedId codec numbers, and the same
    ///   path UTF-8 bytes. Each owned occurrence is charged once.
    ///
    /// This byte measure includes no hypothetical wire framing, cached derived keys/namespaces,
    /// capacities or allocator overhead; it is not an allocator/RSS guarantee or a wire format.
    /// All aggregate bounds are checked before any external profile callback.
    ///
    /// Success retains no validation state. It checks only TypedId/home policy and these resource
    /// bounds, without admitting an artifact, establishing library/entry/kernel metadata,
    /// authenticating a K-to-D binding, proving code availability or granting Protocol admission.
    pub fn validate_homes<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<(), CodecError<P::Error>> {
        self.validate_homes_with_budget(profile, context, &mut Budget::new(limits))
    }

    /// Uses an enclosing operation's budget without resetting any resource consumption.
    ///
    /// This charges the same owned data as `validate_homes`; an enclosing wire codec must also
    /// check its complete wire input/output and required container metadata. On error, callers
    /// must abort their operation rather than treating partially checked data as validated.
    pub(crate) fn validate_homes_with_budget<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        budget: &mut Budget,
    ) -> Result<(), CodecError<P::Error>> {
        budget.records(self.bindings.len())?;
        budget.records(self.visible_paths.len())?;
        budget.records(self.selected_implementations.len())?;

        let mut home_blob_bytes = 0;
        for binding in self.bindings.values() {
            budget.logical_bytes(32)?;
            let home = binding.namespace_plan().home();
            budget.records(home.len())?;
            budget.components(home.len())?;
            for label in home {
                let bytes = label.as_bytes().len();
                budget.logical_bytes(bytes)?;
                home_blob_bytes = checked_add(home_blob_bytes, bytes - 6, "blob bytes")?;
            }
            charge_path_resources(binding.path(), budget)?;
        }
        for path in self.visible_paths.keys() {
            budget.logical_bytes(32)?;
            charge_path_resources(path, budget)?;
        }
        for _ in self.selected_implementations.values() {
            budget.logical_bytes(64)?;
        }
        // Paths were charged above. Home payloads are only checked here, then charged exactly
        // once by the shared HomeV1 contents validator while revalidating external policy.
        budget.check_blob_bytes(home_blob_bytes)?;

        for binding in self.bindings.values() {
            binding
                .namespace_plan()
                .validate_home_contents_with_budget(profile, context, budget)?;
        }
        Ok(())
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

fn charge_path_resources<E>(
    path: &CallableProcedurePath,
    budget: &mut Budget,
) -> Result<(), CodecError<E>> {
    budget.components(path.components().len())?;
    for component in path.components() {
        budget.logical_bytes(component.len())?;
        budget.blob_bytes(component.len())?;
    }
    Ok(())
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
mod home_validation_tests;
#[cfg(test)]
mod tests;
