//! Required generic package names, declarations, selected code and explicit executable entry.

use alloc::{collections::BTreeSet, sync::Arc};

use miden_assembly_syntax::{Path, PathComponent};
use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId},
    program::{ImplementationRoot, Namespace, ProcedureKey},
};

use super::{PackageCallables, PackageManifest, TargetType};
use crate::{CallableProcedurePath, DeclarationError, NamespacePath};

pub(crate) mod serialization;
pub use serialization::{NamingCodecError, UnverifiedPackageSymbols};

/// The complete naming inventory required by a generic code package.
///
/// The package's explicit compilation home does not constrain the homes of foreign bindings.
/// Names, declarations, selected implementations and source-visible aliases remain separate.
/// There is no package-owned library identity, publication profile or implicit home policy.
/// Construction and [`Self::validate_package`] check owned relations only: they do not authorize
/// an environment, authenticate a K-to-D binding or admit a publication/release profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSymbols {
    namespace_plan: NamespacePath,
    callables: PackageCallables,
    entry_key: Option<ProcedureKey>,
}

impl PackageSymbols {
    /// Retains explicit naming metadata, requiring a supplied entry key to be declared.
    ///
    /// Call [`Self::validate_package`] to check the target, manifest and code relations. Home
    /// policy and environment admission require separate, explicitly supplied caller evidence.
    pub fn new(
        namespace_plan: NamespacePath,
        callables: PackageCallables,
        entry_key: Option<ProcedureKey>,
    ) -> Result<Self, PackageSymbolsError> {
        if let Some(key) = entry_key
            && callables.binding(key).is_none()
        {
            return Err(PackageSymbolsError::UnknownEntryKey { key });
        }
        Ok(Self { namespace_plan, callables, entry_key })
    }

    pub fn namespace_plan(&self) -> &NamespacePath {
        &self.namespace_plan
    }

    pub fn callables(&self) -> &PackageCallables {
        &self.callables
    }

    pub fn entry_key(&self) -> Option<ProcedureKey> {
        self.entry_key
    }

    /// Checks required naming against the exact manifest and retained procedure roots.
    ///
    /// Every procedure export has exactly one visible path-to-key entry and a selected D matching
    /// its export digest. Every selected D resolves to a procedure root, and every retained root
    /// has a selected callable binding. Multiple keys may select the same D; declarations need
    /// neither an alias nor selected code. An `External(D)` procedure root is a code availability
    /// hint and passes this structural check without authenticating a binding or supplying code.
    /// Literal runtime invocation keys are not required to be declared by this package.
    ///
    /// A usage tag alone does not make a code candidate runnable: any kind may omit entry metadata
    /// when its manifest has no entrypoint. A manifest entry requires an explicit matching visible
    /// K and selected D. An Executable may instead select a private entry K without a public alias,
    /// but that declared key must select a procedure root. Other kinds cannot carry an entry.
    /// The key is never reconstructed from D or a source path. Kernel public exports must have
    /// immediate parent N0. Private-source helper placement remains a construction/admission
    /// obligation: this persisted inventory cannot distinguish helpers from foreign references.
    /// This operation does not validate homes against a selected profile or authorize an R_E.
    pub fn validate_package(
        &self,
        kind: TargetType,
        mast: &MastForest,
        manifest: &PackageManifest,
    ) -> Result<(), PackageSymbolsError> {
        if !kind.is_executable() && (self.entry_key.is_some() || manifest.entrypoint().is_some()) {
            return Err(PackageSymbolsError::NonExecutableEntrypoint);
        }
        if mast.procedure_roots().is_empty() {
            return Err(PackageSymbolsError::NoProcedures);
        }
        if let Some(key) = self.entry_key
            && self.callables.selected_implementation(key).is_none()
        {
            return Err(PackageSymbolsError::MissingEntryImplementation { key });
        }

        let mut exports = BTreeSet::new();
        for export in manifest.exports().filter_map(|export| export.as_procedure()) {
            let path = callable_path_from_manifest(&export.path)?;
            if !exports.insert(path.clone()) {
                return Err(PackageSymbolsError::DuplicateVisibleExport { path });
            }
            let key = self
                .callables
                .key_for_visible_path(&path)
                .ok_or_else(|| PackageSymbolsError::MissingVisibleExport { path: path.clone() })?;
            let selected = self
                .callables
                .selected_implementation(key)
                .ok_or(PackageSymbolsError::MissingExportImplementation { key })?;
            if selected.into_word() != export.digest {
                return Err(PackageSymbolsError::ExportImplementationMismatch { path, key });
            }
            if let Some(node) = export.node {
                if !mast.is_procedure_root_with_exact_digest(node, export.digest) {
                    return Err(PackageSymbolsError::InvalidProcedureExport {
                        path: export.path.clone(),
                    });
                }
            } else if mast.find_procedure_root(export.digest).is_none() {
                return Err(PackageSymbolsError::MissingProcedureMast {
                    path: export.path.clone(),
                    digest: export.digest,
                });
            }
            if kind == TargetType::Kernel
                && self
                    .callables
                    .binding(key)
                    .expect("visible keys are declared")
                    .parent_namespace()
                    != Namespace::initial()
            {
                return Err(PackageSymbolsError::KernelExportOutsideRoot { path, key });
            }
        }
        for (path, _) in self.callables.visible_paths() {
            if !exports.contains(path) {
                return Err(PackageSymbolsError::UnexpectedVisiblePath { path: path.clone() });
            }
        }

        let mut selected_roots = BTreeSet::new();
        for (&key, &implementation) in self.callables.selected_implementations() {
            if mast.find_procedure_root(implementation.into_word()).is_none() {
                return Err(PackageSymbolsError::MissingSelectedRoot { key, implementation });
            }
            selected_roots.insert(implementation);
        }
        for &node in mast.procedure_roots() {
            let implementation = ImplementationRoot::new(mast[node].digest());
            if !selected_roots.contains(&implementation) {
                return Err(PackageSymbolsError::UnboundProcedureRoot { node, implementation });
            }
        }

        if let Some(entry) = manifest.entrypoint() {
            let key = self.entry_key.ok_or(PackageSymbolsError::MissingEntryKey)?;
            let path = callable_path_from_manifest(&entry)?;
            if self.callables.key_for_visible_path(&path) != Some(key) {
                return Err(PackageSymbolsError::EntryKeyMismatch { key });
            }
            // Export validation above already requires this entry's selected D to match both
            // the manifest digest and an exact procedure root.
        }
        Ok(())
    }
}

/// Lowers a manifest's already parsed source path to exact semantic callable components.
/// Absolute source roots are location syntax, while reserved roots remain ordinary Text.
pub(crate) fn callable_path_from_manifest(
    path: &Path,
) -> Result<CallableProcedurePath, PackageSymbolsError> {
    let convert = || -> Result<CallableProcedurePath, DeclarationError> {
        Path::validate(path.as_str())?;
        let mut components = alloc::vec::Vec::new();
        for component in path.components() {
            let component = component?;
            if component != PathComponent::Root {
                components.push(component.as_str().into());
            }
        }
        CallableProcedurePath::from_semantic_components(components)
    };
    convert().map_err(|source| PackageSymbolsError::InvalidCallablePath {
        path: path.to_path_buf().into(),
        source,
    })
}

/// Inconsistent required naming, manifest, code or entry relations in a generic package.
#[derive(Debug, thiserror::Error)]
pub enum PackageSymbolsError {
    #[error("non-executable package contains an entrypoint")]
    NonExecutableEntrypoint,
    #[error("package must contain at least one callable procedure root")]
    NoProcedures,
    #[error("procedure export '{path}' does not identify an exact procedure root")]
    InvalidProcedureExport { path: Arc<Path> },
    #[error("procedure export '{path}' has no procedure root for digest {digest:?}")]
    MissingProcedureMast { path: Arc<Path>, digest: Word },
    #[error("invalid callable export path '{path}': {source}")]
    InvalidCallablePath {
        path: Arc<Path>,
        #[source]
        source: DeclarationError,
    },
    #[error("entry key {key:?} is not declared")]
    UnknownEntryKey { key: ProcedureKey },
    #[error("manifest contains duplicate semantic procedure export {path:?}")]
    DuplicateVisibleExport { path: CallableProcedurePath },
    #[error("procedure export {path:?} has no visible callable key")]
    MissingVisibleExport { path: CallableProcedurePath },
    #[error("visible callable path {path:?} has no manifest procedure export")]
    UnexpectedVisiblePath { path: CallableProcedurePath },
    #[error("exported callable {key:?} has no selected implementation")]
    MissingExportImplementation { key: ProcedureKey },
    #[error("procedure export {path:?} and callable {key:?} select different implementations")]
    ExportImplementationMismatch {
        path: CallableProcedurePath,
        key: ProcedureKey,
    },
    #[error("callable {key:?} selects {implementation:?} without a matching procedure root")]
    MissingSelectedRoot {
        key: ProcedureKey,
        implementation: ImplementationRoot,
    },
    #[error("procedure root {node:?} ({implementation:?}) has no selected callable binding")]
    UnboundProcedureRoot {
        node: MastNodeId,
        implementation: ImplementationRoot,
    },
    #[error("manifest entrypoint has no explicit entry key")]
    MissingEntryKey,
    #[error("entry key {key:?} has no selected implementation")]
    MissingEntryImplementation { key: ProcedureKey },
    #[error("explicit entry key {key:?} differs from the manifest entry's visible key")]
    EntryKeyMismatch { key: ProcedureKey },
    #[error("public kernel export {path:?} ({key:?}) is outside fixed N0")]
    KernelExportOutsideRoot {
        path: CallableProcedurePath,
        key: ProcedureKey,
    },
}

#[cfg(test)]
mod tests;
