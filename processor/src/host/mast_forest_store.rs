use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt},
    program::{ImplementationRoot, ProcedureKey},
};
use miden_mast_package::{
    CodePackage, PackageDebugInfoError, PackageProcedureOccurrence, PackageSymbols,
    debug_info::PackageDebugInfo,
};

/// An untrusted request for available code, separate from execution authorization.
///
/// Procedure requests preserve an already authenticated key and implementation root so a host can
/// supply their exact code/source occurrence. The request itself is not an authorization token:
/// the processor authenticates the binding and syscall namespace before consulting code witnesses.
/// Structural external requests ask only for a materialized body and do not introduce a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CodeRequest {
    Procedure {
        key: ProcedureKey,
        implementation: ImplementationRoot,
    },
    External {
        implementation: ImplementationRoot,
    },
}

impl CodeRequest {
    /// Returns the implementation root whose materialized code is requested.
    pub const fn implementation(self) -> ImplementationRoot {
        match self {
            Self::Procedure { implementation, .. } | Self::External { implementation } => {
                implementation
            },
        }
    }

    /// Returns the supplied procedure key, if this is a keyed code request.
    pub const fn key(self) -> Option<ProcedureKey> {
        match self {
            Self::Procedure { key, .. } => Some(key),
            Self::External { .. } => None,
        }
    }
}

/// Executable code loaded by the host, retaining its complete owning package for rich loads.
///
/// Code availability supplies no execution authority. Rich package loads retain exact checked
/// symbols and occurrence metadata; raw forests remain available to lower-level custom hosts.
/// Clones share one immutable load owner. Equality compares that owner identity, rather than code
/// digests or metadata contents; separate loads can share code while retaining distinct sources.
#[derive(Debug, Clone)]
pub struct LoadedMastForest {
    inner: Arc<LoadedMastForestData>,
}

#[derive(Debug)]
struct LoadedMastForestData {
    code: LoadedCode,
    debug_info: Result<Option<Arc<PackageDebugInfo>>, Arc<PackageDebugInfoError>>,
}

#[derive(Debug)]
enum LoadedCode {
    Raw(Arc<MastForest>),
    Package(CodePackage),
}

impl PartialEq for LoadedMastForest {
    fn eq(&self, other: &Self) -> bool {
        self.same_owner(other)
    }
}

impl Eq for LoadedMastForest {}

impl LoadedMastForest {
    /// Creates a loaded MAST forest without package-owned debug info.
    pub fn new(mast_forest: Arc<MastForest>) -> Self {
        Self {
            inner: Arc::new(LoadedMastForestData {
                code: LoadedCode::Raw(mast_forest),
                debug_info: Ok(None),
            }),
        }
    }

    /// Creates loaded code retaining its complete package and exact checked symbols.
    ///
    /// Debug info is decoded from the retained package under its existing validation limits.
    /// Decode or trust failures are retained and returned by [`Self::package_debug_info`]; they
    /// are never replaced with unrelated source metadata or silently treated as absent.
    pub fn from_code_package(code: CodePackage) -> Self {
        let debug_info = code.package().debug_info();
        Self {
            inner: Arc::new(LoadedMastForestData {
                code: LoadedCode::Package(code),
                debug_info: debug_info.map(|debug_info| debug_info.map(Arc::new)).map_err(Arc::new),
            }),
        }
    }

    /// Creates a raw loaded MAST forest with separately supplied package debug info.
    ///
    /// This lower-level custom-host path does not retain a checked code package. Ordinary rich
    /// package loading uses [`Self::from_code_package`] so code and source ownership stay together.
    pub fn with_package_debug_info(
        mast_forest: Arc<MastForest>,
        debug_info: Result<Option<PackageDebugInfo>, PackageDebugInfoError>,
    ) -> Self {
        Self {
            inner: Arc::new(LoadedMastForestData {
                code: LoadedCode::Raw(mast_forest),
                debug_info: debug_info.map(|debug_info| debug_info.map(Arc::new)).map_err(Arc::new),
            }),
        }
    }

    /// Returns the executable MAST forest.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        match &self.inner.code {
            LoadedCode::Raw(mast_forest) => mast_forest,
            LoadedCode::Package(code) => code.package().mast_forest(),
        }
    }

    /// Returns the complete owning package for a rich load.
    pub fn code_package(&self) -> Option<&CodePackage> {
        match &self.inner.code {
            LoadedCode::Raw(_) => None,
            LoadedCode::Package(code) => Some(code),
        }
    }

    /// Returns the exact checked symbols retained by a rich load.
    pub fn symbols(&self) -> Option<&Arc<PackageSymbols>> {
        self.code_package().map(CodePackage::symbols)
    }

    /// Returns a supplied exact occurrence for this key without reconstructing one from D.
    pub fn procedure_occurrence(&self, key: ProcedureKey) -> Option<&PackageProcedureOccurrence> {
        self.code_package()?.package().procedure_occurrence(key)
    }

    /// Returns an exact occurrence only when it materializes the requested implementation.
    ///
    /// An occurrence naming an external root supplies no local body, even if another root in the
    /// same forest has the requested digest. This check supplies no execution authority.
    pub(crate) fn materialized_procedure_occurrence(
        &self,
        key: ProcedureKey,
        implementation: ImplementationRoot,
    ) -> Option<&PackageProcedureOccurrence> {
        let occurrence = self.procedure_occurrence(key)?;
        let forest = self.mast_forest();
        if !forest.is_procedure_root(occurrence.exec_node()) {
            return None;
        }
        let node = &forest[occurrence.exec_node()];
        (!node.is_external() && node.digest() == *implementation.as_word()).then_some(occurrence)
    }

    /// Returns whether two handles retain the same immutable load owner.
    pub(crate) fn same_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Returns the package debug info associated with this forest, if any.
    pub fn package_debug_info(
        &self,
    ) -> Result<Option<Arc<PackageDebugInfo>>, Arc<PackageDebugInfoError>> {
        self.inner.debug_info.clone()
    }
}

/// A set of [`MastForest`]s available to the prover that programs may refer to (by means of an
/// [`miden_core::mast::ExternalNode`]).
///
/// For example, a program's kernel and core library would most likely not be compiled directly
/// with the program, and instead be provided separately to the prover. This has the benefit of
/// reducing program binary size. The store could also be much more complex, such as accessing a
/// centralized registry of [`MastForest`]s when it doesn't find one locally.
pub trait MastForestStore {
    /// Returns available code containing a local procedure root for the requested implementation.
    ///
    /// A keyed request lets the store prefer an exact supplied occurrence. Digest-only code
    /// availability remains useful when exact metadata is absent, after the processor has
    /// authenticated the requested binding. Neither response supplies execution authority.
    fn get(&self, request: CodeRequest) -> Option<LoadedMastForest>;
}

/// A simple [`MastForestStore`] where all known [`MastForest`] owners are held in memory.
#[derive(Debug, Default, Clone)]
pub struct MemMastForestStore {
    mast_forests: BTreeMap<Word, Vec<LoadedMastForest>>,
}

impl MemMastForestStore {
    /// Inserts all the procedures of the provided MAST forest in the store.
    pub fn insert(&mut self, mast_forest: Arc<MastForest>) {
        self.insert_loaded(LoadedMastForest::new(mast_forest));
    }

    /// Inserts the local procedures while retaining every distinct loaded owner.
    ///
    /// Reinserting the same handle refreshes its load order without retaining duplicate owners.
    pub fn insert_loaded(&mut self, loaded_mast_forest: LoadedMastForest) {
        for proc_digest in loaded_mast_forest.mast_forest().local_procedure_digests() {
            let owners = self.mast_forests.entry(proc_digest).or_default();
            if let Some(index) =
                owners.iter().position(|owner| owner.same_owner(&loaded_mast_forest))
            {
                let owner = owners.remove(index);
                owners.push(owner);
            } else {
                owners.push(loaded_mast_forest.clone());
            }
        }
    }
}

impl MastForestStore for MemMastForestStore {
    fn get(&self, request: CodeRequest) -> Option<LoadedMastForest> {
        let owners = self.mast_forests.get(request.implementation().as_word())?;
        let exact = request.key().and_then(|key| {
            owners.iter().rev().find(|owner| {
                owner.materialized_procedure_occurrence(key, request.implementation()).is_some()
            })
        });
        exact.or_else(|| owners.last()).cloned()
    }
}

#[cfg(test)]
mod tests;
