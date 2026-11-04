use alloc::{collections::BTreeMap, sync::Arc};

use miden_core::{Word, mast::MastForest, program::ProcedureKey};
use miden_mast_package::{
    CodePackage, PackageDebugInfoError, PackageProcedureOccurrence, PackageSymbols,
    debug_info::PackageDebugInfo,
};

/// Executable code loaded by the host, retaining its complete owning package for rich loads.
///
/// Code availability supplies no execution authority. Rich package loads retain exact checked
/// symbols and occurrence metadata; raw forests remain available to lower-level custom hosts.
#[derive(Debug, Clone)]
pub struct LoadedMastForest {
    code: LoadedCode,
    debug_info: Result<Option<Arc<PackageDebugInfo>>, Arc<PackageDebugInfoError>>,
}

#[derive(Debug, Clone)]
enum LoadedCode {
    Raw(Arc<MastForest>),
    Package(CodePackage),
}

impl LoadedMastForest {
    /// Creates a loaded MAST forest without package-owned debug info.
    pub fn new(mast_forest: Arc<MastForest>) -> Self {
        Self {
            code: LoadedCode::Raw(mast_forest),
            debug_info: Ok(None),
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
            code: LoadedCode::Package(code),
            debug_info: debug_info.map(|debug_info| debug_info.map(Arc::new)).map_err(Arc::new),
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
            code: LoadedCode::Raw(mast_forest),
            debug_info: debug_info.map(|debug_info| debug_info.map(Arc::new)).map_err(Arc::new),
        }
    }

    /// Returns the executable MAST forest.
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        match &self.code {
            LoadedCode::Raw(mast_forest) => mast_forest,
            LoadedCode::Package(code) => code.package().mast_forest(),
        }
    }

    /// Returns the complete owning package for a rich load.
    pub fn code_package(&self) -> Option<&CodePackage> {
        match &self.code {
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

    /// Returns the package debug info associated with this forest, if any.
    pub fn package_debug_info(
        &self,
    ) -> Result<Option<Arc<PackageDebugInfo>>, Arc<PackageDebugInfoError>> {
        self.debug_info.clone()
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
    /// Returns a [`MastForest`] which is guaranteed to contain a procedure with the provided
    /// procedure hash as one of its procedure, if any.
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest>;
}

/// A simple [`MastForestStore`] where all known [`MastForest`]s are held in memory.
#[derive(Debug, Default, Clone)]
pub struct MemMastForestStore {
    mast_forests: BTreeMap<Word, LoadedMastForest>,
}

impl MemMastForestStore {
    /// Inserts all the procedures of the provided MAST forest in the store.
    pub fn insert(&mut self, mast_forest: Arc<MastForest>) {
        self.insert_loaded(LoadedMastForest::new(mast_forest));
    }

    /// Inserts all the procedures of the provided loaded MAST forest in the store.
    pub fn insert_loaded(&mut self, loaded_mast_forest: LoadedMastForest) {
        // only register the procedures which are local to this forest
        for proc_digest in loaded_mast_forest.mast_forest().local_procedure_digests() {
            self.mast_forests.insert(proc_digest, loaded_mast_forest.clone());
        }
    }
}

impl MastForestStore for MemMastForestStore {
    fn get(&self, procedure_hash: &Word) -> Option<LoadedMastForest> {
        self.mast_forests.get(procedure_hash).cloned()
    }
}
