use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::module::ModuleDescriptor;
use miden_core::Word;
use miden_mast_package::{
    CodePackage, ManifestValidationError, MastForest, Package, PackageSymbols,
};
pub use miden_project::Linkage;

/// Represents an assembled module or modules to use when resolving references while linking,
/// as well as the method by which referenced symbols will be linked into the assembled MAST.
#[derive(Clone)]
pub struct LinkLibrary {
    /// Complete package code and its exact checked canonical symbol inventory.
    code: CodePackage,
    /// How to link against this library
    pub linkage: Linkage,
}

impl LinkLibrary {
    /// Retains complete package code with its exact checked canonical symbols.
    pub fn from_code_package(code: CodePackage) -> Self {
        Self { code, linkage: Linkage::Dynamic }
    }

    /// Returns the complete checked code owner retained for this library.
    pub fn code(&self) -> &CodePackage {
        &self.code
    }

    /// Returns the immutable package, including advice and source metadata.
    pub fn package(&self) -> &Arc<Package> {
        self.code.package()
    }

    /// Returns the complete canonical inventory, including private callable declarations.
    pub fn naming(&self) -> &Arc<PackageSymbols> {
        self.code.symbols()
    }

    /// Modify the linkage of this library
    pub fn with_linkage(mut self, linkage: Linkage) -> Self {
        self.linkage = linkage;
        self
    }

    /// Returns the name-aware v2 dependency commitment identifying this library input.
    #[inline(always)]
    pub fn commitment(&self) -> Word {
        self.package().dependency_commitment()
    }

    /// Returns the digest of the package's exported interface.
    #[inline(always)]
    pub fn interface_commitment(&self) -> Result<Word, ManifestValidationError> {
        self.package().interface_commitment()
    }

    #[inline(always)]
    pub fn mast(&self) -> &Arc<MastForest> {
        self.package().mast_forest()
    }

    #[inline]
    pub fn module_descriptors(&self) -> Result<Vec<ModuleDescriptor>, ManifestValidationError> {
        self.package().try_module_descriptors()
    }
}
