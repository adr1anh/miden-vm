use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::module::ModuleDescriptor;
use miden_core::Word;
use miden_mast_package::{ManifestValidationError, MastForest, Package, PackageNaming};
pub use miden_project::Linkage;

/// Represents an assembled module or modules to use when resolving references while linking,
/// as well as the method by which referenced symbols will be linked into the assembled MAST.
#[derive(Clone)]
pub struct LinkLibrary {
    pub package: Arc<Package>,
    /// Canonical metadata retained by compilation or admitted with explicit current policy.
    naming: Arc<PackageNaming>,
    /// How to link against this library
    pub linkage: Linkage,
}

impl LinkLibrary {
    /// Pairs a package with the exact canonical metadata retained by its compiler or obtained by
    /// explicit [`Package::admit_naming`] policy admission. This checks integrity, not home policy.
    pub fn from_package(
        package: Arc<Package>,
        naming: impl Into<Arc<PackageNaming>>,
    ) -> Result<Self, ManifestValidationError> {
        let naming = naming.into();
        package.check_naming(&naming)?;
        Ok(Self {
            package,
            naming,
            linkage: Linkage::Dynamic,
        })
    }

    /// Returns the complete canonical inventory, including private callable declarations.
    pub fn naming(&self) -> &Arc<PackageNaming> {
        &self.naming
    }

    /// Modify the linkage of this library
    pub fn with_linkage(mut self, linkage: Linkage) -> Self {
        self.linkage = linkage;
        self
    }

    /// Returns the name-aware v2 dependency commitment identifying this library input.
    #[inline(always)]
    pub fn commitment(&self) -> Word {
        self.package.dependency_commitment()
    }

    /// Returns the digest of the package's exported interface.
    #[inline(always)]
    pub fn interface_commitment(&self) -> Result<Word, ManifestValidationError> {
        self.package.interface_commitment()
    }

    #[inline(always)]
    pub fn mast(&self) -> &Arc<MastForest> {
        self.package.mast_forest()
    }

    #[inline]
    pub fn module_descriptors(&self) -> Result<Vec<ModuleDescriptor>, ManifestValidationError> {
        self.package.try_module_descriptors()
    }
}
