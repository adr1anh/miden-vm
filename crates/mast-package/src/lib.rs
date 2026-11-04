//! This crate defines the [Package] type - the artifact produced as a result of assembling some
//! Miden Asssembly code to MAST.
#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

mod code_package;
pub mod debug_info;
mod dependency;
pub mod interface;
pub mod namespace_plan;
mod package;
mod serde_helpers;

pub use miden_assembly_syntax::{PathBuf, Version, VersionError, ast::QualifiedProcedureName};
pub use miden_core::{Word, mast::MastForest, program::Program};

#[cfg(feature = "arbitrary")]
pub use self::package::arbitrary;
pub use self::{
    code_package::CodePackage,
    dependency::Dependency,
    interface::{
        CallableProcedurePath, DeclarationError, DeclarationSet, ProcedureDeclaration,
        PublicProcedurePath,
        artifact::{
            ArtifactError, ArtifactProfileOperation, DeclarationCommitment, InterfaceArtifactV1,
            InterfaceProfile, LibraryId,
        },
    },
    namespace_plan::{NamespacePath, ProcedureName},
    package::{
        CallablesCodecError, ConstantExport, EventHandlerManifestEntry, EventHandlerSection,
        EventHandlerSectionError, InvalidSectionIdError, InvalidTargetTypeError, MAX_HANDLERS,
        MAX_MODULE_BYTES, MAX_NAME_BYTES, MIN_ABI_VERSION, ManifestValidationError,
        NamingCodecError, Package, PackageCallables, PackageCallablesError, PackageDebugInfoError,
        PackageExport, PackageId, PackageManifest, PackageModule, PackageProcedureOccurrence,
        PackageProcedureOccurrencesError, PackageStripError, PackageSubmodule, PackageSymbols,
        PackageSymbolsError, ProcedureExport, Section, SectionId, TargetType, TypeExport,
        UnverifiedPackageSymbols, validate_manifest_entries,
    },
};
