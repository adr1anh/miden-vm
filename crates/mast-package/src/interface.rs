//! Semantic callable paths and declaration-only public procedure metadata.
//!
//! These in-memory records do not contain executable bodies or implementation roots. They are
//! not a serialized interface artifact and do not derive or authenticate a LibraryId, publisher,
//! declaration commitment, or dependency closure.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use miden_assembly_syntax::{
    Path, PathComponent, PathError,
    ast::{Ident, IdentError, ProcedureName, types::FunctionType},
};

pub mod artifact;
pub mod serialization;

/// A nonempty callable path relative to an explicitly supplied namespace home.
///
/// Components contain exact semantic Text values, after source parsing/lowering. This general
/// path also names entrypoints and implementation-private helpers; it does not admit them to a
/// public interface. Reserved source roots such as `$exec` and `$kernel` are ordinary Text here,
/// with no alias expansion or kernel authority. The caller supplies every helper prefix and home.
/// No code body, implementation root, profile, or default home participates in its construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallableProcedurePath {
    components: Vec<String>,
}

impl CallableProcedurePath {
    /// Validates decoded component text without rendering, escaping, or parsing source spelling.
    ///
    /// Uses the same component validation and semantic length limits as
    /// [`PublicProcedurePath::from_semantic_components`], while permitting reserved source roots
    /// and the local entrypoint name `$main`. Quoted separators and literal backslashes remain
    /// inside their components; exact UTF-8 bytes are retained without Unicode normalization.
    pub fn from_semantic_components(components: Vec<String>) -> Result<Self, DeclarationError> {
        validate_semantic_components(&components)?;
        Ok(Self { components })
    }

    /// Returns the nonempty sequence of exact semantic component values, ending in the local name.
    pub fn components(&self) -> &[String] {
        &self.components
    }
}

/// A nonempty public procedure path relative to an explicitly supplied namespace home.
///
/// Identity uses the values of parsed source components, rather than a rendered path. Quoting
/// does not contribute to identity, and a quoted `::` stays inside its single component. Component
/// text retains its exact UTF-8 bytes without case folding or Unicode normalization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicProcedurePath {
    components: Vec<String>,
}

impl PublicProcedurePath {
    /// Validates an existing AST path and retains its semantic component text.
    ///
    /// The caller must perform source parsing/lowering first. This method uses
    /// [`Path::components`] and [`PathComponent::as_str`]; it does not interpret escape spelling
    /// a second time. Namespace components obey the existing identifier rules and the final
    /// component obeys the existing procedure-name rules. Absolute paths, special module roots
    /// (`$kernel` and `$exec`), and the reserved entrypoint name `$main` are not public exports.
    pub fn new(path: &Path) -> Result<Self, DeclarationError> {
        Path::validate(path.as_str())?;
        let mut parsed = Vec::new();
        for component in path.components() {
            let component = component?;
            if component == PathComponent::Root {
                return Err(DeclarationError::AbsolutePublicPath);
            }
            parsed.push(component);
        }

        let local = parsed.last().ok_or(PathError::Empty)?;
        // Validate the same forward component whose text will be retained below. A reverse path
        // scan can interpret embedded quotes differently and validate only a suffix of that text.
        let PathComponent::Normal(local_spelling) = local else {
            return Err(DeclarationError::AbsolutePublicPath);
        };
        ProcedureName::new(local_spelling).map_err(PathError::InvalidComponent)?;

        Self::from_semantic_components(
            parsed.into_iter().map(|component| component.as_str().into()).collect(),
        )
    }

    /// Validates decoded component text without rendering, escaping, or parsing source spelling.
    ///
    /// Components are nonempty and retain their exact UTF-8 bytes. Namespace components obey
    /// [`Ident::validate`], and the local name obeys [`ProcedureName::validate_semantic`]. A `::`
    /// inside a component is literal text, never an absolute root or a separator. Reserved module
    /// roots and the entrypoint name are rejected as in [`Self::new`].
    ///
    /// The existing component character limit applies. The path byte limit applies to decoded
    /// component bytes plus separators; source quoting does not contribute to this semantic length.
    pub fn from_semantic_components(components: Vec<String>) -> Result<Self, DeclarationError> {
        validate_semantic_components(&components)?;
        let local = components.last().expect("validated paths are nonempty");
        if matches!(components[0].as_str(), Path::KERNEL_PATH | Path::EXEC_PATH)
            || local == ProcedureName::MAIN_PROC_NAME
        {
            return Err(DeclarationError::ReservedPublicPath);
        }

        Ok(Self { components })
    }

    /// Returns the nonempty sequence of exact semantic component values, ending in the local name.
    pub fn components(&self) -> &[String] {
        &self.components
    }
}

/// Validates semantic names independently of whether they are public declarations or helpers.
fn validate_semantic_components(components: &[String]) -> Result<(), DeclarationError> {
    let (local, namespaces) = components.split_last().ok_or(PathError::Empty)?;
    let mut decoded_len = 0usize;
    for (index, component) in components.iter().enumerate() {
        if component.is_empty() {
            return Err(PathError::EmptyComponent.into());
        }
        if component.chars().count() > Path::MAX_COMPONENT_LENGTH {
            return Err(PathError::InvalidComponent(IdentError::InvalidLength {
                max: Path::MAX_COMPONENT_LENGTH,
            })
            .into());
        }
        decoded_len = decoded_len
            .checked_add(if index == 0 { 0 } else { 2 })
            .and_then(|len| len.checked_add(component.len()))
            .filter(|len| *len <= u16::MAX as usize)
            .ok_or(PathError::TooLong { max: u16::MAX as usize })?;
    }
    for namespace in namespaces {
        Ident::validate(namespace).map_err(PathError::InvalidComponent)?;
    }
    ProcedureName::validate_semantic(local).map_err(PathError::InvalidComponent)?;
    Ok(())
}

/// One public procedure declaration, independent of code availability.
///
/// ABI metadata is optional opaque UTF-8. `None` and `Some("")` are distinct, and whitespace,
/// line endings, and Unicode spelling are retained exactly. It is not a runtime ABI check.
/// The resolved tooling signature is separate metadata and never replaces the author's ABI bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcedureDeclaration {
    path: PublicProcedurePath,
    abi_metadata: Option<String>,
    signature: Option<FunctionType>,
}

impl ProcedureDeclaration {
    /// Creates a declaration without a body, implementation root, forest, or release selection.
    pub fn new(path: PublicProcedurePath, abi_metadata: Option<String>) -> Self {
        Self { path, abi_metadata, signature: None }
    }

    /// Attaches a resolved tooling signature, independently of the opaque ABI metadata.
    pub fn with_signature(mut self, signature: FunctionType) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Returns the public path relative to the namespace home.
    pub fn path(&self) -> &PublicProcedurePath {
        &self.path
    }

    /// Returns the exact ABI text, preserving absence and present-empty metadata.
    pub fn abi_metadata(&self) -> Option<&str> {
        self.abi_metadata.as_deref()
    }

    /// Returns the separate resolved signature used by tooling.
    pub fn signature(&self) -> Option<&FunctionType> {
        self.signature.as_ref()
    }
}

/// Public declarations with unique semantic source paths.
///
/// Duplicate paths are rejected even when ABI text or tooling signatures differ. Source import
/// aliases are resolved separately; they do not rename these paths or select a runtime home.
/// This set alone supplies no publisher identity, publication authority, or closure metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclarationSet {
    declarations: BTreeMap<PublicProcedurePath, ProcedureDeclaration>,
}

impl DeclarationSet {
    /// Builds a set, rejecting every duplicate public path.
    pub fn new(
        declarations: impl IntoIterator<Item = ProcedureDeclaration>,
    ) -> Result<Self, DeclarationError> {
        let mut unique = BTreeMap::new();
        for declaration in declarations {
            let path = declaration.path.clone();
            if unique.insert(path.clone(), declaration).is_some() {
                return Err(DeclarationError::DuplicatePublicPath { path });
            }
        }
        Ok(Self { declarations: unique })
    }

    /// Iterates over declarations in component-value order, without defining a wire encoding.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ProcedureDeclaration> {
        self.declarations.values()
    }

    /// Looks up a declaration by its semantic public path, independently of source aliases.
    pub fn get(&self, path: &PublicProcedurePath) -> Option<&ProcedureDeclaration> {
        self.declarations.get(path)
    }
}

/// Invalid semantic/source paths or duplicate declarations.
#[derive(Debug, thiserror::Error)]
pub enum DeclarationError {
    #[error(transparent)]
    InvalidPath(#[from] PathError),
    #[error("a public procedure path must be relative to its namespace home")]
    AbsolutePublicPath,
    #[error("a public procedure path uses a reserved module root or entrypoint name")]
    ReservedPublicPath,
    #[error("duplicate public procedure path: {path:?}")]
    DuplicatePublicPath { path: PublicProcedurePath },
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod callable_path_tests;
