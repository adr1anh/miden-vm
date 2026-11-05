use alloc::string::{String, ToString};
use core::fmt::Write;

use miden_assembly_syntax::Path;

use crate::*;

/// Explicit construction convention for naming concrete procedures in a source target.
///
/// These conventions do not select an implementation, authenticate a publisher, or establish a
/// package's public callable surface. Complete bindings and aliases retain their own declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum SourceNamingConvention {
    /// Name concrete procedures by their defining module and procedure paths.
    DefiningPaths,
    /// Place public executable kernel exports at fixed root and private helpers beneath their home.
    KernelRootExports,
}

impl SourceNamingConvention {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DefiningPaths => "defining-paths",
            Self::KernelRootExports => "kernel-root-exports",
        }
    }
}

/// A source naming convention and an explicit fallback default-home request.
///
/// An importing dependency's home request takes precedence over this fallback. This configuration
/// supplies no ownership, expected implementation, profile admission, or publication authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceNaming {
    convention: SourceNamingConvention,
    binding: DependencyBinding,
}

impl SourceNaming {
    pub fn new(convention: SourceNamingConvention, binding: DependencyBinding) -> Self {
        Self { convention, binding }
    }

    pub const fn convention(&self) -> SourceNamingConvention {
        self.convention
    }

    pub fn binding(&self) -> &DependencyBinding {
        &self.binding
    }

    /// Reject a convention that cannot construct the selected target kind.
    pub fn validate_target_type(&self, ty: TargetType) -> Result<(), Report> {
        let valid = match self.convention {
            SourceNamingConvention::DefiningPaths => !matches!(ty, TargetType::Kernel),
            SourceNamingConvention::KernelRootExports => matches!(ty, TargetType::Kernel),
        };
        if valid {
            Ok(())
        } else {
            Err(Report::msg(format!(
                "source naming convention '{}' is invalid for target kind '{ty}'",
                self.convention.as_str()
            )))
        }
    }

    fn append_build_provenance_projection(&self, out: &mut String) {
        out.push_str("target:naming:convention:");
        out.push_str(self.convention.as_str());
        out.push('\n');
        out.push_str("target:naming:binding:");
        match &self.binding {
            DependencyBinding::Custom(_) => out.push_str("custom"),
            DependencyBinding::Standard(import) => match import.selection() {
                LibrarySelection::Latest => out.push_str("latest"),
                LibrarySelection::Revision(revision) => {
                    write!(out, "pinned:{revision}").expect("writing to a String cannot fail");
                },
            },
        }
        out.push('\n');
        out.push_str("target:naming:home:");
        for label in self.binding.namespace_plan().home() {
            write!(out, "{}:", label.as_bytes().len()).expect("writing to a String cannot fail");
            for byte in label.as_bytes() {
                write!(out, "{byte:02x}").expect("writing to a String cannot fail");
            }
            out.push('/');
        }
        out.push('\n');
    }
}

/// Represents build target configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub ty: TargetType,
    /// The effective name of this target
    ///
    /// If unspecified in the project file, the name is the same as `namespace`
    ///
    /// The name must be unique within a project
    pub name: Span<Arc<str>>,
    /// The namespace root for this target
    pub namespace: Span<Arc<Path>>,
    /// The path from the project manifest to the root source file for this target
    ///
    /// The path can be to a source file written in any language, e.g. for MASM it might refer to
    /// `mod.masm`, while for Rust it might refer to `src/lib.rs` - as long as an appropriate
    /// source provider is registered with the assembler.
    pub path: Span<Uri>,
    /// Explicit source naming configuration; omission preserves provider-driven naming.
    pub naming: Option<SourceNaming>,
}

impl Target {
    /// Construct a new executable target named `name` and given source `uri`
    pub fn executable(name: impl Into<Arc<str>>, uri: Uri) -> Self {
        Self::new(TargetType::Executable, name.into(), Path::exec_path(), uri)
    }

    /// Construct a new library target named `name` with the given `namespace` and source `uri`
    pub fn library(namespace: impl Into<Arc<Path>>, uri: Uri) -> Self {
        let namespace = namespace.into();
        let name: Arc<str> = namespace.as_str().into();
        Self::new(TargetType::Library, name, namespace, uri)
    }

    /// Construct a new target of type `ty`, with the given `name`, `namespace` and source `uri`
    pub fn new(
        ty: TargetType,
        name: impl Into<Arc<str>>,
        namespace: impl Into<Arc<Path>>,
        uri: Uri,
    ) -> Self {
        Self {
            ty,
            name: Span::unknown(name.into()),
            namespace: Span::unknown(namespace.into()),
            path: Span::unknown(uri),
            naming: None,
        }
    }

    /// Select an explicit source convention and fallback home for this target.
    pub fn with_naming(mut self, naming: SourceNaming) -> Result<Self, Report> {
        naming.validate_target_type(self.ty)?;
        self.naming = Some(naming);
        Ok(self)
    }

    /// Validate source naming after direct edits to the public target fields.
    pub fn validate_naming(&self) -> Result<(), Report> {
        if let Some(naming) = &self.naming {
            naming.validate_target_type(self.ty)?;
        }
        Ok(())
    }

    /// Returns true if this target is an executable target
    pub const fn is_executable(&self) -> bool {
        matches!(self.ty, TargetType::Executable)
    }

    /// Returns true if this target is a non-executable target
    pub const fn is_library(&self) -> bool {
        !self.is_executable()
    }

    /// Returns true if this target is a kernel target
    pub const fn is_kernel(&self) -> bool {
        matches!(self.ty, TargetType::Kernel)
    }

    /// Append the selected target fields that affect package artifact reuse to `out`.
    pub fn append_build_provenance_projection(&self, out: &mut String) {
        let Self { ty, name, namespace, path, naming } = self;

        out.push_str("target:kind:");
        out.push_str(ty.to_string().as_str());
        out.push('\n');
        out.push_str("target:name:");
        out.push_str(name.inner().as_ref());
        out.push('\n');
        out.push_str("target:namespace:");
        out.push_str(namespace.inner().as_str());
        out.push('\n');
        out.push_str("target:path:");
        out.push_str(path.inner().as_str());
        out.push('\n');
        if let Some(naming) = naming {
            naming.append_build_provenance_projection(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::program::CanonicalLabel;
    use miden_mast_package::NamespacePath;

    use super::*;

    fn naming(convention: SourceNamingConvention, home: &str) -> SourceNaming {
        SourceNaming::new(
            convention,
            DependencyBinding::Custom(NamespacePath::new(vec![
                CanonicalLabel::text(home).unwrap(),
            ])),
        )
    }

    #[test]
    fn constructors_keep_source_naming_opt_in_and_validate_explicit_conventions() {
        let library = Target::library(Arc::<Path>::from(Path::new("app")), Uri::new("mod.masm"));
        let executable = Target::executable("app", Uri::new("main.masm"));
        let kernel = Target::new(
            TargetType::Kernel,
            "kernel",
            Arc::<Path>::from(Path::kernel_path()),
            Uri::new("kernel.masm"),
        );
        assert!(library.naming.is_none());
        assert!(executable.naming.is_none());
        assert!(kernel.naming.is_none());
        for target in [library, executable] {
            assert!(
                target
                    .clone()
                    .with_naming(naming(SourceNamingConvention::DefiningPaths, "home"))
                    .is_ok()
            );
            assert!(
                target
                    .with_naming(naming(SourceNamingConvention::KernelRootExports, "home"))
                    .is_err()
            );
        }
        assert!(
            kernel
                .clone()
                .with_naming(naming(SourceNamingConvention::KernelRootExports, "helpers"))
                .is_ok()
        );
        assert!(
            kernel
                .with_naming(naming(SourceNamingConvention::DefiningPaths, "helpers"))
                .is_err()
        );
    }

    #[test]
    fn target_provenance_records_convention_home_and_explicit_binding_selection() {
        let target = Target::library(Arc::<Path>::from(Path::new("app")), Uri::new("mod.masm"));
        let projection = |target: &Target| {
            let mut projection = String::new();
            target.append_build_provenance_projection(&mut projection);
            projection
        };
        let absent = projection(&target);
        let configured = target
            .clone()
            .with_naming(naming(SourceNamingConvention::DefiningPaths, "home"))
            .unwrap();
        let changed = target
            .clone()
            .with_naming(naming(SourceNamingConvention::DefiningPaths, "other"))
            .unwrap();
        assert_ne!(projection(&configured), absent);
        assert_ne!(projection(&configured), projection(&changed));
        assert!(projection(&configured).contains("target:naming:convention:defining-paths\n"));

        let import =
            LibraryRef::new(NamespacePath::new(vec![]), Word::default(), LibrarySelection::Latest);
        let custom = target
            .clone()
            .with_naming(SourceNaming::new(
                SourceNamingConvention::DefiningPaths,
                DependencyBinding::Custom(import.namespace_plan()),
            ))
            .unwrap();
        let standard = target
            .with_naming(SourceNaming::new(
                SourceNamingConvention::DefiningPaths,
                DependencyBinding::Standard(import),
            ))
            .unwrap();
        assert_eq!(
            custom.naming.as_ref().unwrap().binding().namespace_plan(),
            standard.naming.as_ref().unwrap().binding().namespace_plan()
        );
        assert_ne!(projection(&custom), projection(&standard));
    }
}
