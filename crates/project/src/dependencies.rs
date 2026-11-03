#[cfg(all(feature = "std", feature = "serde"))]
mod graph;

use alloc::{format, sync::Arc, vec};
use core::fmt;

use miden_assembly_syntax::debuginfo::Spanned;
use miden_mast_package::PackageId;
pub use miden_package_registry::{SemVer, Version, VersionReq, VersionRequirement};

#[cfg(all(feature = "std", feature = "serde"))]
pub use self::graph::*;
use crate::{Diagnostic, Linkage, SourceSpan, Span, Uri, miette};

/// An explicit source-target default-home request, independent of provenance and code supply.
///
/// Complete callable bindings and reexports retain their separately supplied homes. A Standard
/// request is not an artifact ownership or public-surface claim; preassembled Standard imports
/// require consumer-supplied callable expectations. Custom artifact homes state only the requested
/// package-default metadata, while the naming provider admits the full retained inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyBinding {
    Standard(crate::LibraryImport),
    Custom(miden_mast_package::NamespacePlan),
}

impl DependencyBinding {
    pub fn namespace_plan(&self) -> miden_mast_package::NamespacePlan {
        match self {
            Self::Standard(import) => import.namespace_plan(),
            Self::Custom(home) => home.clone(),
        }
    }
}

/// Represents a project/package dependency declaration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// The source alias (the dependency table key), independent of package provenance.
    name: Span<Arc<str>>,
    /// The package name requested from the selected source or registry.
    package: PackageId,
    /// Retains an explicit same-name override when serializing workspace inheritance.
    package_explicit: bool,
    /// The version requirement and resolution scheme for this dependency.
    version: DependencyVersionScheme,
    /// The linkage for this dependency
    linkage: Linkage,
    /// Missing only for incomplete low-level API inputs; manifest dependencies require a choice.
    binding: Option<DependencyBinding>,
    /// Independently expected complete public mapping, separate from the default-home choice.
    expected_callables: Option<crate::ExpectedVisibleCallables>,
    /// Explicit source lookup projection, independent of runtime binding and supply.
    source_mount: Option<crate::PackageSourceMount>,
}

impl Dependency {
    /// Construct a dependency whose source alias also names the requested package.
    pub fn new(name: Span<Arc<str>>, version: DependencyVersionScheme, linkage: Linkage) -> Self {
        Self {
            package: PackageId::from(name.inner().clone()),
            package_explicit: false,
            name,
            version,
            linkage,
            binding: None,
            expected_callables: None,
            source_mount: None,
        }
    }

    /// Selects the requested package without changing its source alias or runtime naming.
    pub fn with_package(mut self, package: impl Into<PackageId>) -> Self {
        self.package = package.into();
        self.package_explicit = true;
        self
    }

    /// Returns the requested package name, used only for source and registry resolution.
    pub fn package(&self) -> &PackageId {
        &self.package
    }

    /// Returns whether the source alias differs from the requested package name.
    pub fn is_aliased(&self) -> bool {
        self.alias().as_ref() != &*self.package
    }

    #[cfg(feature = "serde")]
    pub(crate) fn explicit_package(&self) -> Option<&PackageId> {
        self.package_explicit.then_some(&self.package)
    }

    /// Selects an explicit source lookup projection without changing canonical callable keys.
    pub fn with_source_mount(mut self, mount: crate::PackageSourceMount) -> Self {
        self.source_mount = Some(mount);
        self
    }

    pub fn source_mount(&self) -> Option<&crate::PackageSourceMount> {
        self.source_mount.as_ref()
    }

    /// Sets an explicit standard or custom runtime home without changing source resolution.
    pub fn with_binding(mut self, binding: DependencyBinding) -> Self {
        self.binding = Some(binding);
        self
    }

    pub fn binding(&self) -> Option<&DependencyBinding> {
        self.binding.as_ref()
    }

    /// Supplies the caller's exact expected visible mapping without changing naming or supply.
    pub fn with_expected_callables(mut self, expected: crate::ExpectedVisibleCallables) -> Self {
        self.expected_callables = Some(expected);
        self
    }

    pub fn expected_callables(&self) -> Option<&crate::ExpectedVisibleCallables> {
        self.expected_callables.as_ref()
    }

    /// Get the source alias of this dependency.
    pub fn alias(&self) -> &Arc<str> {
        &self.name
    }

    /// Get the source alias of this dependency.
    pub fn name(&self) -> &Arc<str> {
        self.alias()
    }

    /// Get the versioning scheme/requirement for this dependency
    pub fn scheme(&self) -> &DependencyVersionScheme {
        &self.version
    }

    /// Get the linkage mode for this dependency
    pub const fn linkage(&self) -> Linkage {
        self.linkage
    }

    /// Get the version requirement for this dependency, if one was given
    pub fn required_version(&self) -> VersionRequirement {
        let req = match &self.version {
            DependencyVersionScheme::Registry(version) => return version.clone(),
            DependencyVersionScheme::Workspace { version, .. } => version.clone(),
            DependencyVersionScheme::WorkspacePath { version, .. } => version.clone(),
            DependencyVersionScheme::Path { version, .. } => version.clone(),
            DependencyVersionScheme::Git { version, .. } => {
                version.as_ref().map(|spanned| VersionRequirement::Semantic(spanned.clone()))
            },
        };
        req.unwrap_or_else(|| VersionRequirement::from(VersionReq::STAR))
    }
}

impl Spanned for Dependency {
    fn span(&self) -> SourceSpan {
        self.name.span()
    }
}

/// Represents the versioning requirement and resolution method for a specific dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyVersionScheme {
    /// Resolve the given semantic version requirement or digest using the configured package
    /// registry, to an assembled Miden package artifact.
    ///
    /// Resolution of packages using this scheme relies on the specific implementation of the
    /// package registry in use, which can vary depending on context.
    Registry(VersionRequirement),
    /// Resolve the given workspace-relative path to a declared member of the current workspace.
    Workspace {
        /// The workspace-relative member path.
        member: Span<Uri>,
        /// If specified on the corresponding `[workspace.dependencies]` entry, the version of the
        /// referenced project/package must satisfy this requirement.
        version: Option<VersionRequirement>,
    },
    /// Resolve the given path inherited from `[workspace.dependencies]`, relative to the
    /// workspace root, to either a Miden project/workspace or an assembled package artifact.
    WorkspacePath {
        /// The path as declared in `[workspace.dependencies]`.
        path: Span<Uri>,
        /// If specified, the version of the referenced project/package _must_ match this version
        /// requirement.
        version: Option<VersionRequirement>,
    },
    /// Resolve the given path to a Miden project/workspace, or assembled Miden package artifact.
    Path {
        /// The path to a Miden project directory containing a `miden-project.toml` OR a Miden
        /// package file (i.e. a file with the `.masp` extension, as produced by the assembler).
        path: Span<Uri>,
        /// If specified, the version of the referenced project/package _must_ match this version
        /// requirement.
        ///
        /// If unspecified, no additional version validation is performed; the current version
        /// declared by the referenced source/package is used as-is.
        version: Option<VersionRequirement>,
    },
    /// Resolve the given Git repository to a Miden project/workspace.
    Git {
        /// The Git repository URI.
        ///
        /// NOTE: Supports any URI scheme supported by the `git` CLI.
        repo: Span<Uri>,
        /// The specific revision to clone.
        revision: Span<GitRevision>,
        /// If specified, the version declared in the manifest found in the cloned repository
        /// _must_ match this version requirement.
        ///
        /// If unspecified, no additional version validation is performed; the current version
        /// declared by the checked out sources is used as-is.
        version: Option<Span<VersionReq>>,
    },
}

/// A reference to a revision in Git
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitRevision {
    /// A reference to the HEAD revision of the given branch.
    Branch(Arc<str>),
    /// A reference to a specific revision with the given hash identifier
    Commit(Arc<str>),
}

impl fmt::Display for GitRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Branch(name) => f.write_str(name.as_ref()),
            Self::Commit(rev) => write!(f, "sha256:{rev}"),
        }
    }
}

#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum InvalidDependencySpecError {
    #[error("package is not a member of a workspace")]
    NotAWorkspace {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("digests cannot be used with 'git' dependencies")]
    #[diagnostic(help(
        "Package digests are only valid when depending on an already-assembled package"
    ))]
    GitWithDigest {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error("'git' dependencies must also specify a revision using either 'branch' or 'rev'")]
    MissingGitRevision {
        #[label(primary)]
        span: SourceSpan,
    },
    #[error(
        "conflicting 'git' revisions: 'branch' and 'rev' may refer to different commits, you cannot specify both"
    )]
    ConflictingGitRevision {
        #[label(primary)]
        first: SourceSpan,
        #[label]
        second: SourceSpan,
    },
    #[error("missing version: expected one of 'version', 'git', or 'digest' to be provided")]
    MissingVersion {
        #[label(primary)]
        span: SourceSpan,
    },
}

#[cfg(feature = "serde")]
impl TryFrom<Span<&crate::ast::DependencySpec>> for DependencyVersionScheme {
    type Error = InvalidDependencySpecError;

    fn try_from(ast: Span<&crate::ast::DependencySpec>) -> Result<Self, Self::Error> {
        if ast.inherits_workspace_version() {
            return Err(InvalidDependencySpecError::NotAWorkspace { span: ast.span() });
        }

        if ast.is_host_resolved() {
            ast.version()
                .cloned()
                .map(Self::Registry)
                .ok_or(InvalidDependencySpecError::MissingVersion { span: ast.span() })
        } else if ast.is_git() {
            let version = match ast.version() {
                Some(VersionRequirement::Digest(digest)) => {
                    return Err(InvalidDependencySpecError::GitWithDigest { span: digest.span() });
                },
                Some(VersionRequirement::Exact(_)) => {
                    return Err(InvalidDependencySpecError::GitWithDigest { span: ast.span() });
                },
                Some(VersionRequirement::Semantic(v)) => Some(v.clone()),
                None => None,
            };
            if let Some(branch) = ast.branch.as_ref()
                && let Some(rev) = ast.rev.as_ref()
            {
                return Err(InvalidDependencySpecError::ConflictingGitRevision {
                    first: branch.span(),
                    second: rev.span(),
                });
            }
            let revision = ast
                .branch
                .as_ref()
                .map(|branch| Span::new(branch.span(), GitRevision::Branch(branch.inner().clone())))
                .or_else(|| {
                    ast.rev
                        .as_ref()
                        .map(|rev| Span::new(rev.span(), GitRevision::Commit(rev.inner().clone())))
                })
                .ok_or_else(|| InvalidDependencySpecError::MissingGitRevision {
                    span: ast.span(),
                })?;
            Ok(Self::Git {
                repo: ast.git.clone().unwrap(),
                revision,
                version,
            })
        } else {
            Ok(Self::Path {
                path: ast.path.clone().unwrap(),
                version: ast.version_or_digest.clone(),
            })
        }
    }
}

#[cfg(feature = "serde")]
impl DependencyVersionScheme {
    /// Parse a dependency spec into [DependencyVersionScheme], taking into account workspace
    /// context.
    #[cfg(feature = "std")]
    pub fn try_from_in_workspace(
        spec: Span<&crate::ast::DependencySpec>,
        workspace: &crate::ast::WorkspaceFile,
    ) -> Result<Self, InvalidDependencySpecError> {
        use std::path::Path;

        use crate::absolutize_path;

        // If the dependency is a path dependency, check if the path refers to any of the workspace
        // members, and if so, convert the dependency version scheme to `Workspace` to aid in
        // dependency resolution
        match Self::try_from(spec)? {
            Self::Path { path: uri, version } => {
                let workspace_path = workspace
                    .source_file
                    .as_ref()
                    .map(|file| Path::new(file.content().uri().path()));
                if uri.scheme().is_none_or(|scheme| scheme == "file")
                    && let Some(workspace_path) = workspace_path.and_then(|p| p.canonicalize().ok())
                    && let Some(workspace_root) = workspace_path.parent()
                    && let Ok(resolved_uri) = absolutize_path(Path::new(uri.path()), workspace_root)
                {
                    let is_member = workspace.workspace.members.iter().any(|member| {
                        let member_path = member.path();
                        uri.path() == member_path
                            || uri.path() == format!("{member_path}/miden-project.toml")
                            || absolutize_path(Path::new(member_path), workspace_root)
                                .ok()
                                .is_some_and(|member_dir| {
                                    resolved_uri == member_dir
                                        || resolved_uri == member_dir.join("miden-project.toml")
                                })
                    });
                    if is_member {
                        Ok(Self::Workspace { member: uri.clone(), version })
                    } else {
                        Ok(Self::WorkspacePath { path: uri.clone(), version })
                    }
                } else {
                    Ok(Self::Path { path: uri, version })
                }
            },
            scheme => Ok(scheme),
        }
    }

    #[cfg(not(feature = "std"))]
    pub fn try_from_in_workspace(
        spec: Span<&crate::ast::DependencySpec>,
        workspace: &crate::ast::WorkspaceFile,
    ) -> Result<Self, InvalidDependencySpecError> {
        use alloc::format;

        match Self::try_from(spec)? {
            Self::Path { path: uri, version } => {
                let workspace_path =
                    workspace.source_file.as_ref().map(|file| file.content().uri().path());
                if uri.scheme().is_none_or(|scheme| scheme == "file") &&
                    let Some(workspace_root) = workspace_path.and_then(|p| p.strip_suffix("miden-project.toml")) &&
                    // Make sure the uri is relative to workspace root
                    (!workspace_root.is_empty() && !(uri.path().starts_with('/') || uri.path().starts_with("..")))
                {
                    let is_member = workspace.workspace.members.iter().any(|member| {
                        let member_path = member.path();
                        uri.path() == member_path
                            || uri.path() == format!("{member_path}/miden-project.toml")
                    });
                    if is_member {
                        Ok(Self::Workspace { member: uri.clone(), version })
                    } else {
                        Ok(Self::WorkspacePath { path: uri.clone(), version })
                    }
                } else {
                    Ok(Self::Path { path: uri, version })
                }
            },
            scheme => Ok(scheme),
        }
    }
}
