use super::{parsing::SetSourceId, *};
use crate::{Linkage, SourceId, Span, Uri, VersionRequirement};

/// Represents information about a project dependency needed to resolve it to a Miden package
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct DependencySpec {
    /// The source alias given by the dependency table key.
    #[cfg_attr(feature = "serde", serde(default, skip))]
    pub name: Span<Arc<str>>,
    /// Requested package name; omission uses the source alias.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub package: Option<Span<Arc<str>>>,
    /// The version requirement specified for this dependency
    #[cfg_attr(
        feature = "serde",
        serde(rename = "version", alias = "digest", skip_serializing_if = "Option::is_none")
    )]
    pub version_or_digest: Option<VersionRequirement>,
    /// Whether or not the version requirement is inherited from the containing workspace
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "does_not_inherit_from_workspace")
    )]
    pub workspace: bool,
    /// If present, specifies the path from which this dependency should be loaded
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub path: Option<Span<Uri>>,
    /// If present, specifies the URI of the git repository to clone in order to load this
    /// dependency.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub git: Option<Span<Uri>>,
    /// If present, specifies the branch of the git repository to checkout when loading this
    /// dependency from the URI specified by `git`.
    ///
    /// NOTE: This field is only valid when specified along with `git`, and may not be used in
    /// conjunction with `rev`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub branch: Option<Span<Arc<str>>>,
    /// If present, specifies the revision of the git repository to checkout when loading this
    /// dependency from the URI specified by `git`.
    ///
    /// NOTE: This field is only valid when specified along with `git`, and may not be used in
    /// conjunction with `branch`.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub rev: Option<Span<Arc<str>>>,
    /// Explicit default-home selection; independent of source version and linkage.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub binding: Option<Span<DependencyBindingSpec>>,
    /// Independently expected exact visible paths and complete defining callable bindings.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "expected-callables", default, skip_serializing_if = "Option::is_none")
    )]
    pub expected_callables: Option<Span<Vec<ExpectedCallableSpec>>>,
    /// Explicit package/source prefixes, independent of runtime naming and artifact expectations.
    #[cfg_attr(
        feature = "serde",
        serde(rename = "source-mount", default, skip_serializing_if = "Option::is_none")
    )]
    pub source_mount: Option<Span<SourceMountSpec>>,
    /// If present, specifies the desired linkage for this dependency during assembly
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub linkage: Option<Span<Linkage>>,
}

/// Explicit source lookup projection. Both absolute bases must be supplied by configuration.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", deny_unknown_fields))]
pub struct SourceMountSpec {
    pub package_base: String,
    pub source_base: String,
}

impl SourceMountSpec {
    /// Validates and normalizes the selected route without inferring either base from a name.
    pub fn resolve(&self) -> Result<crate::PackageSourceMount, Report> {
        crate::PackageSourceMount::new(
            miden_assembly_syntax::Path::new(&self.package_base),
            miden_assembly_syntax::Path::new(&self.source_base),
        )
    }
}

impl From<&crate::PackageSourceMount> for SourceMountSpec {
    fn from(mount: &crate::PackageSourceMount) -> Self {
        Self {
            package_base: mount.package_base().as_str().into(),
            source_base: mount.source_base().as_str().into(),
        }
    }
}

#[inline(always)]
fn does_not_inherit_from_workspace(is_workspace_dependency: &bool) -> bool {
    !(*is_workspace_dependency)
}

impl DependencySpec {
    /// Returns the version constraint to apply to this dependency
    pub fn version(&self) -> Option<&VersionRequirement> {
        self.version_or_digest.as_ref()
    }

    /// Returns true if this dependency inherits its version requirement from a parent workspace
    pub fn inherits_workspace_version(&self) -> bool {
        self.workspace
    }

    /// Returns true if this dependency must be resolved using a host-provided resolver
    pub fn is_host_resolved(&self) -> bool {
        self.git.is_none() && self.path.is_none()
    }

    /// Returns true if this dependency specifies a local filesystem path
    pub fn is_path(&self) -> bool {
        self.path.is_some() && self.git.is_none()
    }

    /// Returns true if this dependency specifies a git repository
    pub fn is_git(&self) -> bool {
        self.git.is_some()
    }
}

impl SetSourceId for DependencySpec {
    fn set_source_id(&mut self, source_id: SourceId) {
        self.name.set_source_id(source_id);
        if let Some(package) = &mut self.package {
            package.set_source_id(source_id);
        }
        if let Some(mount) = &mut self.source_mount {
            Span::set_source_id(mount, source_id);
        }
        if let Some(binding) = &mut self.binding {
            binding.set_source_id(source_id);
        }
        if let Some(expected) = &mut self.expected_callables {
            // Records contain owned semantic values; only the enclosing list carries a span.
            Span::set_source_id(expected, source_id);
        }
        if let Some(version_or_digest) = self.version_or_digest.as_mut() {
            version_or_digest.set_source_id(source_id);
        }

        if let Some(path) = self.path.as_mut() {
            path.set_source_id(source_id);
        }

        if let Some(git) = self.git.as_mut() {
            git.set_source_id(source_id);
        }

        if let Some(branch) = self.branch.as_mut() {
            branch.set_source_id(source_id);
        }

        if let Some(rev) = self.rev.as_mut() {
            rev.set_source_id(source_id);
        }
    }
}

#[cfg(feature = "serde")]
pub use self::serialization::deserialize_dependency_map;

#[cfg(feature = "serde")]
mod serialization {
    use alloc::sync::Arc;

    use miden_assembly_syntax::debuginfo::Span;
    use serde::{
        Deserialize,
        de::{IntoDeserializer, MapAccess, Visitor},
    };

    use super::DependencySpec;
    use crate::Map;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DependencySpecTable {
        #[serde(default, skip)]
        name: Span<Arc<str>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package: Option<Span<Arc<str>>>,
        #[serde(rename = "version", alias = "digest", skip_serializing_if = "Option::is_none")]
        version_or_digest: Option<crate::VersionRequirement>,
        #[serde(default, skip_serializing_if = "super::does_not_inherit_from_workspace")]
        workspace: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<Span<crate::Uri>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        git: Option<Span<crate::Uri>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        branch: Option<Span<Arc<str>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rev: Option<Span<Arc<str>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        linkage: Option<Span<crate::Linkage>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding: Option<Span<super::super::DependencyBindingSpec>>,
        #[serde(rename = "expected-callables", default, skip_serializing_if = "Option::is_none")]
        expected_callables: Option<Span<alloc::vec::Vec<super::super::ExpectedCallableSpec>>>,
        #[serde(rename = "source-mount", default, skip_serializing_if = "Option::is_none")]
        source_mount: Option<Span<super::SourceMountSpec>>,
    }

    impl From<DependencySpecTable> for DependencySpec {
        fn from(table: DependencySpecTable) -> Self {
            Self {
                name: table.name,
                package: table.package,
                version_or_digest: table.version_or_digest,
                workspace: table.workspace,
                path: table.path,
                git: table.git,
                branch: table.branch,
                rev: table.rev,
                linkage: table.linkage,
                binding: table.binding,
                expected_callables: table.expected_callables,
                source_mount: table.source_mount,
            }
        }
    }

    impl<'de> Deserialize<'de> for DependencySpec {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            serde_untagged::UntaggedEnumVisitor::new()
                .expecting("a dependency requirement string or dependency table")
                .string(|value| {
                    crate::VersionRequirement::deserialize(value.into_deserializer()).map(
                        |version_or_digest| Self {
                            name: Span::default(),
                            package: None,
                            version_or_digest: Some(version_or_digest),
                            workspace: false,
                            path: None,
                            git: None,
                            branch: None,
                            rev: None,
                            linkage: None,
                            binding: None,
                            expected_callables: None,
                            source_mount: None,
                        },
                    )
                })
                .map(|map| map.deserialize::<DependencySpecTable>().map(Into::into))
                .deserialize(deserializer)
        }
    }

    struct DependencyMapVisitor;

    impl<'de> Visitor<'de> for DependencyMapVisitor {
        type Value = Map<Span<Arc<str>>, Span<DependencySpec>>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a dependency map")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map = Self::Value::default();

            while let Some((key, mut value)) =
                access.next_entry::<Span<Arc<str>>, Span<DependencySpec>>()?
            {
                value.name = key.clone();
                map.insert(key, value);
            }

            Ok(map)
        }
    }

    pub fn deserialize_dependency_map<'de, D>(
        deserializer: D,
    ) -> Result<Map<Span<Arc<str>>, Span<DependencySpec>>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DependencyMapVisitor)
    }
}
