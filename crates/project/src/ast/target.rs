use crate::{ast::parsing::SetSourceId, *};

/// Explicit source naming configuration, with no omitted convention or binding defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceNamingSpec {
    pub convention: SourceNamingConvention,
    pub binding: super::DependencyBindingSpec,
}

impl SourceNamingSpec {
    pub fn resolve(&self, ty: TargetType) -> Result<SourceNaming, Report> {
        self.resolve_with_catalog(ty, &LibraryCatalog::default())
    }

    /// Resolves explicit identity references before validating the selected target convention.
    pub fn resolve_with_catalog(
        &self,
        ty: TargetType,
        catalog: &LibraryCatalog,
    ) -> Result<SourceNaming, Report> {
        let naming =
            SourceNaming::new(self.convention, self.binding.resolve_with_catalog(catalog)?);
        naming.validate_target_type(ty)?;
        Ok(naming)
    }
}

impl TryFrom<&SourceNaming> for SourceNamingSpec {
    type Error = Report;

    fn try_from(naming: &SourceNaming) -> Result<Self, Report> {
        Ok(Self {
            convention: naming.convention(),
            binding: super::DependencyBindingSpec::try_from(naming.binding())?,
        })
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct LibTarget {
    /// The kind of library target this is.
    ///
    /// Defaults to `library`
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub kind: Option<Span<TargetType>>,
    /// The optional namespace override for modules parsed from this target
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub namespace: Option<Span<Arc<str>>>,
    /// The relative path from the project manifest to the root source file for this target
    pub path: Span<Uri>,
    /// Optional explicit source convention and fallback default-home request.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub naming: Option<Span<SourceNamingSpec>>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct BinTarget {
    /// An optional name for this target.
    ///
    /// If unspecified, the effective target name defaults to the package name.
    ///
    /// All binary target names must be unique in a project.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub name: Option<Span<Arc<str>>>,
    /// The relative path from the project manifest to the root source file for this target
    pub path: Span<Uri>,
    /// Optional explicit source convention and fallback default-home request.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub naming: Option<Span<SourceNamingSpec>>,
}

impl SetSourceId for LibTarget {
    fn set_source_id(&mut self, source_id: SourceId) {
        if let Some(kind) = self.kind.as_mut() {
            kind.set_source_id(source_id);
        }

        if let Some(ns) = self.namespace.as_mut() {
            ns.set_source_id(source_id);
        }

        self.path.set_source_id(source_id);
        if let Some(naming) = self.naming.as_mut() {
            naming.set_source_id(source_id);
        }
    }
}

impl SetSourceId for BinTarget {
    fn set_source_id(&mut self, source_id: SourceId) {
        if let Some(ns) = self.name.as_mut() {
            ns.set_source_id(source_id);
        }

        self.path.set_source_id(source_id);
        if let Some(naming) = self.naming.as_mut() {
            naming.set_source_id(source_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_core::program::CanonicalLabel;
    use miden_mast_package::NamespacePath;

    use super::*;

    #[test]
    fn source_naming_requires_complete_explicit_configuration() {
        for source in [
            "binding = {selection = 'custom', home = []}",
            "convention = 'defining-paths'",
            "convention = 'unknown'\nbinding = {selection = 'custom', home = []}",
            "convention = 'defining-paths'\nbinding = {home = []}",
            "convention = 'defining-paths'\nbinding = {selection = 'custom'}",
            "convention = 'defining-paths'\nbinding = {selection = 'latest', base = []}",
            "convention = 'defining-paths'\nbinding = {selection = 'latest', library-id = '0x0100000000000000020000000000000003000000000000000400000000000000'}",
            "convention = 'defining-paths'\nbinding = {selection = 'pinned', base = [], library-id = '0x0100000000000000020000000000000003000000000000000400000000000000'}",
            "convention = 'defining-paths'\nbinding = {selection = 'custom', home = [], authority = true}",
            "convention = 'defining-paths'\nbinding = {selection = 'custom', home = []}\nimplementation = 'unselected'",
        ] {
            assert!(toml::from_str::<SourceNamingSpec>(source).is_err(), "{source}");
        }
        let spec: SourceNamingSpec = toml::from_str(
            "convention = 'defining-paths'\nbinding = {selection = 'custom', home = []}",
        )
        .unwrap();
        assert!(
            spec.resolve(TargetType::Library)
                .unwrap()
                .binding()
                .namespace_plan()
                .home()
                .is_empty()
        );
    }

    #[test]
    fn source_naming_reuses_typed_ancestor_codec_restrictions() {
        let typed = CanonicalLabel::typed_id(77, &[9, 0, 4], |_, _| Ok(())).unwrap();
        let naming = SourceNaming::new(
            SourceNamingConvention::DefiningPaths,
            DependencyBinding::Custom(NamespacePath::new(vec![typed.clone()])),
        );
        let error = SourceNamingSpec::try_from(&naming).unwrap_err();
        assert!(error.to_string().contains("external codec/profile-aware writer"));

        let spec = SourceNamingSpec {
            convention: SourceNamingConvention::DefiningPaths,
            binding: super::super::DependencyBindingSpec::Custom {
                home: vec![super::super::HomeLabelSpec::Canonical(typed.as_bytes().to_vec())],
            },
        };
        assert!(spec.resolve(TargetType::Library).is_err());
    }
}
