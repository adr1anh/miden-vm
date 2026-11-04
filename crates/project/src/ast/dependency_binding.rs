//! Explicit manifest naming inputs. This is configuration, not a publication/profile codec.

use alloc::{string::String, vec::Vec};
use core::num::NonZeroU32;

use miden_core::{Word, program::CanonicalLabel};
use miden_mast_package::{CallableProcedurePath, NamespacePath, ProcedureName};
use serde::{Deserialize, Serialize};

use crate::{
    DependencyBinding, ExpectedVisibleCallables, LibraryCatalog, LibraryRef, LibrarySelection,
    Report,
};

/// An exact Word literal or an explicitly requested readable catalog name.
///
/// Literal strings never fall back to catalog lookup. Names supply no identity derivation or
/// publisher, release, profile, binding or implementation authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum LibraryIdSpec {
    Literal(String),
    Catalog { catalog: String },
}

impl LibraryIdSpec {
    /// Resolves a literal without any optional readable catalog.
    pub fn resolve(&self) -> Result<Word, Report> {
        self.resolve_with_catalog(&LibraryCatalog::default())
    }

    /// Resolves an explicit catalog reference or validates an exact supplied Word literal.
    pub fn resolve_with_catalog(&self, catalog: &LibraryCatalog) -> Result<Word, Report> {
        match self {
            Self::Literal(identity) => Word::try_from(identity.as_str())
                .map_err(|error| Report::msg(format!("invalid library identity literal: {error}"))),
            Self::Catalog { catalog: name } => catalog.resolve(name),
        }
    }
}

impl From<String> for LibraryIdSpec {
    fn from(identity: String) -> Self {
        Self::Literal(identity)
    }
}

impl From<&str> for LibraryIdSpec {
    fn from(identity: &str) -> Self {
        Self::Literal(identity.into())
    }
}

/// Built-in canonical label input. TypedId codecs require an explicit external provider instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HomeLabelSpec {
    Text(String),
    LibraryId(LibraryIdSpec),
    Revision(NonZeroU32),
    /// Exact existing CanonicalLabel bytes. Decoding still rejects unvalidated TypedId codecs.
    Canonical(Vec<u8>),
}

impl HomeLabelSpec {
    fn label(&self, catalog: &LibraryCatalog) -> Result<CanonicalLabel, Report> {
        match self {
            Self::Text(text) => CanonicalLabel::text(text).map_err(Report::msg),
            Self::LibraryId(id) => id.resolve_with_catalog(catalog).map(CanonicalLabel::library_id),
            Self::Revision(revision) => Ok(CanonicalLabel::revision(*revision)),
            Self::Canonical(bytes) => CanonicalLabel::from_bytes(bytes).map_err(Report::msg),
        }
    }

    fn from_home(home: &NamespacePath) -> Result<Vec<Self>, Report> {
        home.home().iter().map(|label| {
            CanonicalLabel::from_bytes(label.as_bytes()).map_err(|_| Report::msg(
                "manifest serialization of TypedId ancestors requires an external codec/profile-aware writer",
            ))?;
            Ok(Self::Canonical(label.as_bytes().to_vec()))
        }).collect()
    }
}

/// One independently configured visible path and its complete defining callable binding.
///
/// Paths contain semantic components, without source alias expansion or path-string parsing.
/// Every home is explicit, including for reexports whose defining home differs from the dependency
/// default. These records supply no implementation selection or profile admission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ExpectedCallableSpec {
    pub visible_path: Vec<String>,
    pub home: Vec<HomeLabelSpec>,
    pub canonical_path: Vec<String>,
}

impl ExpectedCallableSpec {
    /// Validates built-in home encodings and exact semantic path components.
    pub fn resolve(&self) -> Result<(CallableProcedurePath, ProcedureName), Report> {
        self.resolve_with_catalog(&LibraryCatalog::default())
    }

    /// Resolves every home identity using the explicitly supplied readable catalog.
    pub fn resolve_with_catalog(
        &self,
        catalog: &LibraryCatalog,
    ) -> Result<(CallableProcedurePath, ProcedureName), Report> {
        let visible = CallableProcedurePath::from_semantic_components(self.visible_path.clone())
            .map_err(Report::msg)?;
        let canonical =
            CallableProcedurePath::from_semantic_components(self.canonical_path.clone())
                .map_err(Report::msg)?;
        let binding =
            ProcedureName::new(DependencyBindingSpec::home(&self.home, catalog)?, canonical)
                .map_err(Report::msg)?;
        Ok((visible, binding))
    }

    /// Resolves an exact complete mapping, rejecting duplicate visible records.
    pub fn resolve_all(specs: &[Self]) -> Result<ExpectedVisibleCallables, Report> {
        Self::resolve_all_with_catalog(specs, &LibraryCatalog::default())
    }

    /// Resolves a complete mapping with an explicit readable catalog and rejects duplicate paths.
    pub fn resolve_all_with_catalog(
        specs: &[Self],
        catalog: &LibraryCatalog,
    ) -> Result<ExpectedVisibleCallables, Report> {
        let mappings = specs
            .iter()
            .map(|spec| spec.resolve_with_catalog(catalog))
            .collect::<Result<Vec<_>, _>>()?;
        ExpectedVisibleCallables::new(mappings)
    }
}

impl TryFrom<(&CallableProcedurePath, &ProcedureName)> for ExpectedCallableSpec {
    type Error = Report;

    fn try_from(
        (visible, binding): (&CallableProcedurePath, &ProcedureName),
    ) -> Result<Self, Report> {
        Ok(Self {
            visible_path: visible.components().to_vec(),
            home: HomeLabelSpec::from_home(binding.namespace_plan())?,
            canonical_path: binding.path().components().to_vec(),
        })
    }
}

/// Source-target default home selected independently from version/Git/path provenance and linkage.
///
/// `base` is always the complete caller-supplied ancestor path, even when explicitly empty.
/// Standard choices require an opaque canonical Word ID; Pinned additionally requires a nonzero
/// revision. Custom homes are an explicit escape hatch. Nothing here approves home/publisher
/// policy, public callable mappings or an expected implementation. Complete Bound declarations
/// and reexports remain separate. There is no omitted-selection default.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "selection", rename_all = "lowercase", deny_unknown_fields)]
pub enum DependencyBindingSpec {
    Latest {
        base: Vec<HomeLabelSpec>,
        #[serde(rename = "library-id")]
        library_id: LibraryIdSpec,
    },
    Pinned {
        base: Vec<HomeLabelSpec>,
        #[serde(rename = "library-id")]
        library_id: LibraryIdSpec,
        revision: NonZeroU32,
    },
    Custom {
        home: Vec<HomeLabelSpec>,
    },
}

impl DependencyBindingSpec {
    /// Validates built-in label/Word encodings while retaining the explicit binding choice.
    pub fn resolve(&self) -> Result<DependencyBinding, Report> {
        self.resolve_with_catalog(&LibraryCatalog::default())
    }

    /// Resolves explicit catalog references in both the selected identity and ancestor home.
    pub fn resolve_with_catalog(
        &self,
        catalog: &LibraryCatalog,
    ) -> Result<DependencyBinding, Report> {
        let (base, identity, selection) = match self {
            Self::Latest { base, library_id } => (base, library_id, LibrarySelection::Latest),
            Self::Pinned { base, library_id, revision } => {
                (base, library_id, LibrarySelection::Revision(*revision))
            },
            Self::Custom { home } => {
                return Ok(DependencyBinding::Custom(Self::home(home, catalog)?));
            },
        };
        let identity = identity.resolve_with_catalog(catalog)?;
        Ok(DependencyBinding::Standard(LibraryRef::new(
            Self::home(base, catalog)?,
            identity,
            selection,
        )))
    }

    fn home(labels: &[HomeLabelSpec], catalog: &LibraryCatalog) -> Result<NamespacePath, Report> {
        labels
            .iter()
            .map(|label| label.label(catalog))
            .collect::<Result<Vec<_>, _>>()
            .map(NamespacePath::new)
    }
}

impl TryFrom<&DependencyBinding> for DependencyBindingSpec {
    type Error = Report;

    fn try_from(binding: &DependencyBinding) -> Result<Self, Report> {
        Ok(match binding {
            DependencyBinding::Custom(home) => {
                Self::Custom { home: HomeLabelSpec::from_home(home)? }
            },
            DependencyBinding::Standard(import) => match import.selection() {
                LibrarySelection::Latest => Self::Latest {
                    base: HomeLabelSpec::from_home(import.base())?,
                    library_id: import.library_id().to_hex().into(),
                },
                LibrarySelection::Revision(revision) => Self::Pinned {
                    base: HomeLabelSpec::from_home(import.base())?,
                    library_id: import.library_id().to_hex().into(),
                    revision,
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    const ID: &str = "0x0100000000000000020000000000000003000000000000000400000000000000";

    #[test]
    fn explicit_catalog_selectors_resolve_standard_custom_and_expected_homes() {
        let catalog = LibraryCatalog::new([("math", Word::try_from(ID).unwrap())]).unwrap();
        for (selection, extra) in [("latest", ""), ("pinned", "\nrevision = 7")] {
            let named: DependencyBindingSpec = toml::from_str(&format!(
                "selection = '{selection}'\nbase = [{{library-id = {{catalog = 'math'}}}}]\nlibrary-id = {{catalog = 'math'}}{extra}"
            )).unwrap();
            let literal: DependencyBindingSpec = toml::from_str(&format!(
                "selection = '{selection}'\nbase = [{{library-id = '{ID}'}}]\nlibrary-id = '{ID}'{extra}"
            )).unwrap();
            assert!(named.resolve().unwrap_err().to_string().contains("unknown library catalog"));
            assert_eq!(named.resolve_with_catalog(&catalog).unwrap(), literal.resolve().unwrap());
        }
        let custom: DependencyBindingSpec =
            toml::from_str("selection = 'custom'\nhome = [{library-id = {catalog = 'math'}}]")
                .unwrap();
        let expected: ExpectedCallableSpec = toml::from_str(
            "visible-path = ['api', 'alias']\nhome = [{library-id = {catalog = 'math'}}]\ncanonical-path = ['origin', 'run']",
        ).unwrap();
        let (_, binding) = expected.resolve_with_catalog(&catalog).unwrap();
        assert_eq!(
            binding.namespace_plan(),
            &custom.resolve_with_catalog(&catalog).unwrap().namespace_plan()
        );
        assert!(ExpectedCallableSpec::resolve_all(core::slice::from_ref(&expected)).is_err());
        assert!(
            ExpectedCallableSpec::resolve_all_with_catalog(&[expected.clone(), expected], &catalog)
                .unwrap_err()
                .to_string()
                .contains("duplicate expected visible callable path")
        );
    }

    #[test]
    fn catalog_lookup_never_reinterprets_invalid_literals_or_accepts_policy_fields() {
        let catalog = LibraryCatalog::new([("math", Word::try_from(ID).unwrap())]).unwrap();
        for selector in ["'math'", "{catalog = 'missing'}", "{catalog = 'Math'}"] {
            let spec: DependencyBindingSpec = toml::from_str(&format!(
                "selection = 'latest'\nbase = []\nlibrary-id = {selector}",
            ))
            .unwrap();
            assert!(spec.resolve_with_catalog(&catalog).is_err(), "{selector}");
        }
        for selector in [
            "{catalog = 'math', identity = 'ignored'}",
            "{catalog = 'math', publisher = 'ignored'}",
            "{catalog = 'math', implementation = 'ignored'}",
            "{name = 'math'}",
        ] {
            assert!(
                toml::from_str::<DependencyBindingSpec>(&format!(
                    "selection = 'latest'\nbase = []\nlibrary-id = {selector}",
                ))
                .is_err(),
                "{selector}"
            );
        }
        let literal = LibraryIdSpec::from(ID);
        assert_eq!(literal.resolve().unwrap(), literal.resolve_with_catalog(&catalog).unwrap());
        let typed = CanonicalLabel::typed_id(77, &[9, 0, 4], |_, _| Ok(())).unwrap();
        let spec = DependencyBindingSpec::Custom {
            home: vec![
                HomeLabelSpec::LibraryId(LibraryIdSpec::Catalog { catalog: "math".into() }),
                HomeLabelSpec::Canonical(typed.as_bytes().to_vec()),
            ],
        };
        assert!(spec.resolve_with_catalog(&catalog).is_err());
    }

    #[test]
    fn expected_callable_records_preserve_explicit_homes_and_semantic_component_boundaries() {
        let source = format!(
            "visible-path = ['quoted::module', 'alias']\nhome = [{{text = 'foreign'}}, {{library-id = '{ID}'}}, {{revision = 7}}]\ncanonical-path = ['defining', 'run']"
        );
        let spec: ExpectedCallableSpec = toml::from_str(&source).unwrap();
        let (visible, binding) = spec.resolve().unwrap();
        assert_eq!(visible.components(), &["quoted::module", "alias"]);
        assert_eq!(binding.path().components(), &["defining", "run"]);
        assert_eq!(binding.namespace_plan().home()[0], CanonicalLabel::text("foreign").unwrap());
        assert_eq!(
            binding.namespace_plan().home()[1],
            CanonicalLabel::library_id(Word::try_from(ID).unwrap())
        );
        assert_eq!(
            binding.namespace_plan().home()[2],
            CanonicalLabel::revision(NonZeroU32::new(7).unwrap())
        );
        let written = ExpectedCallableSpec::try_from((&visible, &binding)).unwrap();
        let roundtrip = toml::to_string(&written).unwrap();
        let restored: ExpectedCallableSpec = toml::from_str(&roundtrip).unwrap();
        assert_eq!(restored.resolve().unwrap(), (visible, binding));
        let duplicate = ExpectedCallableSpec::resolve_all(&[spec.clone(), spec]).unwrap_err();
        assert!(duplicate.to_string().contains("duplicate expected visible callable path"));
    }

    #[test]
    fn expected_callable_records_reject_omitted_homes_invalid_paths_and_policy_fields() {
        for source in [
            "visible-path = ['api', 'run']\ncanonical-path = ['defining', 'run']",
            "visible-path = ['api', 'run']\nhome = []",
            "home = []\ncanonical-path = ['defining', 'run']",
            "visible-path = ['api', 'run']\nhome = []\ncanonical-path = ['defining', 'run']\nimplementation = 'unselected'",
        ] {
            assert!(toml::from_str::<ExpectedCallableSpec>(source).is_err(), "{source}");
        }
        for source in [
            "visible-path = []\nhome = []\ncanonical-path = ['defining', 'run']",
            "visible-path = ['api', 'run']\nhome = []\ncanonical-path = []",
            "visible-path = ['api', 'run']\nhome = [{library-id = 'readable-name'}]\ncanonical-path = ['defining', 'run']",
        ] {
            let spec: ExpectedCallableSpec = toml::from_str(source).unwrap();
            assert!(spec.resolve().is_err(), "{source}");
        }
    }

    #[test]
    fn expected_callable_writer_rejects_unvalidated_external_typed_homes() {
        let binding = ProcedureName::new(
            NamespacePath::new(vec![
                CanonicalLabel::typed_id(77, &[9, 0, 4], |_, _| Ok(())).unwrap(),
            ]),
            CallableProcedurePath::from_semantic_components(vec!["run".into()]).unwrap(),
        )
        .unwrap();
        let visible =
            CallableProcedurePath::from_semantic_components(vec!["alias".into()]).unwrap();
        let error = ExpectedCallableSpec::try_from((&visible, &binding)).unwrap_err();
        assert!(error.to_string().contains("external codec/profile-aware writer"));
        let dependency = crate::Dependency::new(
            crate::Span::unknown("dep".into()),
            crate::DependencyVersionScheme::Registry(crate::VersionRequirement::from(
                crate::VersionReq::STAR,
            )),
            crate::Linkage::Dynamic,
        )
        .with_binding(DependencyBinding::Custom(NamespacePath::new(vec![])))
        .with_expected_callables(ExpectedVisibleCallables::new([(visible, binding)]).unwrap());
        let package = crate::Package::new(
            "app",
            crate::Target::library(
                alloc::sync::Arc::<miden_assembly_syntax::Path>::from(
                    miden_assembly_syntax::Path::new("app"),
                ),
                crate::Uri::new("mod.masm"),
            ),
        )
        .with_dependencies([dependency]);
        assert!(
            package
                .to_toml()
                .unwrap_err()
                .to_string()
                .contains("external codec/profile-aware writer")
        );
    }

    #[test]
    fn manifest_writer_rejects_external_typed_ancestors_instead_of_emitting_unreloadable_data() {
        let typed = CanonicalLabel::typed_id(77, &[9, 0, 4], |_, _| Ok(())).unwrap();
        let home = NamespacePath::new(alloc::vec![typed.clone()]);
        let import =
            LibraryRef::new(home.clone(), Word::try_from(ID).unwrap(), LibrarySelection::Latest);
        assert_eq!(import.namespace_plan().home()[0], typed);
        for binding in [DependencyBinding::Standard(import), DependencyBinding::Custom(home)] {
            let error = DependencyBindingSpec::try_from(&binding).unwrap_err();
            assert!(error.to_string().contains("external codec/profile-aware writer"));
            let dependency = crate::Dependency::new(
                crate::Span::unknown("dep".into()),
                crate::DependencyVersionScheme::Registry(crate::VersionRequirement::from(
                    crate::VersionReq::STAR,
                )),
                crate::Linkage::Dynamic,
            )
            .with_binding(binding);
            let package = crate::Package::new(
                "app",
                crate::Target::library(
                    alloc::sync::Arc::<miden_assembly_syntax::Path>::from(
                        miden_assembly_syntax::Path::new("app"),
                    ),
                    crate::Uri::new("mod.masm"),
                ),
            )
            .with_dependencies([dependency]);
            assert!(
                package
                    .to_toml()
                    .unwrap_err()
                    .to_string()
                    .contains("external codec/profile-aware writer")
            );
        }
    }

    #[test]
    fn standard_choices_preserve_typed_ancestor_inputs() {
        for (mode, revision) in [("latest", ""), ("pinned", "revision = 7")] {
            let source = alloc::format!(
                "selection = '{mode}'\nlibrary-id = '{ID}'\nbase = [{{text = 'account'}}, {{revision = 2}}]\n{revision}"
            );
            let spec: DependencyBindingSpec = toml::from_str(&source).unwrap();
            let binding = spec.resolve().unwrap();
            let home = binding.namespace_plan();
            assert_eq!(home.home()[0], CanonicalLabel::text("account").unwrap());
            assert_eq!(home.home()[1], CanonicalLabel::revision(NonZeroU32::new(2).unwrap()));
            assert_eq!(home.home()[2], CanonicalLabel::text(mode).unwrap());
            assert_eq!(home.home()[3], CanonicalLabel::library_id(Word::try_from(ID).unwrap()));
            if mode == "pinned" {
                assert_eq!(home.home()[4], CanonicalLabel::revision(NonZeroU32::new(7).unwrap()));
            } else {
                assert_eq!(home.home().len(), 4);
            }
            let roundtrip = toml::to_string(&spec).unwrap();
            let restored: DependencyBindingSpec = toml::from_str(&roundtrip).unwrap();
            assert_eq!(binding, restored.resolve().unwrap());
        }
    }

    #[test]
    fn omission_ambiguous_modes_and_unknown_policy_inputs_reject() {
        let invalid = [
            alloc::format!("library-id = '{ID}'\nbase = []"),
            alloc::format!("selection = 'latest'\nlibrary-id = '{ID}'"),
            alloc::format!("selection = 'latest'\nlibrary-id = '{ID}'\nbase = []\nrevision = 7"),
            alloc::format!("selection = 'pinned'\nlibrary-id = '{ID}'\nbase = []"),
            alloc::format!("selection = 'pinned'\nlibrary-id = '{ID}'\nbase = []\nrevision = 0"),
            alloc::format!(
                "selection = 'latest'\nlibrary-id = '{ID}'\nbase = [{{typed-id = 'unvalidated'}}]"
            ),
            "selection = 'custom'\nhome = []\nlibrary-id = 'unselected'".into(),
        ];
        for source in invalid {
            assert!(toml::from_str::<DependencyBindingSpec>(&source).is_err(), "{source}");
        }
    }

    #[test]
    fn malformed_or_noncanonical_identity_rejects_and_custom_home_stays_explicit() {
        for id in [
            "name-from-a-catalog",
            "0x01",
            "0x01000000ffffffff000000000000000000000000000000000000000000000000",
        ] {
            let spec: DependencyBindingSpec = toml::from_str(&alloc::format!(
                "selection = 'latest'\nlibrary-id = '{id}'\nbase = []"
            ))
            .unwrap();
            assert!(spec.resolve().is_err(), "{id}");
        }
        let spec: DependencyBindingSpec =
            toml::from_str("selection = 'custom'\nhome = [{text = 'chosen::home'}]").unwrap();
        assert_eq!(
            spec.resolve().unwrap().namespace_plan(),
            NamespacePath::new(alloc::vec![CanonicalLabel::text("chosen::home").unwrap()])
        );
    }
}
