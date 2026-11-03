//! Explicit manifest naming inputs. This is configuration, not a publication/profile codec.

use alloc::{string::String, vec::Vec};
use core::num::NonZeroU32;

use miden_core::{Word, program::CanonicalLabel};
use miden_mast_package::NamespacePlan;
use serde::{Deserialize, Serialize};

use crate::{DependencyBinding, LibraryImport, LibrarySelection, Report};

/// Built-in canonical label input. TypedId codecs require an explicit external provider instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HomeLabelSpec {
    Text(String),
    LibraryId(String),
    Revision(NonZeroU32),
    /// Exact existing CanonicalLabel bytes. Decoding still rejects unvalidated TypedId codecs.
    Canonical(Vec<u8>),
}

impl HomeLabelSpec {
    fn label(&self) -> Result<CanonicalLabel, Report> {
        match self {
            Self::Text(text) => CanonicalLabel::text(text).map_err(Report::msg),
            Self::LibraryId(id) => {
                Word::try_from(id.as_str()).map(CanonicalLabel::library_id).map_err(Report::msg)
            },
            Self::Revision(revision) => Ok(CanonicalLabel::revision(*revision)),
            Self::Canonical(bytes) => CanonicalLabel::from_bytes(bytes).map_err(Report::msg),
        }
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
        library_id: String,
    },
    Pinned {
        base: Vec<HomeLabelSpec>,
        #[serde(rename = "library-id")]
        library_id: String,
        revision: NonZeroU32,
    },
    Custom {
        home: Vec<HomeLabelSpec>,
    },
}

impl DependencyBindingSpec {
    /// Validates built-in label/Word encodings while retaining the explicit binding choice.
    pub fn resolve(&self) -> Result<DependencyBinding, Report> {
        let (base, identity, selection) = match self {
            Self::Latest { base, library_id } => (base, library_id, LibrarySelection::Latest),
            Self::Pinned { base, library_id, revision } => {
                (base, library_id, LibrarySelection::Pinned(*revision))
            },
            Self::Custom { home } => return Ok(DependencyBinding::Custom(Self::home(home)?)),
        };
        let identity = Word::try_from(identity.as_str()).map_err(Report::msg)?;
        Ok(DependencyBinding::Standard(LibraryImport::new(
            Self::home(base)?,
            identity,
            selection,
        )))
    }

    fn home(labels: &[HomeLabelSpec]) -> Result<NamespacePlan, Report> {
        labels
            .iter()
            .map(HomeLabelSpec::label)
            .collect::<Result<Vec<_>, _>>()
            .map(NamespacePlan::new)
    }
}

impl TryFrom<&DependencyBinding> for DependencyBindingSpec {
    type Error = Report;

    fn try_from(binding: &DependencyBinding) -> Result<Self, Report> {
        let labels = |home: &NamespacePlan| -> Result<Vec<HomeLabelSpec>, Report> {
            home.home().iter().map(|label| {
                CanonicalLabel::from_bytes(label.as_bytes()).map_err(|_| Report::msg(
                    "manifest serialization of TypedId ancestors requires an external codec/profile-aware writer",
                ))?;
                Ok(HomeLabelSpec::Canonical(label.as_bytes().to_vec()))
            }).collect()
        };
        Ok(match binding {
            DependencyBinding::Custom(home) => Self::Custom { home: labels(home)? },
            DependencyBinding::Standard(import) => match import.selection() {
                LibrarySelection::Latest => Self::Latest {
                    base: labels(import.base())?,
                    library_id: import.library_id().to_hex(),
                },
                LibrarySelection::Pinned(revision) => Self::Pinned {
                    base: labels(import.base())?,
                    library_id: import.library_id().to_hex(),
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
    fn manifest_writer_rejects_external_typed_ancestors_instead_of_emitting_unreloadable_data() {
        let typed = CanonicalLabel::typed_id(77, &[9, 0, 4], |_, _| Ok(())).unwrap();
        let home = NamespacePlan::new(alloc::vec![typed.clone()]);
        let import =
            LibraryImport::new(home.clone(), Word::try_from(ID).unwrap(), LibrarySelection::Latest);
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
            NamespacePlan::new(alloc::vec![CanonicalLabel::text("chosen::home").unwrap()])
        );
    }
}
