use alloc::{format, string::String, vec::Vec};

use miden_assembly_syntax::diagnostics::Report;
use miden_core::{
    Word,
    serde::{ByteReader, Deserializable, Serializable, SliceReader},
    utils::hash_string_to_word,
};
use miden_mast_package::{Package as MastPackage, Section, SectionId};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

use super::PackageBuildSettings;

// PACKAGE BUILD PROVENANCE
// ================================================================================================

/// Provenance metadata attached to packages that were assembled from concrete project sources.
///
/// `ProjectAssembler` uses this metadata to decide whether a canonical package already present in
/// the package store is still a valid reuse candidate for a source dependency, or whether the
/// current sources have diverged and the dependency must be rebuilt or semver-bumped instead.
///
/// The value is serialized into the package's [`SectionId::PROJECT_SOURCE_PROVENANCE`] section via
/// [`Self::to_section`] when a package is built from real on-disk sources. Builds that use
/// caller-provided modules or other virtual sources intentionally omit this section because there
/// is no stable filesystem or git identity to compare on a later reuse attempt.
///
/// The recorded fields differ by source origin:
///
/// - [`Self::Path`] tracks a hash of the selected target's build-provenance projection and resolved
///   source files, along with a hash of the fully resolved dependency closure and the build-profile
///   knobs that affect the emitted package bytes.
/// - [`Self::Git`] records the repository identity and resolved revision instead of hashing the
///   checked-out source tree directly, but still includes the dependency-closure hash and build
///   settings for the same reuse decision.
/// - Both origins optionally record the exact resolved compilation commitment. Legacy records omit
///   it and cannot compare equal to a record carrying current compiler inputs.
///
/// Parent dependency-closure hashing frames the exact serialized record. [`Self::describe`] is
/// used in semver-bump diagnostics to explain why an existing canonical artifact no longer
/// matches the current sources.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub(super) enum PackageBuildProvenance {
    /// Provenance for a package assembled from sources addressed by a local filesystem path.
    Path {
        /// Hash of the build-provenance projection plus the root/support modules for the target.
        source_hash: Word,
        /// Hash of the resolved dependency closure, including linkage and exact selected
        /// artifacts.
        dependency_hash: Word,
        /// Build-profile settings that materially affect the produced package bytes.
        build_settings: PackageBuildSettings,
        /// Exact resolved compiler inputs, including required namespace naming.
        compilation_commitment: Option<Word>,
    },
    /// Provenance for a package assembled from a checked-out Git source.
    Git {
        /// Repository URI used to fetch the sources.
        repo: String,
        /// Fully resolved revision used for the checkout, after branch/tag resolution.
        resolved_revision: String,
        /// Hash of the resolved dependency closure, including linkage and exact selected
        /// artifacts.
        dependency_hash: Word,
        /// Build-profile settings that materially affect the produced package bytes.
        build_settings: PackageBuildSettings,
        /// Exact resolved compiler inputs, including required namespace naming.
        compilation_commitment: Option<Word>,
    },
}

impl PackageBuildProvenance {
    /// The canonical dependency hash for packages that have no dependencies.
    ///
    /// This keeps the serialized format compact and provides a stable value for older provenance
    /// encodings that predated explicit dependency-closure hashing.
    pub fn empty_dependency_hash() -> Word {
        hash_string_to_word("")
    }

    /// Return the exact resolved compiler inputs, when recorded by the producer.
    pub fn compilation_commitment(&self) -> Option<Word> {
        match self {
            Self::Path { compilation_commitment, .. }
            | Self::Git { compilation_commitment, .. } => *compilation_commitment,
        }
    }

    /// Attach the exact resolved compiler inputs to this source provenance.
    pub fn with_compilation_commitment(mut self, commitment: Word) -> Self {
        match &mut self {
            Self::Path { compilation_commitment, .. }
            | Self::Git { compilation_commitment, .. } => {
                *compilation_commitment = Some(commitment);
            },
        }
        self
    }

    /// Encode this provenance record as a package section that can be embedded in a `.masp`.
    pub fn to_section(&self) -> Section {
        let mut data = Vec::new();
        self.write_into(&mut data);
        Section::new(SectionId::PROJECT_SOURCE_PROVENANCE, data)
    }

    /// Decode source provenance from `package`, if the package carries a provenance section.
    ///
    /// This is used when considering reuse of a canonical store artifact for a source dependency:
    /// the decoded value is compared against the provenance that would be produced from the current
    /// dependency graph and build profile.
    pub fn from_package(package: &MastPackage) -> Result<Option<Self>, Report> {
        let Some(section) = package
            .sections
            .iter()
            .find(|section| section.id == SectionId::PROJECT_SOURCE_PROVENANCE)
        else {
            return Ok(None);
        };

        let mut reader = SliceReader::new(section.data.as_ref());
        let provenance = Self::read_from(&mut reader).map_err(|error| {
            Report::msg(format!(
                "failed to decode source provenance for package '{}': {error}",
                package.name
            ))
        })?;
        if reader.has_more_bytes() {
            return Err(Report::msg(format!(
                "failed to decode source provenance for package '{}': trailing provenance bytes",
                package.name
            )));
        }
        Ok(Some(provenance))
    }

    /// Render a human-readable summary for diagnostics.
    pub fn describe(&self) -> String {
        match self {
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: Some(commitment),
            } => format!(
                "path({source_hash}, deps={dependency_hash}, debug={}, trim_paths={}, compilation={commitment})",
                build_settings.emit_debug_info, build_settings.trim_paths
            ),
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: Some(commitment),
            } => format!(
                "git({repo}@{resolved_revision}, deps={dependency_hash}, debug={}, trim_paths={}, compilation={commitment})",
                build_settings.emit_debug_info, build_settings.trim_paths
            ),
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                format!("path({source_hash})")
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if build_settings.is_legacy() => {
                format!("path({source_hash}, deps={dependency_hash})")
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } => {
                format!(
                    "path({source_hash}, deps={dependency_hash}, debug={}, trim_paths={})",
                    build_settings.emit_debug_info, build_settings.trim_paths
                )
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                format!("git({repo}@{resolved_revision})")
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if build_settings.is_legacy() => {
                format!("git({repo}@{resolved_revision}, deps={dependency_hash})")
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } => {
                format!(
                    "git({repo}@{resolved_revision}, deps={dependency_hash}, debug={}, trim_paths={})",
                    build_settings.emit_debug_info, build_settings.trim_paths
                )
            },
        }
    }
}

impl Serializable for PackageBuildProvenance {
    fn write_into<W: miden_core::serde::ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: Some(commitment),
            } => {
                target.write_u8(6);
                source_hash.write_into(target);
                dependency_hash.write_into(target);
                target.write_bool(build_settings.emit_debug_info);
                target.write_bool(build_settings.trim_paths);
                commitment.write_into(target);
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: Some(commitment),
            } => {
                target.write_u8(7);
                repo.write_into(target);
                resolved_revision.write_into(target);
                dependency_hash.write_into(target);
                target.write_bool(build_settings.emit_debug_info);
                target.write_bool(build_settings.trim_paths);
                commitment.write_into(target);
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                target.write_u8(0);
                source_hash.write_into(target);
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if *dependency_hash == Self::empty_dependency_hash()
                && build_settings.is_legacy() =>
            {
                target.write_u8(1);
                repo.write_into(target);
                resolved_revision.write_into(target);
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if build_settings.is_legacy() => {
                target.write_u8(2);
                source_hash.write_into(target);
                dependency_hash.write_into(target);
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } if build_settings.is_legacy() => {
                target.write_u8(3);
                repo.write_into(target);
                resolved_revision.write_into(target);
                dependency_hash.write_into(target);
            },
            Self::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } => {
                target.write_u8(4);
                source_hash.write_into(target);
                dependency_hash.write_into(target);
                target.write_bool(build_settings.emit_debug_info);
                target.write_bool(build_settings.trim_paths);
            },
            Self::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            } => {
                target.write_u8(5);
                repo.write_into(target);
                resolved_revision.write_into(target);
                dependency_hash.write_into(target);
                target.write_bool(build_settings.emit_debug_info);
                target.write_bool(build_settings.trim_paths);
            },
        }
    }
}

impl Deserializable for PackageBuildProvenance {
    fn read_from<R: ByteReader>(
        source: &mut R,
    ) -> Result<Self, miden_core::serde::DeserializationError> {
        match source.read_u8()? {
            0 => Ok(Self::Path {
                source_hash: Word::read_from(source)?,
                dependency_hash: Self::empty_dependency_hash(),
                build_settings: PackageBuildSettings::legacy(),
                compilation_commitment: None,
            }),
            1 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
                dependency_hash: Self::empty_dependency_hash(),
                build_settings: PackageBuildSettings::legacy(),
                compilation_commitment: None,
            }),
            2 => Ok(Self::Path {
                source_hash: Word::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings::legacy(),
                compilation_commitment: None,
            }),
            3 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings::legacy(),
                compilation_commitment: None,
            }),
            4 => Ok(Self::Path {
                source_hash: Word::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings {
                    emit_debug_info: source.read_bool()?,
                    trim_paths: source.read_bool()?,
                },
                compilation_commitment: None,
            }),
            5 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings {
                    emit_debug_info: source.read_bool()?,
                    trim_paths: source.read_bool()?,
                },
                compilation_commitment: None,
            }),
            6 => Ok(Self::Path {
                source_hash: Word::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings {
                    emit_debug_info: source.read_bool()?,
                    trim_paths: source.read_bool()?,
                },
                compilation_commitment: Some(Word::read_from(source)?),
            }),
            7 => Ok(Self::Git {
                repo: String::read_from(source)?,
                resolved_revision: String::read_from(source)?,
                dependency_hash: Word::read_from(source)?,
                build_settings: PackageBuildSettings {
                    emit_debug_info: source.read_bool()?,
                    trim_paths: source.read_bool()?,
                },
                compilation_commitment: Some(Word::read_from(source)?),
            }),
            invalid => Err(miden_core::serde::DeserializationError::InvalidValue(format!(
                "invalid project source provenance tag '{invalid}'"
            ))),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for PackageBuildSettings {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<bool>(), any::<bool>())
            .prop_map(|(emit_debug_info, trim_paths)| Self { emit_debug_info, trim_paths })
            .boxed()
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for PackageBuildProvenance {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let word =
            proptest::collection::vec(proptest::char::range('a', 'z'), 1..16).prop_map(|chars| {
                let material = chars.into_iter().collect::<String>();
                hash_string_to_word(material.as_str())
            });
        let text = proptest::collection::vec(
            proptest::prop_oneof![
                proptest::char::range('a', 'z'),
                proptest::char::range('0', '9'),
                Just('/'),
                Just('-'),
                Just('_'),
                Just('.'),
                Just(':'),
            ],
            1..40,
        )
        .prop_map(|chars| chars.into_iter().collect::<String>());
        let commitment = proptest::option::of(word.clone());

        proptest::prop_oneof![
            (word.clone(), word.clone(), any::<PackageBuildSettings>(), commitment.clone())
                .prop_map(
                    |(source_hash, dependency_hash, build_settings, compilation_commitment)| {
                        Self::Path {
                            source_hash,
                            dependency_hash,
                            build_settings,
                            compilation_commitment,
                        }
                    }
                ),
            (text.clone(), text, word, any::<PackageBuildSettings>(), commitment).prop_map(
                |(
                    repo,
                    resolved_revision,
                    dependency_hash,
                    build_settings,
                    compilation_commitment,
                )| Self::Git {
                    repo,
                    resolved_revision,
                    dependency_hash,
                    build_settings,
                    compilation_commitment,
                }
            ),
        ]
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_core::serde::ByteWriter;
    use miden_mast_package::TargetType;

    use super::*;

    /// Construct the historical wire records independently of the current provenance writer.
    fn legacy_record(tag: u8) -> (Vec<u8>, PackageBuildProvenance) {
        let source_hash = hash_string_to_word("target sources");
        let dependency_hash = if tag < 2 {
            PackageBuildProvenance::empty_dependency_hash()
        } else {
            hash_string_to_word("resolved dependency artifacts")
        };
        let build_settings = if tag < 4 {
            PackageBuildSettings::legacy()
        } else {
            PackageBuildSettings { emit_debug_info: false, trim_paths: true }
        };
        let repo = String::from("https://example.com/library.git");
        let resolved_revision = String::from("0123456789abcdef");
        let mut bytes = Vec::new();
        bytes.write_u8(tag);
        if tag & 1 == 0 {
            source_hash.write_into(&mut bytes);
        } else {
            repo.write_into(&mut bytes);
            resolved_revision.write_into(&mut bytes);
        }
        if tag >= 2 {
            dependency_hash.write_into(&mut bytes);
        }
        if tag >= 4 {
            bytes.write_bool(build_settings.emit_debug_info);
            bytes.write_bool(build_settings.trim_paths);
        }

        let expected = if tag & 1 == 0 {
            PackageBuildProvenance::Path {
                source_hash,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            }
        } else {
            PackageBuildProvenance::Git {
                repo,
                resolved_revision,
                dependency_hash,
                build_settings,
                compilation_commitment: None,
            }
        };
        (bytes, expected)
    }

    #[test]
    fn legacy_wire_variants_remain_readable_without_compilation_commitments() {
        for tag in 0..=5 {
            let (bytes, expected) = legacy_record(tag);
            let mut reader = SliceReader::new(&bytes);
            let actual = PackageBuildProvenance::read_from(&mut reader)
                .expect("historical provenance should remain readable");
            assert!(!reader.has_more_bytes(), "legacy tag {tag}");
            assert_eq!(actual, expected, "legacy tag {tag}");
            assert_eq!(actual.compilation_commitment(), None, "legacy tag {tag}");
            assert_eq!(actual.to_bytes(), bytes, "legacy tag {tag}");
        }
    }

    #[test]
    fn compilation_wire_variants_round_trip_and_distinguish_compiler_inputs() {
        let commitment = hash_string_to_word("resolved home and callable bindings");
        let other_commitment = hash_string_to_word("different resolved home and callable bindings");
        for legacy_tag in 0..=5 {
            let (_, legacy) = legacy_record(legacy_tag);
            let current = legacy.clone().with_compilation_commitment(commitment);
            let bytes = current.to_bytes();
            assert_eq!(bytes[0], 6 + legacy_tag % 2);
            let mut reader = SliceReader::new(&bytes);
            let decoded = PackageBuildProvenance::read_from(&mut reader)
                .expect("exact compilation provenance should round trip");
            assert!(!reader.has_more_bytes());
            assert_eq!(decoded, current);
            assert_eq!(decoded.compilation_commitment(), Some(commitment));
            assert_ne!(decoded, legacy);
            assert_ne!(decoded.describe(), legacy.describe());

            let changed = decoded.clone().with_compilation_commitment(other_commitment);
            assert_ne!(decoded, changed);
            assert_ne!(decoded.describe(), changed.describe());
            assert_ne!(decoded.to_bytes(), changed.to_bytes());
            assert!(PackageBuildProvenance::read_from_bytes(&bytes[..bytes.len() - 1]).is_err());
        }
    }

    #[test]
    fn package_provenance_requires_complete_section_consumption() {
        let mut package = MastPackage::generate(
            "provenance-fixture".into(),
            "1.0.0".parse().unwrap(),
            TargetType::Library,
            [],
        );
        let commitment = hash_string_to_word("resolved compiler inputs");
        for legacy_tag in 0..=5 {
            let (legacy_bytes, legacy) = legacy_record(legacy_tag);
            let current = legacy.clone().with_compilation_commitment(commitment);
            for (mut bytes, expected) in [(legacy_bytes, legacy), (current.to_bytes(), current)] {
                package.sections =
                    alloc::vec![Section::new(SectionId::PROJECT_SOURCE_PROVENANCE, bytes.clone(),)];
                assert_eq!(PackageBuildProvenance::from_package(&package).unwrap(), Some(expected));
                bytes.push(0);
                package.sections =
                    alloc::vec![Section::new(SectionId::PROJECT_SOURCE_PROVENANCE, bytes,)];
                let error = PackageBuildProvenance::from_package(&package)
                    .expect_err("trailing bytes must not be ignored");
                assert!(error.to_string().contains("trailing provenance bytes"));
            }
        }
    }
}
