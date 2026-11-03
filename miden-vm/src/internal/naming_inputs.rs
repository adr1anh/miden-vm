//! Explicit, bounded naming choices for CLI source and artifact inputs.
//!
//! JSON v1 selects `builtin-exact-v1`, four `codec_limits`, independently authorized
//! `allowed_homes`, a `target`, a required nullable `kernel`, and ordered `libraries`.
//! Homes are arrays of `0x`-prefixed canonical label-envelope hex strings. Source choices are
//! `{ "kind": "source", "compilation_home": [...], "bindings": [
//! { "declaration": "::source::procedure", "home": [...], "path": ["canonical", "name"] }
//! ] }`. Artifact choices are `{ "kind": "artifact", "expected_naming": "inventory.bin" }`.
//! Libraries must be artifact choices, one per command-line `-l` input in the same order.
//!
//! Sidecar paths resolve relative to the JSON file's parent directory. They contain exactly the
//! existing binary NamingV1 payload, without a package wrapper. Their complete inventory is an
//! independent caller expectation: package metadata, filenames, source aliases, implementation
//! digests and export spelling never select homes or canonical bindings. This local exact-home
//! profile recognizes only built-in Text, LibraryId and Revision labels; it makes no external
//! Protocol, publisher, release or environment-admission claim.
//!
//! The explicit JSON byte cap bounds configuration input; parsing and owned source-policy
//! construction have their own overhead. CodecLimits apply to each complete existing binary
//! naming/home operation, not aggregate configuration allocations, allocator metadata or RSS.

use std::{fmt, path::Path, sync::Arc};

use miden_assembly::{
    NamespaceInputs, PathBuf as SourcePathBuf, Report,
    diagnostics::{IntoDiagnostic, WrapErr},
};
use miden_core::{program::CanonicalLabel, serde::read_file_bounded};
use miden_mast_package::{
    CallableBinding, CallableProcedurePath, NamespacePlan, Package, PackageCallables,
    PackageNaming,
    interface::serialization::{CodecLimits, HomeProfile, TypedIdProfile},
};
use serde::Deserialize;

/// Selects a command-line input without deriving identity from its filesystem location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamingRole {
    Target,
    Kernel,
    Library(usize),
}

impl fmt::Display for NamingRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Target => f.write_str("target"),
            Self::Kernel => f.write_str("kernel"),
            Self::Library(index) => write!(f, "library {index}"),
        }
    }
}

/// A package with its independently expected and profile-admitted complete naming retained.
#[derive(Clone, Debug)]
pub struct LoadedPackage {
    pub package: Arc<Package>,
    pub naming: Arc<PackageNaming>,
}

/// Current caller naming policy, exact source bindings and independent artifact expectations.
#[derive(Debug)]
pub struct NamingInputs {
    profile: ExactBuiltinProfile,
    context: ExactHomes,
    limits: CodecLimits,
    target: SelectedChoice,
    kernel: Option<SelectedChoice>,
    libraries: Vec<SelectedChoice>,
}

#[derive(Debug)]
enum SelectedChoice {
    Source(NamespaceInputs),
    Artifact(Arc<PackageNaming>),
}

#[derive(Debug)]
struct ExactBuiltinProfile;

#[derive(Debug)]
struct ExactHomes {
    homes: Vec<Vec<CanonicalLabel>>,
}

impl TypedIdProfile for ExactBuiltinProfile {
    type Context = ExactHomes;
    type Error = &'static str;

    fn validate_typed_id(
        &self,
        _context: &Self::Context,
        _codec: u32,
        _canonical_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        Err("builtin-exact-v1 does not recognize any TypedId codec")
    }
}

impl HomeProfile for ExactBuiltinProfile {
    fn validate_home(
        &self,
        context: &Self::Context,
        home: &[CanonicalLabel],
    ) -> Result<(), Self::Error> {
        if context.homes.iter().any(|allowed| allowed == home) {
            Ok(())
        } else {
            Err("complete home is absent from independently authorized allowed_homes")
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    profile: String,
    codec_limits: Limits,
    allowed_homes: Vec<Vec<String>>,
    target: Choice,
    // deserialize_with makes this field required even though its value may be null.
    #[serde(deserialize_with = "required_kernel")]
    kernel: Option<Choice>,
    libraries: Vec<Choice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Limits {
    max_bytes: u32,
    max_records: u32,
    max_components: u32,
    max_blob_bytes: u32,
}

impl From<Limits> for CodecLimits {
    fn from(limits: Limits) -> Self {
        Self::new(
            limits.max_bytes,
            limits.max_records,
            limits.max_components,
            limits.max_blob_bytes,
        )
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Choice {
    Source {
        compilation_home: Vec<String>,
        bindings: Vec<SourceBinding>,
    },
    Artifact {
        expected_naming: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceBinding {
    declaration: String,
    home: Vec<String>,
    path: Vec<String>,
}

fn required_kernel<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Choice>, D::Error> {
    Option::deserialize(deserializer)
}

impl NamingInputs {
    /// Reads a bounded regular JSON file and prepares every role before any code is compiled.
    ///
    /// No configuration or codec defaults are supplied. Expected artifact inventories are read
    /// here under `codec_limits.max_bytes` and decoded using this document's independently
    /// selected profile/context. Symlinks to regular files are accepted by the bounded reader.
    pub fn read(path: &Path, max_bytes: usize) -> Result<Self, Report> {
        let bytes = read_file_bounded(path, max_bytes)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read naming inputs '{}'", path.display()))?;
        let document: Document = serde_json::from_slice(&bytes)
            .into_diagnostic()
            .wrap_err_with(|| format!("invalid naming inputs '{}'", path.display()))?;
        if document.version != 1 {
            return Err(Report::msg("unsupported naming-inputs JSON version; expected 1"));
        }
        if document.profile != "builtin-exact-v1" {
            return Err(Report::msg("unsupported naming profile; expected builtin-exact-v1"));
        }
        let limits = document.codec_limits.into();
        let profile = ExactBuiltinProfile;
        let mut homes = Vec::new();
        for encoded in document.allowed_homes {
            let home = builtin_home(encoded)?;
            if homes.contains(&home) {
                return Err(Report::msg("duplicate complete home in allowed_homes"));
            }
            homes.push(home);
        }
        let context = ExactHomes { homes };
        // Even unused permissions must contain valid built-in labels and fit the selected
        // individual home budget. The authorization list itself is bounded by the JSON limit.
        for home in &context.homes {
            NamespacePlan::new(home.clone())
                .encode_home_v1(&profile, &context, limits)
                .map_err(|error| Report::msg(format!("invalid allowed home: {error}")))?;
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let target = prepare_choice(document.target, parent, &profile, &context, limits)
            .wrap_err("invalid target naming choice")?;
        let kernel = document
            .kernel
            .map(|choice| prepare_choice(choice, parent, &profile, &context, limits))
            .transpose()
            .wrap_err("invalid kernel naming choice")?;
        let mut libraries = Vec::new();
        for (index, choice) in document.libraries.into_iter().enumerate() {
            if !matches!(choice, Choice::Artifact { .. }) {
                return Err(Report::msg(format!(
                    "library {index} requires an artifact naming expectation"
                )));
            }
            libraries.push(
                prepare_choice(choice, parent, &profile, &context, limits)
                    .wrap_err_with(|| format!("invalid library {index} naming choice"))?,
            );
        }
        Ok(Self {
            profile,
            context,
            limits,
            target,
            kernel,
            libraries,
        })
    }

    /// Returns complete source metadata selected before code generation.
    pub fn source(&self, role: NamingRole) -> Result<NamespaceInputs, Report> {
        match self.choice(role)? {
            SelectedChoice::Source(inputs) => Ok(inputs.clone()),
            SelectedChoice::Artifact(_) => Err(Report::msg(format!(
                "{role} naming choice is artifact, but this input requires source bindings"
            ))),
        }
    }

    /// Admits a package under current policy and compares its complete independent expectation.
    pub fn admit(&self, role: NamingRole, package: Arc<Package>) -> Result<LoadedPackage, Report> {
        let expected = match self.choice(role)? {
            SelectedChoice::Artifact(expected) => expected,
            SelectedChoice::Source(_) => {
                return Err(Report::msg(format!(
                    "{role} naming choice is source, but this input requires an artifact expectation"
                )));
            },
        };
        let naming = package
            .admit_naming(&self.profile, &self.context, self.limits)
            .map_err(|error| Report::msg(format!("{role} naming admission failed: {error}")))?;
        if naming != **expected {
            return Err(Report::msg(format!(
                "{role} complete naming differs from its independently supplied expectation"
            )));
        }
        Ok(LoadedPackage { package, naming: Arc::new(naming) })
    }

    /// Requires one ordered artifact expectation for every explicit `-l` input.
    pub fn check_library_count(&self, count: usize) -> Result<(), Report> {
        if self.libraries.len() != count {
            return Err(Report::msg(format!(
                "naming inputs specify {} library expectations for {count} library inputs",
                self.libraries.len()
            )));
        }
        Ok(())
    }

    pub fn has_kernel(&self) -> bool {
        self.kernel.is_some()
    }

    /// Exports owned compiler naming using the existing codec and the selected current policy.
    pub fn encode_owned(&self, naming: &PackageNaming) -> Result<Vec<u8>, Report> {
        naming
            .encode_v1(&self.profile, &self.context, self.limits)
            .map_err(|error| Report::msg(format!("cannot encode owned naming: {error}")))
    }

    fn choice(&self, role: NamingRole) -> Result<&SelectedChoice, Report> {
        match role {
            NamingRole::Target => Ok(&self.target),
            NamingRole::Kernel => self
                .kernel
                .as_ref()
                .ok_or_else(|| Report::msg("naming inputs have no kernel choice")),
            NamingRole::Library(index) => self
                .libraries
                .get(index)
                .ok_or_else(|| Report::msg(format!("missing library {index} naming expectation"))),
        }
    }
}

fn builtin_home(encoded: Vec<String>) -> Result<Vec<CanonicalLabel>, Report> {
    encoded
        .into_iter()
        .map(|label| {
            let hex = label.strip_prefix("0x").ok_or_else(|| {
                Report::msg("home labels require 0x-prefixed canonical envelope hex")
            })?;
            let bytes = hex::decode(hex)
                .into_diagnostic()
                .wrap_err("invalid canonical label-envelope hex")?;
            CanonicalLabel::from_bytes(&bytes)
                .into_diagnostic()
                .wrap_err("invalid built-in canonical label envelope")
        })
        .collect()
}

fn prepare_choice(
    choice: Choice,
    parent: &Path,
    profile: &ExactBuiltinProfile,
    context: &ExactHomes,
    limits: CodecLimits,
) -> Result<SelectedChoice, Report> {
    match choice {
        Choice::Source { compilation_home, bindings } => {
            let compilation_home = NamespacePlan::new(builtin_home(compilation_home)?);
            let mut inputs = NamespaceInputs::new().with_namespace_plan(compilation_home.clone());
            let mut inventory = Vec::new();
            for binding in bindings {
                // Parse the defining MASM path as source syntax. Its components do not supply
                // any canonical home/path: the separately supplied complete binding does.
                let declaration = SourcePathBuf::new(&binding.declaration)
                    .into_diagnostic()
                    .wrap_err("invalid defining source declaration path")?;
                let path = CallableProcedurePath::from_semantic_components(binding.path)
                    .into_diagnostic()
                    .wrap_err("invalid canonical callable path components")?;
                let binding =
                    CallableBinding::new(NamespacePlan::new(builtin_home(binding.home)?), path)
                        .into_diagnostic()?;
                inputs = inputs.with_callable_binding(declaration.into(), binding.clone())?;
                inventory.push(binding);
            }
            // Use the existing complete naming codec's aggregate preflight/policy checks even
            // for declaration-only source choices. Codegen will retain aliases, private roots
            // and entry selections; encode_owned checks that resulting inventory afresh.
            let callables = PackageCallables::new(inventory, [], []).into_diagnostic()?;
            let naming = PackageNaming::new(compilation_home, callables, None).into_diagnostic()?;
            naming
                .encode_v1(profile, context, limits)
                .map_err(|error| Report::msg(format!("source naming rejected: {error}")))?;
            Ok(SelectedChoice::Source(inputs))
        },
        Choice::Artifact { expected_naming } => {
            if expected_naming.is_empty() {
                return Err(Report::msg("expected_naming must name a binary NamingV1 sidecar"));
            }
            let path = parent.join(expected_naming);
            let bytes = read_file_bounded(&path, limits.max_bytes() as usize)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read expected naming '{}'", path.display()))?;
            let expected = PackageNaming::decode_v1(&bytes, profile, context, limits)
                .map_err(|error| Report::msg(format!("expected NamingV1 rejected: {error}")))?;
            Ok(SelectedChoice::Artifact(Arc::new(expected)))
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, num::NonZeroU32};

    use miden_core::{
        Word,
        mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
        operations::Operation,
        program::ImplementationRoot,
    };
    use miden_mast_package::{PackageExport, PackageId, ProcedureExport, TargetType, Version};
    use serde_json::{Value, json};

    use super::*;

    const JSON_LIMIT: usize = 65536;

    fn limits() -> CodecLimits {
        CodecLimits::new(65536, 4096, 4096, 65536)
    }

    fn home(name: &str) -> NamespacePlan {
        NamespacePlan::new(vec![CanonicalLabel::text(name).unwrap()])
    }

    fn canonical(components: &[&str]) -> CallableProcedurePath {
        CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| (*component).to_owned()).collect(),
        )
        .unwrap()
    }

    fn encoded_home(home: &NamespacePlan) -> Value {
        json!(
            home.home()
                .iter()
                .map(|label| format!("0x{}", hex::encode(label.as_bytes())))
                .collect::<Vec<_>>()
        )
    }

    fn document(homes: &[NamespacePlan], target: Value) -> Value {
        json!({
            "version": 1,
            "profile": "builtin-exact-v1",
            "codec_limits": {
                "max_bytes": 65536,
                "max_records": 4096,
                "max_components": 4096,
                "max_blob_bytes": 65536
            },
            "allowed_homes": homes.iter().map(encoded_home).collect::<Vec<_>>(),
            "target": target,
            "kernel": null,
            "libraries": []
        })
    }

    fn source_choice(compilation: &NamespacePlan, bindings: Value) -> Value {
        json!({
            "kind": "source",
            "compilation_home": encoded_home(compilation),
            "bindings": bindings
        })
    }

    fn source_binding(declaration: &str, home: &NamespacePlan, path: &[&str]) -> Value {
        json!({"declaration": declaration, "home": encoded_home(home), "path": path})
    }

    fn artifact_choice(filename: &str) -> Value {
        json!({"kind": "artifact", "expected_naming": filename})
    }

    fn write_document(directory: &Path, document: &Value) -> std::path::PathBuf {
        let path = directory.join("naming.json");
        fs::write(&path, serde_json::to_vec(document).unwrap()).unwrap();
        path
    }

    fn write_expectation(
        directory: &Path,
        name: &str,
        naming: &PackageNaming,
        homes: &[NamespacePlan],
    ) {
        let context = ExactHomes {
            homes: homes.iter().map(|home| home.home().to_vec()).collect(),
        };
        let bytes = naming.encode_v1(&ExactBuiltinProfile, &context, limits()).unwrap();
        fs::write(directory.join(name), bytes).unwrap();
    }

    // An owned, locally constructed artifact with a private entry and a foreign callable
    // reexported under a source alias. Its metadata and code do not select any of these homes.
    fn fixture(private_name: &str) -> (Arc<Package>, PackageNaming, Vec<NamespacePlan>) {
        let compilation = home("compilation");
        let private = home(private_name);
        let foreign = NamespacePlan::new(vec![
            CanonicalLabel::text("pinned").unwrap(),
            CanonicalLabel::library_id(Word::from([7u32; 4])),
            CanonicalLabel::revision(NonZeroU32::MIN),
        ]);
        let entry =
            CallableBinding::new(private.clone(), canonical(&["helpers", "entry"])).unwrap();
        let imported = CallableBinding::new(foreign.clone(), canonical(&["api", "run"])).unwrap();
        let mut forest = MastForest::new();
        let entry_node = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(entry_node);
        let public_node = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(public_node);
        let public_digest = forest[public_node].digest();
        let callables = PackageCallables::new(
            [entry.clone(), imported.clone()],
            [(canonical(&["alias", "visible"]), imported.key())],
            [
                (entry.key(), ImplementationRoot::new(forest[entry_node].digest())),
                (imported.key(), ImplementationRoot::new(public_digest)),
            ],
        )
        .unwrap();
        let naming = PackageNaming::new(compilation.clone(), callables, Some(entry.key())).unwrap();
        let public_path: miden_assembly::PathBuf = "::alias::visible".parse().unwrap();
        let package = Package::create(
            PackageId::from("unrelated-metadata"),
            Version::new(1, 0, 0),
            TargetType::Executable,
            Arc::new(forest),
            [PackageExport::Procedure(ProcedureExport::new(
                public_path.into(),
                Some(public_node),
                public_digest,
                None,
            ))],
            [],
            &naming,
        )
        .unwrap();
        (Arc::new(package), naming, vec![compilation, private, foreign])
    }

    #[test]
    fn independent_artifact_expectation_preserves_mixed_homes_alias_private_entry_and_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let (package, naming, homes) = fixture("private");
        write_expectation(directory.path(), "chosen.bin", &naming, &homes);
        let config = document(&homes, artifact_choice("chosen.bin"));
        let path = write_document(directory.path(), &config);
        let inputs = NamingInputs::read(&path, JSON_LIMIT).unwrap();
        let loaded = inputs.admit(NamingRole::Target, package.clone()).unwrap();
        assert_eq!(*loaded.naming, naming);
        assert_eq!(loaded.naming.entry_key(), naming.entry_key());
        assert_eq!(loaded.naming.callables().bindings().len(), 2);
        assert_eq!(loaded.naming.callables().visible_paths().len(), 1);
        assert_eq!(
            inputs.encode_owned(&loaded.naming).unwrap(),
            fs::read(directory.path().join("chosen.bin")).unwrap(),
        );
        assert!(inputs.source(NamingRole::Target).is_err());
        let mut renamed = (*package).clone();
        renamed.name = PackageId::from("different-metadata");
        assert!(inputs.admit(NamingRole::Target, Arc::new(renamed)).is_ok());
    }

    #[test]
    fn complete_expected_inventory_is_independent_of_actual_package_and_export_digest() {
        let directory = tempfile::tempdir().unwrap();
        let (actual, _, mut homes) = fixture("actual-private");
        let (other, expected, expected_homes) = fixture("expected-private");
        assert_eq!(actual.code_commitment(), other.code_commitment());
        assert_eq!(actual.interface_commitment().unwrap(), other.interface_commitment().unwrap());
        homes.push(expected_homes[1].clone());
        write_expectation(directory.path(), "expected.bin", &expected, &homes);
        let path =
            write_document(directory.path(), &document(&homes, artifact_choice("expected.bin")));
        let inputs = NamingInputs::read(&path, JSON_LIMIT).unwrap();
        let error = inputs.admit(NamingRole::Target, actual).unwrap_err();
        assert!(error.to_string().contains("independently supplied expectation"));
    }

    #[test]
    fn all_artifact_binding_homes_require_independent_permission_before_admission() {
        let directory = tempfile::tempdir().unwrap();
        let (_, naming, homes) = fixture("private");
        write_expectation(directory.path(), "expected.bin", &naming, &homes);
        for excluded in 0..homes.len() {
            let allowed = homes
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != excluded)
                .map(|(_, home)| home.clone())
                .collect::<Vec<_>>();
            let path = write_document(
                directory.path(),
                &document(&allowed, artifact_choice("expected.bin")),
            );
            assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
        }
    }

    #[test]
    fn source_metadata_supplies_complete_independent_bindings_before_codegen() {
        let directory = tempfile::tempdir().unwrap();
        let compilation = home("compilation");
        let private = home("private");
        let foreign = home("foreign");
        let target = source_choice(
            &compilation,
            json!([
                source_binding("::client::hidden", &private, &["helpers", "local"]),
                source_binding("::client::public", &foreign, &["api", "canonical"])
            ]),
        );
        let path = write_document(
            directory.path(),
            &document(&[compilation.clone(), private.clone(), foreign.clone()], target.clone()),
        );
        let inputs = NamingInputs::read(&path, JSON_LIMIT).unwrap();
        let expected = NamespaceInputs::new()
            .with_namespace_plan(compilation.clone())
            .with_callable_binding(
                SourcePathBuf::new("::client::hidden").unwrap().into(),
                CallableBinding::new(private, canonical(&["helpers", "local"])).unwrap(),
            )
            .unwrap()
            .with_callable_binding(
                SourcePathBuf::new("::client::public").unwrap().into(),
                CallableBinding::new(foreign.clone(), canonical(&["api", "canonical"])).unwrap(),
            )
            .unwrap();
        assert_eq!(inputs.source(NamingRole::Target).unwrap(), expected);
        let (package, ..) = fixture("private");
        assert!(inputs.admit(NamingRole::Target, package).is_err());

        let path = write_document(directory.path(), &document(&[compilation, foreign], target));
        assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
    }

    #[test]
    fn rejects_typed_ids_in_permission_inputs_and_existing_naming_transport() {
        let directory = tempfile::tempdir().unwrap();
        for codec in [0, 1, 77, u32::MAX] {
            let typed = CanonicalLabel::typed_id(codec, &[0xa5], |_, _| Ok(())).unwrap();
            let typed_home = NamespacePlan::new(vec![typed]);
            let path = write_document(
                directory.path(),
                &document(std::slice::from_ref(&typed_home), source_choice(&typed_home, json!([]))),
            );
            assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
            let (base, base_naming, homes) = fixture("private");
            let mut allowed = homes.iter().map(|home| home.home().to_vec()).collect::<Vec<_>>();
            allowed.push(typed_home.home().to_vec());
            let context = ExactHomes { homes: allowed };
            assert!(ExactBuiltinProfile.validate_typed_id(&context, codec, &[0xa5]).is_err());
            // Even an owned label constructed elsewhere cannot bypass the selected profile.
            let naming = PackageNaming::new(
                typed_home,
                base_naming.callables().clone(),
                base_naming.entry_key(),
            )
            .unwrap();
            assert!(naming.encode_v1(&ExactBuiltinProfile, &context, limits()).is_err());
            let package = Package::create(
                base.name.clone(),
                Version::new(1, 0, 0),
                base.kind,
                base.mast_forest().clone(),
                base.manifest.exports().cloned(),
                [],
                &naming,
            )
            .unwrap();
            assert!(package.admit_naming(&ExactBuiltinProfile, &context, limits()).is_err());
            assert!(
                PackageNaming::decode_v1(
                    package.naming_transport().as_bytes(),
                    &ExactBuiltinProfile,
                    &context,
                    limits(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_unknown_missing_duplicate_fields_and_nonfinite_or_malformed_limits() {
        let directory = tempfile::tempdir().unwrap();
        let compilation = home("compilation");
        let valid =
            document(std::slice::from_ref(&compilation), source_choice(&compilation, json!([])));
        let mut cases = Vec::new();
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("kernel");
        cases.push(serde_json::to_string(&missing).unwrap());
        let mut unknown = valid.clone();
        unknown["unknown"] = json!(true);
        cases.push(serde_json::to_string(&unknown).unwrap());
        let raw = serde_json::to_string(&valid).unwrap();
        cases.push(raw.replacen('"', "\"version\":1,\"", 1));
        for value in [json!(-1), json!(4294967296u64), json!(1.5), json!("unlimited"), Value::Null]
        {
            let mut malformed = valid.clone();
            malformed["codec_limits"]["max_records"] = value;
            cases.push(serde_json::to_string(&malformed).unwrap());
        }
        let mut missing_limit = valid.clone();
        missing_limit["codec_limits"].as_object_mut().unwrap().remove("max_components");
        cases.push(serde_json::to_string(&missing_limit).unwrap());
        for key in ["target", "codec_limits"] {
            let mut unknown_nested = valid.clone();
            unknown_nested[key]["unknown"] = json!(0);
            cases.push(serde_json::to_string(&unknown_nested).unwrap());
        }
        for raw in cases {
            let path = directory.path().join("naming.json");
            fs::write(&path, raw).unwrap();
            assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
        }
    }

    #[test]
    fn rejects_invalid_label_envelopes_source_paths_bindings_and_budget_overruns() {
        let directory = tempfile::tempdir().unwrap();
        let compilation = home("compilation");
        let binding = source_binding("::client::run", &compilation, &["canonical", "run"]);
        let valid = document(
            std::slice::from_ref(&compilation),
            source_choice(&compilation, json!([binding])),
        );
        let mut cases = Vec::new();
        for envelope in ["", "0x0", "0xzz", "0x020000000000", "0x01020400000000000000"] {
            let mut invalid = valid.clone();
            invalid["allowed_homes"] = json!([[envelope]]);
            cases.push(invalid);
        }
        let mut bad_source = valid.clone();
        bad_source["target"]["bindings"][0]["declaration"] = json!("::bad::::path");
        cases.push(bad_source);
        let mut empty_path = valid.clone();
        empty_path["target"]["bindings"][0]["path"] = json!([]);
        cases.push(empty_path);
        let mut duplicate = valid.clone();
        duplicate["target"]["bindings"] = json!([binding, binding]);
        cases.push(duplicate);
        let mut duplicate_key = valid.clone();
        let mut second = binding;
        second["declaration"] = json!("::client::other");
        duplicate_key["target"]["bindings"].as_array_mut().unwrap().push(second);
        cases.push(duplicate_key);
        for name in ["max_bytes", "max_records", "max_components", "max_blob_bytes"] {
            let mut too_small = valid.clone();
            too_small["codec_limits"][name] = json!(0);
            cases.push(too_small);
        }
        for invalid in cases {
            let path = write_document(directory.path(), &invalid);
            assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
        }
    }

    #[test]
    fn kernel_and_ordered_library_roles_each_require_explicit_artifact_expectations() {
        let directory = tempfile::tempdir().unwrap();
        let (package, naming, homes) = fixture("private");
        write_expectation(directory.path(), "chosen.bin", &naming, &homes);
        let mut config = document(&homes, artifact_choice("chosen.bin"));
        config["kernel"] = artifact_choice("chosen.bin");
        config["libraries"] = json!([artifact_choice("chosen.bin")]);
        let path = write_document(directory.path(), &config);
        let inputs = NamingInputs::read(&path, JSON_LIMIT).unwrap();
        assert!(inputs.has_kernel());
        assert!(inputs.check_library_count(1).is_ok());
        assert!(inputs.check_library_count(0).is_err());
        assert!(inputs.admit(NamingRole::Kernel, package.clone()).is_ok());
        assert!(inputs.admit(NamingRole::Library(0), package.clone()).is_ok());
        assert!(inputs.admit(NamingRole::Library(1), package).is_err());
        config["libraries"] = json!([source_choice(&homes[0], json!([]))]);
        let path = write_document(directory.path(), &config);
        assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
    }

    #[test]
    fn json_and_binary_expectations_are_regular_bounded_files_with_exact_framing() {
        let directory = tempfile::tempdir().unwrap();
        let (_, naming, homes) = fixture("private");
        write_expectation(directory.path(), "chosen.bin", &naming, &homes);
        let config = document(&homes, artifact_choice("chosen.bin"));
        let path = write_document(directory.path(), &config);
        let size = fs::metadata(&path).unwrap().len() as usize;
        assert!(NamingInputs::read(&path, size).is_ok());
        assert!(NamingInputs::read(&path, size - 1).is_err());
        assert!(NamingInputs::read(directory.path(), JSON_LIMIT).is_err());
        let mut bytes = fs::read(directory.path().join("chosen.bin")).unwrap();
        bytes.push(0);
        fs::write(directory.path().join("chosen.bin"), bytes).unwrap();
        assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
        fs::write(directory.path().join("chosen.bin"), vec![0u8; 65537]).unwrap();
        assert!(NamingInputs::read(&path, JSON_LIMIT).is_err());
    }
}
