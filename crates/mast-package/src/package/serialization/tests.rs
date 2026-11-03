#[cfg(feature = "std")]
use alloc::format;
use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{assert_matches, cell::Cell};
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::fs;

use miden_assembly_syntax::ast::{Ident, Path as AstPath, PathBuf, ProcedureName};
use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    mast::{
        BasicBlockNodeBuilder, DenseMastForestBuilder, ExecNodeBuilder, ExternalNodeBuilder,
        MastForest, MastNode, MastNodeEntry, MastNodeExt, MastNodeId,
    },
    operations::Operation,
    program::{CanonicalLabel, ProcedureKey},
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
    utils::IndexVec,
};

use super::{
    MAGIC_PACKAGE, PACKAGE_BYTE_READ_BUDGET_MULTIPLIER, Package, PackageManifest, Section, VERSION,
};
use crate::{
    Dependency, ManifestValidationError, NamespacePlan, PackageExport, PackageId, PackageModule,
    PackageSubmodule, ProcedureExport, SectionId, TargetType, UnverifiedPackageNaming,
    debug_info::{DebugSourceAsmOp, DebugSourceNode, DebugSourceNodeId, PackageDebugInfoBuilder},
    interface::serialization::{CodecLimits, HomeProfile, TypedIdProfile},
    package::arbitrary::fixture_naming,
};

fn build_single_node_forest(
    operations: Vec<Operation>,
    make_root: bool,
) -> (MastForest, MastNodeId) {
    let mut builder = DenseMastForestBuilder::new();
    let node_id = builder
        .push_node(BasicBlockNodeBuilder::new(operations))
        .expect("failed to build basic block");
    if make_root {
        builder.mark_root(node_id);
    }
    let (forest, remapping) = builder.build_with_id_map().expect("forest should be valid");
    let node_id = remapping.get(node_id).expect("node should be retained");
    (forest, node_id)
}

fn build_forest() -> (MastForest, MastNodeId) {
    build_single_node_forest(vec![Operation::Add], true)
}

fn absolute_path(name: &str) -> Arc<AstPath> {
    let path = PathBuf::new(name).expect("invalid path");
    let path = path.as_path().to_absolute().unwrap().into_owned();
    Arc::from(path.into_boxed_path())
}

fn build_package_exports() -> (Arc<MastForest>, Vec<PackageExport>) {
    let (forest, node_id) = build_forest();
    let path = absolute_path("test::proc");
    let export =
        ProcedureExport::new(Arc::clone(&path), Some(node_id), forest[node_id].digest(), None);

    (Arc::new(forest), vec![PackageExport::Procedure(export)])
}

fn fixture_home() -> NamespacePlan {
    NamespacePlan::new(vec![CanonicalLabel::text("package-serde-fixture").unwrap()])
}

fn fixture_create(
    name: PackageId,
    version: crate::Version,
    kind: TargetType,
    mast: Arc<MastForest>,
    exports: impl IntoIterator<Item = PackageExport>,
    dependencies: impl IntoIterator<Item = Dependency>,
) -> Result<Package, ManifestValidationError> {
    let exports = exports.into_iter().collect::<Vec<_>>();
    let naming = fixture_naming(fixture_home(), kind, &mast, &exports);
    Package::create(name, version, kind, mast, exports, dependencies, &naming)
}

#[allow(clippy::too_many_arguments)]
fn fixture_create_with_modules(
    name: PackageId,
    version: crate::Version,
    kind: TargetType,
    mast: Arc<MastForest>,
    exports: impl IntoIterator<Item = PackageExport>,
    modules: impl IntoIterator<Item = PackageModule>,
    dependencies: impl IntoIterator<Item = Dependency>,
) -> Result<Package, ManifestValidationError> {
    let exports = exports.into_iter().collect::<Vec<_>>();
    let naming = fixture_naming(fixture_home(), kind, &mast, &exports);
    Package::create_with_modules(name, version, kind, mast, exports, modules, dependencies, &naming)
}

fn build_package() -> Package {
    let (mast, exports) = build_package_exports();

    fixture_create(
        PackageId::from("test_pkg"),
        crate::Version::new(0, 0, 0),
        TargetType::Library,
        mast,
        exports,
        None,
    )
    .expect("test package should be valid")
}

fn build_package_with_debug_info() -> Package {
    let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
    let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
        .build()
        .expect("failed to build basic block");
    let digest = node.digest();
    let node_id = nodes.push(node.into()).expect("failed to add basic block");
    let source_node = DebugSourceNodeId::from(0);

    let mast = Arc::new(
        MastForest::from_raw_parts(nodes, vec![node_id], AdviceMap::default())
            .expect("forest should be valid"),
    );
    let path = absolute_path("test::proc");
    let exports = vec![PackageExport::Procedure(
        ProcedureExport::new(path, Some(node_id), digest, None).with_source_node(Some(source_node)),
    )];
    let mut package = fixture_create(
        PackageId::from("test_pkg"),
        crate::Version::new(0, 0, 0),
        TargetType::Library,
        mast,
        exports,
        None,
    )
    .expect("test package should be valid");
    let mut debug_info = PackageDebugInfoBuilder::default();
    let context_name_idx = debug_info.add_string("trusted");
    let op_name_idx = debug_info.add_string("add");
    let added_source_node = debug_info
        .add_node(DebugSourceNode {
            exec_node: node_id,
            children: Vec::new(),
            op_start: 0,
            op_end: 1,
            asm_ops: vec![DebugSourceAsmOp::new(0, None, context_name_idx, op_name_idx, 1)],
            debug_vars: Vec::new(),
            inline_calls: Vec::new(),
        })
        .unwrap();
    assert_eq!(added_source_node, source_node);
    debug_info.add_root(source_node);
    package
        .sections
        .push(Section::new(SectionId::DEBUG_INFO, debug_info.build().to_bytes()));
    package
}

fn build_dependency() -> Dependency {
    Dependency {
        name: PackageId::from("dep"),
        kind: TargetType::Library,
        version: crate::Version::new(1, 0, 0),
        digest: Default::default(),
    }
}

fn same_name_dependencies() -> Vec<Dependency> {
    let original = build_dependency();
    let mut versioned = original.clone();
    versioned.version = crate::Version::new(2, 0, 0);
    let mut different_kind = original.clone();
    different_kind.kind = TargetType::AccountComponent;
    let mut different_commitment = original.clone();
    different_commitment.digest = Word::from([1_u32, 2, 3, 4]);
    vec![original, versioned, different_kind, different_commitment]
}

fn package_bytes_with_sections_count(count: usize) -> Vec<u8> {
    let package = build_package();
    let mut bytes = Vec::new();

    bytes.write_bytes(MAGIC_PACKAGE);
    bytes.write_bytes(&VERSION);
    package.name.write_into(&mut bytes);
    package.version.to_string().write_into(&mut bytes);
    package.description.write_into(&mut bytes);
    bytes.write_u8(package.kind.into());
    package.mast.write_into(&mut bytes);
    bytes.write_u32(package.naming_transport().as_bytes().len().try_into().unwrap());
    bytes.write_bytes(package.naming_transport().as_bytes());
    package.manifest.write_into(&mut bytes);
    bytes.write_usize(count);

    bytes
}

#[test]
fn package_serialization_roundtrip() {
    use proptest::{
        prelude::*,
        test_runner::{Config, TestRunner},
    };

    // since the test is quite expensive, 128 cases should be enough to cover all edge cases
    // (default is 256)
    let cases = 128;
    TestRunner::new(Config::with_cases(cases))
        .run(&any::<Package>(), move |package| {
            let bytes = package.to_bytes();
            let deserialized = Package::read_from_bytes(&bytes).unwrap();
            let mut expected = package;
            expected.sections.retain(|section| !section.id.is_debug());
            prop_assert_eq!(expected.to_bytes(), deserialized.to_bytes());
            Ok(())
        })
        .unwrap_or_else(|err| {
            panic!("{err}");
        });
}

#[test]
fn package_roundtrip_preserves_content_addressed_and_arbitrary_advice_entries() {
    let resource = vec![Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3)];
    let resource_key = miden_core::chiplets::hasher::hash_elements(&resource);
    let private = vec![Felt::from_u32(7), Felt::from_u32(8)];
    let private_key = Word::from([9_u32, 10, 11, 12]);
    assert_ne!(private_key, miden_core::chiplets::hasher::hash_elements(&private));
    let mut advice = AdviceMap::default();
    advice.insert(resource_key, resource.clone());
    advice.insert(private_key, private.clone());
    let package = build_package_with_debug_info().with_advice_map(advice);
    let expected_commitment = package.dependency_commitment();
    let debug_commitment = package.commitment();

    let mut decoded = Package::read_from_bytes_trusted(&package.to_bytes()).unwrap();
    assert!(decoded.sections.iter().any(|section| section.id.is_debug()));
    assert_eq!(decoded.commitment(), debug_commitment);
    for strip_debug in [false, true] {
        if strip_debug {
            decoded.strip_debug_info().unwrap();
            assert!(!decoded.sections.iter().any(|section| section.id.is_debug()));
            assert_ne!(decoded.commitment(), debug_commitment);
        }
        let untrusted = Package::read_from_bytes(&decoded.to_bytes()).unwrap();
        for candidate in [&decoded, &untrusted] {
            let advice = candidate.mast_forest().advice_map();
            assert_eq!(advice.get(&resource_key).unwrap().as_ref(), resource.as_slice());
            assert_eq!(advice.get(&private_key).unwrap().as_ref(), private.as_slice());
            assert_eq!(candidate.dependency_commitment(), expected_commitment);
        }
    }
}

#[test]
fn private_only_code_package_roundtrips_without_public_exports() {
    let (forest, _) = build_forest();
    // An explicit implementation reference is also a code candidate. Its root records the
    // caller-supplied D without asserting code availability or creating a public export.
    let mut builder = DenseMastForestBuilder::new();
    let external = builder
        .push_node(ExternalNodeBuilder::new(forest.procedure_digests().next().unwrap()))
        .unwrap();
    builder.mark_root(external);
    let external_forest = builder.build().unwrap();

    for mast in [forest, external_forest] {
        for kind in [TargetType::Library, TargetType::Executable, TargetType::Kernel] {
            let package = fixture_create_with_modules(
                PackageId::from("private"),
                crate::Version::new(0, 0, 0),
                kind,
                Arc::new(mast.clone()),
                [],
                [PackageModule::new(absolute_path("private"), [])],
                [],
            )
            .expect("private callable roots should form a package without a public API");
            let bytes = package.to_bytes();

            for decoded in [
                Package::read_from_bytes(&bytes)
                    .expect("safe reader should accept private callable roots"),
                Package::read_from_bytes_trusted(&bytes)
                    .expect("trusted reader should accept private callable roots"),
            ] {
                assert_eq!(package, decoded);
                assert_eq!(decoded.manifest.num_exports(), 0);
                assert_eq!(decoded.manifest.num_modules(), 1);
                assert_eq!(decoded.entrypoint(), None);
                assert_eq!(decoded.mast_forest().procedure_roots().len(), 1);
                assert_eq!(decoded.code_commitment(), package.code_commitment());
                assert_eq!(decoded.commitment(), package.commitment());
                let naming = fixture_naming(fixture_home(), kind, decoded.mast_forest(), &[]);
                decoded.check_naming(&naming).unwrap();
                assert!(decoded.try_into_program(&naming).is_err());
                assert!(decoded.check_kernel_code(&naming).is_err());
            }
        }
    }
}

#[test]
fn package_readers_reject_empty_and_unrooted_private_code() {
    let (unrooted, _) = build_single_node_forest(vec![Operation::Add], false);

    for mast in [MastForest::new(), unrooted] {
        for kind in [TargetType::Library, TargetType::Executable] {
            let mut package = build_package();
            package.kind = kind;
            package.mast = Arc::new(mast.clone());
            package.manifest = PackageManifest::new([])
                .and_then(|manifest| {
                    manifest.with_modules([PackageModule::new(absolute_path("declarations"), [])])
                })
                .unwrap();
            let bytes = package.to_bytes();

            for result in
                [Package::read_from_bytes(&bytes), Package::read_from_bytes_trusted(&bytes)]
            {
                assert_matches!(
                    result,
                    Err(DeserializationError::InvalidValue(message))
                        if message.contains("at least one callable procedure root")
                );
            }
        }
    }
}

#[test]
fn trusted_package_reader_still_requires_roots_for_public_code() {
    let (forest, node) = build_single_node_forest(vec![Operation::Add], false);
    let mut package = build_package();
    package.manifest = PackageManifest::new([PackageExport::Procedure(ProcedureExport::new(
        absolute_path("public::procedure"),
        Some(node),
        forest[node].digest(),
        None,
    ))])
    .unwrap();
    package.mast = Arc::new(forest);

    let error = Package::read_from_bytes_trusted(&package.to_bytes())
        .expect_err("trusted readers must reject code packages with no callable roots");
    assert!(error.to_string().contains("at least one callable procedure root"));
}

#[test]
fn package_readers_reject_non_executable_entrypoint() {
    let mut package = build_package();
    let node = package.mast.procedure_roots()[0];
    let entrypoint =
        Arc::from(AstPath::exec_path().join(ProcedureName::MAIN_PROC_NAME).into_boxed_path());
    package.manifest = PackageManifest::new([PackageExport::Procedure(ProcedureExport::new(
        entrypoint,
        Some(node),
        package.mast[node].digest(),
        None,
    ))])
    .unwrap();
    let bytes = package.to_bytes();

    for result in [Package::read_from_bytes(&bytes), Package::read_from_bytes_trusted(&bytes)] {
        assert_matches!(
            result,
            Err(DeserializationError::InvalidValue(message))
                if message.contains("entrypoint in a package declared with non-executable type")
        );
    }
}

#[test]
fn package_format_version_rejects_previous_version() {
    let bytes = build_package().to_bytes();
    let version_offset = MAGIC_PACKAGE.len();
    assert_eq!(&bytes[version_offset..version_offset + 3], &[9, 0, 0]);

    for previous in [[8, 0, 0], [7, 0, 0], [4, 0, 0]] {
        let mut old_bytes = bytes.clone();
        old_bytes[version_offset..version_offset + 3].copy_from_slice(&previous);
        // The header alone must reject old versions, before reading the package body.
        old_bytes.truncate(version_offset + 3);
        for result in [
            Package::read_from_bytes(&old_bytes),
            Package::read_from_bytes_trusted(&old_bytes),
        ] {
            assert_matches!(
                result,
                Err(DeserializationError::InvalidValue(message))
                    if message == alloc::format!(
                        "unsupported version. Got '{previous:?}', but only '[9, 0, 0]' is supported"
                    )
            );
        }
    }
}

fn package_naming_offset(package: &Package) -> usize {
    let mut prefix = Vec::new();
    package.write_header_into(&mut prefix);
    package.mast.write_into(&mut prefix);
    assert!(package.to_bytes().starts_with(&prefix));
    prefix.len()
}

#[test]
fn package_readers_require_complete_exactly_framed_naming_transport() {
    let package = build_package();
    let bytes = package.to_bytes();
    let offset = package_naming_offset(&package);
    let payload = package.naming_transport().as_bytes();
    let payload_start = offset + size_of::<u32>();
    let payload_end = payload_start + payload.len();
    assert_eq!(
        u32::from_le_bytes(bytes[offset..payload_start].try_into().unwrap()) as usize,
        payload.len(),
        "NamingV1 must use the required u32 little-endian length frame"
    );
    assert_eq!(&bytes[payload_start..payload_end], payload);

    let mut absent = bytes[..offset].to_vec();
    absent.extend_from_slice(&bytes[payload_end..]);
    let mut empty = bytes[..offset].to_vec();
    empty.write_u32(0);
    empty.extend_from_slice(&bytes[payload_end..]);
    let mut oversized_length = bytes.clone();
    oversized_length[offset..payload_start].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut unsupported = bytes.clone();
    unsupported[payload_start] = 2;
    let mut trailing_payload = bytes[..offset].to_vec();
    trailing_payload.write_u32((payload.len() + 1).try_into().unwrap());
    trailing_payload.extend_from_slice(payload);
    trailing_payload.push(0);
    trailing_payload.extend_from_slice(&bytes[payload_end..]);

    for (case, malformed) in [
        ("missing required naming", bytes[..offset].to_vec()),
        ("absent naming before manifest", absent),
        ("truncated length frame", bytes[..payload_start - 1].to_vec()),
        ("truncated NamingV1", bytes[..payload_end - 1].to_vec()),
        ("empty NamingV1", empty),
        ("oversized declared NamingV1 length", oversized_length),
        ("unsupported NamingV1 version", unsupported),
        ("trailing bytes inside NamingV1 frame", trailing_payload),
    ] {
        for result in [
            Package::read_from_bytes(&malformed),
            Package::read_from_bytes_trusted(&malformed),
        ] {
            assert!(result.is_err(), "reader accepted {case}");
        }
    }
}

#[test]
fn package_byte_slice_readers_reject_trailing_bytes() {
    let mut bytes = build_package().to_bytes();
    bytes.push(0);
    for result in [Package::read_from_bytes(&bytes), Package::read_from_bytes_trusted(&bytes)] {
        assert_matches!(
            result,
            Err(DeserializationError::InvalidValue(message)) if message == "trailing package bytes"
        );
    }
}

struct SerdeNamingProfile {
    codec: u32,
    typed_calls: Cell<usize>,
    home_calls: Cell<usize>,
}

impl SerdeNamingProfile {
    fn new(codec: u32) -> Self {
        Self {
            codec,
            typed_calls: Cell::new(0),
            home_calls: Cell::new(0),
        }
    }
}

impl TypedIdProfile for SerdeNamingProfile {
    type Context = NamespacePlan;
    type Error = &'static str;

    fn validate_typed_id(
        &self,
        _context: &Self::Context,
        codec: u32,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.typed_calls.set(self.typed_calls.get() + 1);
        if codec == self.codec && bytes == [0xa5, 0, 0xff] {
            Ok(())
        } else {
            Err("unknown fixture TypedId codec or noncanonical payload")
        }
    }
}

impl HomeProfile for SerdeNamingProfile {
    fn validate_home(
        &self,
        context: &Self::Context,
        home: &[CanonicalLabel],
    ) -> Result<(), Self::Error> {
        self.home_calls.set(self.home_calls.get() + 1);
        if context.home() == home {
            Ok(())
        } else {
            Err("home is absent from current fixture evidence")
        }
    }
}

#[test]
fn package_readers_preserve_unknown_typed_ids_until_explicit_current_admission() {
    let codec = 9127;
    let home = NamespacePlan::new(vec![
        CanonicalLabel::typed_id(codec, &[0xa5, 0, 0xff], |_, _| Ok(())).unwrap(),
    ]);
    let (mast, exports) = build_package_exports();
    let naming = fixture_naming(home.clone(), TargetType::Library, &mast, &exports);
    let package = Package::create(
        PackageId::from("typed_naming"),
        crate::Version::new(0, 0, 0),
        TargetType::Library,
        mast,
        exports,
        [],
        &naming,
    )
    .unwrap();
    let bytes = package.to_bytes();
    let limits = super::super::FORMAT_NAMING_LIMITS;

    for trusted in [false, true] {
        let selected = SerdeNamingProfile::new(codec);
        let decoded = if trusted {
            Package::read_from_bytes_trusted(&bytes)
        } else {
            Package::read_from_bytes(&bytes)
        }
        .expect("raw readers must retain structurally bounded unknown TypedId transport");
        assert_eq!(selected.typed_calls.get(), 0);
        assert_eq!(selected.home_calls.get(), 0);
        assert_eq!(decoded.naming_transport(), package.naming_transport());
        assert_eq!(decoded.to_bytes(), bytes);

        let unknown = SerdeNamingProfile::new(77);
        assert!(decoded.admit_naming(&unknown, &home, limits).is_err());
        assert!(unknown.typed_calls.get() > 0);
        assert_eq!(decoded.admit_naming(&selected, &home, limits).unwrap(), naming);
        assert!(selected.typed_calls.get() > 0);
        assert!(selected.home_calls.get() > 0);
        // Prior admission confers no cached permission under a changed caller context.
        assert!(decoded.admit_naming(&selected, &fixture_home(), limits).is_err());
        let calls = (selected.typed_calls.get(), selected.home_calls.get());
        assert!(decoded.admit_naming(&selected, &home, CodecLimits::new(0, 0, 0, 0)).is_err());
        assert_eq!((selected.typed_calls.get(), selected.home_calls.get()), calls);
        assert_eq!(decoded.naming_transport(), package.naming_transport());
    }
}

#[test]
fn executable_package_entrypoint_roundtrips() {
    let (forest, node_id) = build_forest();
    let entrypoint =
        Arc::from(AstPath::exec_path().join(ProcedureName::MAIN_PROC_NAME).into_boxed_path());
    let export = ProcedureExport::new(
        Arc::clone(&entrypoint),
        Some(node_id),
        forest[node_id].digest(),
        None,
    );
    let package = fixture_create(
        PackageId::from("test_pkg"),
        crate::Version::new(0, 0, 0),
        TargetType::Executable,
        Arc::new(forest),
        [PackageExport::Procedure(export)],
        None,
    )
    .expect("executable package should be valid");

    let deserialized = Package::read_from_bytes(&package.to_bytes())
        .expect("executable package should deserialize without duplicate entrypoint errors");

    assert_eq!(deserialized.manifest.entrypoint(), Some(entrypoint));
}

#[test]
fn package_checked_deserialization_preserves_validated_debug_sections() {
    let package = build_package_with_debug_info();
    let bytes = package.to_bytes();

    let deserialized = Package::read_from_bytes(&bytes).unwrap();

    assert!(deserialized.sections.iter().any(|section| section.id == SectionId::DEBUG_INFO));
    assert!(deserialized.debug_info().unwrap().is_some());
    let debug_info_id = SectionId::DEBUG_INFO.as_str().as_bytes();
    assert!(
        deserialized
            .to_bytes()
            .windows(debug_info_id.len())
            .any(|window| window == debug_info_id),
        "validated debug sections should be reserialized"
    );
}

#[test]
fn package_trusted_deserialization_preserves_trusted_debug_sections() {
    let package = build_package_with_debug_info();
    let bytes = package.to_bytes();

    let deserialized = Package::read_from_bytes_trusted(&bytes).unwrap();

    assert!(deserialized.sections.iter().any(|section| section.id == SectionId::DEBUG_INFO));
    assert!(deserialized.debug_info().unwrap().is_some());
}

#[cfg(feature = "std")]
#[test]
fn package_deserialize_from_file_preserves_validated_debug_sections() {
    let package = build_package_with_debug_info();
    let path = std::env::temp_dir().join(format!(
        "miden-package-deserialize-{}-{}.masp",
        std::process::id(),
        "debug-sections"
    ));
    package.write_to_file(&path).unwrap();

    let deserialized = Package::deserialize_from_file(&path).unwrap();
    fs::remove_file(&path).unwrap();

    assert!(deserialized.sections.iter().any(|section| section.id == SectionId::DEBUG_INFO));
    assert!(deserialized.debug_info().unwrap().is_some());
}

#[cfg(feature = "std")]
#[test]
fn package_deserialize_from_file_trusted_preserves_trusted_debug_sections() {
    let package = build_package_with_debug_info();
    let path = std::env::temp_dir().join(format!(
        "miden-package-deserialize-{}-{}.masp",
        std::process::id(),
        "trusted-debug-sections"
    ));
    package.write_to_file(&path).unwrap();

    let deserialized = Package::deserialize_from_file_trusted(&path).unwrap();
    fs::remove_file(&path).unwrap();

    assert!(deserialized.sections.iter().any(|section| section.id == SectionId::DEBUG_INFO));
    assert!(deserialized.debug_info().unwrap().is_some());
}

#[cfg(feature = "std")]
#[test]
fn package_file_readers_reject_oversized_files_before_decoding() {
    let path =
        std::env::temp_dir().join(format!("miden-package-oversized-{}.masp", std::process::id()));
    let file = fs::File::create(&path).unwrap();
    file.set_len(Package::MAX_FILE_SIZE as u64 + 1).unwrap();

    for result in [
        Package::deserialize_from_file(&path),
        Package::deserialize_from_file_trusted(&path),
    ] {
        let err = result.unwrap_err().to_string();
        assert!(err.contains("size limit of 536870912 bytes"), "{err}");
        assert!(err.contains(&path.display().to_string()), "{err}");
    }
    drop(file);
    fs::remove_file(path).unwrap();
}

#[cfg(feature = "std")]
#[test]
fn package_file_readers_reject_non_regular_files() {
    let path = std::env::temp_dir();
    for result in [
        Package::deserialize_from_file(&path),
        Package::deserialize_from_file_trusted(&path),
    ] {
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expected a regular file"), "{err}");
    }
}

#[test]
fn artifact_and_package_commitments_change_with_header_fields() {
    let package = build_package();
    let code_commitment = package.code_commitment();
    let dependency_commitment = package.dependency_commitment();
    let artifacts_commitment = package.artifacts_commitment();
    let package_commitment = package.commitment();

    let renamed = Package {
        name: PackageId::from("renamed_pkg"),
        ..package.clone()
    };
    assert_eq!(code_commitment, renamed.code_commitment());
    assert_ne!(dependency_commitment, renamed.dependency_commitment());
    assert_ne!(artifacts_commitment, renamed.artifacts_commitment());
    assert_ne!(package_commitment, renamed.commitment());

    let versioned = Package {
        version: crate::Version::new(1, 2, 3),
        ..package.clone()
    };
    assert_eq!(code_commitment, versioned.code_commitment());
    assert_ne!(dependency_commitment, versioned.dependency_commitment());
    assert_ne!(artifacts_commitment, versioned.artifacts_commitment());
    assert_ne!(package_commitment, versioned.commitment());

    let executable = Package { kind: TargetType::Executable, ..package };
    assert_eq!(code_commitment, executable.code_commitment());
    assert_ne!(dependency_commitment, executable.dependency_commitment());
    assert_ne!(artifacts_commitment, executable.artifacts_commitment());
    assert_ne!(package_commitment, executable.commitment());
}

#[test]
fn artifact_and_package_commitments_change_with_manifest() {
    let package = build_package();
    let interface_commitment = package.interface_commitment().unwrap();
    let dependency_commitment = package.dependency_commitment();
    let artifacts_commitment = package.artifacts_commitment();
    let package_commitment = package.commitment();

    let mut with_dependency = package.clone();
    with_dependency
        .manifest
        .add_dependency(Dependency {
            name: PackageId::from("dep_pkg"),
            kind: TargetType::Library,
            version: crate::Version::new(1, 0, 0),
            digest: Word::from([1_u32, 2, 3, 4]),
        })
        .expect("test dependency should be unique");
    assert_eq!(interface_commitment, with_dependency.interface_commitment().unwrap());
    assert_eq!(package.code_commitment(), with_dependency.code_commitment());
    assert_ne!(dependency_commitment, with_dependency.dependency_commitment());
    assert_ne!(artifacts_commitment, with_dependency.artifacts_commitment());
    assert_ne!(package_commitment, with_dependency.commitment());
}

#[test]
fn artifact_and_package_commitments_change_with_sections() {
    let package = build_package();
    let artifacts_commitment = package.artifacts_commitment();
    let dependency_commitment = package.dependency_commitment();
    let package_commitment = package.commitment();

    let with_metadata = Package {
        sections: vec![Section::new(SectionId::ACCOUNT_COMPONENT_METADATA, vec![1, 2, 3, 4])],
        ..package.clone()
    };
    assert_ne!(artifacts_commitment, with_metadata.artifacts_commitment());
    assert_ne!(dependency_commitment, with_metadata.dependency_commitment());
    assert_ne!(package_commitment, with_metadata.commitment());

    let described = Package {
        description: Some(String::from("human-facing package description")),
        ..package.clone()
    };
    assert_ne!(artifacts_commitment, described.artifacts_commitment());
    assert_eq!(dependency_commitment, described.dependency_commitment());
    assert_ne!(package_commitment, described.commitment());

    let with_opaque_section = Package {
        sections: vec![Section::new(
            SectionId::custom("opaque").expect("valid custom section id"),
            vec![1, 2, 3, 4],
        )],
        ..package
    };
    assert_ne!(artifacts_commitment, with_opaque_section.artifacts_commitment());
    assert_eq!(dependency_commitment, with_opaque_section.dependency_commitment());
    assert_ne!(package_commitment, with_opaque_section.commitment());
}

#[test]
fn dependency_commitment_ignores_optional_debug_info() {
    let package = build_package_with_debug_info();
    let stripped = package.clone().without_debug_info().expect("debug stripping should succeed");

    assert_eq!(package.dependency_commitment(), stripped.dependency_commitment());
    assert_ne!(package.commitment(), stripped.commitment());
}

#[test]
fn interface_and_code_commitments_change_with_exports() {
    let mut builder = DenseMastForestBuilder::new();
    let first_node_id = builder
        .push_node(BasicBlockNodeBuilder::new(vec![Operation::Add]))
        .expect("first basic block should be valid");
    let second_node_id = builder
        .push_node(BasicBlockNodeBuilder::new(vec![Operation::Mul]))
        .expect("second basic block should be valid");
    builder.mark_root(first_node_id);
    builder.mark_root(second_node_id);
    let (forest, remapping) = builder.build_with_id_map().expect("forest should be valid");
    let first_node_id = remapping.get(first_node_id).expect("first root should be retained");
    let second_node_id = remapping.get(second_node_id).expect("second root should be retained");
    let forest = Arc::new(forest);
    let package_with_export = |node_id| {
        fixture_create(
            PackageId::from("test_pkg"),
            crate::Version::new(0, 0, 0),
            TargetType::Library,
            Arc::clone(&forest),
            [PackageExport::Procedure(ProcedureExport::new(
                absolute_path("test::proc"),
                Some(node_id),
                forest[node_id].digest(),
                None,
            ))],
            None,
        )
        .expect("package with one export should be valid")
    };
    let package = package_with_export(first_node_id);
    let different_export = package_with_export(second_node_id);

    assert_eq!(package.mast_forest_commitment(), different_export.mast_forest_commitment());
    assert_ne!(
        package.interface_commitment().unwrap(),
        different_export.interface_commitment().unwrap()
    );
    assert_ne!(package.code_commitment(), different_export.code_commitment());
    assert_ne!(package.artifacts_commitment(), different_export.artifacts_commitment());
    assert_ne!(package.commitment(), different_export.commitment());
}

#[test]
fn package_manifest_rejects_over_budget_dependencies() {
    let mut bytes = Vec::new();
    bytes.write_usize(0);
    bytes.write_usize(0);
    bytes.write_usize(2);

    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), 2);
    let err = PackageManifest::read_from(&mut reader).unwrap_err();
    assert!(matches!(err, DeserializationError::InvalidValue(_)));
}

#[test]
fn package_rejects_over_budget_sections() {
    let bytes = package_bytes_with_sections_count(2);
    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    let err = Package::read_from(&mut reader).unwrap_err();
    assert!(matches!(err, DeserializationError::InvalidValue(_)));
}

#[test]
fn package_read_from_bytes_rejects_fuzzed_oom_payload() {
    // This fuzz payload encodes counts large enough to cause excessive allocation or read work.
    // If this starts succeeding, package byte-slice deserialization is no longer budgeted.
    let payload = [
        0x4d, 0x41, 0x53, 0x50, 0x00, 0x04, 0x00, 0x00, 0x11, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x70,
        0x6b, 0x67, 0x0b, 0x30, 0x2e, 0x30, 0x2e, 0x30, 0x00, 0x00, 0x4d, 0x41, 0x53, 0x54, 0x00,
        0x00, 0x00, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x17, 0x03, 0x22, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x2f,
        0x08, 0x0a, 0x21, 0xa9, 0xb6, 0xf6, 0x1a, 0x52, 0x30, 0xc5, 0x64, 0xc7, 0xdb, 0x4d, 0x83,
        0x0b, 0x32, 0x58, 0x89, 0x88, 0xb2, 0x78, 0x69, 0xbb, 0x23, 0xa6, 0x18, 0x9c, 0xc9, 0x35,
        0x2d, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x03, 0x00, 0x0c,
        0x00, 0x3a, 0x3a, 0x74, 0x65, 0x73, 0x74, 0x3a, 0x3a, 0x70, 0x72, 0x6f, 0x63, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x03, 0x0f, 0x03, 0x0f, 0x01, 0x00, 0x00, 0x17, 0x03, 0x22, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9c, 0xc9, 0x35, 0x2d, 0x01, 0x00,
        0x03, 0x0f, 0x03, 0x0f, 0x01, 0x01, 0x01,
    ];

    let result = Package::read_from_bytes(&payload);
    assert!(result.is_err());

    // Wrapped fuzz inputs must use the generic budgeted entry point; otherwise the outer
    // collection length can drive unbounded work before the inner package fails.
    let mut vec_payload = vec![0];
    vec_payload.extend_from_slice(&1000u64.to_le_bytes());
    let budget = vec_payload.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
    let result = Vec::<Package>::read_from_bytes_with_budget(&vec_payload, budget);
    assert!(result.is_err());

    let mut option_payload = vec![1];
    option_payload.extend_from_slice(&payload);
    let budget = option_payload.len().saturating_mul(PACKAGE_BYTE_READ_BUDGET_MULTIPLIER);
    let result = Option::<Package>::read_from_bytes_with_budget(&option_payload, budget);
    assert!(result.is_err());
}

/// Verifies that deserializing a library rejects procedure exports whose `MastNodeId` is not a
/// procedure root in the underlying MAST forest (issue #2831).
#[test]
fn package_rejects_non_root_export() {
    let (forest, node_id) = build_single_node_forest(vec![Operation::Add], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("test::proc");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("test_pkg"),
        version: crate::Version::new(0, 0, 0),
        description: None,
        kind: TargetType::Library,
        naming: UnverifiedPackageNaming::from_owned(
            &fixture_naming(fixture_home(), TargetType::Library, &forest, &exports),
            super::super::FORMAT_NAMING_LIMITS,
        )
        .unwrap(),
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    // Manually serialize the tampered package: forest + one export referencing a non-root node.
    let mut tampered_bytes = Vec::new();
    package.write_into(&mut tampered_bytes);

    // Deserializing should fail because the export references a non-root node.
    let result = Package::read_from_bytes(&tampered_bytes);
    assert!(
        result.is_err(),
        "deserialization should reject exports referencing non-root nodes"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("node id and digest do not correspond to a procedure root"),
        "error should mention missing procedure root, got: {err_msg}"
    );
}

#[test]
fn package_manifest_new_rejects_duplicate_export_paths() {
    let path = absolute_path("test::proc");
    let exports = vec![
        PackageExport::Procedure(ProcedureExport::new(path.clone(), None, Word::default(), None)),
        PackageExport::Procedure(ProcedureExport::new(path.clone(), None, Word::default(), None)),
    ];

    let err = PackageManifest::new(exports)
        .expect_err("duplicate export paths should be rejected by constructors");
    assert_matches!(err, ManifestValidationError::DuplicateExport(err_path) if err_path == path);
}

#[test]
fn package_manifest_without_procedure_exports_roundtrips_independently_of_code() {
    let manifest = PackageManifest::new([])
        .and_then(|manifest| manifest.with_modules([PackageModule::new(absolute_path("api"), [])]))
        .and_then(|manifest| manifest.with_dependencies([build_dependency()]))
        .expect("declaration metadata does not require public procedures");
    let bytes = manifest.to_bytes();
    let decoded = PackageManifest::read_from_bytes(&bytes).unwrap();

    assert_eq!(decoded, manifest);
    assert_eq!(decoded.num_exports(), 0);
    assert_eq!(decoded.entrypoint(), None);
    assert_eq!(decoded.num_modules(), 1);
    assert_eq!(decoded.num_dependencies(), 1);
}

#[test]
fn package_manifest_roundtrips_module_surfaces() {
    let export = PackageExport::Procedure(ProcedureExport::new(
        absolute_path("test::api::foo"),
        None,
        Word::default(),
        None,
    ));
    let module = PackageModule::new(
        absolute_path("test"),
        [PackageSubmodule::new(Ident::new("api").unwrap())],
    );
    let child = PackageModule::new(absolute_path("test::api"), []);

    let manifest = PackageManifest::new([export])
        .and_then(|manifest| manifest.with_modules([module, child]))
        .expect("manifest should be valid");
    let bytes = manifest.to_bytes();
    let decoded = PackageManifest::read_from_bytes(&bytes).expect("manifest should roundtrip");

    let root = decoded
        .get_module(absolute_path("test").as_ref())
        .expect("root module surface should be present");
    assert_eq!(root.submodules().len(), 1);
    assert_eq!(root.submodules()[0].name.as_str(), "api");
    assert!(decoded.get_module(absolute_path("test::api").as_ref()).is_some());
}

#[test]
fn package_manifest_add_dependency_rejects_duplicate_dependencies() {
    let mut manifest = PackageManifest {
        exports: Default::default(),
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };
    let dependency = build_dependency();

    manifest
        .add_dependency(dependency.clone())
        .expect("first dependency should be accepted");
    let err = manifest
        .add_dependency(dependency)
        .expect_err("duplicate dependencies should be rejected by helpers");
    assert_matches!(err, ManifestValidationError::DuplicateDependency(pkgid) if pkgid == "dep");
    assert_eq!(manifest.num_dependencies(), 1);
}

#[test]
fn package_manifest_preserves_distinct_same_name_dependencies_in_all_readers() {
    let dependencies = same_name_dependencies();
    let manifest = PackageManifest::new([])
        .unwrap()
        .with_dependencies(dependencies.clone())
        .expect("same-name supplies with distinct exact metadata must coexist");
    let bytes = manifest.to_bytes();
    let (mast, _) = build_forest();

    for decoded in [
        PackageManifest::read_from_bytes(&bytes),
        PackageManifest::read_from_safe(&mut SliceReader::new(&bytes), &mast),
        PackageManifest::read_from_trusted(&mut SliceReader::new(&bytes), &mast),
    ] {
        let decoded = decoded.expect("each reader must retain distinct same-name records");
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.dependencies().cloned().collect::<Vec<_>>(), dependencies);
    }
}

#[test]
fn package_readers_preserve_and_commit_each_same_name_dependency_record() {
    let dependencies = same_name_dependencies();
    let mut package = build_package();
    package.manifest = package.manifest.with_dependencies(dependencies.clone()).unwrap();
    let bytes = package.to_bytes();

    for decoded in [Package::read_from_bytes(&bytes), Package::read_from_bytes_trusted(&bytes)] {
        let decoded = decoded.expect("distinct same-name supplies must roundtrip");
        assert_eq!(decoded.manifest.dependencies().cloned().collect::<Vec<_>>(), dependencies);
        assert_eq!(decoded.dependency_commitment(), package.dependency_commitment());
        assert_eq!(decoded.commitment(), package.commitment());
    }

    // None of these fields can be silently projected away before computing the commitment.
    let original = &dependencies[3];
    let mut renamed = original.clone();
    renamed.name = PackageId::from("another-dep");
    let mut versioned = original.clone();
    versioned.version = crate::Version::new(3, 0, 0);
    let mut different_kind = original.clone();
    different_kind.kind = TargetType::Note;
    let mut different_commitment = original.clone();
    different_commitment.digest = Word::from([5_u32, 6, 7, 8]);
    for replacement in [renamed, versioned, different_kind, different_commitment] {
        let mut tampered = package.clone();
        tampered.manifest.dependencies[3] = replacement;
        let bytes = tampered.to_bytes();
        for decoded in [Package::read_from_bytes(&bytes), Package::read_from_bytes_trusted(&bytes)]
        {
            let decoded = decoded.expect("changed distinct records remain structurally valid");
            assert_eq!(decoded.manifest.num_dependencies(), dependencies.len());
            assert_eq!(decoded.code_commitment(), package.code_commitment());
            assert_ne!(decoded.dependency_commitment(), package.dependency_commitment());
            assert_ne!(decoded.commitment(), package.commitment());
        }
    }
}

#[test]
fn package_readers_reject_tampered_exact_duplicate_dependency_records() {
    let mut package = build_package();
    package.manifest.dependencies = same_name_dependencies();
    package.manifest.dependencies[3] = package.manifest.dependencies[0].clone();
    let bytes = package.to_bytes();

    for result in [Package::read_from_bytes(&bytes), Package::read_from_bytes_trusted(&bytes)] {
        let error = result.expect_err("reader trust must not admit duplicate exact requirements");
        assert!(error.to_string().contains("duplicate dependency 'dep'"));
    }
}

#[test]
fn package_manifest_rejects_duplicate_export_paths() {
    let path = absolute_path("test::proc");
    let export = PackageExport::Procedure(ProcedureExport::new(path, None, Word::default(), None));

    let mut bytes = Vec::new();
    bytes.write_usize(2);
    export.write_into(&mut bytes);
    export.write_into(&mut bytes);
    bytes.write_usize(0);
    bytes.write_usize(0);
    bytes.write_bool(false);

    let mut reader = SliceReader::new(&bytes);
    let err = PackageManifest::read_from(&mut reader)
        .expect_err("duplicate export paths should be rejected during deserialization");
    assert!(matches!(err, DeserializationError::InvalidValue(_)));
}

#[test]
fn package_manifest_rejects_duplicate_dependencies() {
    let dependency = build_dependency();

    let mut bytes = Vec::new();
    bytes.write_usize(0);
    bytes.write_usize(0);
    bytes.write_usize(2);
    dependency.write_into(&mut bytes);
    dependency.write_into(&mut bytes);
    bytes.write_bool(false);

    let (mast, _) = build_forest();
    for result in [
        PackageManifest::read_from_bytes(&bytes),
        PackageManifest::read_from_safe(&mut SliceReader::new(&bytes), &mast),
        PackageManifest::read_from_trusted(&mut SliceReader::new(&bytes), &mast),
    ] {
        let err = result.expect_err("duplicate exact dependencies must reject in every reader");
        assert!(matches!(err, DeserializationError::InvalidValue(_)));
        assert!(err.to_string().contains("duplicate dependency 'dep'"));
    }
}

#[test]
fn package_manifest_deserialization_rejects_malformed_quoted_procedure_leaf() {
    let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
    let exports = BTreeMap::from_iter([(
        bad.clone(),
        PackageExport::Procedure(ProcedureExport::new(bad, None, Default::default(), None)),
    )]);

    let manifest = PackageManifest {
        exports,
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };

    let bytes = manifest.to_bytes();

    let err = PackageManifest::read_from_bytes(&bytes).expect_err(
        "expected malformed procedure export leaf name rejection during deserialization",
    );
    let message = alloc::format!("{err}");
    assert_matches!(
        message,
        msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
    );
}

#[test]
fn package_manifest_deserialization_rejects_malformed_quoted_constant_leaf() {
    let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
    let exports = BTreeMap::from_iter([(
        bad.clone(),
        PackageExport::Constant(crate::ConstantExport {
            path: bad,
            value: miden_assembly_syntax::ast::ConstantValue::Int(
                miden_debug_types::Span::unknown(1u32.into()),
            ),
        }),
    )]);

    let manifest = PackageManifest {
        exports,
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };

    let bytes = manifest.to_bytes();

    let err = PackageManifest::read_from_bytes(&bytes).expect_err(
        "expected malformed constant export leaf name rejection during deserialization",
    );
    let message = alloc::format!("{err}");
    assert_matches!(
        message,
        msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
    );
}

#[test]
fn package_manifest_deserialization_rejects_malformed_quoted_type_leaf() {
    let bad = Arc::<AstPath>::from(AstPath::validate(r#"::foo::"bad name""#).unwrap());
    let exports = BTreeMap::from_iter([(
        bad.clone(),
        PackageExport::Type(crate::TypeExport {
            path: bad,
            ty: miden_assembly_syntax::ast::types::Type::Felt,
        }),
    )]);

    let manifest = PackageManifest {
        exports,
        modules: Default::default(),
        dependencies: Default::default(),
        entrypoint: None,
    };

    let bytes = manifest.to_bytes();

    let err = PackageManifest::read_from_bytes(&bytes)
        .expect_err("expected malformed type export leaf name rejection during deserialization");
    let message = alloc::format!("{err}");
    assert_matches!(
        message,
        msg if msg.contains("invalid export path '::foo::\"bad name\"': invalid item path component"),
    );
}

#[test]
fn regression_package_deserialisation_rejects_spoofed_mast_node_digests() {
    // Build mast for:
    //
    // pub proc p
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("lib::p");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("lib"),
        version: crate::Version::new(0, 0, 0),
        description: None,
        kind: TargetType::Library,
        naming: UnverifiedPackageNaming::from_owned(
            &fixture_naming(fixture_home(), TargetType::Library, &forest, &exports),
            super::super::FORMAT_NAMING_LIMITS,
        )
        .unwrap(),
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-library-digest");
    let err = Package::read_from_bytes(&bytes)
        .expect_err("expected package deserialization to reject inconsistent node digests");
    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

#[test]
fn trusted_package_deserialisation_accepts_spoofed_mast_hashes() {
    // Build mast for:
    //
    // pub proc p
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], true);
    let digest = forest[node_id].digest();

    let path = absolute_path("lib::p");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("lib"),
        version: crate::Version::new(0, 0, 0),
        description: None,
        kind: TargetType::Library,
        naming: UnverifiedPackageNaming::from_owned(
            &fixture_naming(fixture_home(), TargetType::Library, &forest, &exports),
            super::super::FORMAT_NAMING_LIMITS,
        )
        .unwrap(),
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, spoofed_digest) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-library-digest");
    let trusted = Package::read_from_bytes_trusted(&bytes)
        .expect("trusted package deserialization should not recompute MAST hashes");
    assert_eq!(trusted.mast_forest()[node_id].digest(), spoofed_digest);

    let err = Package::read_from_bytes(&bytes)
        .expect_err("untrusted package deserialization should reject spoofed MAST hashes");
    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

#[test]
fn regression_kernel_package_deserialisation_rejects_spoofed_mast_node_digests() {
    // Build mast for:
    //
    // pub proc k1
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("$kernel::k1");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("kernel"),
        version: crate::Version::new(0, 0, 0),
        description: None,
        kind: TargetType::Kernel,
        naming: UnverifiedPackageNaming::from_owned(
            &fixture_naming(fixture_home(), TargetType::Kernel, &forest, &exports),
            super::super::FORMAT_NAMING_LIMITS,
        )
        .unwrap(),
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
    let err = Package::read_from_bytes(&bytes)
        .expect_err("expected kernel package deserialization to reject inconsistent node digests");
    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

#[cfg(feature = "std")]
#[test]
fn package_deserialize_from_file_rejects_spoofed_kernel_mast_node_digests() {
    // Build mast for:
    //
    // pub proc k1
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], false);
    let digest = forest[node_id].digest();

    let path = absolute_path("$kernel::k1");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("kernel"),
        version: crate::Version::new(0, 0, 0),
        description: None,
        kind: TargetType::Kernel,
        naming: UnverifiedPackageNaming::from_owned(
            &fixture_naming(fixture_home(), TargetType::Kernel, &forest, &exports),
            super::super::FORMAT_NAMING_LIMITS,
        )
        .unwrap(),
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, _) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
    let file_path = std::env::temp_dir().join(format!(
        "miden-package-deserialize-{}-{}.masp",
        std::process::id(),
        "spoofed-kernel-digest"
    ));
    fs::write(&file_path, bytes).expect("failed to write tampered package file");

    let err = Package::deserialize_from_file(&file_path)
        .expect_err("expected file deserialization to reject inconsistent node digests");
    fs::remove_file(&file_path).unwrap();

    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

#[test]
fn trusted_kernel_package_deserialisation_accepts_spoofed_mast_hashes() {
    // Build mast for:
    //
    // pub proc k1
    //     push.1
    // end
    let (forest, node_id) =
        build_single_node_forest(vec![Operation::Push(Felt::from_u32(1))], true);
    let digest = forest[node_id].digest();

    let path = absolute_path("$kernel::k1");
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        Arc::clone(&path),
        Some(node_id),
        digest,
        None,
    ))];

    let package = Package {
        name: PackageId::from("kernel"),
        version: crate::Version::new(0, 0, 0),
        description: None,
        kind: TargetType::Kernel,
        naming: UnverifiedPackageNaming::from_owned(
            &fixture_naming(fixture_home(), TargetType::Kernel, &forest, &exports),
            super::super::FORMAT_NAMING_LIMITS,
        )
        .unwrap(),
        mast: Arc::new(forest),
        manifest: PackageManifest::new(exports).expect("test manifest should be valid"),
        sections: Default::default(),
        debug_sections_trusted: true,
    };

    let (bytes, spoofed_digest) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-kernel-digest");
    let trusted = Package::read_from_bytes_trusted(&bytes)
        .expect("trusted kernel deserialization should not recompute MAST hashes");
    assert_eq!(trusted.mast_forest()[node_id].digest(), spoofed_digest);
}

#[test]
fn spoofed_mast_hash_with_keyed_target_is_rejected_unless_trusted() {
    let target = ProcedureKey::new(miden_core::utils::hash_string_to_word("package-exec-target"));
    let mut builder = DenseMastForestBuilder::new();
    let node_id = builder.push_node(ExecNodeBuilder::new(target)).unwrap();
    builder.mark_root(node_id);
    let forest = builder.build().unwrap();
    let digest = forest[node_id].digest();
    let exports = vec![PackageExport::Procedure(ProcedureExport::new(
        absolute_path("lib::p"),
        Some(node_id),
        digest,
        None,
    ))];
    let package = fixture_create(
        PackageId::from("lib"),
        crate::Version::new(0, 0, 0),
        TargetType::Library,
        Arc::new(forest),
        exports,
        None,
    )
    .unwrap();

    let (bytes, spoofed_digest) =
        build_package_bytes_with_spoofed_first_node_digest(&package, "spoofed-keyed-digest");
    let trusted = Package::read_from_bytes_trusted(&bytes)
        .expect("trusted package deserialization should preserve the spoofed hash");
    let MastNode::Exec(node) = &trusted.mast_forest()[node_id] else {
        panic!("expected the keyed invocation to be preserved");
    };
    assert_eq!(node.target(), target, "the target table must not be patched");
    assert_eq!(node.digest(), spoofed_digest);

    let err = Package::read_from_bytes(&bytes)
        .expect_err("untrusted package deserialization should reject the spoofed hash");
    assert!(
        err.to_string().contains("invalid untrusted MAST forest"),
        "expected untrusted-MAST validation failure, got: {err}"
    );
    assert!(
        err.to_string().contains("hash mismatch for node"),
        "expected digest mismatch failure, got: {err}"
    );
}

fn locate_first_node_hash(bytes: &[u8]) -> (usize, usize) {
    // Core's public wire view does not expose byte offsets. Use its shared integer codec and
    // track consumed bytes with the budget, then skip the fixed-width MAST v6 sections.
    let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
    assert_eq!(
        reader.read_array::<8>().expect("missing MAST header"),
        *b"MAST\0\0\0\x06",
        "expected a hash-bearing MAST v6 fixture"
    );

    let internal_node_count = reader.read_usize().expect("missing internal node count");
    let external_node_count = reader.read_usize().expect("missing external node count");
    let target_count = usize::try_from(reader.read_u32().expect("missing invocation target count"))
        .expect("invocation target count does not fit host usize");
    let node_count = internal_node_count
        .checked_add(external_node_count)
        .expect("node count overflow");

    // Roots: len (usize) + elements (u32 LE)
    let roots_len = reader.read_usize().expect("missing root count");
    reader
        .read_slice(roots_len.checked_mul(size_of::<u32>()).expect("root section length overflow"))
        .expect("truncated root section");

    // Basic block data: len (usize) + bytes
    let bb_len = reader.read_usize().expect("missing basic block data length");
    reader.read_slice(bb_len).expect("truncated basic block data");

    for (count, entry_size) in [
        (node_count, MastNodeEntry::SERIALIZED_SIZE),
        (external_node_count, Word::SERIALIZED_SIZE),
        (target_count, ProcedureKey::min_serialized_size()),
    ] {
        let section_len = count.checked_mul(entry_size).expect("MAST section length overflow");
        reader.read_slice(section_len).expect("truncated MAST section");
    }

    let offset = bytes.len().checked_sub(reader.remaining()).expect("MAST offset overflow");
    (offset, internal_node_count)
}

fn build_package_bytes_with_spoofed_first_node_digest(
    lib: &Package,
    spoof_seed: &str,
) -> (Vec<u8>, Word) {
    use miden_core::serde::Serializable;

    // Serialize the MastForest normally so the byte layout is stable.
    let forest = lib.mast_forest().as_ref();
    let first_node = &forest[MastNodeId::new_unchecked(0)];
    assert!(!first_node.is_external(), "fixture node 0 must have an internal hash");
    let original_digest = first_node.digest();
    let mut output_bytes = Vec::new();
    lib.write_header_into(&mut output_bytes);
    let forest_offset = output_bytes.len();
    forest.write_into(&mut output_bytes);

    let (node_hashes_start, node_count) = locate_first_node_hash(&output_bytes[forest_offset..]);
    assert!(node_count > 0, "expected at least one node info entry");

    // Patch node 0 digest in-place.
    let spoofed_digest = miden_core::utils::hash_string_to_word(spoof_seed);
    assert_ne!(spoofed_digest, original_digest, "spoofed digest must differ");

    let mut spoofed_digest_bytes = Vec::new();
    spoofed_digest.write_into(&mut spoofed_digest_bytes);
    assert_eq!(spoofed_digest_bytes.len(), 32, "Word must serialize to 32 bytes");

    let node0_digest_offset =
        forest_offset.checked_add(node_hashes_start).expect("node hash offset overflow");
    let node0_digest_end = node0_digest_offset
        .checked_add(Word::SERIALIZED_SIZE)
        .expect("node hash end offset overflow");
    let node0_digest_bytes = output_bytes
        .get_mut(node0_digest_offset..node0_digest_end)
        .expect("truncated first node hash");
    assert_eq!(
        Word::read_from_bytes(node0_digest_bytes).expect("invalid first node hash"),
        original_digest,
        "fixture must patch the original node 0 hash"
    );
    node0_digest_bytes.copy_from_slice(&spoofed_digest_bytes);

    lib.write_trailer_into(&mut output_bytes);

    (output_bytes, spoofed_digest)
}
