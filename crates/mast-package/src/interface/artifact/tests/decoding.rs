use super::*;

// Build adversarial frames independently of the production writer/EncodingPlan. In particular,
// malformed DB fixtures receive their own correct commitment over the exact mutated bytes, so
// rejecting a hash mismatch cannot stand in for checking canonical wire structure.
fn push_u32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&u32::try_from(value).unwrap().to_le_bytes());
}

fn envelope(version: u8, tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![version, tag];
    push_u32(&mut bytes, payload.len());
    bytes.extend_from_slice(payload);
    bytes
}

fn text(value: &str) -> Vec<u8> {
    envelope(1, 0, value.as_bytes())
}

fn abi(value: Option<&[u8]>) -> Vec<u8> {
    match value {
        None => vec![0],
        Some(value) => {
            let mut bytes = vec![1];
            push_u32(&mut bytes, value.len());
            bytes.extend_from_slice(value);
            bytes
        },
    }
}

fn public(labels: &[Vec<u8>], abi_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, labels.len());
    for label in labels {
        bytes.extend_from_slice(label);
    }
    bytes.extend_from_slice(abi_bytes);
    bytes
}

fn raw_id(value: u32) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..4].copy_from_slice(&value.to_le_bytes());
    bytes
}

fn db(public: &[Vec<u8>], direct: &[[u8; 32]], closure: &[[u8; 32]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_u32(&mut bytes, public.len());
    for declaration in public {
        bytes.extend_from_slice(declaration);
    }
    for ids in [direct, closure] {
        push_u32(&mut bytes, ids.len());
        for id in ids {
            bytes.extend_from_slice(id);
        }
    }
    bytes
}

fn raw_commitment(descriptor: &[u8], db: &[u8]) -> Word {
    let mut dcl = Vec::new();
    push_u32(&mut dcl, descriptor.len());
    dcl.extend_from_slice(descriptor);
    dcl.extend_from_slice(db);
    let mut payload = vec![Felt::ONE, Felt::from_u32(u32::try_from(dcl.len()).unwrap())];
    // Independent LE-u32 packing, including zero padding only in the last partial group.
    for chunk in dcl.chunks(4) {
        let mut packed = [0; 4];
        packed[..chunk.len()].copy_from_slice(chunk);
        payload.push(Felt::from_u32(u32::from_le_bytes(packed)));
    }
    hasher::hash_elements_in_domain(&payload, TestOnlyDomain)
}

fn wire(descriptor: &[u8], db: &[u8]) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&raw_id(99));
    bytes.extend_from_slice(&raw_commitment(descriptor, db).as_bytes());
    push_u32(&mut bytes, descriptor.len());
    bytes.extend_from_slice(descriptor);
    push_u32(&mut bytes, db.len());
    bytes.extend_from_slice(db);
    bytes
}

fn no_callbacks<D>(profile: &TestProfile<D>) {
    assert!(profile.calls.borrow().is_empty(), "authority ran before wire rejection");
    assert_eq!(profile.typed_id_calls.get(), 0, "a declaration called the TypedId validator");
}

fn reject(bytes: &[u8], limits: CodecLimits) -> ArtifactError<&'static str> {
    let profile = TestProfile::new(TestOnlyDomain);
    let error = InterfaceArtifactV1::decode_verified(bytes, library_id(99), &profile, &7, limits)
        .expect_err("malformed wire was accepted");
    no_callbacks(&profile);
    assert!(!matches!(error, ArtifactError::ProfileRejected { .. }));
    error
}

fn reject_db(db: &[u8]) -> ArtifactError<&'static str> {
    let error = reject(&wire(b"Q", db), limits());
    assert!(!matches!(error, ArtifactError::CommitmentMismatch));
    error
}

#[test]
fn empty_and_mixed_artifacts_round_trip_with_exact_bytes_and_without_tooling_signatures() {
    let empty = wire(b"", &db(&[], &[], &[]));
    let profile = TestProfile::new(TestOnlyDomain);
    let exact_empty = CodecLimits::new(85, 0, 0, 0);
    let decoded =
        InterfaceArtifactV1::decode_verified(&empty, library_id(99), &profile, &7, exact_empty)
            .unwrap();
    assert_eq!(decoded.id(), library_id(99));
    assert!(decoded.publisher_descriptor().is_empty());
    assert_eq!(decoded.encode_v1(&profile, &7, exact_empty).unwrap(), empty);

    let declarations = vec![
        declaration(&["a"], None),
        declaration(&["a", "b"], Some("")),
        declaration(&["a::b"], Some("Å\r\n")),
        declaration(&["f#tag"], None),
        declaration(&[r"f\tag"], None),
        declaration(&["Å"], Some("exact ABI")),
        declaration(&["Å"], None),
    ];
    let mut typed = declarations.clone();
    typed[0] = typed[0].clone().with_signature(FunctionType::new(
        CallConv::Fast,
        [Type::U32],
        [Type::U32],
    ));
    let artifact = verified_artifact(
        typed,
        vec![library_id(1), library_id(256)],
        vec![library_id(2), library_id(1), library_id(256)],
    );
    let bytes = artifact.encode_v1(&profile, &7, limits()).unwrap();
    profile.calls.borrow_mut().clear();
    let decoded =
        InterfaceArtifactV1::decode_verified(&bytes, library_id(99), &profile, &7, limits())
            .unwrap();
    assert_eq!(decoded.declarations(), &DeclarationSet::new(declarations).unwrap());
    assert!(
        decoded
            .declarations()
            .iter()
            .all(|declaration| declaration.signature().is_none())
    );
    assert_eq!(decoded.id(), artifact.id());
    assert_eq!(decoded.commitment(), artifact.commitment());
    assert_eq!(decoded.publisher_descriptor(), artifact.publisher_descriptor());
    assert_eq!(decoded.direct_requirements(), artifact.direct_requirements());
    assert_eq!(decoded.dependency_closure(), artifact.dependency_closure());
    assert_eq!(decoded.encode_v1(&profile, &7, limits()).unwrap(), bytes);
    assert_eq!(profile.typed_id_calls.get(), 0);
}

#[test]
fn outer_and_label_versions_reject_without_authority() {
    let valid = wire(b"Q", &db(&[], &[], &[]));
    for version in [0, 2, u8::MAX] {
        let mut bytes = valid.clone();
        bytes[0] = version;
        assert!(matches!(
            reject(&bytes, limits()),
            ArtifactError::Codec(CodecError::UnsupportedVersion { version: actual, .. })
                if actual == version
        ));
        let label = envelope(version, 0, b"run");
        assert!(matches!(
            reject_db(&db(&[public(&[label], &abi(None))], &[], &[])),
            ArtifactError::Codec(CodecError::InvalidLabel(_))
        ));
    }
}

#[test]
fn every_outer_and_nested_truncation_and_both_trailing_boundaries_reject() {
    let db = db(
        &[public(&[text("a"), text("run")], &abi(Some("Ω".as_bytes())))],
        &[raw_id(256), raw_id(1)],
        &[raw_id(256), raw_id(1), raw_id(2)],
    );
    let bytes = wire(b"Q", &db);
    InterfaceArtifactV1::decode_verified(
        &bytes,
        library_id(99),
        &TestProfile::new(TestOnlyDomain),
        &7,
        limits(),
    )
    .unwrap();
    for end in 0..bytes.len() {
        reject(&bytes[..end], limits());
    }
    for end in 0..db.len() {
        reject_db(&db[..end]);
    }
    let mut outer_trailing = bytes;
    outer_trailing.push(0);
    assert!(matches!(
        reject(&outer_trailing, limits()),
        ArtifactError::Codec(CodecError::TrailingBytes(_))
    ));
    let mut nested_trailing = db;
    nested_trailing.push(0);
    assert!(matches!(
        reject_db(&nested_trailing),
        ArtifactError::Codec(CodecError::TrailingBytes(_))
    ));
}

#[test]
fn every_word_limb_is_canonical_and_header_identity_is_never_reduced() {
    const MODULUS: u64 = 0xffff_ffff_0000_0001;
    let bytes = wire(b"Q", &db(&[], &[], &[]));
    for start in [1, 33] {
        for limb in 0..4 {
            for value in [MODULUS, u64::MAX] {
                let mut malformed = bytes.clone();
                let offset = start + limb * 8;
                malformed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                assert!(matches!(reject(&malformed, limits()), ArtifactError::InvalidWord { .. }));
            }
        }
    }
    // A reducing decoder would alias this to the expected external I=99; I is outside the hash.
    let mut alias = bytes;
    alias[1..9].copy_from_slice(&(MODULUS + 99).to_le_bytes());
    assert!(matches!(reject(&alias, limits()), ArtifactError::InvalidWord { .. }));
    for limb in 0..4 {
        let mut noncanonical = raw_id(1);
        noncanonical[limb * 8..limb * 8 + 8].copy_from_slice(&MODULUS.to_le_bytes());
        for (direct, closure) in
            [(vec![noncanonical], vec![raw_id(1)]), (vec![], vec![noncanonical])]
        {
            assert!(matches!(
                reject_db(&db(&[], &direct, &closure)),
                ArtifactError::InvalidWord { .. }
            ));
        }
    }
}

#[test]
fn empty_reserved_and_invalid_semantic_paths_reject_with_a_matching_commitment() {
    for components in [
        vec![],
        vec![text("")],
        vec![text("a"), text("")],
        vec![text("$kernel"), text("run")],
        vec![text("$exec"), text("run")],
        vec![text("$main")],
        vec![text("bad namespace"), text("run")],
        vec![text("bad#namespace"), text("run")],
        vec![text("bad name")],
        vec![text("bad\0name")],
        vec![text("\"run\"")],
        vec![text("e\u{301}")],
    ] {
        assert!(matches!(
            reject_db(&db(&[public(&components, &abi(None))], &[], &[raw_id(1)])),
            ArtifactError::InvalidDeclarations(_)
        ));
    }
    let invalid_utf8 = envelope(1, 0, &[0xff]);
    assert!(matches!(
        reject_db(&db(&[public(&[invalid_utf8], &abi(None))], &[], &[])),
        ArtifactError::Codec(CodecError::InvalidLabel(_))
    ));
}

#[test]
fn every_non_text_tag_rejects_before_any_external_typed_id_validation() {
    for tag in 1..=u8::MAX {
        let payload = match tag {
            1 => raw_id(1).to_vec(),
            2 => 1u32.to_le_bytes().to_vec(),
            3 => vec![1, 0, 0, 0, b'x'],
            _ => vec![b'x'],
        };
        let label = envelope(1, tag, &payload);
        assert!(matches!(
            reject_db(&db(&[public(&[label], &abi(None))], &[], &[])),
            ArtifactError::NonTextPublicLabel { tag: actual } if actual == tag
        ));
    }
}

#[test]
fn abi_discriminants_and_present_payload_utf8_are_strict() {
    for tag in [2, 3, u8::MAX] {
        assert!(matches!(
            reject_db(&db(&[public(&[text("run")], &[tag])], &[], &[])),
            ArtifactError::InvalidAbiDiscriminator { tag: actual } if actual == tag
        ));
    }
    for payload in [&[0xff][..], &[0xc0, 0xaf], &[0xe2, 0x82]] {
        assert!(matches!(
            reject_db(&db(&[public(&[text("run")], &abi(Some(payload)))], &[], &[])),
            ArtifactError::InvalidAbiUtf8(_)
        ));
    }
}

#[test]
fn raw_public_order_uses_envelope_vectors_prefixes_and_little_endian_lengths() {
    let a = public(&[text("a")], &abi(None));
    let az = public(&[text("a"), text("z")], &abi(None));
    let z = public(&[text("z")], &abi(None));
    let aa = public(&[text("aa")], &abi(None));
    let canonical = wire(b"Q", &db(&[a.clone(), az.clone(), z.clone(), aa.clone()], &[], &[]));
    let profile = TestProfile::new(TestOnlyDomain);
    let decoded =
        InterfaceArtifactV1::decode_verified(&canonical, library_id(99), &profile, &7, limits())
            .unwrap();
    assert_eq!(decoded.encode_v1(&profile, &7, limits()).unwrap(), canonical);
    for public in [
        vec![aa.clone(), z], // String ordering disagrees with complete envelope ordering.
        vec![aa, az.clone()], // Serialized component counts must not define vector order.
        vec![az, a.clone()], // A path prefix precedes its extension.
        vec![a.clone(), a.clone()],
        vec![a, public(&[text("a")], &abi(Some(b"")))], // ABI cannot distinguish paths.
    ] {
        assert!(matches!(
            reject_db(&db(&public, &[], &[])),
            ArtifactError::NonCanonicalPublicPathOrder
        ));
    }
    let short = public(&[text(&"a".repeat(255))], &abi(None));
    let long = public(&[text(&"a".repeat(256))], &abi(None));
    let canonical = wire(b"Q", &db(&[long.clone(), short.clone()], &[], &[]));
    InterfaceArtifactV1::decode_verified(&canonical, library_id(99), &profile, &7, limits())
        .unwrap();
    assert!(matches!(
        reject_db(&db(&[short, long], &[], &[])),
        ArtifactError::NonCanonicalPublicPathOrder
    ));
}

#[test]
fn raw_id_sets_require_strict_canonical_byte_order_and_uniqueness() {
    let canonical =
        wire(b"Q", &db(&[], &[raw_id(256), raw_id(1)], &[raw_id(256), raw_id(1), raw_id(2)]));
    let profile = TestProfile::new(TestOnlyDomain);
    let decoded =
        InterfaceArtifactV1::decode_verified(&canonical, library_id(99), &profile, &7, limits())
            .unwrap();
    assert_eq!(decoded.encode_v1(&profile, &7, limits()).unwrap(), canonical);
    for (direct, closure, kind) in [
        (vec![raw_id(1), raw_id(256)], vec![raw_id(256), raw_id(1)], "direct"),
        (vec![], vec![raw_id(1), raw_id(256)], "closure"),
    ] {
        assert!(matches!(
            reject_db(&db(&[], &direct, &closure)),
            ArtifactError::NonCanonicalLibraryIdOrder { kind: actual } if actual == kind
        ));
    }
    for (direct, closure, kind) in [
        (vec![raw_id(1); 2], vec![raw_id(1)], "direct"),
        (vec![], vec![raw_id(1); 2], "closure"),
    ] {
        assert!(matches!(
            reject_db(&db(&[], &direct, &closure)),
            ArtifactError::DuplicateLibraryId { kind: actual, .. } if actual == kind
        ));
    }
}

#[test]
fn own_identity_and_direct_subset_constraints_precede_authority() {
    for (direct, closure, kind) in [
        (vec![raw_id(99)], vec![raw_id(99)], "direct"),
        (vec![], vec![raw_id(99)], "closure"),
    ] {
        assert!(matches!(
            reject_db(&db(&[], &direct, &closure)),
            ArtifactError::OwnLibraryId { kind: actual } if actual == kind
        ));
    }
    assert!(matches!(
        reject_db(&db(&[], &[raw_id(1)], &[raw_id(2)])),
        ArtifactError::MissingDirectRequirement { id } if id == library_id(1)
    ));
}

#[test]
fn expected_identity_commitment_and_profile_domain_reject_before_authority() {
    let bytes = wire(b"Q", &db(&[], &[], &[]));
    let profile = TestProfile::new(TestOnlyDomain);
    assert!(matches!(
        InterfaceArtifactV1::decode_verified(&bytes, library_id(100), &profile, &7, limits()),
        Err(ArtifactError::UnexpectedLibraryId { expected, actual })
            if expected == library_id(100) && actual == library_id(99)
    ));
    no_callbacks(&profile);
    let mut changed_identity = bytes.clone();
    changed_identity[1..33].copy_from_slice(&raw_id(100));
    assert!(matches!(
        reject(&changed_identity, limits()),
        ArtifactError::UnexpectedLibraryId { .. }
    ));
    let mut changed_commitment = bytes.clone();
    changed_commitment[33..65].copy_from_slice(&raw_id(0));
    assert!(matches!(
        reject(&changed_commitment, limits()),
        ArtifactError::CommitmentMismatch
    ));
    let mut changed_descriptor = bytes.clone();
    changed_descriptor[69] = b'R';
    assert!(matches!(
        reject(&changed_descriptor, limits()),
        ArtifactError::CommitmentMismatch
    ));
    let mut changed_db = wire(b"Q", &db(&[public(&[text("a")], &abi(None))], &[], &[]));
    changed_db[88] = b'b'; // Canonical Text payload changes; its original Cdecl stays fixed.
    assert!(matches!(reject(&changed_db, limits()), ArtifactError::CommitmentMismatch));
    let changed = TestProfile::new(OtherTestOnlyDomain);
    assert!(matches!(
        InterfaceArtifactV1::decode_verified(&bytes, library_id(99), &changed, &7, limits()),
        Err(ArtifactError::CommitmentMismatch)
    ));
    no_callbacks(&changed);
    fn rejects_domain<D: EidosDomain<Encoding = FeltSequence>>(bytes: &[u8], domain: D) {
        let profile = TestProfile::new(domain);
        assert!(matches!(
            InterfaceArtifactV1::decode_verified(bytes, library_id(99), &profile, &7, limits()),
            Err(ArtifactError::InvalidDeclarationDomain { .. })
        ));
        no_callbacks(&profile);
    }
    rejects_domain(&bytes, WrongNamespace);
    rejects_domain(&bytes, WrongVersion);
    rejects_domain(&bytes, DelegatedVersion);
}

#[test]
fn aggregate_budgets_accept_exact_totals_and_reject_each_one_below() {
    let db = db(
        &[
            public(&[text("a"), text("b")], &abi(Some("Ω".as_bytes()))),
            public(&[text("z")], &abi(Some(b""))),
        ],
        &[raw_id(1)],
        &[raw_id(1), raw_id(2)],
    );
    let bytes = wire(b"Q", &db);
    // 2 declarations + 3 IDs; 3 labels; Q0 + 3 label bytes + 2 ABI bytes.
    assert_eq!(bytes.len(), 223);
    let exact = CodecLimits::new(223, 5, 3, 6);
    InterfaceArtifactV1::decode_verified(
        &bytes,
        library_id(99),
        &TestProfile::new(TestOnlyDomain),
        &7,
        exact,
    )
    .unwrap();
    for (limits, resource) in [
        (CodecLimits::new(222, 5, 3, 6), "wire bytes"),
        (CodecLimits::new(223, 4, 3, 6), "records"),
        (CodecLimits::new(223, 5, 2, 6), "components"),
        (CodecLimits::new(223, 5, 3, 5), "blob bytes"),
    ] {
        assert!(matches!(
            reject(&bytes, limits),
            ArtifactError::Codec(CodecError::LimitExceeded { resource: actual, .. })
                if actual == resource
        ));
    }
}

#[test]
fn huge_counts_and_lengths_fail_remaining_wire_or_layout_checks_before_allocation() {
    let generous = CodecLimits::new(u32::MAX, u32::MAX, u32::MAX, u32::MAX);
    let empty = wire(b"", &db(&[], &[], &[]));
    for offset in [65, 69] {
        let mut bytes = empty.clone();
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            reject(&bytes, generous),
            ArtifactError::Codec(CodecError::Truncated(_) | CodecError::LengthOverflow(_))
        ));
    }
    let mut impossible_public = vec![];
    push_u32(&mut impossible_public, u32::MAX as usize);
    impossible_public.extend_from_slice(&[0; 8]);
    let mut impossible_components = vec![1, 0, 0, 0];
    push_u32(&mut impossible_components, u32::MAX as usize);
    impossible_components.extend_from_slice(&[0; 9]);
    let mut impossible_direct = vec![0; 4];
    push_u32(&mut impossible_direct, u32::MAX as usize);
    impossible_direct.extend_from_slice(&[0; 4]);
    let mut impossible_closure = vec![0; 8];
    push_u32(&mut impossible_closure, u32::MAX as usize);
    let mut huge_label = vec![1, 0];
    push_u32(&mut huge_label, u32::MAX as usize);
    let mut huge_abi = vec![1];
    push_u32(&mut huge_abi, (u32::MAX - 1) as usize);
    for db in [
        impossible_public,
        impossible_components,
        impossible_direct,
        impossible_closure,
        db(&[public(&[huge_label], &abi(None))], &[], &[raw_id(1)]),
        db(&[public(&[text("a")], &huge_abi)], &[], &[]),
    ] {
        assert!(matches!(
            reject(&wire(b"", &db), generous),
            ArtifactError::Codec(CodecError::Truncated(_) | CodecError::LengthOverflow(_))
        ));
    }
}

#[test]
fn each_authority_and_context_rejection_short_circuits_in_the_required_order() {
    let bytes = wire(b"Q", &db(&[], &[raw_id(1)], &[raw_id(1)]));
    let order = [
        ArtifactProfileOperation::PublisherDescriptor,
        ArtifactProfileOperation::Association,
        ArtifactProfileOperation::DependencyClosure,
    ];
    let successful = TestProfile::new(TestOnlyDomain);
    InterfaceArtifactV1::decode_verified(&bytes, library_id(99), &successful, &7, limits())
        .unwrap();
    assert_eq!(*successful.calls.borrow(), order);
    for (index, operation) in order.into_iter().enumerate() {
        let mut profile = TestProfile::new(TestOnlyDomain);
        profile.reject = Some(operation);
        assert!(matches!(
            InterfaceArtifactV1::decode_verified(&bytes, library_id(99), &profile, &7, limits()),
            Err(ArtifactError::ProfileRejected { operation: actual, .. }) if actual == operation
        ));
        assert_eq!(*profile.calls.borrow(), order[..=index]);
        assert_eq!(profile.typed_id_calls.get(), 0);
    }
    let context = TestProfile::new(TestOnlyDomain);
    assert!(matches!(
        InterfaceArtifactV1::decode_verified(&bytes, library_id(99), &context, &8, limits()),
        Err(ArtifactError::ProfileRejected {
            operation: ArtifactProfileOperation::PublisherDescriptor,
            ..
        })
    ));
    assert_eq!(*context.calls.borrow(), order[..1]);
    let descriptor = TestProfile::new(TestOnlyDomain);
    assert!(matches!(
        InterfaceArtifactV1::decode_verified(
            &wire(b"unknown", &db(&[], &[], &[])),
            library_id(99),
            &descriptor,
            &7,
            limits(),
        ),
        Err(ArtifactError::ProfileRejected {
            operation: ArtifactProfileOperation::PublisherDescriptor,
            ..
        })
    ));
    assert_eq!(*descriptor.calls.borrow(), order[..1]);
}
