use core::cell::{Cell, RefCell};

use miden_assembly_syntax::ast::types::{CallConv, FunctionType, Type};
use miden_core::program::CanonicalLabel;
use miden_crypto::hash::eidos::DELEGATED_VERSIONING;

use super::*;
use crate::interface::{ProcedureDeclaration, PublicProcedurePath};

mod decoding;

// Synthetic test markers only: these IDs make no Protocol allocation or registry claim.
macro_rules! test_domain {
    ($name:ident, $namespace:expr, $local:expr, $version:expr) => {
        #[derive(Clone, Copy)]
        struct $name;
        impl EidosDomain for $name {
            type Encoding = FeltSequence;
            const NAME: &'static str = stringify!($name);
            const TAG: DomainTag = DomainTag::new($namespace, $local, $version);
        }
    };
}
test_domain!(TestOnlyDomain, namespace::MIDEN_PROTOCOL, 0xfffe, DomainVersion::numbered(1));
test_domain!(
    OtherTestOnlyDomain,
    namespace::MIDEN_PROTOCOL,
    0xfffd,
    DomainVersion::numbered(1)
);
test_domain!(WrongNamespace, namespace::MIDEN_VM, 0xfffe, DomainVersion::numbered(1));
test_domain!(WrongVersion, namespace::MIDEN_PROTOCOL, 0xfffe, DomainVersion::numbered(2));
test_domain!(DelegatedVersion, namespace::MIDEN_PROTOCOL, 0xfffe, DELEGATED_VERSIONING);

struct TestProfile<D> {
    domain: D,
    reject: Option<ArtifactProfileOperation>,
    calls: RefCell<Vec<ArtifactProfileOperation>>,
    typed_id_calls: Cell<usize>,
}

impl<D> TestProfile<D> {
    fn new(domain: D) -> Self {
        Self {
            domain,
            reject: None,
            calls: RefCell::new(Vec::new()),
            typed_id_calls: Cell::new(0),
        }
    }

    fn validate(
        &self,
        context: &u8,
        operation: ArtifactProfileOperation,
    ) -> Result<(), &'static str> {
        self.calls.borrow_mut().push(operation);
        if *context != 7 || self.reject == Some(operation) {
            return Err("test evidence rejected");
        }
        Ok(())
    }
}

impl<D> TypedIdProfile for TestProfile<D> {
    type Context = u8;
    type Error = &'static str;

    fn validate_typed_id(&self, _: &u8, _: u32, _: &[u8]) -> Result<(), Self::Error> {
        self.typed_id_calls.set(self.typed_id_calls.get() + 1);
        Err("no test TypedId codec")
    }
}

impl<D: EidosDomain<Encoding = FeltSequence>> InterfaceProfile for TestProfile<D> {
    type DeclarationDomain = D;

    fn declaration_domain(&self) -> D {
        self.domain
    }

    fn validate_publisher_descriptor(
        &self,
        context: &u8,
        descriptor: &[u8],
    ) -> Result<(), Self::Error> {
        self.validate(context, ArtifactProfileOperation::PublisherDescriptor)?;
        if !matches!(descriptor, b"" | b"Q") {
            return Err("unknown test descriptor");
        }
        Ok(())
    }

    fn validate_association(
        &self,
        context: &u8,
        _: &[u8],
        id: LibraryId,
        _: DeclarationCommitment,
    ) -> Result<(), Self::Error> {
        self.validate(context, ArtifactProfileOperation::Association)?;
        if id != library_id(99) {
            return Err("wrong test identity");
        }
        Ok(())
    }

    fn validate_dependency_closure(
        &self,
        context: &u8,
        _: LibraryId,
        _: &[LibraryId],
        _: &[LibraryId],
    ) -> Result<(), Self::Error> {
        // Real profiles must authenticate contributing declarations, not just accept structure.
        self.validate(context, ArtifactProfileOperation::DependencyClosure)
    }
}

fn limits() -> CodecLimits {
    CodecLimits::new(10_000, 100, 100, 10_000)
}

fn library_id(first: u32) -> LibraryId {
    LibraryId::new(Word::new([Felt::from_u32(first), Felt::ZERO, Felt::ZERO, Felt::ZERO]))
}

fn declaration(components: &[&str], abi: Option<&str>) -> ProcedureDeclaration {
    ProcedureDeclaration::new(
        PublicProcedurePath::from_semantic_components(
            components.iter().map(|text| (*text).into()).collect(),
        )
        .unwrap(),
        abi.map(Into::into),
    )
}

fn verified_artifact(
    declarations: Vec<ProcedureDeclaration>,
    direct: Vec<LibraryId>,
    closure: Vec<LibraryId>,
) -> InterfaceArtifactV1 {
    InterfaceArtifactV1::new_verified(
        library_id(99),
        b"Q".to_vec(),
        DeclarationSet::new(declarations).unwrap(),
        direct,
        closure,
        &TestProfile::new(TestOnlyDomain),
        &7,
        limits(),
    )
    .unwrap()
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "test hex must contain complete byte pairs");
    pairs
        .iter()
        .map(|pair| {
            let digit = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("bad test hex"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

#[test]
fn empty_interface_has_independent_canonical_wire_and_hash_preimage() {
    let profile = TestProfile::new(TestOnlyDomain);
    let artifact = InterfaceArtifactV1::new_verified(
        library_id(99),
        Vec::new(),
        DeclarationSet::new([]).unwrap(),
        Vec::new(),
        Vec::new(),
        &profile,
        &7,
        CodecLimits::new(85, 0, 0, 0),
    )
    .unwrap();
    // DB is three zero counts; DCL is B(empty Q0) followed by DB: sixteen zero bytes.
    let expected_commitment = hasher::hash_elements_in_domain(
        &[Felt::ONE, Felt::from_u32(16), Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO],
        TestOnlyDomain,
    );
    assert_eq!(artifact.commitment().into_word(), expected_commitment);
    let mut expected = vec![1];
    expected.extend_from_slice(&library_id(99).as_word().as_bytes());
    expected.extend_from_slice(&expected_commitment.as_bytes());
    expected.extend_from_slice(&[0, 0, 0, 0, 12, 0, 0, 0]);
    expected.extend_from_slice(&[0; 12]);
    assert_eq!(
        artifact.encode_v1(&profile, &7, CodecLimits::new(85, 0, 0, 0)).unwrap(),
        expected
    );
}

#[test]
fn envelope_order_and_present_empty_abi_have_independent_wire_and_hash_preimage() {
    let artifact = verified_artifact(
        vec![declaration(&["aa"], Some("")), declaration(&["z"], None)],
        vec![],
        vec![],
    );
    // Envelope length bytes place z before aa, while DeclarationSet/String order is aa,z.
    let db = hex_bytes(
        "02000000010000000100010000007a0001000000010002000000616101000000000000000000000000",
    );
    let payload = [
        1, 46, 1, 593, 256, 16777472, 2046820352, 256, 33554688, 1627389952, 353, 0, 0, 0,
    ]
    .map(Felt::from_u32);
    let commitment = hasher::hash_elements_in_domain(&payload, TestOnlyDomain);
    assert_eq!(artifact.commitment().into_word(), commitment);
    let mut expected = vec![1];
    expected.extend_from_slice(&library_id(99).as_word().as_bytes());
    expected.extend_from_slice(&commitment.as_bytes());
    expected.extend_from_slice(&[1, 0, 0, 0, b'Q', 41, 0, 0, 0]);
    expected.extend(db);
    assert_eq!(
        artifact.encode_v1(&TestProfile::new(TestOnlyDomain), &7, limits()).unwrap(),
        expected
    );
    let absent = verified_artifact(vec![declaration(&["aa"], None)], vec![], vec![]);
    let present = verified_artifact(vec![declaration(&["aa"], Some(""))], vec![], vec![]);
    assert_ne!(absent.commitment(), present.commitment());
}

#[test]
fn text_envelope_length_order_uses_little_endian_bytes_not_numeric_lengths() {
    let short = "a".repeat(255);
    let long = "a".repeat(256);
    let artifact = verified_artifact(
        vec![declaration(&[&short], None), declaration(&[&long], None)],
        vec![],
        vec![],
    );
    let bytes = artifact.encode_v1(&TestProfile::new(TestOnlyDomain), &7, limits()).unwrap();
    // 256 encodes as [0,1,0,0], preceding 255's [255,0,0,0] in unsigned byte order.
    // Build DB independently from literal count/path/envelope/ABI framing, without the encoder.
    let mut expected_db = vec![2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0];
    expected_db.extend_from_slice(&[b'a'; 256]);
    expected_db.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, 255, 0, 0, 0]);
    expected_db.extend_from_slice(&[b'a'; 255]);
    expected_db.extend_from_slice(&[0; 9]); // absent ABI and empty direct/closure ID sets
    assert_eq!(&bytes[74..], expected_db);
}

#[test]
fn exact_semantic_components_and_path_prefixes_survive_encoding() {
    let inputs = [
        declaration(&["a", "b"], None),
        declaration(&["a"], None),
        declaration(&["a::b"], Some("Å\r\n")),
        declaration(&["f#tag"], None),
        declaration(&[r"f\tag"], None),
        declaration(&["Å"], None),
        declaration(&["Å"], None),
    ];
    let artifact = verified_artifact(inputs.to_vec(), vec![], vec![]);
    let bytes = artifact.encode_v1(&TestProfile::new(TestOnlyDomain), &7, limits()).unwrap();
    let db = &bytes[74..]; // version, I, Cdecl, B(Q0='Q'), DB length
    // Prefix paths compare before extensions, independently of the serialized P component count.
    assert_eq!(&db[..15], &[7, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, b'a']);
    for input in inputs {
        for component in input.path().components() {
            let envelope = CanonicalLabel::text(component).unwrap();
            assert!(
                db.windows(envelope.as_bytes().len())
                    .any(|window| window == envelope.as_bytes())
            );
        }
    }
    assert!(db.windows("Å\r\n".len()).any(|window| window == "Å\r\n".as_bytes()));
}

#[test]
fn native_id_order_canonicalizes_by_word_bytes_and_rejects_every_duplicate() {
    let artifact = verified_artifact(
        vec![],
        vec![library_id(1), library_id(256)],
        vec![library_id(1), library_id(2), library_id(256)],
    );
    assert_eq!(artifact.direct_requirements(), &[library_id(256), library_id(1)]);
    assert_eq!(artifact.dependency_closure(), &[library_id(256), library_id(1), library_id(2)]);
    let wire = artifact.encode_v1(&TestProfile::new(TestOnlyDomain), &7, limits()).unwrap();
    assert_eq!(&wire[82..114], &library_id(256).as_word().as_bytes());
    for (direct, closure, kind) in [
        (vec![library_id(1); 2], vec![library_id(1)], "direct"),
        (vec![], vec![library_id(1); 2], "closure"),
    ] {
        let profile = TestProfile::new(TestOnlyDomain);
        assert!(
            matches!(InterfaceArtifactV1::new_verified(library_id(99), vec![], DeclarationSet::new([]).unwrap(), direct, closure, &profile, &7, limits()), Err(ArtifactError::DuplicateLibraryId { kind: actual, .. }) if actual == kind)
        );
        assert!(profile.calls.borrow().is_empty());
    }
}

#[test]
fn self_exclusion_direct_inclusion_and_external_completeness_are_distinct() {
    for (direct, closure, expected_kind) in [
        (vec![library_id(99)], vec![], Some("direct")),
        (vec![], vec![library_id(99)], Some("closure")),
        (vec![library_id(1)], vec![], None),
    ] {
        let profile = TestProfile::new(TestOnlyDomain);
        let result = InterfaceArtifactV1::new_verified(
            library_id(99),
            vec![],
            DeclarationSet::new([]).unwrap(),
            direct,
            closure,
            &profile,
            &7,
            limits(),
        );
        match expected_kind {
            Some(kind) => assert!(
                matches!(result, Err(ArtifactError::OwnLibraryId { kind: actual }) if actual == kind)
            ),
            None => assert!(matches!(result, Err(ArtifactError::MissingDirectRequirement { .. }))),
        }
        assert!(profile.calls.borrow().is_empty());
    }
    let mut profile = TestProfile::new(TestOnlyDomain);
    profile.reject = Some(ArtifactProfileOperation::DependencyClosure);
    assert!(matches!(
        InterfaceArtifactV1::new_verified(
            library_id(99),
            vec![],
            DeclarationSet::new([]).unwrap(),
            vec![library_id(1)],
            vec![library_id(1)],
            &profile,
            &7,
            limits()
        ),
        Err(ArtifactError::ProfileRejected {
            operation: ArtifactProfileOperation::DependencyClosure,
            ..
        })
    ));
}

#[test]
fn profile_domain_context_and_every_authority_callback_are_required() {
    let order = [
        ArtifactProfileOperation::PublisherDescriptor,
        ArtifactProfileOperation::Association,
        ArtifactProfileOperation::DependencyClosure,
    ];
    let successful_profile = TestProfile::new(TestOnlyDomain);
    let artifact = InterfaceArtifactV1::new_verified(
        library_id(99),
        vec![],
        DeclarationSet::new([]).unwrap(),
        vec![],
        vec![],
        &successful_profile,
        &7,
        limits(),
    )
    .unwrap();
    assert_eq!(*successful_profile.calls.borrow(), order);
    successful_profile.calls.borrow_mut().clear();
    artifact.encode_v1(&successful_profile, &7, limits()).unwrap();
    assert_eq!(*successful_profile.calls.borrow(), order);
    for (index, reject) in order.into_iter().enumerate() {
        let mut profile = TestProfile::new(TestOnlyDomain);
        profile.reject = Some(reject);
        assert!(
            matches!(InterfaceArtifactV1::new_verified(library_id(99), vec![], DeclarationSet::new([]).unwrap(), vec![], vec![], &profile, &7, limits()), Err(ArtifactError::ProfileRejected { operation, .. }) if operation == reject)
        );
        assert_eq!(*profile.calls.borrow(), order[..=index]);
        profile.calls.borrow_mut().clear();
        assert!(
            matches!(artifact.encode_v1(&profile, &7, limits()), Err(ArtifactError::ProfileRejected { operation, .. }) if operation == reject)
        );
        assert_eq!(*profile.calls.borrow(), order[..=index]);
    }
    let wrong_context = TestProfile::new(TestOnlyDomain);
    assert!(matches!(
        artifact.encode_v1(&wrong_context, &8, limits()),
        Err(ArtifactError::ProfileRejected { .. })
    ));
    assert_eq!(*wrong_context.calls.borrow(), order[..1]);
    let changed = TestProfile::new(OtherTestOnlyDomain);
    assert!(matches!(
        artifact.encode_v1(&changed, &7, limits()),
        Err(ArtifactError::CommitmentMismatch)
    ));
    assert!(changed.calls.borrow().is_empty());
    fn rejects_domain<D: EidosDomain<Encoding = FeltSequence>>(domain: D) {
        let profile = TestProfile::new(domain);
        assert!(matches!(
            InterfaceArtifactV1::new_verified(
                library_id(99),
                vec![],
                DeclarationSet::new([]).unwrap(),
                vec![],
                vec![],
                &profile,
                &7,
                limits()
            ),
            Err(ArtifactError::InvalidDeclarationDomain { .. })
        ));
        assert!(profile.calls.borrow().is_empty());
    }
    rejects_domain(WrongNamespace);
    rejects_domain(WrongVersion);
    rejects_domain(DelegatedVersion);
}

#[test]
fn aggregate_limits_precede_hashing_and_authority_with_exact_boundaries() {
    let declarations =
        DeclarationSet::new([declaration(&["z"], Some("")), declaration(&["aa"], None)]).unwrap();
    // Q0 + Text payloads = 1 + 1 + 2; 2 public and 2 ID records, 2 components.
    let exact = CodecLimits::new(179, 4, 2, 4);
    let artifact = InterfaceArtifactV1::new_verified(
        library_id(99),
        b"Q".to_vec(),
        declarations.clone(),
        vec![library_id(1)],
        vec![library_id(1)],
        &TestProfile::new(TestOnlyDomain),
        &7,
        exact,
    )
    .unwrap();
    assert_eq!(
        artifact.encode_v1(&TestProfile::new(TestOnlyDomain), &7, exact).unwrap().len(),
        179
    );
    for limits in [
        CodecLimits::new(178, 4, 2, 4),
        CodecLimits::new(179, 3, 2, 4),
        CodecLimits::new(179, 4, 1, 4),
        CodecLimits::new(179, 4, 2, 3),
    ] {
        let profile = TestProfile::new(TestOnlyDomain);
        assert!(matches!(
            artifact.encode_v1(&profile, &7, limits),
            Err(ArtifactError::Codec(CodecError::LimitExceeded { .. }))
        ));
        assert!(profile.calls.borrow().is_empty());
        assert!(matches!(
            InterfaceArtifactV1::new_verified(
                library_id(99),
                b"Q".to_vec(),
                declarations.clone(),
                vec![library_id(1)],
                vec![library_id(1)],
                &profile,
                &7,
                limits
            ),
            Err(ArtifactError::Codec(CodecError::LimitExceeded { .. }))
        ));
        assert!(profile.calls.borrow().is_empty());
    }
}

#[test]
fn tooling_signatures_are_retained_but_excluded_from_wire_hash_and_authority() {
    let plain = declaration(&["run"], Some("opaque"));
    let typed =
        plain
            .clone()
            .with_signature(FunctionType::new(CallConv::Fast, [Type::U32], [Type::U32]));
    let plain = verified_artifact(vec![plain], vec![], vec![]);
    let typed = verified_artifact(vec![typed], vec![], vec![]);
    assert!(typed.declarations().iter().next().unwrap().signature().is_some());
    assert_ne!(plain, typed);
    assert_eq!(plain.commitment(), typed.commitment());
    let profile = TestProfile::new(TestOnlyDomain);
    assert_eq!(
        plain.encode_v1(&profile, &7, limits()).unwrap(),
        typed.encode_v1(&profile, &7, limits()).unwrap()
    );
}
