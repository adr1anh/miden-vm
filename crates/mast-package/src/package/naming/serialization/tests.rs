use alloc::vec;
use core::cell::Cell;

use miden_core::{
    Felt,
    program::{CanonicalLabel, ImplementationRoot},
};

use super::*;
use crate::{
    CallableBinding, CallableProcedurePath, PackageCallables, PackageCallablesError,
    interface::serialization::{ProfileOperation, TypedIdProfile},
};

type Error = NamingCodecError<&'static str>;

#[derive(Default)]
struct Profile {
    typed_calls: Cell<usize>,
    home_calls: Cell<usize>,
}

struct Context {
    homes: Vec<Vec<CanonicalLabel>>,
    permit_typed: bool,
}

impl TypedIdProfile for Profile {
    type Context = Context;
    type Error = &'static str;

    fn validate_typed_id(
        &self,
        context: &Context,
        codec: u32,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.typed_calls.set(self.typed_calls.get() + 1);
        if codec != 77 {
            Err("unknown codec")
        } else if bytes != [0xa5, 0, 0xff] {
            Err("noncanonical ID")
        } else if !context.permit_typed {
            Err("TypedId forbidden")
        } else {
            Ok(())
        }
    }
}

impl HomeProfile for Profile {
    fn validate_home(&self, context: &Context, home: &[CanonicalLabel]) -> Result<(), Self::Error> {
        self.home_calls.set(self.home_calls.get() + 1);
        if context.homes.iter().any(|permitted| permitted == home) {
            Ok(())
        } else {
            Err("home association mismatch")
        }
    }
}

fn typed(codec: u32) -> CanonicalLabel {
    // In-memory construction grants no selected-profile admission.
    CanonicalLabel::typed_id(codec, &[0xa5, 0, 0xff], |_, _| Ok(())).unwrap()
}

fn limits() -> CodecLimits {
    CodecLimits::new(65536, 4096, 4096, 65536)
}

fn fixture() -> (PackageNaming, Context) {
    let own_home = vec![typed(77)];
    let entry_home = vec![CanonicalLabel::text("e").unwrap()];
    let unused_home = vec![CanonicalLabel::text("u").unwrap(), typed(77)];
    let entry = CallableBinding::new(
        NamespacePlan::new(entry_home.clone()),
        CallableProcedurePath::from_semantic_components(vec!["run".into()]).unwrap(),
    )
    .unwrap();
    let unused = CallableBinding::new(
        NamespacePlan::new(unused_home.clone()),
        CallableProcedurePath::from_semantic_components(vec!["hidden".into()]).unwrap(),
    )
    .unwrap();
    let key = entry.key();
    let callables = PackageCallables::new([entry, unused], [], []).unwrap();
    (
        PackageNaming::new(NamespacePlan::new(own_home.clone()), callables, Some(key)).unwrap(),
        Context {
            homes: vec![own_home, entry_home, unused_home],
            permit_typed: true,
        },
    )
}

fn assert_no_policy(profile: &Profile) {
    assert_eq!(profile.typed_calls.get(), 0);
    assert_eq!(profile.home_calls.get(), 0);
}

fn resource(error: &Error) -> Option<&'static str> {
    match error {
        Error::Codec(CodecError::LimitExceeded { resource, .. })
        | Error::Callables(CallablesCodecError::Codec(CodecError::LimitExceeded {
            resource,
            ..
        })) => Some(*resource),
        _ => None,
    }
}

#[test]
fn empty_wire_golden_requires_explicit_n0_admission() {
    let naming = PackageNaming::new(
        NamespacePlan::new(vec![]),
        PackageCallables::new([], [], []).unwrap(),
        None,
    )
    .unwrap();
    let bytes = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let exact = CodecLimits::new(20, 0, 0, 0);
    let context = Context { homes: vec![vec![]], permit_typed: true };
    let profile = Profile::default();
    assert_eq!(naming.encode_unverified_v1(exact).unwrap(), bytes);
    let raw = UnverifiedPackageNaming::from_bytes_with_limits(&bytes, exact).unwrap();
    assert_eq!(raw.as_bytes(), bytes);
    assert_no_policy(&profile);
    assert_eq!(naming.encode_v1(&profile, &context, exact).unwrap(), bytes);
    assert_eq!(raw.decode(&profile, &context, exact).unwrap(), naming);
    assert_eq!(profile.home_calls.get(), 2);
    let forbidden = Context { homes: vec![], permit_typed: true };
    assert!(matches!(
        raw.decode(&profile, &forbidden, exact),
        Err(Error::Codec(CodecError::ProfileRejected {
            operation: ProfileOperation::Home,
            ..
        }))
    ));
}

#[test]
fn aggregate_exact_bounds_include_own_home_entry_and_unused_bindings() {
    let (naming, context) = fixture();
    // Own Home18 + outer version/tag2 + entry32 + inventory143 = 195 wire bytes.
    // Home labels4 + entry1 + declarations2 = 7 records. Home labels4 + paths2 = 6
    // components. Home payloads(7+1+1+7) + path UTF-8(3+6) = 25 blob bytes.
    let exact = CodecLimits::new(195, 7, 6, 25);
    let bytes = naming.encode_unverified_v1(exact).unwrap();
    assert_eq!(bytes.len(), 195);
    assert_eq!(naming.callables().bindings().count(), 2);
    let profile = Profile::default();
    assert_eq!(naming.encode_v1(&profile, &context, exact).unwrap(), bytes);
    assert_eq!(PackageNaming::decode_v1(&bytes, &profile, &context, exact).unwrap(), naming);
    assert_eq!(profile.typed_calls.get(), 4);
    assert_eq!(profile.home_calls.get(), 6);

    for (bounded, expected) in [
        (CodecLimits::new(194, 7, 6, 25), "wire bytes"),
        (CodecLimits::new(195, 6, 6, 25), "records"),
        (CodecLimits::new(195, 7, 5, 25), "components"),
        (CodecLimits::new(195, 7, 6, 24), "blob bytes"),
    ] {
        for decode in [false, true] {
            let profile = Profile::default();
            let result = if decode {
                PackageNaming::decode_v1(&bytes, &profile, &context, bounded).map(|_| ())
            } else {
                naming.encode_v1(&profile, &context, bounded).map(|_| ())
            };
            let error = result.unwrap_err();
            assert_eq!(resource(&error), Some(expected), "{error}");
            assert_no_policy(&profile);
        }
        assert!(UnverifiedPackageNaming::new(bytes.clone(), bounded).is_err());
    }
}

#[test]
fn all_truncations_counts_versions_and_trailing_bytes_precede_policy() {
    let (naming, context) = fixture();
    let bytes = naming.encode_unverified_v1(limits()).unwrap();
    for end in 0..bytes.len() {
        let profile = Profile::default();
        assert!(PackageNaming::decode_v1(&bytes[..end], &profile, &context, limits()).is_err());
        assert_no_policy(&profile);
    }
    for offset in [2, 53] {
        // Own HomeV1 label count and callable binding count.
        let mut bad = bytes.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let profile = Profile::default();
        assert!(PackageNaming::decode_v1(&bad, &profile, &context, limits()).is_err());
        assert_no_policy(&profile);
    }
    for offset in [0, 1, 52] {
        let mut bad = bytes.clone();
        bad[offset] = 2;
        let profile = Profile::default();
        assert!(PackageNaming::decode_v1(&bad, &profile, &context, limits()).is_err());
        assert_no_policy(&profile);
    }
    let mut bad = bytes;
    bad.push(0);
    let profile = Profile::default();
    assert!(matches!(
        PackageNaming::decode_v1(&bad, &profile, &context, limits()),
        Err(Error::Codec(CodecError::TrailingBytes("NamingV1")))
    ));
    assert_no_policy(&profile);
}

#[test]
fn entry_tags_and_noncanonical_words_fail_before_any_callback() {
    let (naming, context) = fixture();
    let bytes = naming.encode_unverified_v1(limits()).unwrap();
    for tag in [2, 255] {
        let mut bad = bytes.clone();
        bad[19] = tag;
        let profile = Profile::default();
        assert!(matches!(
            PackageNaming::decode_v1(&bad, &profile, &context, limits()),
            Err(Error::InvalidEntryTag { tag: actual }) if actual == tag
        ));
        assert_no_policy(&profile);
    }
    for lane in 0..4 {
        let mut bad = bytes.clone();
        bad[20 + lane * 8..28 + lane * 8].copy_from_slice(&Felt::ORDER.to_le_bytes());
        let profile = Profile::default();
        assert!(matches!(
            PackageNaming::decode_v1(&bad, &profile, &context, limits()),
            Err(Error::InvalidEntryKey)
        ));
        assert_no_policy(&profile);
        assert!(UnverifiedPackageNaming::new(bad, limits()).is_err());
    }
}

#[test]
fn structurally_valid_raw_entry_must_still_reference_a_declaration_on_admission() {
    let (naming, context) = fixture();
    let mut bytes = naming.encode_unverified_v1(limits()).unwrap();
    let key = ProcedureKey::new(Word::new([11; 4].map(Felt::from_u32)));
    assert!(naming.callables().binding(key).is_none());
    bytes[20..52].copy_from_slice(&key.as_word().as_bytes());
    let raw = UnverifiedPackageNaming::new(bytes, limits()).unwrap();
    let profile = Profile::default();
    assert!(matches!(
        raw.decode(&profile, &context, limits()),
        Err(Error::InvalidNaming(PackageNamingError::UnknownEntryKey { key: actual }))
            if actual == key
    ));
    assert_no_policy(&profile);
}

#[test]
fn dangling_nested_references_fail_before_even_the_own_home_policy() {
    let (naming, context) = fixture();
    let entry_key = naming.entry_key().unwrap();
    let bindings = naming.callables().bindings().map(|(_, binding)| binding.clone());
    let alias = CallableProcedurePath::from_semantic_components(vec!["alias".into()]).unwrap();
    let implementation = ImplementationRoot::new(Word::new([7; 4].map(Felt::from_u32)));
    let callables =
        PackageCallables::new(bindings, [(alias, entry_key)], [(entry_key, implementation)])
            .unwrap();
    let naming =
        PackageNaming::new(naming.namespace_plan().clone(), callables, Some(entry_key)).unwrap();
    let bytes = naming.encode_unverified_v1(limits()).unwrap();
    let unknown = ProcedureKey::new(Word::new([11; 4].map(Felt::from_u32)));
    assert!(naming.callables().binding(unknown).is_none());

    for visible in [true, false] {
        let mut bad = bytes.clone();
        // The final selection is 64 bytes, preceded by its count and the alias target K.
        let offset = if visible { bad.len() - 100 } else { bad.len() - 64 };
        bad[offset..offset + 32].copy_from_slice(&unknown.as_word().as_bytes());
        // Raw transport deliberately retains structurally valid but unadmitted references.
        let raw = UnverifiedPackageNaming::new(bad, limits()).unwrap();
        let profile = Profile::default();
        let error = raw.decode(&profile, &context, limits()).unwrap_err();
        match error {
            Error::Callables(CallablesCodecError::InvalidInventory(
                PackageCallablesError::UnknownVisiblePathTarget { key, .. },
            )) => {
                assert!(visible);
                assert_eq!(key, unknown);
            },
            Error::Callables(CallablesCodecError::InvalidInventory(
                PackageCallablesError::UnknownImplementationTarget { key },
            )) => {
                assert!(!visible);
                assert_eq!(key, unknown);
            },
            error => panic!("unexpected error: {error}"),
        }
        assert_no_policy(&profile);
    }
}

#[test]
fn raw_transport_cannot_bypass_unknown_codecs_or_malformed_labels() {
    let naming = PackageNaming::new(
        NamespacePlan::new(vec![typed(999)]),
        PackageCallables::new([], [], []).unwrap(),
        None,
    )
    .unwrap();
    let bytes = naming.encode_unverified_v1(limits()).unwrap();
    let raw = UnverifiedPackageNaming::new(bytes.clone(), limits()).unwrap();
    let profile = Profile::default();
    let context = Context {
        homes: vec![vec![typed(999)]],
        permit_typed: true,
    };
    for error in [
        raw.decode(&profile, &context, limits()).unwrap_err(),
        naming.encode_v1(&profile, &context, limits()).unwrap_err(),
    ] {
        assert!(matches!(
            error,
            Error::Codec(CodecError::ProfileRejected {
                operation: ProfileOperation::TypedId,
                error: "unknown codec",
            })
        ));
    }
    assert_eq!(profile.home_calls.get(), 0);

    let mut malformed = bytes;
    malformed[6] = 0; // The label envelope is complete but its version is invalid.
    let raw = UnverifiedPackageNaming::from_bytes_with_limits(&malformed, limits()).unwrap();
    let profile = Profile::default();
    assert!(matches!(
        raw.decode(&profile, &context, limits()),
        Err(Error::Codec(CodecError::InvalidLabel(_)))
    ));
    assert_no_policy(&profile);
}

#[test]
fn every_admission_and_encoding_revalidates_current_context_and_unused_homes() {
    let (naming, mut context) = fixture();
    let bytes = naming.encode_unverified_v1(limits()).unwrap();
    let raw = UnverifiedPackageNaming::new(bytes, limits()).unwrap();
    let profile = Profile::default();
    assert_eq!(raw.decode(&profile, &context, limits()).unwrap(), naming);
    context.homes.pop(); // The unaliased, unselected declaration is still mandatory.
    for result in [
        raw.decode(&profile, &context, limits()).map(|_| ()),
        naming.encode_v1(&profile, &context, limits()).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(Error::Callables(CallablesCodecError::Codec(CodecError::ProfileRejected {
                operation: ProfileOperation::Home,
                error: "home association mismatch",
            })))
        ));
    }
    context.permit_typed = false;
    assert!(matches!(
        raw.decode(&profile, &context, limits()),
        Err(Error::Codec(CodecError::ProfileRejected {
            operation: ProfileOperation::TypedId,
            error: "TypedId forbidden",
        }))
    ));
}
