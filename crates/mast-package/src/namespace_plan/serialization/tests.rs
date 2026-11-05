use alloc::vec;
use core::{cell::Cell, num::NonZeroU32};

use miden_core::{Felt, Word, program::Namespace};

use super::*;
use crate::interface::serialization::TypedIdProfile;

type Error = CodecError<&'static str>;

const CODEC: u32 = 77;
const ID: &[u8] = &[0xa5, 0, 0xff];

struct FixtureProfile {
    typed_calls: Cell<usize>,
    home_calls: Cell<usize>,
}

struct Context {
    expected_home: Vec<CanonicalLabel>,
    permit_home: bool,
    permit_typed: bool,
}

impl TypedIdProfile for FixtureProfile {
    type Context = Context;
    type Error = &'static str;

    fn validate_typed_id(
        &self,
        context: &Context,
        codec: u32,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.typed_calls.set(self.typed_calls.get() + 1);
        if codec != CODEC {
            Err("unrecognized synthetic codec")
        } else if bytes != ID {
            Err("noncanonical synthetic ID")
        } else if !context.permit_typed {
            Err("synthetic codec rejected in this context")
        } else {
            Ok(())
        }
    }
}

impl HomeProfile for FixtureProfile {
    fn validate_home(&self, context: &Context, home: &[CanonicalLabel]) -> Result<(), Self::Error> {
        self.home_calls.set(self.home_calls.get() + 1);
        if !context.permit_home {
            Err("home forbidden in this context")
        } else if home != context.expected_home {
            Err("home association mismatch")
        } else {
            Ok(())
        }
    }
}

fn profile() -> FixtureProfile {
    FixtureProfile {
        typed_calls: Cell::new(0),
        home_calls: Cell::new(0),
    }
}

fn context(home: &[CanonicalLabel]) -> Context {
    Context {
        expected_home: home.to_vec(),
        permit_home: true,
        permit_typed: true,
    }
}

fn fixture_home() -> Vec<CanonicalLabel> {
    vec![
        CanonicalLabel::text("a::β").unwrap(),
        CanonicalLabel::library_id(Word::new([1, 2, 3, 4].map(Felt::from_u32))),
        CanonicalLabel::revision(NonZeroU32::new(7).unwrap()),
        CanonicalLabel::typed_id(CODEC, ID, |codec, id| {
            assert_eq!((codec, id), (CODEC, ID));
            Ok(())
        })
        .unwrap(),
    ]
}

fn limits() -> CodecLimits {
    CodecLimits::new(4096, 32, 32, 2048)
}

fn envelope(version: u8, tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![version, tag];
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn home_bytes(labels: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&(labels.len() as u32).to_le_bytes());
    for label in labels {
        bytes.extend_from_slice(label);
    }
    bytes
}

fn assert_structural_failure(bytes: &[u8]) {
    let profile = profile();
    let error =
        NamespacePlan::decode_home_v1(bytes, &profile, &context(&[]), limits()).unwrap_err();
    assert!(!matches!(error, Error::ProfileRejected { .. }), "{error}");
    assert_eq!(profile.home_calls.get(), 0);
}

#[test]
fn interface_home_frozen_builtin_and_synthetic_typed_vector_roundtrips() {
    let home = fixture_home();
    let plan = NamespacePlan::new(home.clone());
    let profile = profile();
    let context = context(&home);
    // This is a portable wire fixture using a synthetic external codec, never AccountId policy.
    let frozen = [
        1, 4, 0, 0, 0, 1, 0, 5, 0, 0, 0, b'a', b':', b':', 0xce, 0xb2, 1, 1, 32, 0, 0, 0, 1, 0, 0,
        0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1,
        2, 4, 0, 0, 0, 7, 0, 0, 0, 1, 3, 7, 0, 0, 0, 77, 0, 0, 0, 0xa5, 0, 0xff,
    ];
    assert_eq!(plan.encode_home_v1(&profile, &context, limits()).unwrap(), frozen);
    assert_eq!(
        NamespacePlan::decode_home_v1(&frozen, &profile, &context, limits()).unwrap(),
        plan
    );
    assert_eq!(profile.typed_calls.get(), 2);
    assert_eq!(profile.home_calls.get(), 2);
}

#[test]
fn interface_home_empty_is_explicit_and_requires_policy_for_both_directions() {
    let plan = NamespacePlan::new(vec![]);
    let profile = profile();
    let mut context = context(&[]);
    let limits = CodecLimits::new(5, 0, 0, 0);
    assert_eq!(plan.encode_home_v1(&profile, &context, limits).unwrap(), [1, 0, 0, 0, 0]);
    let decoded =
        NamespacePlan::decode_home_v1(&[1, 0, 0, 0, 0], &profile, &context, limits).unwrap();
    assert_eq!(decoded.namespace(), Namespace::initial());
    assert_eq!(profile.typed_calls.get(), 0);
    assert_eq!(profile.home_calls.get(), 2);
    context.permit_home = false;
    assert!(matches!(
        plan.encode_home_v1(&profile, &context, limits),
        Err(Error::ProfileRejected { operation: ProfileOperation::Home, .. })
    ));
    assert!(matches!(
        NamespacePlan::decode_home_v1(&[1, 0, 0, 0, 0], &profile, &context, limits),
        Err(Error::ProfileRejected { operation: ProfileOperation::Home, .. })
    ));
}

#[test]
fn interface_home_preserves_exact_text_tags_and_component_boundaries() {
    let labels = ["", "a::b", "é", "e\u{301}", "a\\b", "#", "\0", "\n", "🦀"]
        .into_iter()
        .map(|text| CanonicalLabel::text(text).unwrap())
        .collect::<Vec<_>>();
    let plan = NamespacePlan::new(labels.clone());
    let profile = profile();
    let context = context(&labels);
    let bytes = plan.encode_home_v1(&profile, &context, limits()).unwrap();
    assert_eq!(
        NamespacePlan::decode_home_v1(&bytes, &profile, &context, limits()).unwrap(),
        plan
    );
    assert_eq!(profile.typed_calls.get(), 0);
}

#[test]
fn interface_home_rejects_unknown_outer_versions_truncation_and_trailing_bytes() {
    let home = fixture_home();
    let bytes = NamespacePlan::new(home.clone())
        .encode_home_v1(&profile(), &context(&home), limits())
        .unwrap();
    for end in 0..bytes.len() {
        assert_structural_failure(&bytes[..end]);
    }
    for version in [0, 2, 255] {
        let mut bad = bytes.clone();
        bad[0] = version;
        let profile = profile();
        assert!(matches!(
            NamespacePlan::decode_home_v1(&bad, &profile, &context(&home), limits()),
            Err(Error::UnsupportedVersion { kind: "home", version: v }) if v == version
        ));
        assert_eq!(profile.home_calls.get(), 0);
        assert_eq!(profile.typed_calls.get(), 0);
    }
    for suffix in [&[0][..], &[1, 2, 3][..]] {
        let mut bad = bytes.clone();
        bad.extend_from_slice(suffix);
        let profile = profile();
        assert!(matches!(
            NamespacePlan::decode_home_v1(&bad, &profile, &context(&home), limits()),
            Err(Error::TrailingBytes("HomeV1"))
        ));
        assert_eq!(profile.home_calls.get(), 0);
    }
}

#[test]
fn interface_home_core_label_decoder_rejects_versions_tags_utf8_words_and_revisions() {
    let mut malformed = vec![
        envelope(0, 0, b"ok"),
        envelope(2, 0, b"ok"),
        envelope(1, 4, b"unknown"),
        envelope(1, 255, &[]),
        envelope(1, 0, &[0xff]),
        envelope(1, 0, &[0xc0, 0xaf]),
        envelope(1, 1, &[0; 31]),
        envelope(1, 1, &[0; 33]),
        envelope(1, 2, &[0; 4]),
        envelope(1, 2, &[1; 3]),
        envelope(1, 2, &[1; 5]),
        envelope(1, 3, &[0; 3]),
    ];
    for lane in 0..4 {
        let mut bad_word = [0; 32];
        bad_word[lane * 8..(lane + 1) * 8].copy_from_slice(&Felt::ORDER.to_le_bytes());
        malformed.push(envelope(1, 1, &bad_word));
    }
    for label in malformed {
        let profile = profile();
        assert!(matches!(
            NamespacePlan::decode_home_v1(
                &home_bytes(&[&label]),
                &profile,
                &context(&[]),
                limits()
            ),
            Err(Error::InvalidLabel(_))
        ));
        assert_eq!(profile.typed_calls.get(), 0);
        assert_eq!(profile.home_calls.get(), 0);
    }
}

#[test]
fn interface_home_external_codec_canonicality_and_context_rejections_are_distinct() {
    for (codec, id, expected_error) in [
        (0, ID, "unrecognized synthetic codec"),
        (1, ID, "unrecognized synthetic codec"),
        (u32::MAX, ID, "unrecognized synthetic codec"),
        (CODEC, &ID[..2], "noncanonical synthetic ID"),
        (CODEC, &[][..], "noncanonical synthetic ID"),
    ] {
        let mut payload = codec.to_le_bytes().to_vec();
        payload.extend_from_slice(id);
        let bytes = home_bytes(&[&envelope(1, 3, &payload)]);
        let profile = profile();
        assert!(matches!(
            NamespacePlan::decode_home_v1(&bytes, &profile, &context(&[]), limits()),
            Err(Error::ProfileRejected { operation: ProfileOperation::TypedId, error })
                if error == expected_error
        ));
        assert_eq!(profile.typed_calls.get(), 1);
        assert_eq!(profile.home_calls.get(), 0);
    }

    let home = fixture_home();
    let plan = NamespacePlan::new(home.clone());
    let bytes = plan.encode_home_v1(&profile(), &context(&home), limits()).unwrap();
    let profile = profile();
    let mut wrong = context(&home);
    wrong.permit_typed = false;
    for result in [
        plan.encode_home_v1(&profile, &wrong, limits()).map(|_| ()),
        NamespacePlan::decode_home_v1(&bytes, &profile, &wrong, limits()).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(Error::ProfileRejected { operation: ProfileOperation::TypedId, .. })
        ));
    }
    assert_eq!(profile.home_calls.get(), 0);
    wrong.permit_typed = true;
    wrong.expected_home.swap(0, 1);
    for result in [
        plan.encode_home_v1(&profile, &wrong, limits()).map(|_| ()),
        NamespacePlan::decode_home_v1(&bytes, &profile, &wrong, limits()).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(Error::ProfileRejected {
                operation: ProfileOperation::Home,
                error: "home association mismatch"
            })
        ));
    }
    assert_eq!(profile.home_calls.get(), 2);
}

#[test]
fn interface_home_exact_budgets_and_each_aggregate_limit_apply_in_both_directions() {
    let home = fixture_home();
    let plan = NamespacePlan::new(home.clone());
    let profile = profile();
    let context = context(&home);
    let bytes = plan.encode_home_v1(&profile, &context, limits()).unwrap();
    let blob_bytes = home.iter().map(|label| label.as_bytes().len() - 6).sum::<usize>() as u32;
    let count = home.len() as u32;
    let exact = CodecLimits::new(bytes.len() as u32, count, count, blob_bytes);
    assert_eq!(plan.encode_home_v1(&profile, &context, exact).unwrap(), bytes);
    assert_eq!(NamespacePlan::decode_home_v1(&bytes, &profile, &context, exact).unwrap(), plan);
    for (limits, expected_resource) in [
        (CodecLimits::new(bytes.len() as u32 - 1, count, count, blob_bytes), "wire bytes"),
        (CodecLimits::new(bytes.len() as u32, count - 1, count, blob_bytes), "records"),
        (CodecLimits::new(bytes.len() as u32, count, count - 1, blob_bytes), "components"),
        (CodecLimits::new(bytes.len() as u32, count, count, blob_bytes - 1), "blob bytes"),
    ] {
        for result in [
            plan.encode_home_v1(&profile, &context, limits).map(|_| ()),
            NamespacePlan::decode_home_v1(&bytes, &profile, &context, limits).map(|_| ()),
        ] {
            assert!(matches!(result,
                Err(Error::LimitExceeded { resource, .. }) if resource == expected_resource));
        }
    }
}

#[test]
fn interface_home_huge_counts_lengths_and_component_lower_bounds_reject_before_policy() {
    let bytes = [1, 255, 255, 255, 255];
    assert_structural_failure(&bytes);
    for payload in [u32::MAX, u32::MAX - 5, 1] {
        let mut bytes = vec![1, 1, 0, 0, 0, 1, 0];
        bytes.extend_from_slice(&payload.to_le_bytes());
        assert_structural_failure(&bytes);
    }
    // Count two has only one six-byte envelope: reject before allocating or decoding it.
    let mut bytes = vec![1, 2, 0, 0, 0];
    bytes.extend_from_slice(CanonicalLabel::text("").unwrap().as_bytes());
    let profile = profile();
    assert!(matches!(
        NamespacePlan::decode_home_v1(&bytes, &profile, &context(&[]), limits()),
        Err(Error::Truncated("HomeV1 components"))
    ));
    assert_eq!(profile.typed_calls.get(), 0);
    assert_eq!(profile.home_calls.get(), 0);
}
