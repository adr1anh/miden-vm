use alloc::{format, vec};
use core::{cell::Cell, num::NonZeroU32};

use miden_core::Felt;

use super::*;
use crate::interface::serialization::{ProfileOperation, TypedIdProfile};

type Error = CallablesCodecError<&'static str>;

const CODEC: u32 = 77;
const ID: &[u8] = &[0xa5, 0, 0xff];

#[derive(Default)]
struct Profile {
    typed_calls: Cell<usize>,
    home_calls: Cell<usize>,
}

struct Context {
    homes: Vec<Vec<CanonicalLabel>>,
    permit_typed: bool,
    permit_home: bool,
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
        if codec != CODEC {
            Err("unknown synthetic codec")
        } else if bytes != ID {
            Err("noncanonical synthetic ID")
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
        if !context.permit_home {
            Err("home forbidden")
        } else if !context.homes.iter().any(|permitted| permitted == home) {
            Err("home association mismatch")
        } else {
            Ok(())
        }
    }
}

fn context(homes: Vec<Vec<CanonicalLabel>>) -> Context {
    Context {
        homes,
        permit_typed: true,
        permit_home: true,
    }
}

fn limits() -> CodecLimits {
    CodecLimits::new(65536, 4096, 4096, 65536)
}

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|text| (*text).into()).collect(),
    )
    .unwrap()
}

fn binding(home: Vec<CanonicalLabel>, components: &[&str]) -> CallableBinding {
    CallableBinding::new(NamespacePlan::new(home), path(components)).unwrap()
}

fn typed(codec: u32) -> CanonicalLabel {
    // Synthetic construction only; every codec operation must use the real current profile.
    CanonicalLabel::typed_id(codec, ID, |_, _| Ok(())).unwrap()
}

fn implementation() -> ImplementationRoot {
    ImplementationRoot::new(Word::new([7; 4].map(Felt::from_u32)))
}

fn fixture() -> (PackageCallables, Context) {
    let home = vec![CanonicalLabel::text("hβ").unwrap(), typed(CODEC)];
    let entry = binding(home.clone(), &["$exec", "$main"]);
    let hidden = binding(home.clone(), &["helpers", "runβ"]);
    let key = entry.key();
    let other = hidden.key();
    let callables = PackageCallables::new(
        [entry, hidden],
        [(path(&["legacy", "go"]), key), (path(&["x"]), key)],
        [(key, implementation()), (other, implementation())],
    )
    .unwrap();
    (callables, context(vec![home]))
}

fn exact_fixture_limits() -> CodecLimits {
    // Framing13 + binding records85/87 + visible records56/43 + two selections128 = 412.
    // Six relation records + four home labels = 10 records. Four home labels + four canonical
    // path components + three visible components = 11 components. Home payloads20 + canonical
    // path UTF-8(10+12) + visible UTF-8(8+1) = 51 blob bytes.
    CodecLimits::new(412, 10, 11, 51)
}

fn text_path(components: &[&str]) -> Vec<u8> {
    let mut bytes = (components.len() as u32).to_le_bytes().to_vec();
    for text in components {
        bytes.extend_from_slice(CanonicalLabel::text(text).unwrap().as_bytes());
    }
    bytes
}

fn home_bytes(home: &[CanonicalLabel]) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&(home.len() as u32).to_le_bytes());
    for label in home {
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes
}

fn binding_bytes(binding: &CallableBinding) -> Vec<u8> {
    let mut bytes = binding.key().as_word().as_bytes().to_vec();
    bytes.extend_from_slice(&home_bytes(binding.namespace_plan().home()));
    let components = binding.path().components().iter().map(String::as_str).collect::<Vec<_>>();
    bytes.extend_from_slice(&text_path(&components));
    bytes
}

fn wire(
    bindings: &[Vec<u8>],
    visible: &[(Vec<u8>, ProcedureKey)],
    selections: &[(ProcedureKey, ImplementationRoot)],
) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&(bindings.len() as u32).to_le_bytes());
    for binding in bindings {
        bytes.extend_from_slice(binding);
    }
    bytes.extend_from_slice(&(visible.len() as u32).to_le_bytes());
    for (path, key) in visible {
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&key.as_word().as_bytes());
    }
    bytes.extend_from_slice(&(selections.len() as u32).to_le_bytes());
    for (key, root) in selections {
        bytes.extend_from_slice(&key.as_word().as_bytes());
        bytes.extend_from_slice(&root.as_word().as_bytes());
    }
    bytes
}

fn sorted_bindings(bindings: &[CallableBinding]) -> Vec<Vec<u8>> {
    let mut records = bindings.iter().map(binding_bytes).collect::<Vec<_>>();
    records.sort_unstable_by(|left, right| left[..32].cmp(&right[..32]));
    records
}

fn assert_no_policy(profile: &Profile) {
    assert_eq!(profile.typed_calls.get(), 0);
    assert_eq!(profile.home_calls.get(), 0);
}

#[test]
fn explicit_wire_goldens_and_all_home_label_types_roundtrip_reserved_paths() {
    let empty = PackageCallables::new([], [], []).unwrap();
    let profile = Profile::default();
    let empty_context = context(vec![]);
    let frozen_empty = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        empty
            .encode_v1(&profile, &empty_context, CodecLimits::new(13, 0, 0, 0))
            .unwrap(),
        frozen_empty
    );
    assert_eq!(
        PackageCallables::decode_v1(
            &frozen_empty,
            &profile,
            &empty_context,
            CodecLimits::new(13, 0, 0, 0)
        )
        .unwrap(),
        empty
    );
    assert_no_policy(&profile);

    let home = vec![
        CanonicalLabel::text("hβ").unwrap(),
        CanonicalLabel::library_id(Word::new([1, 2, 3, 4].map(Felt::from_u32))),
        CanonicalLabel::revision(NonZeroU32::new(7).unwrap()),
        typed(CODEC),
    ];
    let binding = binding(home.clone(), &["$kernel", "$main"]);
    let key = binding.key();
    let inventory = PackageCallables::new([binding], [], [(key, implementation())]).unwrap();
    // Freeze complete HomeV1 and counted Text envelopes explicitly. K uses the independently
    // constructed binding's existing key derivation; the inventory codec does not derive this
    // fixture.
    let mut frozen = vec![1, 1, 0, 0, 0];
    frozen.extend_from_slice(&key.as_word().as_bytes());
    frozen.extend_from_slice(&[
        1, 4, 0, 0, 0, 1, 0, 3, 0, 0, 0, b'h', 0xce, 0xb2, 1, 1, 32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 0, 0,
        0, 7, 0, 0, 0, 1, 3, 7, 0, 0, 0, 77, 0, 0, 0, 0xa5, 0, 0xff, 2, 0, 0, 0, 1, 0, 7, 0, 0, 0,
        b'$', b'k', b'e', b'r', b'n', b'e', b'l', 1, 0, 5, 0, 0, 0, b'$', b'm', b'a', b'i', b'n',
        0, 0, 0, 0, 1, 0, 0, 0,
    ]);
    frozen.extend_from_slice(&key.as_word().as_bytes());
    frozen.extend_from_slice(&implementation().as_word().as_bytes());
    let context = context(vec![home]);
    assert_eq!(inventory.encode_v1(&profile, &context, limits()).unwrap(), frozen);
    assert_eq!(
        PackageCallables::decode_v1(&frozen, &profile, &context, limits()).unwrap(),
        inventory
    );
    assert_eq!(profile.typed_calls.get(), 2);
    assert_eq!(profile.home_calls.get(), 2);
}

#[test]
fn canonical_word_and_text_envelope_order_is_independent_of_native_map_order() {
    let numeric_first = Word::new([1, 0, 0, 0].map(Felt::from_u32));
    let byte_first = Word::new([256, 0, 0, 0].map(Felt::from_u32));
    assert!(numeric_first < byte_first);
    assert!(byte_first.as_bytes() < numeric_first.as_bytes());
    let mut previous = Some(byte_first);
    check_word_order::<&str>(&mut previous, numeric_first, "deterministic Word trap").unwrap();
    let mut previous = Some(numeric_first);
    assert!(
        check_word_order::<&str>(&mut previous, byte_first, "deterministic Word trap").is_err()
    );

    let bindings = (0..24)
        .map(|index| binding(vec![], &[&format!("proc{index}")]))
        .collect::<Vec<_>>();
    let key = bindings[0].key();
    let long = "β".repeat(128); // 256 UTF-8 bytes: LE length starts 0, before length one.
    let inventory = PackageCallables::new(
        bindings.clone(),
        [(path(&["aa"]), key), (path(&["z"]), key), (path(&[&long]), key)],
        bindings.iter().map(|binding| (binding.key(), implementation())),
    )
    .unwrap();
    let native = inventory.bindings.keys().copied().collect::<Vec<_>>();
    let mut canonical = native.clone();
    canonical.sort_unstable_by_key(|key| key.as_word().as_bytes());
    assert_ne!(native, canonical);
    let mut selections = inventory
        .selected_implementations()
        .map(|(key, root)| (*key, *root))
        .collect::<Vec<_>>();
    selections.sort_unstable_by_key(|(key, _)| key.as_word().as_bytes());
    let expected = wire(
        &sorted_bindings(&bindings),
        &[(text_path(&[&long]), key), (text_path(&["z"]), key), (text_path(&["aa"]), key)],
        &selections,
    );
    let profile = Profile::default();
    let context = context(vec![vec![]]);
    assert_eq!(inventory.encode_v1(&profile, &context, limits()).unwrap(), expected);
    assert_eq!(
        PackageCallables::decode_v1(&expected, &profile, &context, limits()).unwrap(),
        inventory
    );
}

#[test]
fn repeated_alias_targets_shared_implementations_and_unaliased_declarations_survive() {
    let (inventory, context) = fixture();
    let profile = Profile::default();
    let bytes = inventory.encode_v1(&profile, &context, limits()).unwrap();
    assert_eq!(
        PackageCallables::decode_v1(&bytes, &profile, &context, limits()).unwrap(),
        inventory
    );
    let declaration = binding(vec![], &["$exec", "$main"]);
    let declaration_only = PackageCallables::new([declaration], [], []).unwrap();
    let n0_context = self::context(vec![vec![]]);
    let bytes = declaration_only.encode_v1(&profile, &n0_context, limits()).unwrap();
    assert_eq!(
        PackageCallables::decode_v1(&bytes, &profile, &n0_context, limits()).unwrap(),
        declaration_only
    );
}

#[test]
fn every_aggregate_limit_and_complete_wire_length_fail_before_policy_in_both_directions() {
    let (inventory, context) = fixture();
    let bytes = inventory.encode_v1(&Profile::default(), &context, limits()).unwrap();
    let exact = exact_fixture_limits();
    assert_eq!(bytes.len(), 412);
    assert_eq!(inventory.encode_v1(&Profile::default(), &context, exact).unwrap(), bytes);
    assert_eq!(
        PackageCallables::decode_v1(&bytes, &Profile::default(), &context, exact).unwrap(),
        inventory
    );
    for (limits, expected) in [
        (
            CodecLimits::new(
                exact.max_bytes() - 1,
                exact.max_records(),
                exact.max_components(),
                exact.max_blob_bytes(),
            ),
            "wire bytes",
        ),
        (
            CodecLimits::new(
                exact.max_bytes(),
                exact.max_records() - 1,
                exact.max_components(),
                exact.max_blob_bytes(),
            ),
            "records",
        ),
        (
            CodecLimits::new(
                exact.max_bytes(),
                exact.max_records(),
                exact.max_components() - 1,
                exact.max_blob_bytes(),
            ),
            "components",
        ),
        (
            CodecLimits::new(
                exact.max_bytes(),
                exact.max_records(),
                exact.max_components(),
                exact.max_blob_bytes() - 1,
            ),
            "blob bytes",
        ),
    ] {
        for decode in [false, true] {
            let profile = Profile::default();
            let error = if decode {
                PackageCallables::decode_v1(&bytes, &profile, &context, limits).map(|_| ())
            } else {
                inventory.encode_v1(&profile, &context, limits).map(|_| ())
            }
            .unwrap_err();
            assert!(
                matches!(error, Error::Codec(CodecError::LimitExceeded { resource, .. }) if resource == expected),
                "{error}"
            );
            assert_no_policy(&profile);
        }
    }
}

#[test]
fn ongoing_budget_consumption_is_preserved_without_recharging_or_accumulating_wire_bytes() {
    let (inventory, context) = fixture();
    let bytes = inventory.encode_v1(&Profile::default(), &context, limits()).unwrap();
    let exact = exact_fixture_limits();
    for resource in ["records", "components", "blob bytes"] {
        for decode in [false, true] {
            let mut budget = Budget::new(exact);
            let charged: Result<(), CodecError<&str>> = match resource {
                "records" => budget.records(1),
                "components" => budget.components(1),
                _ => budget.blob_bytes(1),
            };
            charged.unwrap();
            let profile = Profile::default();
            let error = if decode {
                let mut reader = Reader::new::<&str>(&bytes, &budget).unwrap();
                preflight_v1_decoding::<&str>(&mut reader, &mut budget).map(|_| ())
            } else {
                inventory.preflight_v1_encoding::<&str>(&mut budget).map(|_| ())
            }
            .unwrap_err();
            assert!(
                matches!(error, Error::Codec(CodecError::LimitExceeded { resource: actual, .. }) if actual == resource)
            );
            assert_no_policy(&profile);
        }
    }
    let profile = Profile::default();
    let mut budget = Budget::new(exact);
    budget.logical_bytes::<&str>(exact.max_bytes() as usize).unwrap();
    let plan = inventory.preflight_v1_encoding::<&str>(&mut budget).unwrap();
    assert_no_policy(&profile);
    plan.validate(&profile, &context).unwrap();
    assert_eq!(profile.home_calls.get(), 2);
    let mut writer = Writer::new::<&str>(bytes.len(), &budget).unwrap();
    plan.write::<&str>(&mut writer).unwrap();
    assert_eq!(writer.finish::<&str>().unwrap(), bytes);

    let mut budget = Budget::new(exact);
    let mut reader = Reader::new::<&str>(&bytes, &budget).unwrap();
    let plan = preflight_v1_decoding::<&str>(&mut reader, &mut budget).unwrap();
    assert_eq!(plan.decode(&Profile::default(), &context, &budget).unwrap(), inventory);
}

#[test]
fn staged_embedding_defers_policy_until_later_fields_have_been_preflighted() {
    let (inventory, context) = fixture();
    let bytes = inventory.encode_v1(&Profile::default(), &context, limits()).unwrap();
    let exact = exact_fixture_limits();
    let profile = Profile::default();
    let mut budget = Budget::new(exact);
    let _plan = inventory.preflight_v1_encoding::<&str>(&mut budget).unwrap();
    assert!(budget.records::<&str>(1).is_err());
    assert_no_policy(&profile);

    let mut embedded = bytes;
    embedded.extend_from_slice(&[1, 0, 0, 0]);
    let mut budget = Budget::new(CodecLimits::new(
        embedded.len() as u32,
        exact.max_records(),
        exact.max_components(),
        exact.max_blob_bytes(),
    ));
    let mut reader = Reader::new::<&str>(&embedded, &budget).unwrap();
    let _plan = preflight_v1_decoding::<&str>(&mut reader, &mut budget).unwrap();
    assert_eq!(reader.u32::<&str>("later field").unwrap(), 1);
    assert!(budget.records::<&str>(1).is_err());
    assert_no_policy(&profile);
    // A successful enclosing preflight can subsequently decode the retained field without reset.
    let mut budget = Budget::new(CodecLimits::new(
        embedded.len() as u32,
        exact.max_records() + 1,
        exact.max_components(),
        exact.max_blob_bytes(),
    ));
    let mut reader = Reader::new::<&str>(&embedded, &budget).unwrap();
    let plan = preflight_v1_decoding::<&str>(&mut reader, &mut budget).unwrap();
    reader.u32::<&str>("later field").unwrap();
    budget.records::<&str>(1).unwrap();
    assert_eq!(plan.decode(&profile, &context, &budget).unwrap(), inventory);
}

#[test]
fn malformed_versions_all_truncations_trailing_bytes_and_unsupported_counts_precede_policy() {
    let (inventory, context) = fixture();
    let bytes = inventory.encode_v1(&Profile::default(), &context, limits()).unwrap();
    for end in 0..bytes.len() {
        let profile = Profile::default();
        assert!(
            PackageCallables::decode_v1(&bytes[..end], &profile, &context, limits()).is_err(),
            "prefix {end}"
        );
        assert_no_policy(&profile);
    }
    for version in [0, 2, 255] {
        let mut bad = bytes.clone();
        bad[0] = version;
        let profile = Profile::default();
        assert!(
            matches!(PackageCallables::decode_v1(&bad, &profile, &context, limits()), Err(Error::Codec(CodecError::UnsupportedVersion { kind: "callables", version: actual })) if actual == version)
        );
        assert_no_policy(&profile);
    }
    let mut bad = bytes.clone();
    bad.push(0);
    let profile = Profile::default();
    assert!(matches!(
        PackageCallables::decode_v1(&bad, &profile, &context, limits()),
        Err(Error::Codec(CodecError::TrailingBytes("PackageCallablesV1")))
    ));
    assert_no_policy(&profile);
    for offset in [1, 38] {
        // binding count and first HomeV1 label count
        let mut bad = bytes.clone();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let profile = Profile::default();
        assert!(PackageCallables::decode_v1(&bad, &profile, &context, limits()).is_err());
        assert_no_policy(&profile);
    }
}

#[test]
fn duplicate_and_descending_keys_paths_and_selections_are_rejected() {
    let declarations = [binding(vec![], &["one"]), binding(vec![], &["two"])];
    let records = sorted_bindings(&declarations);
    let key = declarations[0].key();
    let mut selected = declarations
        .iter()
        .map(|binding| (binding.key(), implementation()))
        .collect::<Vec<_>>();
    selected.sort_unstable_by_key(|(key, _)| key.as_word().as_bytes());
    for (bytes, kind) in [
        (wire(&[records[0].clone(), records[0].clone()], &[], &[]), "callable bindings"),
        (wire(&[records[1].clone(), records[0].clone()], &[], &[]), "callable bindings"),
        (
            wire(&records, &[(text_path(&["a"]), key), (text_path(&["a"]), key)], &[]),
            "visible callable paths",
        ),
        (
            wire(&records, &[(text_path(&["aa"]), key), (text_path(&["z"]), key)], &[]),
            "visible callable paths",
        ),
        (wire(&records, &[], &[selected[0], selected[0]]), "implementation selections"),
        (wire(&records, &[], &[selected[1], selected[0]]), "implementation selections"),
    ] {
        let profile = Profile::default();
        assert!(
            matches!(PackageCallables::decode_v1(&bytes, &profile, &context(vec![vec![]]), limits()), Err(Error::NonCanonicalOrder { kind: actual }) if actual == kind)
        );
        assert_no_policy(&profile);
    }
}

#[test]
fn undeclared_alias_and_selection_targets_fail_before_external_policy() {
    let declaration = binding(vec![typed(CODEC)], &["run"]);
    let unknown = binding(vec![], &["unknown"]).key();
    for (bytes, visible) in [
        (
            wire(&[binding_bytes(&declaration)], &[(text_path(&["alias"]), unknown)], &[]),
            true,
        ),
        (wire(&[binding_bytes(&declaration)], &[], &[(unknown, implementation())]), false),
    ] {
        let profile = Profile::default();
        let error = PackageCallables::decode_v1(
            &bytes,
            &profile,
            &context(vec![vec![typed(CODEC)]]),
            limits(),
        )
        .unwrap_err();
        match error {
            Error::InvalidInventory(PackageCallablesError::UnknownVisiblePathTarget { .. }) => {
                assert!(visible)
            },
            Error::InvalidInventory(PackageCallablesError::UnknownImplementationTarget {
                ..
            }) => assert!(!visible),
            error => panic!("unexpected error: {error}"),
        }
        assert_no_policy(&profile);
    }
}

#[test]
fn canonical_words_recomputed_keys_text_tags_and_core_label_validity_are_enforced() {
    let declaration = binding(vec![], &["run"]);
    let key = declaration.key();
    let valid = wire(
        &[binding_bytes(&declaration)],
        &[(text_path(&["alias"]), key)],
        &[(key, implementation())],
    );
    let selection_key_offset = valid.len() - 64;
    let alias_key_offset = selection_key_offset - 36;
    for offset in [5, alias_key_offset, selection_key_offset, selection_key_offset + 32] {
        for lane in 0..4 {
            let mut bad = valid.clone();
            bad[offset + lane * 8..offset + (lane + 1) * 8]
                .copy_from_slice(&Felt::ORDER.to_le_bytes());
            let profile = Profile::default();
            assert!(matches!(
                PackageCallables::decode_v1(&bad, &profile, &context(vec![vec![]]), limits()),
                Err(Error::InvalidWord { .. })
            ));
            assert_no_policy(&profile);
        }
    }
    let mut bad = wire(&[binding_bytes(&declaration)], &[], &[]);
    bad[5..37].fill(0);
    assert!(matches!(
        PackageCallables::decode_v1(&bad, &Profile::default(), &context(vec![vec![]]), limits()),
        Err(Error::KeyMismatch { .. })
    ));
    // N0 framing ends at byte 42; path count at 42..46, first envelope at 46.
    for (offset, value) in [(37, 2), (46, 0), (47, 3), (52, 0xff)] {
        let mut bad = wire(&[binding_bytes(&declaration)], &[], &[]);
        bad[offset] = value;
        assert!(
            PackageCallables::decode_v1(
                &bad,
                &Profile::default(),
                &context(vec![vec![]]),
                limits()
            )
            .is_err()
        );
    }
}

#[test]
fn every_operation_revalidates_typed_ids_n0_and_current_home_context() {
    for codec in [CODEC, 999] {
        let home = vec![typed(codec)];
        let declaration = binding(home.clone(), &["run"]);
        let inventory = PackageCallables::new([declaration.clone()], [], []).unwrap();
        let bytes = wire(&[binding_bytes(&declaration)], &[], &[]);
        for decode in [false, true] {
            let profile = Profile::default();
            let mut context = context(vec![home.clone()]);
            context.permit_typed = codec != CODEC;
            let error = if decode {
                PackageCallables::decode_v1(&bytes, &profile, &context, limits()).map(|_| ())
            } else {
                inventory.encode_v1(&profile, &context, limits()).map(|_| ())
            }
            .unwrap_err();
            assert!(matches!(
                error,
                Error::Codec(CodecError::ProfileRejected {
                    operation: ProfileOperation::TypedId,
                    ..
                })
            ));
            assert_eq!(profile.typed_calls.get(), 1);
            assert_eq!(profile.home_calls.get(), 0);
        }
    }
    let declaration = binding(vec![], &["$main"]);
    let inventory = PackageCallables::new([declaration], [], []).unwrap();
    let profile = Profile::default();
    let mut context = context(vec![vec![]]);
    let bytes = inventory.encode_v1(&profile, &context, limits()).unwrap();
    context.permit_home = false;
    for result in [
        inventory.encode_v1(&profile, &context, limits()).map(|_| ()),
        PackageCallables::decode_v1(&bytes, &profile, &context, limits()).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(Error::Codec(CodecError::ProfileRejected {
                operation: ProfileOperation::Home,
                error: "home forbidden"
            }))
        ));
    }
    assert_eq!(profile.home_calls.get(), 3);
    context.permit_home = true;
    context.homes.clear();
    assert!(matches!(
        PackageCallables::decode_v1(&bytes, &profile, &context, limits()),
        Err(Error::Codec(CodecError::ProfileRejected {
            operation: ProfileOperation::Home,
            error: "home association mismatch"
        }))
    ));
}
