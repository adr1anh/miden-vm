//! Fuzz target for MastNodeInfo deserialization.
//!
//! MastNodeInfo combines a fixed-width entry, a digest, and an optional procedure key from
//! separate wire sections. This target exercises their consistency through the trusted wire view.
//!
//! Run with: cargo +nightly fuzz run mast_node_info --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{
    mast::{MastForestWireView, MastNodeEntry},
    program::ProcedureKey,
    serde::{Deserializable, Serializable},
};

fuzz_target!(|data: &[u8]| {
    let Ok(view) = MastForestWireView::new(data) else {
        return;
    };

    assert!(view.node_target_at(view.node_count()).is_err());
    if view.node_count() == 0 {
        return;
    }

    let last = view.node_count() - 1;

    let _ = view.node_entry_at(0);
    let _ = view.node_info_at(0);
    let _ = view.node_digest_at(0);
    let _ = view.node_target_at(0);

    let _ = view.node_entry_at(last);
    let _ = view.node_info_at(last);
    let _ = view.node_digest_at(last);
    let _ = view.node_target_at(last);

    // Check keys even when a lazily decoded digest below is invalid.
    for i in 0..view.node_count() {
        let entry = view.node_entry_at(i).expect("in-range entry must decode");
        let target = view.node_target_at(i).expect("in-range target must decode");
        let is_invocation = matches!(
            entry,
            MastNodeEntry::Exec { .. } | MastNodeEntry::Call { .. } | MastNodeEntry::SysCall { .. }
        );
        assert_eq!(target.is_some(), is_invocation, "only immediate modes have keys");
        assert_eq!(entry.target_slot().is_some(), is_invocation);
        if let Some(key) = target {
            let bytes = key.to_bytes();
            let word = miden_core::Word::read_from_bytes(&bytes)
                .expect("a key must use canonical Word encoding");
            assert_eq!(word, key.into_word());
            assert_eq!(word.to_bytes(), bytes, "key Word encoding must be stable");
            assert_eq!(ProcedureKey::read_from_bytes(&bytes).unwrap(), key);
        }
        // Non-external digest limbs are intentionally decoded lazily. Permit only the field-range
        // error, and require both digest-bearing accessors to agree exactly.
        let info = match view.node_info_at(i) {
            Ok(info) => info,
            Err(miden_core::serde::DeserializationError::InvalidValue(msg))
                if msg == "value not in the appropriate range" =>
            {
                assert_eq!(
                    view.node_digest_at(i),
                    Err(miden_core::serde::DeserializationError::InvalidValue(msg)),
                    "in-range digest accessors must return the same error"
                );
                continue;
            },
            Err(e) => panic!("in-range node {i} failed with an unexpected error: {e:?}"),
        };
        // With info materialized, both independent accessors must succeed.
        assert_eq!(info.node_entry(), entry, "info's entry must match the view's entry accessor");
        assert_eq!(info.target(), target, "info and target accessor must agree");
        let digest = info.digest();
        let view_digest =
            view.node_digest_at(i).expect("in-range digest must materialize once info did");
        assert_eq!(digest, view_digest, "info's digest must match the view's digest accessor");
        // Word digest roundtrip through ungated serde: encode -> decode -> equal.
        let bytes = digest.to_bytes();
        let redecoded = miden_core::Word::read_from_bytes(&bytes).expect("digest must re-decode");
        assert_eq!(redecoded, digest, "digest roundtrip must be stable");
    }
});
