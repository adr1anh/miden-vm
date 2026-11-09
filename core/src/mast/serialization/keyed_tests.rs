use alloc::{string::ToString, vec, vec::Vec};

use super::{
    ForestLayout, MastForestReadMode, MastForestWireView, MastNodeEntry, MastNodeInfo, VERSION,
    basic_blocks::BasicBlockDataDecoder,
    layout::{OffsetTrackingReader, TrackingReader, read_header_and_scan_layout},
};
use crate::{
    Felt, Word,
    advice::AdviceMap,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DenseMastForestBuilder, DynNodeBuilder,
        ExecNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder, MastForest, MastForestError,
        MastForestView, MastNode, MastNodeExt, UntrustedMastForest, UntrustedMastForestReadOptions,
    },
    operations::Operation,
    program::ProcedureKey,
    serde::{ByteReader, Deserializable, Serializable, SliceReader},
};

fn key(seed: u32) -> ProcedureKey {
    ProcedureKey::new(Word::from([
        Felt::from_u32(seed),
        Felt::from_u32(seed + 1),
        Felt::from_u32(seed + 2),
        Felt::from_u32(seed + 3),
    ]))
}

/// Include every section and interleave invocation modes with other node kinds. Three different
/// modes deliberately share a key, and an external digest has the same word as that key.
fn keyed_forest() -> MastForest {
    let mut builder = DenseMastForestBuilder::new();
    let call = builder.push_node(CallNodeBuilder::new(key(10))).unwrap();
    let external = builder.push_node(ExternalNodeBuilder::new(key(10).into_word())).unwrap();
    let dynexec = builder.push_node(DynNodeBuilder::new_dyn()).unwrap();
    let block = builder
        .push_node(BasicBlockNodeBuilder::new(vec![
            Operation::Push(Felt::from_u32(7)),
            Operation::Add,
        ]))
        .unwrap();
    let syscall = builder.push_node(CallNodeBuilder::new_syscall(key(10))).unwrap();
    let exec = builder.push_node(ExecNodeBuilder::new(key(10))).unwrap();
    let dyncall = builder.push_node(DynNodeBuilder::new_dyncall()).unwrap();
    let other_exec = builder.push_node(ExecNodeBuilder::new(key(20))).unwrap();
    let join = builder.push_node(JoinNodeBuilder::new([call, other_exec])).unwrap();
    for root in [call, external, dynexec, block, syscall, exec, dyncall, other_exec, join] {
        builder.mark_root(root);
    }
    builder.build().unwrap()
}

fn encode(forest: &MastForest, hashless: bool) -> Vec<u8> {
    if hashless {
        let mut bytes = Vec::new();
        forest.write_hashless(&mut bytes);
        bytes
    } else {
        forest.to_bytes()
    }
}

fn layout(bytes: &[u8]) -> ForestLayout {
    let mut reader = SliceReader::new(bytes);
    let mut scanner = TrackingReader::new(&mut reader);
    read_header_and_scan_layout(&mut scanner, true).unwrap().1
}

fn target_count_offset(bytes: &[u8]) -> usize {
    let mut reader = SliceReader::new(bytes);
    let mut reader = TrackingReader::new(&mut reader);
    reader.read_slice(8).unwrap();
    reader.read_usize().unwrap();
    reader.read_usize().unwrap();
    reader.offset()
}

fn invocation_indices(bytes: &[u8]) -> Vec<usize> {
    let layout = layout(bytes);
    (0..layout.node_count)
        .filter(|&index| layout.read_node_entry_at(bytes, index).unwrap().target_slot().is_some())
        .collect()
}

fn replace_entry(bytes: &mut [u8], layout: ForestLayout, index: usize, entry: MastNodeEntry) {
    let offset = layout.node_entry_offset() + index * MastNodeEntry::SERIALIZED_SIZE;
    bytes[offset..offset + MastNodeEntry::SERIALIZED_SIZE].copy_from_slice(&entry.to_bytes());
}

fn set_target_slot(bytes: &mut [u8], index: usize, slot: u32) {
    let layout = layout(bytes);
    let entry = match layout.read_node_entry_at(bytes, index).unwrap() {
        MastNodeEntry::Call { .. } => MastNodeEntry::Call { target_slot: slot },
        MastNodeEntry::SysCall { .. } => MastNodeEntry::SysCall { target_slot: slot },
        MastNodeEntry::Exec { .. } => MastNodeEntry::Exec { target_slot: slot },
        entry => panic!("expected immediate invocation, got {entry:?}"),
    };
    replace_entry(bytes, layout, index, entry);
}

/// Malformed fixed structure must fail before materialization on every parsing entry point.
fn assert_structure_rejected(bytes: &[u8]) {
    let mut reader = SliceReader::new(bytes);
    let mut scanner = TrackingReader::new(&mut reader);
    assert!(read_header_and_scan_layout(&mut scanner, true).is_err());
    assert!(MastForest::read_from_bytes(bytes).is_err());
    assert!(MastForest::read_from(&mut SliceReader::new(bytes)).is_err());
    assert!(MastForestWireView::new(bytes).is_err());
    assert!(UntrustedMastForest::read_from_bytes(bytes).is_err());
    assert!(UntrustedMastForest::read_from_reader(&mut SliceReader::new(bytes)).is_err());
}

#[test]
fn digest_invocations_round_trip_and_commit_their_modes() {
    let mut builder = DenseMastForestBuilder::new();
    builder.push_node(BasicBlockNodeBuilder::new(vec![Operation::Noop])).unwrap();
    let callee_digest = key(10).into_word();
    let callee = builder.push_node(ExternalNodeBuilder::new(callee_digest)).unwrap();
    let digest_call = builder.push_node(CallNodeBuilder::new_digest(callee)).unwrap();
    let keyed_call = builder.push_node(CallNodeBuilder::new(key(10))).unwrap();
    let digest_dyn = builder.push_node(DynNodeBuilder::new_digest()).unwrap();
    let digest_dyncall = builder.push_node(DynNodeBuilder::new_digest_dyncall()).unwrap();
    for root in [digest_call, keyed_call, digest_dyn, digest_dyncall] {
        builder.mark_root(root);
    }
    let (forest, remap) = builder.build_with_id_map().unwrap();
    let digest_call = remap.get(digest_call).unwrap();
    let digest_dyn = remap.get(digest_dyn).unwrap();
    assert_eq!(forest[digest_call].unwrap_call().digest_callee(), remap.get(callee));
    assert_ne!(forest[digest_call].digest(), forest[remap.get(keyed_call).unwrap()].digest());
    assert_ne!(forest[digest_dyn].digest(), crate::mast::DynNode::DYN_DEFAULT_DIGEST);
    assert_ne!(
        forest[remap.get(digest_dyncall).unwrap()].digest(),
        crate::mast::DynNode::DYNCALL_DEFAULT_DIGEST
    );
    for hashless in [false, true] {
        let bytes = encode(&forest, hashless);
        assert_eq!(
            UntrustedMastForest::read_from_bytes(&bytes).unwrap().validate().unwrap(),
            forest
        );
    }

    let mut bytes = forest.to_bytes();
    let layout = layout(&bytes);
    let index = u32::from(digest_dyn) as usize;
    replace_entry(&mut bytes, layout, index, MastNodeEntry::Dyn);
    let result = UntrustedMastForest::read_from_bytes(&bytes).unwrap().validate();
    assert!(matches!(result, Err(MastForestError::HashMismatch { .. })));
}

#[test]
fn keyed_dense_roundtrip_preserves_modes_keys_and_views() {
    let forest = keyed_forest().with_advice_map(AdviceMap::from_iter([(
        key(30).into_word(),
        vec![Felt::from_u32(40), Felt::from_u32(41)],
    )]));
    let bytes = forest.to_bytes();
    assert_eq!(&bytes[5..8], &[0, 0, 6]);
    assert_eq!(bytes.len(), forest.get_size_hint());
    assert_eq!(MastForest::read_from_bytes(&bytes).unwrap(), forest);
    assert_eq!(MastForest::read_from(&mut SliceReader::new(&bytes)).unwrap(), forest);
    assert_eq!(
        UntrustedMastForest::read_from_bytes(&bytes).unwrap().validate().unwrap(),
        forest
    );

    let wire = MastForestWireView::new(&bytes).unwrap();
    assert_eq!(wire.all_node_infos().unwrap(), forest.all_node_infos().unwrap());
    let expected_keys = [key(10), key(10), key(10), key(20)];
    let indices = invocation_indices(&bytes);
    assert_eq!(indices.len(), expected_keys.len());
    assert_eq!(layout(&bytes).external_node_count, 1);
    assert_eq!(layout(&bytes).target_count, expected_keys.len());
    for (slot, (&index, &target)) in indices.iter().zip(&expected_keys).enumerate() {
        assert_eq!(wire.node_entry_at(index).unwrap().target_slot(), Some(slot as u32));
        assert_eq!(wire.node_target_at(index).unwrap(), Some(target));
        assert_eq!(wire.node_info_at(index).unwrap().target(), Some(target));
    }
    let mode_entries: Vec<_> =
        indices.iter().map(|&index| wire.node_entry_at(index).unwrap()).collect();
    assert_eq!(
        mode_entries,
        [
            MastNodeEntry::Call { target_slot: 0 },
            MastNodeEntry::SysCall { target_slot: 1 },
            MastNodeEntry::Exec { target_slot: 2 },
            MastNodeEntry::Exec { target_slot: 3 },
        ]
    );
    assert_ne!(
        wire.node_digest_at(indices[0]).unwrap(),
        wire.node_digest_at(indices[1]).unwrap()
    );
    assert_ne!(
        wire.node_digest_at(indices[0]).unwrap(),
        wire.node_digest_at(indices[2]).unwrap()
    );
    assert_ne!(
        wire.node_digest_at(indices[1]).unwrap(),
        wire.node_digest_at(indices[2]).unwrap()
    );

    for mode in [MastForestReadMode::Materialized, MastForestReadMode::WireBacked] {
        let view = MastForest::read_view_from_bytes(&bytes, mode).unwrap();
        assert_eq!(view.node_count(), forest.nodes().len());
        assert_eq!(view.all_node_infos().unwrap(), forest.all_node_infos().unwrap());
        for (index, node) in forest.nodes().iter().enumerate() {
            let target = match node {
                MastNode::Call(node) => Some(node.target()),
                MastNode::Exec(node) => Some(node.target()),
                _ => None,
            };
            assert_eq!(view.node_entry_at(index).unwrap(), forest.node_entry_at(index).unwrap());
            assert_eq!(view.node_digest_at(index).unwrap(), node.digest());
            assert_eq!(view.node_target_at(index).unwrap(), target);
            assert_eq!(view.node_info_at(index).unwrap().target(), target);
            assert_eq!(forest.node_target_at(index).unwrap(), target);
            assert_eq!(forest.node_info_at(index).unwrap().target(), target);
        }
        assert!(view.node_target_at(view.node_count()).is_err());
        assert_eq!(view.procedure_roots().unwrap(), forest.procedure_roots());
        assert_eq!(
            view.advice_map().get(&key(30).into_word()).unwrap().unwrap().as_slice(),
            &[Felt::from_u32(40), Felt::from_u32(41)]
        );
    }
    assert!(wire.node_target_at(wire.node_count()).is_err());
    assert!(forest.node_target_at(forest.nodes().len()).is_err());
}

#[test]
fn keyed_hashless_keeps_keys_and_rebuilds_childless_invocation_hashes() {
    let forest = keyed_forest();
    let full = encode(&forest, false);
    let hashless = encode(&forest, true);
    let full_layout = layout(&full);
    let hashless_layout = layout(&hashless);
    let targets_len = full_layout.target_count * Word::SERIALIZED_SIZE;
    assert_eq!(hashless.len(), forest.hashless_size_hint());
    assert_eq!(
        full.len() - hashless.len(),
        full_layout.internal_node_count * Word::SERIALIZED_SIZE
    );
    assert_eq!(
        &full[full_layout.target_offset()..full_layout.target_offset() + targets_len],
        &hashless[hashless_layout.target_offset()..hashless_layout.target_offset() + targets_len],
    );
    assert_eq!(hashless_layout.external_node_count, 1);
    assert_eq!(hashless_layout.target_count, 4);
    assert!(hashless_layout.node_hash_offset().is_none());
    assert!(MastForest::read_from_bytes(&hashless).is_err());
    assert!(MastForestWireView::new(&hashless).is_err());
    assert_eq!(
        UntrustedMastForest::read_from_bytes(&hashless).unwrap().validate().unwrap(),
        forest
    );
    assert_eq!(
        UntrustedMastForest::read_from_reader(&mut SliceReader::new(&hashless))
            .unwrap()
            .validate()
            .unwrap(),
        forest,
    );
}

#[test]
fn keyed_target_changes_are_bound_by_hashes_in_both_wire_modes() {
    let forest = keyed_forest();
    for hashless in [false, true] {
        let mut bytes = encode(&forest, hashless);
        let layout = layout(&bytes);
        let index = invocation_indices(&bytes)[0];
        bytes[layout.target_offset()..layout.target_offset() + Word::SERIALIZED_SIZE]
            .copy_from_slice(&key(99).to_bytes());
        let result = UntrustedMastForest::read_from_bytes(&bytes).unwrap().validate();
        if hashless {
            let rebuilt = result.unwrap();
            assert_eq!(rebuilt.node_target_at(index).unwrap(), Some(key(99)));
            assert_ne!(
                rebuilt.node_digest_at(index).unwrap(),
                forest.node_digest_at(index).unwrap()
            );
            assert_eq!(rebuilt.nodes()[0], forest.nodes()[0]); // External(D) is unchanged.
            assert_eq!(rebuilt.nodes()[1], forest.nodes()[1]); // So is the basic block.
        } else {
            assert!(matches!(result, Err(MastForestError::HashMismatch { .. })));
        }
    }
}

#[test]
fn keyed_external_digest_changes_preserve_invocation_targets_and_hashes() {
    let forest = keyed_forest();
    for hashless in [false, true] {
        let mut bytes = encode(&forest, hashless);
        let offset = layout(&bytes).external_digest_offset();
        bytes[offset..offset + Word::SERIALIZED_SIZE].copy_from_slice(&key(99).to_bytes());
        let rebuilt = UntrustedMastForest::read_from_bytes(&bytes).unwrap().validate().unwrap();
        assert_ne!(rebuilt.node_digest_at(0).unwrap(), forest.node_digest_at(0).unwrap());
        for index in 1..forest.nodes().len() {
            assert_eq!(
                rebuilt.node_target_at(index).unwrap(),
                forest.node_target_at(index).unwrap()
            );
            assert_eq!(
                rebuilt.node_digest_at(index).unwrap(),
                forest.node_digest_at(index).unwrap()
            );
        }
    }
}

#[test]
fn keyed_metadata_and_reconstruction_require_exact_target_presence() {
    let target = key(10);
    let decoder = BasicBlockDataDecoder::new(&[]);
    for (entry, node) in [
        (
            MastNodeEntry::Call { target_slot: 0 },
            MastNode::Call(CallNodeBuilder::new(target).build()),
        ),
        (
            MastNodeEntry::SysCall { target_slot: 0 },
            MastNode::Call(CallNodeBuilder::new_syscall(target).build()),
        ),
        (
            MastNodeEntry::Exec { target_slot: 0 },
            MastNode::Exec(ExecNodeBuilder::new(target).build()),
        ),
    ] {
        assert!(MastNodeInfo::from_entry(entry, node.digest(), None).is_err());
        assert!(entry.try_into_mast_node_builder(0, &decoder, node.digest(), None).is_err());

        let info = MastNodeInfo::from_entry(entry, node.digest(), Some(target)).unwrap();
        assert_eq!(info.node_entry(), entry);
        assert_eq!(info.target(), Some(target));
        assert_eq!(info.digest(), node.digest());
        // No structural node ID or callee body is required to reconstruct any invocation mode.
        let reconstructed = entry
            .try_into_mast_node_builder(0, &decoder, node.digest(), Some(target))
            .unwrap()
            .build_linked()
            .unwrap();
        assert_eq!(reconstructed, node);
        assert!(!reconstructed.has_children());
    }

    for entry in [
        MastNodeEntry::Block { ops_offset: 0 },
        MastNodeEntry::Join { left_child_id: 0, right_child_id: 0 },
        MastNodeEntry::Split { if_branch_id: 0, else_branch_id: 0 },
        MastNodeEntry::Loop { body_id: 0 },
        MastNodeEntry::Dyn,
        MastNodeEntry::Dyncall,
        MastNodeEntry::External,
    ] {
        assert!(MastNodeInfo::from_entry(entry, Word::default(), Some(target)).is_err());
        assert!(
            entry
                .try_into_mast_node_builder(0, &decoder, Word::default(), Some(target))
                .is_err()
        );
        assert_eq!(MastNodeInfo::from_entry(entry, Word::default(), None).unwrap().target(), None);
    }
}

#[test]
fn keyed_dense_rejects_noncanonical_slot_assignments() {
    let forest = keyed_forest();
    for hashless in [false, true] {
        let bytes = encode(&forest, hashless);
        let indices = invocation_indices(&bytes);
        for (index, slot) in [
            (indices[0], 1), // Skips slot zero.
            (indices[1], 0), // Reuses a slot even though equal key values are valid.
            (indices[2], 3), // Skips a middle slot.
            (indices[3], 4), // Exactly one past the section.
            (indices[3], u32::MAX),
        ] {
            let mut malformed = bytes.clone();
            set_target_slot(&mut malformed, index, slot);
            assert_structure_rejected(&malformed);
        }
    }
}

#[test]
fn keyed_dense_rejects_missing_and_unused_targets() {
    let forest = keyed_forest();
    for hashless in [false, true] {
        let bytes = encode(&forest, hashless);
        let layout = layout(&bytes);
        let count_offset = target_count_offset(&bytes);
        let targets_end = layout.target_offset() + layout.target_count * Word::SERIALIZED_SIZE;

        let mut missing = bytes.clone();
        missing[count_offset..count_offset + 4].copy_from_slice(&3u32.to_le_bytes());
        missing.drain(targets_end - Word::SERIALIZED_SIZE..targets_end);
        assert_structure_rejected(&missing);

        let mut unused = bytes.clone();
        unused[count_offset..count_offset + 4].copy_from_slice(&5u32.to_le_bytes());
        unused.splice(targets_end..targets_end, key(50).to_bytes());
        assert_structure_rejected(&unused);

        let mut absent = bytes.clone();
        absent[count_offset..count_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        absent.drain(layout.target_offset()..targets_end);
        assert_structure_rejected(&absent);

        // Keep the declared count but remove the bytes of a target.
        let mut truncated = bytes.clone();
        truncated.drain(targets_end - Word::SERIALIZED_SIZE..targets_end);
        assert_structure_rejected(&truncated);
    }
}

#[test]
fn keyed_dense_rejects_noncanonical_key_limbs() {
    let forest = keyed_forest();
    for hashless in [false, true] {
        let bytes = encode(&forest, hashless);
        let layout = layout(&bytes);
        // Check every limb position, including the final key at the section boundary.
        for slot in [0, layout.target_count - 1] {
            for limb in 0..4 {
                let mut malformed = bytes.clone();
                let offset = layout.target_offset() + slot * Word::SERIALIZED_SIZE + limb * 8;
                malformed[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
                assert_structure_rejected(&malformed);
            }
        }
    }
}

#[test]
fn keyed_dense_entries_preserve_tags_and_reject_unused_payload_bits() {
    for (tag, entry) in [
        (4u64, MastNodeEntry::Call { target_slot: u32::MAX }),
        (5, MastNodeEntry::SysCall { target_slot: u32::MAX }),
        (9, MastNodeEntry::Exec { target_slot: u32::MAX }),
        (10, MastNodeEntry::DigestCall { callee_id: u32::MAX }),
    ] {
        let bytes = entry.to_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes, ((tag << 60) | u64::from(u32::MAX)).to_le_bytes());
        assert_eq!(MastNodeEntry::read_from_bytes(&bytes).unwrap(), entry);
    }

    let forest = keyed_forest();
    for hashless in [false, true] {
        let bytes = encode(&forest, hashless);
        let layout = layout(&bytes);
        for index in 0..layout.node_count {
            let entry = layout.read_node_entry_at(&bytes, index).unwrap();
            let unused_bit = match entry {
                MastNodeEntry::Call { .. }
                | MastNodeEntry::SysCall { .. }
                | MastNodeEntry::Exec { .. }
                | MastNodeEntry::DigestCall { .. }
                | MastNodeEntry::Block { .. }
                | MastNodeEntry::Loop { .. } => 1u64 << 32,
                MastNodeEntry::Dyn
                | MastNodeEntry::Dyncall
                | MastNodeEntry::DigestDyn
                | MastNodeEntry::DigestDyncall
                | MastNodeEntry::External => 1,
                MastNodeEntry::Join { .. } | MastNodeEntry::Split { .. } => continue,
            };
            let mut malformed = bytes.clone();
            let offset = layout.node_entry_offset() + index * MastNodeEntry::SERIALIZED_SIZE;
            let raw = u64::from_le_bytes(malformed[offset..offset + 8].try_into().unwrap());
            malformed[offset..offset + 8].copy_from_slice(&(raw | unused_bit).to_le_bytes());
            assert_structure_rejected(&malformed);
        }
        for tag in 13u64..=15 {
            let mut malformed = bytes.clone();
            let offset = layout.node_entry_offset();
            malformed[offset..offset + 8].copy_from_slice(&(tag << 60).to_le_bytes());
            assert_structure_rejected(&malformed);
        }
    }
}

#[test]
fn keyed_dense_rejects_old_and_reserved_versions_on_every_reader() {
    assert_eq!(VERSION, [0, 0, 6]);
    for hashless in [false, true] {
        let bytes = encode(&keyed_forest(), hashless);
        for version in [[0, 0, 5], [0, 0, 7], [255, 255, 255]] {
            let mut malformed = bytes.clone();
            malformed[5..8].copy_from_slice(&version);
            assert_structure_rejected(&malformed);
        }
    }
}

#[test]
fn keyed_dense_rejects_truncation_and_trailing_target_payloads() {
    let forest = keyed_forest();
    for hashless in [false, true] {
        let bytes = encode(&forest, hashless);
        for end in 0..bytes.len() {
            let truncated = &bytes[..end];
            assert!(
                MastForest::read_from_bytes(truncated).is_err(),
                "trusted accepted prefix {end}"
            );
            assert!(MastForestWireView::new(truncated).is_err(), "view accepted prefix {end}");
            assert!(
                UntrustedMastForest::read_from_bytes(truncated).is_err(),
                "untrusted accepted prefix {end}"
            );
        }
        let mut trailing = bytes;
        trailing.extend_from_slice(&key(80).to_bytes());
        assert!(MastForest::read_from_bytes(&trailing).is_err());
        assert!(MastForestWireView::new(&trailing).is_err());
        assert!(UntrustedMastForest::read_from_bytes(&trailing).is_err());
    }
}

#[test]
fn keyed_dense_bounds_target_count_before_allocating() {
    for hashless in [false, true] {
        let mut bytes = encode(&keyed_forest(), hashless);
        let offset = target_count_offset(&bytes);
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_structure_rejected(&bytes);
    }

    // Both node entries fit the allocation bound, but two 32-byte keys do not. A header-only
    // input demonstrates that rejection happens before the scanner asks for section bytes.
    let mut header = b"MAST\x02\x00\x00\x06".to_vec();
    use crate::serde::ByteWriter;
    header.write_usize(2);
    header.write_usize(0);
    header.write_u32(2);
    let err = UntrustedMastForest::read_from_bytes_with_options(
        &header,
        UntrustedMastForestReadOptions::new().with_wire_byte_budget(64),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("invocation target count 2 exceeds reader allocation bound"),
        "unexpected rejection: {err}"
    );
}

#[test]
fn keyed_hashless_validation_obeys_helper_allocation_budget() {
    let bytes = encode(&keyed_forest(), true);
    let untrusted = UntrustedMastForest::read_from_bytes_with_options(
        &bytes,
        UntrustedMastForestReadOptions::new()
            .with_wire_byte_budget(bytes.len())
            .with_validation_allocation_budget(0),
    )
    .unwrap();
    let err = untrusted.validate().unwrap_err();
    assert!(err.to_string().contains("allocation budget"), "unexpected rejection: {err}");
}
