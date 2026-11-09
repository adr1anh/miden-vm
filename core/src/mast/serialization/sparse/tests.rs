use alloc::vec;

use super::*;
use crate::{Felt, mast::ExecutableMastForest};

fn target() -> ProcedureKey {
    ProcedureKey::new(Word::new(
        [0, 255, 0x0102_0304_0506_0708, Felt::ORDER - 1].map(Felt::new_unchecked),
    ))
}

fn invocation_nodes() -> [(u8, MastNode); 3] {
    [
        (SPARSE_CALL, CallNodeBuilder::new(target()).build().into()),
        (SPARSE_SYSCALL, CallNodeBuilder::new_syscall(target()).build().into()),
        (SPARSE_EXEC, ExecNodeBuilder::new(target()).build().into()),
    ]
}

fn sparse_invocations() -> SparseMastForest {
    let nodes: Vec<_> = invocation_nodes()
        .into_iter()
        .enumerate()
        .map(|(index, (_, node))| (MastNodeId::from(7 + index as u32 * 4), node))
        .collect();
    let roots = nodes.iter().map(|(id, _)| *id).collect();
    SparseMastForest::from_serialized_parts(nodes, Vec::new(), roots, AdviceMap::default()).unwrap()
}

fn assert_target(node: &MastNode, expected_tag: u8) {
    match (node, expected_tag) {
        (MastNode::Call(call), SPARSE_CALL | SPARSE_SYSCALL) => {
            assert_eq!(call.target(), target());
            assert_eq!(call.is_syscall(), expected_tag == SPARSE_SYSCALL);
        },
        (MastNode::Exec(exec), SPARSE_EXEC) => assert_eq!(exec.target(), target()),
        _ => panic!("unexpected invocation node: {node:?}"),
    }
    assert!(!node.has_children());
}

/// A single full node with no procedure roots, digest-only entries, or advice.
fn raw_node_payload(tag: u8, key_bytes: &[u8]) -> (Vec<u8>, usize) {
    let mut bytes = Vec::new();
    0usize.write_into(&mut bytes);
    1usize.write_into(&mut bytes);
    MastNodeId::from(7).write_into(&mut bytes);
    tag.write_into(&mut bytes);
    Word::default().write_into(&mut bytes);
    let key_offset = bytes.len();
    bytes.extend_from_slice(key_bytes);
    0usize.write_into(&mut bytes);
    AdviceMap::default().write_into(&mut bytes);
    (bytes, key_offset)
}

#[test]
fn invocation_round_trip_preserves_keys_and_modes_without_callee_code() {
    let sparse = sparse_invocations();
    let bytes = sparse.to_bytes();
    let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();

    assert_eq!(restored.to_bytes(), bytes);
    assert_eq!(restored.procedure_roots(), sparse.procedure_roots());
    assert!(restored.digest_entries().is_empty());
    assert_eq!(restored.nodes().len(), 3);
    for ((&id, original), (tag, _)) in sparse.nodes().iter().zip(invocation_nodes()) {
        let node = restored.get_node_by_id(id).unwrap();
        assert_eq!(node, original);
        assert_target(node, tag);
    }

    let [(_, call), (_, syscall), (_, exec)] = invocation_nodes();
    assert_ne!(call.digest(), syscall.digest());
    assert_ne!(call.digest(), exec.digest());
    assert_ne!(syscall.digest(), exec.digest());
}

#[test]
fn invocation_wire_retains_existing_tags_and_full_key_words() {
    assert_eq!((SPARSE_CALL, SPARSE_SYSCALL, SPARSE_EXEC), (4, 5, 9));
    let sparse = sparse_invocations();
    let bytes = sparse.to_bytes();
    let mut reader = SliceReader::new(&bytes);
    assert_eq!(read_node_ids(&mut reader, "test roots").unwrap(), sparse.procedure_roots());
    assert_eq!(reader.read_usize().unwrap(), 3);

    for ((&id, original), (tag, _)) in sparse.nodes().iter().zip(invocation_nodes()) {
        assert_eq!(MastNodeId::read_from(&mut reader).unwrap(), id);
        assert_eq!(reader.read_u8().unwrap(), tag);
        assert_eq!(Word::read_from(&mut reader).unwrap(), original.digest());
        assert_eq!(ProcedureKey::read_from(&mut reader).unwrap(), target());
    }
    assert_eq!(reader.read_usize().unwrap(), 0);
    assert_eq!(reader.read_usize().unwrap(), 0);
    assert!(!reader.has_more_bytes());
}

#[test]
fn trusted_invocation_reader_preserves_supplied_digest_cache() {
    for (tag, node) in invocation_nodes() {
        let (bytes, _) = raw_node_payload(tag, &target().to_bytes());
        let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();
        let restored_node = restored.get_node_by_id(MastNodeId::from(7)).unwrap();
        assert_target(restored_node, tag);
        assert_eq!(restored_node.digest(), Word::default());
        assert_ne!(restored_node.digest(), node.digest());
    }
}

#[test]
fn invocation_reader_rejects_every_truncated_key() {
    for (tag, _) in invocation_nodes() {
        let key = target().to_bytes();
        let (bytes, key_offset) = raw_node_payload(tag, &key);
        for length in 0..key.len() {
            assert!(
                SparseMastForest::read_from_bytes(&bytes[..key_offset + length]).is_err(),
                "tag {tag} accepted a {length}-byte procedure key"
            );
        }

        // The prior callee-ID payload is not a substitute for a canonical key Word.
        let (legacy, _) = raw_node_payload(tag, &7u32.to_bytes());
        assert!(SparseMastForest::read_from_bytes(&legacy).is_err());
    }
}

#[test]
fn invocation_reader_rejects_noncanonical_key_limbs() {
    for (tag, _) in invocation_nodes() {
        let (bytes, key_offset) = raw_node_payload(tag, &target().to_bytes());
        for lane in 0..4 {
            for invalid in [Felt::ORDER, u64::MAX] {
                let mut tampered = bytes.clone();
                let limb_offset = key_offset + lane * 8;
                tampered[limb_offset..limb_offset + 8].copy_from_slice(&invalid.to_le_bytes());
                assert!(
                    SparseMastForest::read_from_bytes(&tampered).is_err(),
                    "tag {tag} accepted noncanonical key limb {lane}"
                );
            }
        }
    }
}

#[test]
fn invocation_reader_rejects_trailing_bytes() {
    let mut bytes = sparse_invocations().to_bytes();
    bytes.push(0);
    let error = SparseMastForest::read_from_bytes(&bytes).unwrap_err();
    assert!(error.to_string().contains("extra bytes after SparseMastForest payload"));
}

#[test]
fn sparse_digest_call_requires_its_callee_digest() {
    let callee = MastNodeId::from(2);
    let digest = target().into_word();
    let call = CallNodeBuilder::new_digest(callee)
        .with_digest(crate::mast::CallNode::digest_for_callee(digest))
        .build()
        .into();
    let call_id = MastNodeId::from(7);
    let dyn_id = MastNodeId::from(8);
    let dyncall_id = MastNodeId::from(9);
    let nodes = vec![
        (call_id, call),
        (dyn_id, DynNodeBuilder::new_digest().build().into()),
        (dyncall_id, DynNodeBuilder::new_digest_dyncall().build().into()),
    ];
    assert!(
        SparseMastForest::from_serialized_parts(
            nodes.clone(),
            Vec::new(),
            vec![call_id],
            AdviceMap::default(),
        )
        .is_err()
    );
    let forest = SparseMastForest::from_serialized_parts(
        nodes,
        vec![(callee, digest)],
        vec![call_id],
        AdviceMap::default(),
    )
    .unwrap();
    let bytes = forest.to_bytes();
    let restored = SparseMastForest::read_from_bytes(&bytes).unwrap();
    assert_eq!(restored.nodes(), forest.nodes());
    assert_eq!(restored.get_digest_by_id(callee), Some(digest));
    assert_eq!(restored.to_bytes(), bytes);
}

#[test]
fn sparse_reader_rejects_unknown_tags_after_digest_invocations() {
    for tag in [SPARSE_DIGEST_DYNCALL + 1, u8::MAX] {
        let (bytes, _) = raw_node_payload(tag, &[]);
        let error = SparseMastForest::read_from_bytes(&bytes).unwrap_err();
        assert!(error.to_string().contains("invalid sparse MAST node tag"));
    }
}
