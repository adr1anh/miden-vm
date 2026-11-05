use alloc::vec;

use super::*;
use crate::{
    Word,
    program::{ImplementationRoot, LabelCommitment},
};

#[test]
fn explicit_zero_limits_create_an_empty_store_without_allocating() {
    let limits = EnvironmentBuildLimits {
        max_submitted_nodes: 0,
        max_visits: 0,
        max_depth: 0,
        max_list_children: 0,
        max_encoded_bytes: 0,
        max_bindings: 0,
        max_storage_bytes: 0,
    };
    let mut builder = EnvironmentBuilder::new(limits);
    assert_eq!(builder.limits(), &limits);
    assert!(builder.is_empty());
    assert_eq!(snapshot(&builder), (0, 0, 0, 0, 0));
    assert_eq!(builder.get(root(1)), None);
    assert_limit(builder.insert(mast(1)), EnvironmentBuildResource::SubmittedNodes, 0, 1);
    assert_eq!(snapshot(&builder), (0, 0, 0, 0, 0));
}

#[test]
fn stored_commitments_match_existing_object_hashes_and_lookup_is_read_only() {
    let label = LabelCommitment::new(word(1));
    let nodes = vec![
        EnvNode::Env { label, child: root(2) },
        mast(3),
        EnvNode::Data { kind: u32::MAX, label, value: word(4) },
        EnvNode::Merkle { left: root(5), right: root(6) },
        EnvNode::List(vec![]),
        EnvNode::List(vec![root(7)]),
        EnvNode::List(vec![root(8), root(9), root(10)]),
    ];
    let mut builder = EnvironmentBuilder::new(limits());
    let mut expected = Vec::new();
    for node in nodes {
        let root = node.commitment().unwrap();
        expected.push((root, node.clone()));
        assert_eq!(builder.insert(node), Ok(root));
    }
    assert_eq!(builder.len(), expected.len());
    assert_eq!(builder.submitted_nodes(), expected.len());
    for (root, node) in expected {
        assert_eq!(builder.get(root), Some(&node));
    }
    assert_eq!(builder.get(root(999)), None);
}

#[test]
fn duplicate_submissions_consume_exact_work_and_byte_budgets_without_more_records() {
    let node = mast(1);
    let encoded_len = node.encoded_len().unwrap();
    let record_bytes = size_of::<NodeRecord>();
    let mut limits = limits();
    limits.max_submitted_nodes = 2;
    limits.max_encoded_bytes = 2 * encoded_len;
    limits.max_storage_bytes = record_bytes;
    let mut builder = EnvironmentBuilder::new(limits);
    let root = builder.insert(node.clone()).unwrap();
    assert_eq!(builder.insert(node.clone()), Ok(root));
    assert_eq!(snapshot(&builder), (1, 2, 2 * encoded_len, record_bytes, record_bytes));
    let before = snapshot(&builder);
    assert_limit(builder.insert(node), EnvironmentBuildResource::SubmittedNodes, 2, 3);
    assert_eq!(snapshot(&builder), before);
    assert_eq!(builder.get(root), Some(&mast(1)));
}

#[test]
fn encoded_byte_limit_rejects_a_duplicate_one_byte_short_without_changing_state() {
    let node = mast(1);
    let encoded_len = node.encoded_len().unwrap();
    let mut limits = limits();
    limits.max_encoded_bytes = 2 * encoded_len - 1;
    let mut builder = EnvironmentBuilder::new(limits);
    let root = builder.insert(node.clone()).unwrap();
    let before = snapshot(&builder);
    assert_limit(
        builder.insert(node.clone()),
        EnvironmentBuildResource::EncodedBytes,
        2 * encoded_len - 1,
        2 * encoded_len,
    );
    assert_eq!(snapshot(&builder), before);
    assert_eq!(builder.get(root), Some(&node));
}

#[test]
fn every_preimage_has_an_exact_and_one_short_encoded_byte_limit() {
    let label = LabelCommitment::new(word(1));
    for node in [
        EnvNode::Env { label, child: root(2) },
        mast(3),
        EnvNode::Data { kind: 4, label, value: word(5) },
        EnvNode::Merkle { left: root(6), right: root(7) },
        EnvNode::List(vec![]),
        EnvNode::List(vec![root(8), root(9), root(10)]),
    ] {
        let encoded_len = node.encoded_len().unwrap();
        let mut exact = limits();
        exact.max_encoded_bytes = encoded_len;
        let mut builder = EnvironmentBuilder::new(exact);
        assert!(builder.insert(node.clone()).is_ok());
        assert_eq!(builder.encoded_bytes(), encoded_len);

        exact.max_encoded_bytes -= 1;
        let mut builder = EnvironmentBuilder::new(exact);
        assert_limit(
            builder.insert(node),
            EnvironmentBuildResource::EncodedBytes,
            encoded_len - 1,
            encoded_len,
        );
        assert_eq!(snapshot(&builder), (0, 0, 0, 0, 0));
    }
}

#[test]
fn list_child_limit_is_exact_and_counts_immediate_children() {
    let node = EnvNode::List(vec![root(1), root(2), root(3)]);
    let mut exact = limits();
    exact.max_list_children = 3;
    let mut builder = EnvironmentBuilder::new(exact);
    assert!(builder.insert(node.clone()).is_ok());

    exact.max_list_children = 2;
    let mut builder = EnvironmentBuilder::new(exact);
    assert_limit(builder.insert(node), EnvironmentBuildResource::ListChildren, 2, 3);
    assert_eq!(snapshot(&builder), (0, 0, 0, 0, 0));
}

#[test]
fn record_growth_accounts_for_old_and_new_requests_at_exact_and_one_short_limits() {
    let record_bytes = size_of::<NodeRecord>();
    let mut exact = limits();
    exact.max_storage_bytes = 3 * record_bytes;
    let mut builder = EnvironmentBuilder::new(exact);
    let first_root = builder.insert(mast(1)).unwrap();
    assert!(builder.insert(mast(2)).is_ok());
    assert_eq!(builder.storage_bytes(), 2 * record_bytes);
    assert_eq!(builder.peak_storage_bytes(), 3 * record_bytes);

    exact.max_storage_bytes -= 1;
    let mut builder = EnvironmentBuilder::new(exact);
    assert_eq!(builder.insert(mast(1)), Ok(first_root));
    let before = snapshot(&builder);
    assert_limit(
        builder.insert(mast(2)),
        EnvironmentBuildResource::StorageBytes,
        3 * record_bytes - 1,
        3 * record_bytes,
    );
    assert_eq!(snapshot(&builder), before);
    assert_eq!(builder.get(first_root), Some(&mast(1)));
    assert_eq!(builder.get(mast(2).commitment().unwrap()), None);
}

#[test]
fn first_record_request_requires_its_exact_storage_budget() {
    let record_bytes = size_of::<NodeRecord>();
    let mut exact = limits();
    exact.max_storage_bytes = record_bytes;
    assert!(EnvironmentBuilder::new(exact).insert(mast(1)).is_ok());
    exact.max_storage_bytes -= 1;
    let mut builder = EnvironmentBuilder::new(exact);
    assert_limit(
        builder.insert(mast(1)),
        EnvironmentBuildResource::StorageBytes,
        record_bytes - 1,
        record_bytes,
    );
    assert_eq!(snapshot(&builder), (0, 0, 0, 0, 0));
}

#[test]
fn list_hash_scratch_has_an_exact_and_one_short_peak_budget() {
    let children = vec![root(1); 32];
    let input_bytes = children.capacity() * size_of::<EnvironmentRoot>();
    let scratch_bytes = children.len() * WORD_SIZE * size_of::<Felt>();
    assert!(scratch_bytes > size_of::<NodeRecord>());
    let hash_peak = input_bytes + scratch_bytes;
    let mut exact = limits();
    exact.max_storage_bytes = hash_peak;
    let mut builder = EnvironmentBuilder::new(exact);
    assert!(builder.insert(EnvNode::List(children)).is_ok());
    assert_eq!(builder.storage_bytes(), size_of::<NodeRecord>() + input_bytes);
    assert_eq!(builder.peak_storage_bytes(), hash_peak);

    let children = vec![root(1); 32];
    assert_eq!(children.capacity() * size_of::<EnvironmentRoot>(), input_bytes);
    exact.max_storage_bytes -= 1;
    let mut builder = EnvironmentBuilder::new(exact);
    assert_limit(
        builder.insert(EnvNode::List(children)),
        EnvironmentBuildResource::StorageBytes,
        hash_peak - 1,
        hash_peak,
    );
    assert_eq!(snapshot(&builder), (0, 0, 0, 0, 0));
}

#[test]
fn retained_list_capacity_is_charged_even_when_len_is_zero() {
    let children = Vec::with_capacity(8);
    let capacity_bytes = children.capacity() * size_of::<EnvironmentRoot>();
    let required = size_of::<NodeRecord>() + capacity_bytes;
    let mut exact = limits();
    exact.max_list_children = 0;
    exact.max_storage_bytes = required;
    let mut builder = EnvironmentBuilder::new(exact);
    let root = builder.insert(EnvNode::List(children)).unwrap();
    assert_eq!(builder.storage_bytes(), required);
    assert_eq!(builder.get(root), Some(&EnvNode::List(vec![])));

    exact.max_storage_bytes = required - 1;
    let mut builder = EnvironmentBuilder::new(exact);
    assert_limit(
        builder.insert(EnvNode::List(Vec::with_capacity(8))),
        EnvironmentBuildResource::StorageBytes,
        required - 1,
        required,
    );
    assert_eq!(snapshot(&builder), (0, 0, 0, 0, 0));
}

#[test]
fn duplicate_list_capacity_and_hash_scratch_are_charged_while_the_original_is_retained() {
    let original = list_with_capacity(4);
    let duplicate = list_with_capacity(8);
    let original_bytes = list_capacity_bytes(&original);
    let duplicate_bytes = list_capacity_bytes(&duplicate);
    let record_bytes = size_of::<NodeRecord>();
    let scratch_bytes = WORD_SIZE * size_of::<Felt>();
    let duplicate_peak = record_bytes + original_bytes + duplicate_bytes + scratch_bytes;
    let mut exact = limits();
    exact.max_storage_bytes = duplicate_peak;
    let mut builder = EnvironmentBuilder::new(exact);
    let commitment = builder.insert(original).unwrap();
    assert_eq!(builder.insert(duplicate), Ok(commitment));
    assert_eq!(builder.len(), 1);
    assert_eq!(builder.submitted_nodes(), 2);
    assert_eq!(builder.storage_bytes(), record_bytes + original_bytes);
    assert_eq!(builder.peak_storage_bytes(), duplicate_peak);

    exact.max_storage_bytes -= 1;
    let mut builder = EnvironmentBuilder::new(exact);
    assert_eq!(builder.insert(list_with_capacity(4)), Ok(commitment));
    let before = snapshot(&builder);
    assert_limit(
        builder.insert(list_with_capacity(8)),
        EnvironmentBuildResource::StorageBytes,
        duplicate_peak - 1,
        duplicate_peak,
    );
    assert_eq!(snapshot(&builder), before);
    assert_eq!(builder.get(commitment), Some(&EnvNode::List(vec![root(1)])));
}

#[test]
fn arithmetic_and_layout_overflow_are_rejected_without_large_allocations() {
    assert_eq!(checked_add(usize::MAX, 1), Err(EnvironmentBuildError::LengthOverflow));
    assert_eq!(
        array_bytes::<NodeRecord>(usize::MAX),
        Err(EnvironmentBuildError::LengthOverflow)
    );
    let too_many_roots = isize::MAX as usize / size_of::<EnvironmentRoot>() + 1;
    assert_eq!(
        array_bytes::<EnvironmentRoot>(too_many_roots),
        Err(EnvironmentBuildError::LengthOverflow)
    );
    assert_eq!(list_hash_scratch_bytes(usize::MAX), Err(EnvironmentBuildError::LengthOverflow));
    assert_eq!(
        list_hash_scratch_bytes(too_many_roots),
        Err(EnvironmentBuildError::LengthOverflow)
    );

    let mut builder = EnvironmentBuilder::new(limits());
    let root = builder.insert(mast(1)).unwrap();
    builder.encoded_bytes = usize::MAX;
    let before = snapshot(&builder);
    assert_eq!(builder.insert(mast(2)), Err(EnvironmentBuildError::LengthOverflow));
    assert_eq!(snapshot(&builder), before);
    assert_eq!(builder.get(root), Some(&mast(1)));

    builder.encoded_bytes = 0;
    builder.submitted_nodes = usize::MAX;
    let before = snapshot(&builder);
    assert_eq!(builder.insert(mast(2)), Err(EnvironmentBuildError::LengthOverflow));
    assert_eq!(snapshot(&builder), before);
}

#[test]
fn unequal_preimages_with_the_same_index_commitment_are_rejected_transactionally() {
    let mut builder = EnvironmentBuilder::new(limits());
    builder.insert(mast(1)).unwrap();
    // A synthetic hash collision exercises the otherwise infeasible unequal-preimage branch.
    let colliding_root = mast(2).commitment().unwrap();
    builder.records.get_mut(0).unwrap().root = colliding_root;
    let before = snapshot(&builder);
    assert_eq!(builder.insert(mast(2)), Err(EnvironmentBuildError::CommitmentCollision));
    assert_eq!(snapshot(&builder), before);
    assert_eq!(builder.get(colliding_root), Some(&mast(1)));
}

fn limits() -> EnvironmentBuildLimits {
    EnvironmentBuildLimits {
        max_submitted_nodes: usize::MAX,
        max_visits: 0,
        max_depth: 0,
        max_list_children: usize::MAX,
        max_encoded_bytes: usize::MAX,
        max_bindings: 0,
        max_storage_bytes: usize::MAX,
    }
}

fn snapshot(builder: &EnvironmentBuilder) -> (usize, usize, usize, usize, usize) {
    (
        builder.len(),
        builder.submitted_nodes(),
        builder.encoded_bytes(),
        builder.storage_bytes(),
        builder.peak_storage_bytes(),
    )
}

fn assert_limit(
    result: Result<EnvironmentRoot, EnvironmentBuildError>,
    resource: EnvironmentBuildResource,
    limit: usize,
    requested: usize,
) {
    assert_eq!(result, Err(EnvironmentBuildError::LimitExceeded { resource, limit, requested }));
}

fn list_with_capacity(capacity: usize) -> EnvNode {
    let mut children = Vec::with_capacity(capacity);
    children.push(root(1));
    EnvNode::List(children)
}

fn list_capacity_bytes(node: &EnvNode) -> usize {
    match node {
        EnvNode::List(children) => children.capacity() * size_of::<EnvironmentRoot>(),
        _ => unreachable!("fixture must be a List"),
    }
}

fn mast(value: u32) -> EnvNode {
    EnvNode::Mast {
        label: LabelCommitment::new(word(value)),
        implementation: ImplementationRoot::new(word(value + 1)),
    }
}

fn root(value: u32) -> EnvironmentRoot {
    EnvironmentRoot::new(word(value))
}

fn word(value: u32) -> Word {
    Word::new([Felt::from_u32(value); WORD_SIZE])
}
