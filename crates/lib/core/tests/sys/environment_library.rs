use miden_core::{
    Felt, Word,
    crypto::{hash::Eidos, merkle::InnerNodeInfo},
    program::{EnvNode, ImplementationRoot, LabelCommitment, Namespace},
};
use miden_core_lib::handlers::environment::{
    ENVIRONMENT_BUILD_TREE_EVENT_NAME, MAX_ENVIRONMENT_TREE_LEAVES,
};
use miden_processor::{
    ExecutionError, ExecutionOutput, ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
};

use crate::helpers::{masm_push_word, masm_store_felts};

const ENTRIES_PTR: u32 = 1024;
const SCRATCH_PTR: u32 = 4096;

#[derive(Clone)]
struct Entry {
    label: LabelCommitment,
    key: Word,
    implementation: ImplementationRoot,
}

fn word(seed: u32) -> Word {
    Word::new([seed, seed + 1, seed + 2, seed + 3].map(Felt::from_u32))
}

fn entries(namespace: Namespace, count: usize) -> Vec<Entry> {
    let mut entries: Vec<_> = (0..count)
        .map(|index| {
            let label = LabelCommitment::new(word(10 + index as u32 * 8));
            Entry {
                label,
                key: namespace.procedure_key(label).into_word(),
                implementation: ImplementationRoot::new(word(100 + index as u32 * 8)),
            }
        })
        .collect();
    entries.sort_by_key(|entry| entry.key);
    entries
}

fn entry_memory(entries: &[Entry]) -> Vec<Felt> {
    entries
        .iter()
        .flat_map(|entry| {
            [entry.label.into_word(), entry.key, entry.implementation.into_word()]
                .into_iter()
                .flat_map(|word| word.into_elements())
        })
        .collect()
}

fn leaf(entry: &Entry) -> Word {
    EnvNode::Mast {
        label: entry.label,
        implementation: entry.implementation,
    }
    .commitment()
    .unwrap()
    .into_word()
}

/// Split recursively, independently of the handler's iterative pair-and-promote reduction.
fn native_tree(leaves: &[Word]) -> (Word, Vec<InnerNodeInfo>) {
    fn visit(leaves: &[Word], nodes: &mut Vec<InnerNodeInfo>) -> Word {
        match leaves.len() {
            0 => EnvNode::List(Vec::new()).commitment().unwrap().into_word(),
            1 => leaves[0],
            n => {
                let split = 1 << (n - 1).ilog2();
                let left = visit(&leaves[..split], nodes);
                let right = visit(&leaves[split..], nodes);
                let value = Eidos::merge(&[left, right]);
                nodes.push(InnerNodeInfo { value, left, right });
                value
            },
        }
    }
    let mut nodes = Vec::new();
    (visit(leaves, &mut nodes), nodes)
}

fn expected_tree(entries: &[Entry]) -> (Word, Vec<(Word, Vec<Felt>)>) {
    let leaves: Vec<_> = entries.iter().map(leaf).collect();
    let (root, nodes) = native_tree(&leaves);
    let mut preimages: Vec<_> = entries
        .iter()
        .zip(leaves)
        .map(|(entry, root)| {
            let payload = [entry.label.into_word(), entry.implementation.into_word()];
            (root, Word::words_as_elements(&payload).to_vec())
        })
        .collect();
    preimages.extend(
        nodes
            .into_iter()
            .map(|node| (node.value, Word::words_as_elements(&[node.left, node.right]).to_vec())),
    );
    if entries.is_empty() {
        preimages.push((root, Vec::new()));
    }
    (root, preimages)
}

fn create_inputs(namespace: Namespace, count: usize) -> Vec<u64> {
    let mut inputs: Vec<_> = namespace.as_word().iter().map(Felt::as_canonical_u64).collect();
    inputs.extend([ENTRIES_PTR as u64, count as u64, SCRATCH_PTR as u64]);
    inputs
}

fn source(entries: &[Entry], operation: &str) -> String {
    format!(
        "use miden::core::sys::environment::library
         use miden::core::sys::environment
         use miden::core::sys
         begin {} {operation} exec.sys::truncate_stack end",
        masm_store_felts(&entry_memory(entries), ENTRIES_PTR),
    )
}

#[test]
fn environment_library_creation_matches_native_tree_and_exports_all_preimages() {
    let namespace = Namespace::new(word(700));
    for count in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 17] {
        let entries = entries(namespace, count);
        let (root, preimages) = expected_tree(&entries);
        let mut inputs = create_inputs(namespace, count);
        inputs.push(901);
        let body = if count > 1 {
            "exec.library::create dupw exec.environment::open_merkle dropw dropw"
        } else {
            "exec.library::create"
        };
        let (output, _) =
            build_test!(source(&entries, body), &inputs).execute_for_output().unwrap();
        assert_root_and_tail(&output, root);
        for (node, payload) in preimages {
            assert_eq!(output.advice.get_mapped_values(&node), Some(payload.as_slice()));
        }
    }
}

#[test]
fn environment_library_verifies_a_public_root_and_preserves_stack_tail() {
    let namespace = Namespace::initial();
    let entries = entries(namespace, 5);
    let (root, _) = expected_tree(&entries);
    let mut inputs: Vec<_> = root.iter().map(Felt::as_canonical_u64).collect();
    inputs.extend(create_inputs(namespace, entries.len()));
    inputs.extend([901, 902]);
    build_test!(source(&entries, "exec.library::verify"), &inputs).expect_stack(&[901, 902]);

    inputs[0] += 1;
    assert!(
        build_test!(source(&entries, "exec.library::verify"), &inputs)
            .execute()
            .is_err(),
        "an independently supplied root must match the reconstructed tree",
    );
}

#[test]
fn environment_library_rejects_invalid_keys_labels_order_and_namespace() {
    let namespace = Namespace::initial();
    let sorted = entries(namespace, 2);
    let mut bad_label = sorted.clone();
    bad_label[0].label = LabelCommitment::new(word(900));
    let mut bad_key = sorted.clone();
    bad_key[0].key = word(900);
    for (entries, namespace) in [
        (sorted.clone(), Namespace::new(word(800))),
        (bad_label, namespace),
        (bad_key, namespace),
        (vec![sorted[1].clone(), sorted[0].clone()], namespace),
        (vec![sorted[0].clone(); 2], namespace),
    ] {
        assert!(
            build_test!(
                source(&entries, "exec.library::create"),
                &create_inputs(namespace, entries.len())
            )
            .execute()
            .is_err()
        );
    }
}

/// Execute the actual private comparator with prefix ties that derived hashes rarely produce.
/// Including the source as a local fixture avoids expanding the core library's public API.
#[test]
fn environment_library_key_comparison_checks_every_coordinate_and_full_field_values() {
    // These imports are Latest when the module is compiled outside the core package. Retain
    // their calls in this functional fixture; production source can inline its fixed local bodies.
    let implementation = include_str!("../../asm/sys/environment/library.masm")
        .replace("pub proc ", "proc ")
        .replace("inline.environment::", "exec.environment::")
        .replace("inline.word::", "exec.word::");
    let max = 0xffff_ffff_0000_0000;
    let mut pairs =
        vec![([0; 4], [0; 4]), ([max; 4], [max; 4]), ([u32::MAX as u64; 4], [1 << 32; 4])];
    for coordinate in 0..4 {
        let mut lesser = [max; 4];
        let mut greater = [0; 4];
        lesser[coordinate] = 0;
        greater[coordinate] = max;
        // Higher coordinates tie; lower coordinates point in the opposite direction.
        for index in coordinate + 1..4 {
            lesser[index] = 42;
            greater[index] = 42;
        }
        pairs.extend([(lesser, greater), (greater, lesser)]);
    }
    for (previous, current) in pairs {
        let previous = Word::new(previous.map(Felt::new_unchecked));
        let current = Word::new(current.map(Felt::new_unchecked));
        let source = format!(
            "{implementation}
             use miden::core::sys
             begin {} {} push.901 push.{} inline.assert_increasing_key
                 exec.sys::truncate_stack end",
            masm_store_felts(previous.as_elements(), ENTRIES_PTR + 4),
            masm_store_felts(current.as_elements(), ENTRIES_PTR + 16),
            ENTRIES_PTR + 12,
        );
        let result = build_test!(source, &[]).execute_for_output();
        if previous < current {
            let (output, _) = result.expect("an increasing key pair must be accepted");
            assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(901)));
        } else {
            assert!(result.is_err(), "equal or descending full-word keys must be rejected");
        }
    }
}

#[test]
fn environment_library_rejects_invalid_memory_ranges() {
    let namespace = Namespace::initial();
    let invalid = [
        (ENTRIES_PTR as u64 + 1, 1, SCRATCH_PTR as u64),
        (ENTRIES_PTR as u64, 1, SCRATCH_PTR as u64 + 1),
        (1 << 32, 1, SCRATCH_PTR as u64),
        (ENTRIES_PTR as u64, 1 << 32, SCRATCH_PTR as u64),
        (ENTRIES_PTR as u64, 1, 1 << 32),
        (u32::MAX as u64 - 3, 1, SCRATCH_PTR as u64),
        (ENTRIES_PTR as u64, 1, u32::MAX as u64 - 3),
        (ENTRIES_PTR as u64, 65537, SCRATCH_PTR as u64),
        (ENTRIES_PTR as u64, 2, ENTRIES_PTR as u64),
        (ENTRIES_PTR as u64, 2, ENTRIES_PTR as u64 + 20),
        (ENTRIES_PTR as u64, 2, ENTRIES_PTR as u64 - 4),
    ];
    let source = "use miden::core::sys::environment::library begin exec.library::create end";
    for (entries_ptr, count, scratch_ptr) in invalid {
        let mut inputs: Vec<_> = namespace.as_word().iter().map(Felt::as_canonical_u64).collect();
        inputs.extend([entries_ptr, count, scratch_ptr]);
        let test = build_test!(source, &inputs);
        if count == 65537 {
            crate::expect_assert_error_code_from_msg!(
                test,
                "environment library exceeds 65536 entries"
            );
        } else {
            assert!(
                test.execute().is_err(),
                "invalid range must fail: entries={entries_ptr}, count={count}, scratch={scratch_ptr}",
            );
        }
    }
}

#[test]
fn environment_library_accepts_adjacent_ranges_and_high_memory() {
    let namespace = Namespace::initial();
    for count in [7, 8] {
        let entries = entries(namespace, count);
        let (root, _) = expected_tree(&entries);
        for (entries_ptr, scratch_ptr) in [
            (ENTRIES_PTR, ENTRIES_PTR - count as u32 * 4),
            (ENTRIES_PTR, ENTRIES_PTR + count as u32 * 12),
            (0xc000_0000, 0xc000_1000),
        ] {
            let source = format!(
                "use miden::core::sys use miden::core::sys::environment::library
                 begin {} exec.library::create exec.sys::truncate_stack end",
                masm_store_felts(&entry_memory(&entries), entries_ptr),
            );
            let mut inputs: Vec<_> =
                namespace.as_word().iter().map(Felt::as_canonical_u64).collect();
            inputs.extend([entries_ptr as u64, count as u64, scratch_ptr as u64, 901]);
            let (output, _) = build_test!(source, &inputs).execute_for_output().unwrap();
            assert_root_and_tail(&output, root);
        }
    }
}

#[test]
fn environment_library_accepts_entries_and_scratch_in_the_callers_local_frame() {
    let namespace = Namespace::initial();
    for count in [7, 8] {
        let entries = entries(namespace, count);
        let (root, _) = expected_tree(&entries);
        let stores = entry_memory(&entries)
            .iter()
            .enumerate()
            .map(|(index, value)| format!("push.{} loc_store.{index}", value.as_canonical_u64()))
            .collect::<Vec<_>>()
            .join(" ");
        let scratch_offset = count * 12;
        // Scratch fills the remainder of the caller's frame; create uses no working locals.
        let source = format!(
            "use miden::core::sys::environment
             use miden::core::sys::environment::library
             use miden::core::sys
             @locals({local_count})
             proc construct_in_locals
                 {stores}
                 locaddr.{scratch_offset} push.{count} locaddr.0
                 exec.environment::initial_namespace
                 exec.library::create
             end
             begin push.901 exec.construct_in_locals exec.sys::truncate_stack end",
            local_count = count * 16,
        );
        let mut expected: Vec<_> = root.iter().map(Felt::as_canonical_u64).collect();
        expected.push(901);
        build_test!(source, &[]).expect_stack(&expected);
    }
}

/// Independent bottom-up geometry, unlike the MASM's streaming right-spine block traversal.
fn leaf_position(mut count: usize, mut position: usize) -> (u32, u64) {
    let (mut depth, mut index) = (0, 0);
    while count > 1 {
        if count % 2 == 0 || position != count - 1 {
            index |= ((position % 2) as u64) << depth;
            depth += 1;
        }
        position /= 2;
        count = count.div_ceil(2);
    }
    (depth, index)
}

#[test]
fn environment_library_rejects_untrusted_roots_missing_nodes_and_incomplete_frontiers() {
    let namespace = Namespace::initial();
    for count in [8, 13] {
        let entries = entries(namespace, count);
        let leaves: Vec<_> = entries.iter().map(leaf).collect();
        let (correct_root, correct_nodes) = native_tree(&leaves);
        let mut extra = leaves.clone();
        extra.push(word(9000));
        let mut repeated = leaves.clone();
        repeated[1] = repeated[0];
        let mut altered = leaves.clone();
        altered[1] = word(8000);
        let supplies = [
            (word(7000), correct_nodes, false),
            (correct_root, Vec::new(), false),
            {
                let (root, nodes) = native_tree(&extra);
                (root, nodes, false)
            },
            {
                let (root, nodes) = native_tree(&leaves[..count - 1]);
                (root, nodes, false)
            },
            {
                let (root, nodes) = native_tree(&repeated);
                (root, nodes, false)
            },
            {
                let (root, nodes) = native_tree(&altered);
                (root, nodes, true)
            },
        ];
        for (candidate_root, nodes, second_leaf) in supplies {
            let mut test = build_test!(
                source(&entries, "exec.library::create"),
                &create_inputs(namespace, count)
            );
            test.handlers.retain(|(name, _)| *name != ENVIRONMENT_BUILD_TREE_EVENT_NAME);
            let test = test.with_event_handler(
                ENVIRONMENT_BUILD_TREE_EVENT_NAME,
                move |_: &ProcessorState| -> Result<Vec<AdviceMutation>, EventError> {
                    let mut stack = AdviceStack::new();
                    stack.append_word(candidate_root);
                    Ok(vec![
                        AdviceMutation::extend_merkle_store(nodes.clone()),
                        AdviceMutation::extend_advice_stack(stack),
                    ])
                },
            );
            let error = test.execute_for_output().unwrap_err();
            if second_leaf {
                match error {
                    ExecutionError::OperationError {
                        err:
                            miden_processor::operation::OperationError::MerklePathVerificationFailed {
                                inner,
                            },
                        ..
                    } => assert_eq!(inner.index, Felt::ONE, "the first leaf must authenticate"),
                    error => panic!("expected the substituted second leaf to fail, got {error:?}"),
                }
            }
        }
    }
}

#[test]
fn environment_library_only_prepares_trees_above_the_small_tree_cutoff() {
    let namespace = Namespace::initial();
    for count in 0..=8 {
        let entries = entries(namespace, count);
        let (root, _) = expected_tree(&entries);
        let mut test =
            build_test!(source(&entries, "exec.library::create"), &create_inputs(namespace, count));
        test.handlers.retain(|(name, _)| *name != ENVIRONMENT_BUILD_TREE_EVENT_NAME);
        let test = test.with_event_handler(
            ENVIRONMENT_BUILD_TREE_EVENT_NAME,
            |_: &ProcessorState| -> Result<Vec<AdviceMutation>, EventError> {
                Err(EventError::from("tree preparation invoked"))
            },
        );
        if count <= 7 {
            test.expect_stack(&root.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>());
        } else {
            match test.execute_for_output().unwrap_err() {
                ExecutionError::EventError { error, .. } => {
                    assert!(error.to_string().contains("tree preparation invoked"));
                },
                error => panic!("expected tree-preparation error, got {error:?}"),
            }
        }
    }
}

#[test]
fn environment_tree_handler_rejects_invalid_ranges_and_cap_before_reading() {
    for (pointer, count, expected) in [
        (1 << 32, 0, "must fit in u32"),
        (ENTRIES_PTR as u64, 1 << 32, "must fit in u32"),
        (ENTRIES_PTR as u64 + 1, 0, "word-aligned"),
        (u32::MAX as u64 - 3, 1, "exceeds u32"),
        (ENTRIES_PTR as u64, MAX_ENVIRONMENT_TREE_LEAVES as u64 + 1, "exceeds maximum"),
    ] {
        let source = format!(
            "const BUILD = event(\"miden::core::sys::environment::library::build_tree\")
             begin push.{count}.{pointer} emit.BUILD end"
        );
        match build_test!(source, &[]).execute_for_output().unwrap_err() {
            ExecutionError::EventError { error, .. } => {
                assert!(error.to_string().contains(expected))
            },
            error => panic!("expected tree-handler error, got {error:?}"),
        }
    }
}

fn update_descriptor(
    entry: &Entry,
    replacement: ImplementationRoot,
    depth: u32,
    index: u64,
) -> Vec<Felt> {
    let mut descriptor = entry.label.into_word().into_elements().to_vec();
    descriptor.extend(entry.implementation.into_word().into_elements());
    descriptor.extend(replacement.into_word().into_elements());
    descriptor.extend([Felt::from_u32(depth), Felt::new_unchecked(index), Felt::ZERO, Felt::ZERO]);
    descriptor
}

fn update_program(
    entries: &[Entry],
    descriptor: &[Felt],
    key: Word,
    namespace: Namespace,
) -> String {
    format!(
        "use miden::core::sys use miden::core::sys::environment::library
         begin
             {} {}
             push.901 push.{SCRATCH_PTR} push.{} push.{ENTRIES_PTR} {}
             exec.library::create
             {} swapw {} swapw push.5000 exec.library::update_at
             exec.sys::truncate_stack
         end",
        masm_store_felts(&entry_memory(entries), ENTRIES_PTR),
        masm_store_felts(descriptor, 5000),
        entries.len(),
        masm_push_word(Namespace::initial().as_word()),
        masm_push_word(namespace.as_word()),
        masm_push_word(&key),
    )
}

fn assert_root_and_tail(output: &ExecutionOutput, root: Word) {
    for (index, value) in root.iter().enumerate() {
        assert_eq!(output.stack.get_element(index), Some(*value));
    }
    assert_eq!(output.stack.get_element(4), Some(Felt::from_u32(901)));
}

#[test]
fn indexed_updates_match_native_roots_and_preserve_all_unselected_leaves() {
    let namespace = Namespace::initial();
    for count in [1, 3, 7, 8, 13] {
        let entries = entries(namespace, count);
        let mut positions = vec![0, count / 2, count - 1];
        positions.sort_unstable();
        positions.dedup();
        for position in positions {
            let (depth, index) = leaf_position(count, position);
            let replacement = ImplementationRoot::new(word(9000 + position as u32 * 8));
            let descriptor = update_descriptor(&entries[position], replacement, depth, index);
            let source = update_program(&entries, &descriptor, entries[position].key, namespace);
            let mut updated = entries.clone();
            updated[position].implementation = replacement;
            let expected = expected_tree(&updated).0;
            let (output, _) = build_test!(source, &[]).execute_for_output().unwrap();
            assert_root_and_tail(&output, expected);
            let new_leaf = leaf(&updated[position]);
            let payload = [updated[position].label.into_word(), replacement.into_word()];
            assert_eq!(
                output.advice.get_mapped_values(&new_leaf),
                Some(Word::words_as_elements(&payload)),
            );
        }
    }
}

#[test]
fn indexed_update_rejects_wrong_bindings_headers_positions_and_aliases() {
    let namespace = Namespace::initial();
    let entries = entries(namespace, 2);
    let descriptor = update_descriptor(&entries[0], ImplementationRoot::new(word(9000)), 1, 0);
    for (offset, value) in
        [(0, 9000), (4, 9000), (12, 65), (12, 1 << 32), (13, 2), (14, 1), (15, 1)]
    {
        let mut invalid = descriptor.clone();
        invalid[offset] = Felt::new_unchecked(value);
        let source = update_program(&entries, &invalid, entries[0].key, namespace);
        assert!(build_test!(source, &[]).execute_for_output().is_err());
    }
    for (key, namespace) in [(word(7000), namespace), (entries[0].key, Namespace::new(word(8000)))]
    {
        let source = update_program(&entries, &descriptor, key, namespace);
        assert!(build_test!(source, &[]).execute_for_output().is_err());
    }
    for pointer in [5001, 1 << 31, 1 << 32, u32::MAX as u64 - 3] {
        let source = update_program(&entries, &descriptor, entries[0].key, namespace).replace(
            "push.5000 exec.library::update_at",
            &format!("push.{pointer} exec.library::update_at"),
        );
        assert!(build_test!(source, &[]).execute_for_output().is_err());
    }
    let singleton = &entries[..1];
    let mut invalid = update_descriptor(&entries[0], ImplementationRoot::new(word(9000)), 0, 1);
    let source = update_program(singleton, &invalid, entries[0].key, namespace);
    crate::expect_assert_error_code_from_msg!(
        build_test!(source, &[]),
        "environment singleton update index must be zero"
    );
    invalid[13] = Felt::ZERO;
    invalid[4] += Felt::ONE;
    let source = update_program(singleton, &invalid, entries[0].key, namespace);
    crate::expect_assert_error_code_from_msg!(
        build_test!(source, &[]),
        "environment singleton update does not match the old leaf"
    );
}

#[test]
fn indexed_updates_support_successive_roots_noops_and_reject_stale_old_values() {
    let namespace = Namespace::initial();
    let entries = entries(namespace, 2);
    let first = ImplementationRoot::new(word(9000));
    let second = ImplementationRoot::new(word(9100));
    let descriptor0 = update_descriptor(&entries[0], first, 1, 0);
    let descriptor1 = update_descriptor(&entries[1], second, 1, 1);
    let initial = update_program(&entries, &descriptor0, entries[0].key, namespace);
    let source = initial.replace(
        "exec.sys::truncate_stack",
        &format!(
            "{} {} swapw {} swapw push.5016 exec.library::update_at exec.sys::truncate_stack",
            masm_store_felts(&descriptor1, 5016),
            masm_push_word(namespace.as_word()),
            masm_push_word(&entries[1].key),
        ),
    );
    let mut updated = entries.clone();
    updated[0].implementation = first;
    updated[1].implementation = second;
    let (output, _) = build_test!(source, &[]).execute_for_output().unwrap();
    assert_root_and_tail(&output, expected_tree(&updated).0);

    let noop = update_descriptor(&entries[0], entries[0].implementation, 1, 0);
    let source = update_program(&entries, &noop, entries[0].key, namespace);
    let (output, _) = build_test!(source, &[]).execute_for_output().unwrap();
    assert_root_and_tail(&output, expected_tree(&entries).0);

    let stale = initial.replace(
        "exec.sys::truncate_stack",
        &format!(
            "{} swapw {} swapw push.5000 exec.library::update_at exec.sys::truncate_stack",
            masm_push_word(namespace.as_word()),
            masm_push_word(&entries[0].key),
        ),
    );
    crate::expect_assert_error_code_from_msg!(
        build_test!(stale, &[]),
        "environment update does not match the old leaf"
    );
}

#[test]
fn indexed_updates_support_native_depth_64_and_indices_wider_than_u32() {
    let namespace = Namespace::initial();
    let entry = entries(namespace, 1).remove(0);
    let replacement = ImplementationRoot::new(word(9000));
    let mut updated = entry.clone();
    updated.implementation = replacement;
    for (depth, index) in [(33, (1u64 << 32) + 5), (64, (1u64 << 63) + 9)] {
        let mut old_root = leaf(&entry);
        let mut new_root = leaf(&updated);
        let mut nodes = Vec::new();
        for level in 0..depth {
            let sibling = word(10000 + level * 8);
            let old_pair = if (index >> level) & 1 == 0 {
                [old_root, sibling]
            } else {
                [sibling, old_root]
            };
            let new_pair = if (index >> level) & 1 == 0 {
                [new_root, sibling]
            } else {
                [sibling, new_root]
            };
            old_root = Eidos::merge(&old_pair);
            new_root = Eidos::merge(&new_pair);
            nodes.push(InnerNodeInfo {
                value: old_root,
                left: old_pair[0],
                right: old_pair[1],
            });
        }
        let mut store = miden_utils_testing::crypto::MerkleStore::new();
        store.extend(nodes);
        let descriptor = update_descriptor(&entry, replacement, depth, index);
        let source = format!(
            "use miden::core::sys use miden::core::sys::environment::library
             begin {} push.901 {} {} {} push.5000 exec.library::update_at
                 exec.sys::truncate_stack end",
            masm_store_felts(&descriptor, 5000),
            masm_push_word(namespace.as_word()),
            masm_push_word(&entry.key),
            masm_push_word(&old_root),
        );
        let (output, _) = build_test!(source, &[], &[], store, Vec::<(Word, Vec<Felt>)>::new())
            .execute_for_output()
            .unwrap();
        assert_root_and_tail(&output, new_root);
    }
}

#[test]
fn indexed_update_accepts_a_descriptor_in_the_callers_local_frame() {
    let namespace = Namespace::initial();
    let mut entries = entries(namespace, 2);
    let replacement = ImplementationRoot::new(word(9000));
    let descriptor = update_descriptor(&entries[1], replacement, 1, 1);
    let stores = descriptor
        .iter()
        .enumerate()
        .map(|(index, value)| format!("push.{} loc_store.{index}", value.as_canonical_u64()))
        .collect::<Vec<_>>()
        .join(" ");
    let source = update_program(&entries, &descriptor, entries[1].key, namespace)
        .replace("push.5000 exec.library::update_at", "exec.local_update")
        .replacen(
            "begin\n",
            &format!(
                "@locals(16) proc local_update {stores} locaddr.0 exec.library::update_at end\nbegin\n"
            ),
            1,
        );
    entries[1].implementation = replacement;
    let (output, _) = build_test!(source, &[]).execute_for_output().unwrap();
    assert_root_and_tail(&output, expected_tree(&entries).0);
}
