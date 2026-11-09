use miden_core::{
    Felt, Word,
    program::{EnvNode, EnvironmentRoot, ImplementationRoot, LabelCommitment, Namespace},
};
use miden_processor::{ExecutionError, operation::OperationError};

use crate::helpers::{masm_push_felts, masm_store_felts};

fn word(values: [u64; 4]) -> Word {
    Word::new(values.map(Felt::new_unchecked))
}

fn fixed_objects() -> [(&'static str, EnvNode); 3] {
    let label = LabelCommitment::new(word([1, 2, 3, 4]));
    let child = EnvironmentRoot::new(word([5, 6, 7, 8]));
    [
        ("env", EnvNode::Env { label, child }),
        (
            "mast",
            EnvNode::Mast {
                label,
                implementation: ImplementationRoot::new(child.into_word()),
            },
        ),
        (
            "merkle",
            EnvNode::Merkle {
                left: EnvironmentRoot::new(label.into_word()),
                right: child,
            },
        ),
    ]
}

fn check_hash(procedure: &str, input: &[Felt], expected: Word, payload: Option<&[Felt]>) {
    let source = format!(
        "use miden::core::sys use miden::core::sys::environment
         begin push.99 {} exec.environment::{procedure} exec.sys::truncate_stack end",
        masm_push_felts(input),
    );
    let (output, _) = build_test!(source, &[]).execute_for_output().unwrap();
    let mut stack = [Felt::ZERO; 16];
    stack[..4].copy_from_slice(expected.as_elements());
    stack[4] = Felt::from_u32(99);
    assert_eq!(*output.stack, stack);
    if let Some(payload) = payload {
        assert_eq!(output.advice.get_mapped_values(&expected), Some(payload));
    }
}

fn assert_input_error(invocation: &str, message: &str) {
    let source = format!("use miden::core::sys::environment begin {invocation} end");
    match build_test!(source, &[]).execute_for_output().unwrap_err() {
        ExecutionError::OperationError {
            err:
                OperationError::FailedAssertion { err_code, .. }
                | OperationError::U32AssertionFailed { err_code, .. },
            ..
        } => assert_eq!(err_code, miden_core::mast::error_code_from_msg(message)),
        error => panic!("expected input assertion {message:?}, got {error:?}"),
    }
}

#[test]
fn namespace_derivations_match_native() {
    check_hash("initial_namespace", &[], Namespace::initial().into_word(), None);
    let parent = Namespace::new(word([1, 2, 3, 4]));
    let label = LabelCommitment::new(word([5, 6, 7, 8]));
    let input = [parent.into_word(), label.into_word()];
    let input = Word::words_as_elements(&input);
    check_hash("child_namespace", input, parent.child(label).into_word(), None);
    check_hash("procedure_key", input, parent.procedure_key(label).into_word(), None);

    let initial = Namespace::initial();
    let input = [initial.into_word(), label.into_word()];
    check_hash("procedure_key", Word::words_as_elements(&input), label.into_word(), None);
}

#[test]
fn fixed_objects_match_native_and_record_exact_payloads() {
    let payload: Vec<_> = (1..=8).map(Felt::from_u32).collect();
    for (kind, node) in fixed_objects() {
        check_hash(
            &format!("hash_{kind}"),
            &payload,
            node.commitment().unwrap().into_word(),
            Some(&payload),
        );
    }
    for kind in [0, u32::MAX] {
        let node = EnvNode::Data {
            kind,
            label: LabelCommitment::new(word([1, 2, 3, 4])),
            value: word([5, 6, 7, 8]),
        };
        let payload = [vec![Felt::from_u32(kind)], payload.clone()].concat();
        check_hash("hash_data", &payload, node.commitment().unwrap().into_word(), Some(&payload));
    }
}

#[test]
fn fixed_object_openings_authenticate_payloads_and_lengths() {
    let payload: Vec<_> = (1..=8).map(Felt::from_u32).collect();
    for (kind, node) in fixed_objects() {
        let root = node.commitment().unwrap().into_word();
        let source = format!(
            "use miden::core::sys use miden::core::sys::environment
             begin push.99 {} exec.environment::open_{kind} exec.sys::truncate_stack end",
            crate::helpers::masm_push_word(&root),
        );
        for values in
            [payload.clone(), vec![Felt::ZERO; 8], vec![Felt::ZERO; 7], vec![Felt::ZERO; 9]]
        {
            let valid = values == payload;
            let length = values.len();
            let test = build_test!(
                source.as_str(),
                &[],
                Vec::<u64>::new(),
                miden_utils_testing::crypto::MerkleStore::new(),
                vec![(root, values)]
            );
            if valid {
                test.expect_stack(&[1, 2, 3, 4, 5, 6, 7, 8, 99]);
            } else {
                let message = if length == 8 {
                    "environment object commitment mismatch"
                } else {
                    "environment object preimage must contain two words"
                };
                crate::expect_assert_error_code_from_msg!(test, message);
            }
        }
    }
}

#[test]
fn lists_match_native_and_record_only_the_logical_payload() {
    let children: Vec<_> = (0..5)
        .map(|i| EnvironmentRoot::new(word([4 * i + 1, 4 * i + 2, 4 * i + 3, 4 * i + 4])))
        .collect();
    let memory: Vec<_> = children
        .iter()
        .flat_map(|root| root.into_word().into_elements())
        .chain(word([91, 92, 93, 94]).into_elements())
        .collect();
    // A nonzero word after each odd list must not enter its commitment or advice preimage.
    for count in 0..=children.len() {
        let root = EnvNode::List(children[..count].to_vec()).commitment().unwrap().into_word();
        let source = format!(
            "use miden::core::sys use miden::core::sys::environment
             begin {} push.99 push.{count}.1000 exec.environment::hash_list
                 exec.sys::truncate_stack end",
            masm_store_felts(&memory, 1000),
        );
        let (output, _) = build_test!(source, &[]).execute_for_output().unwrap();
        assert_eq!(&output.stack[..4], root.as_elements());
        assert_eq!(output.stack[4], Felt::from_u32(99));
        assert_eq!(output.advice.get_mapped_values(&root), Some(&memory[..4 * count]));
    }
}

#[test]
fn lists_reject_invalid_addresses_and_lengths() {
    for (invocation, message) in [
        ("push.0.4294967296", "environment list pointer and count must fit in u32"),
        ("push.4294967296.1000", "environment list pointer and count must fit in u32"),
        ("push.0.1001", "environment list pointer must be word-aligned"),
        ("push.1073741824.0", "environment list length exceeds a u32"),
        ("push.1.4294967292", "environment list range exceeds a u32"),
    ] {
        assert_input_error(&format!("{invocation} exec.environment::hash_list"), message);
    }
}

#[test]
fn lists_accept_high_memory_and_caller_locals() {
    let children: Vec<_> = (0..3)
        .map(|i| EnvironmentRoot::new(word([i * 4 + 1, i * 4 + 2, i * 4 + 3, i * 4 + 4])))
        .collect();
    let payload: Vec<_> =
        children.iter().flat_map(|root| root.into_word().into_elements()).collect();
    let root = EnvNode::List(children).commitment().unwrap().into_word();
    let high_memory = format!(
        "begin {} push.3.3221225472 exec.environment::hash_list exec.sys::truncate_stack end",
        masm_store_felts(&payload, 0xc000_0000),
    );
    let local_stores = payload
        .iter()
        .enumerate()
        .map(|(i, value)| format!("push.{} loc_store.{i}", value.as_canonical_u64()))
        .collect::<Vec<_>>()
        .join(" ");
    let caller_locals = format!(
        "@locals(12) proc run {local_stores} push.3 locaddr.0 exec.environment::hash_list end
         begin exec.run exec.sys::truncate_stack end",
    );
    for body in [high_memory, caller_locals] {
        let source = format!("use miden::core::sys use miden::core::sys::environment {body}");
        build_test!(source, &[])
            .expect_stack(&root.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>());
    }
}

#[test]
fn data_rejects_non_u32_kind() {
    assert_input_error(
        "padw padw push.4294967296 exec.environment::hash_data",
        "environment data kind must fit in a u32",
    );
}
