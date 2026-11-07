use miden_core::{
    Felt, Word,
    program::{
        CanonicalLabel, EnvNode, EnvironmentRoot, ImplementationRoot, LabelCommitment, Namespace,
        ProcedureKey,
    },
};

use crate::helpers::{masm_push_word, masm_store_felts};

const DESCRIPTOR: u32 = 1000;
const PATH: u32 = 2000;
const TAIL: u64 = 424242;

struct Binding {
    label: LabelCommitment,
    implementation: ImplementationRoot,
    // Bottom-up (kind, selected child, sibling or label).
    path: Vec<(u32, u32, Word)>,
}

impl Binding {
    fn nodes_with(&self, implementation: ImplementationRoot) -> Vec<(EnvironmentRoot, [Word; 2])> {
        let leaf = EnvNode::Mast { label: self.label, implementation }.commitment().unwrap();
        let mut nodes = vec![(leaf, [self.label.into_word(), implementation.into_word()])];
        for &(kind, selector, value) in &self.path {
            let child = nodes.last().unwrap().0;
            let payload = if kind == 0 || selector == 1 {
                [value, child.into_word()]
            } else {
                [child.into_word(), value]
            };
            let node = if kind == 0 {
                EnvNode::Env {
                    label: LabelCommitment::new(value),
                    child,
                }
            } else {
                EnvNode::Merkle {
                    left: EnvironmentRoot::new(payload[0]),
                    right: EnvironmentRoot::new(payload[1]),
                }
            };
            nodes.push((node.commitment().unwrap(), payload));
        }
        nodes
    }

    fn root_with(&self, implementation: ImplementationRoot) -> EnvironmentRoot {
        self.nodes_with(implementation).last().unwrap().0
    }

    fn namespace(&self) -> Namespace {
        self.path
            .iter()
            .rev()
            .fold(Namespace::initial(), |parent, &(kind, _, payload)| {
                if kind == 0 {
                    parent.child(LabelCommitment::new(payload))
                } else {
                    parent
                }
            })
    }

    fn key(&self) -> ProcedureKey {
        self.namespace().procedure_key(self.label)
    }

    fn descriptor(&self) -> Vec<Felt> {
        let mut result = self.label.into_word().as_elements().to_vec();
        result.extend_from_slice(self.implementation.as_word().as_elements());
        result.extend([Felt::from_u32(PATH), Felt::from_u32(self.path.len() as u32)]);
        result.extend([Felt::ZERO; 2]);
        result
    }

    fn records(&self) -> Vec<Felt> {
        self.path
            .iter()
            .flat_map(|&(kind, selector, payload)| {
                [
                    vec![Felt::from_u32(kind), Felt::from_u32(selector), Felt::ZERO, Felt::ZERO],
                    payload.as_elements().to_vec(),
                ]
                .concat()
            })
            .collect()
    }

    fn program(&self, replacement: Option<ImplementationRoot>) -> String {
        self.program_with(
            &self.descriptor(),
            &self.records(),
            self.root_with(self.implementation),
            self.key(),
            replacement,
        )
    }

    fn program_with(
        &self,
        descriptor: &[Felt],
        records: &[Felt],
        root: EnvironmentRoot,
        key: ProcedureKey,
        replacement: Option<ImplementationRoot>,
    ) -> String {
        let invocation = match replacement {
            Some(implementation) => {
                format!("{} exec.paths::update_binding", masm_push_word(implementation.as_word()))
            },
            None => "exec.paths::verify_binding".into(),
        };
        format!(
            "use miden::core::sys::environment::paths use miden::core::sys
             begin {} {} push.{TAIL} {} {} push.{DESCRIPTOR}
                 {invocation} exec.sys::truncate_stack end",
            masm_store_felts(descriptor, DESCRIPTOR),
            masm_store_felts(records, PATH),
            masm_push_word(key.as_word()),
            masm_push_word(root.as_word()),
        )
    }
}

fn word(seed: u32) -> Word {
    Word::new([seed, seed + 1, seed + 2, seed + 3].map(Felt::from_u32))
}

fn label(text: &str) -> LabelCommitment {
    CanonicalLabel::text(text).unwrap().commitment()
}

fn fixture() -> Binding {
    Binding {
        label: label("export"),
        implementation: ImplementationRoot::new(word(10)),
        path: vec![
            (1, 0, word(20)),
            (0, 0, label("inner").into_word()),
            (1, 1, word(30)),
            (0, 0, label("outer").into_word()),
            (1, 0, word(40)),
        ],
    }
}

fn expected_stack(words: &[Word]) -> Vec<u64> {
    let mut expected = words
        .iter()
        .flat_map(|word| word.iter().map(Felt::as_canonical_u64))
        .collect::<Vec<_>>();
    expected.push(TAIL);
    expected.resize(16, 0);
    expected
}

#[test]
fn binding_operations_match_native_for_empty_single_and_mixed_paths() {
    for length in [0, 1, 5, 16] {
        let mut binding = fixture();
        if length == 16 {
            binding.path = (0..length)
                .map(|i| {
                    if i % 3 == 2 {
                        (0, 0, label(&format!("ancestor{i}")).into_word())
                    } else {
                        (1, i % 2, word(100 + i * 4))
                    }
                })
                .collect();
        } else {
            binding.path.truncate(length as usize);
        }
        for replacement in [None, Some(ImplementationRoot::new(word(900)))] {
            let words = match replacement {
                Some(replacement) => vec![binding.root_with(replacement).into_word()],
                None => vec![binding.implementation.into_word(), binding.namespace().into_word()],
            };
            build_test!(binding.program(replacement), &[]).expect_stack(&expected_stack(&words));
        }
    }
}

#[test]
fn binding_rejects_tampered_commitments_and_namespace_order() {
    let binding = fixture();
    for field in ["root", "key", "label", "implementation", "sibling", "slot", "namespace"] {
        let mut descriptor = binding.descriptor();
        let mut records = binding.records();
        let mut root = binding.root_with(binding.implementation);
        let mut key = binding.key();
        match field {
            "root" => root = EnvironmentRoot::new(word(500)),
            "key" => key = ProcedureKey::new(word(600)),
            "label" => descriptor[0] += Felt::ONE,
            "implementation" => descriptor[4] += Felt::ONE,
            "sibling" => records[4] += Felt::ONE,
            "slot" => records[1] += Felt::ONE,
            "namespace" => {
                for i in 0..4 {
                    records.swap(12 + i, 28 + i);
                }
            },
            _ => unreachable!(),
        }
        let source = binding.program_with(&descriptor, &records, root, key, None);
        assert!(build_test!(source, &[]).execute_for_output().is_err(), "{field}");
    }
}

#[test]
fn binding_rejects_malformed_records_descriptors_and_ranges() {
    let binding = fixture();
    let record_errors = [
        (0, 2),
        (0, 1 << 32),
        (1, 2),
        (1, 1 << 32),
        (2, 1),
        (3, 1),
        (9, 1), // Env selectors must be zero.
    ];
    let descriptor_errors = [
        (8, PATH as u64 + 1),
        (8, 1 << 32),
        (8, u32::MAX as u64 - 3),
        (9, 1 << 32),
        (9, 1 << 29),
        (10, 1),
        (11, 1),
    ];
    for (is_record, errors) in
        [(true, record_errors.as_slice()), (false, descriptor_errors.as_slice())]
    {
        for &(index, value) in errors {
            let mut descriptor = binding.descriptor();
            let mut records = binding.records();
            if is_record {
                records[index] = Felt::new_unchecked(value);
            } else {
                descriptor[index] = Felt::new_unchecked(value);
            }
            let source = binding.program_with(
                &descriptor,
                &records,
                binding.root_with(binding.implementation),
                binding.key(),
                None,
            );
            assert!(build_test!(source, &[]).execute_for_output().is_err());
        }
    }
    for pointer in [DESCRIPTOR as u64 + 1, 1 << 32, u32::MAX as u64 - 3] {
        let source = binding
            .program(None)
            .replace(&format!("push.{DESCRIPTOR}\n"), &format!("push.{pointer}\n"));
        assert!(build_test!(source, &[]).execute_for_output().is_err());
    }
}

#[test]
fn update_binding_records_all_new_preimages_and_handles_noops() {
    let binding = fixture();
    for replacement in [binding.implementation, ImplementationRoot::new(word(100))] {
        let (output, _) = build_test!(binding.program(Some(replacement)), &[])
            .execute_for_output()
            .unwrap();
        let root = binding.root_with(replacement);
        assert_eq!(
            output.stack.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>(),
            expected_stack(&[root.into_word()])
        );
        for (node, payload) in binding.nodes_with(replacement) {
            assert_eq!(
                output.advice.get_mapped_values(node.as_word()),
                Some(Word::words_as_elements(&payload))
            );
        }
    }
    let source = binding.program_with(
        &binding.descriptor(),
        &binding.records(),
        EnvironmentRoot::new(word(500)),
        binding.key(),
        Some(ImplementationRoot::new(word(100))),
    );
    assert!(build_test!(source, &[]).execute_for_output().is_err());
}

#[test]
fn binding_operations_reject_input_aliasing_their_local_frames() {
    let binding = fixture();
    let frame_start = 1u32 << 31;
    for replacement in [None, Some(ImplementationRoot::new(word(100)))] {
        let source = binding
            .program(replacement)
            .replace(&format!("push.{DESCRIPTOR}\n"), &format!("push.{frame_start}\n"));
        crate::expect_assert_error_code_from_msg!(
            build_test!(source, &[]),
            "environment descriptor must stay below the local frame"
        );
        let mut descriptor = binding.descriptor();
        descriptor[8] = Felt::from_u32(frame_start);
        let source = binding.program_with(
            &descriptor,
            &binding.records(),
            binding.root_with(binding.implementation),
            binding.key(),
            replacement,
        );
        crate::expect_assert_error_code_from_msg!(
            build_test!(source, &[]),
            "environment path must stay below the local frame"
        );
    }
}

#[test]
fn verify_binding_accepts_inputs_in_caller_locals() {
    let binding = fixture();
    let root = binding.root_with(binding.implementation);
    let mut descriptor = binding.descriptor();
    descriptor[8] = Felt::ZERO; // Replaced at runtime with the caller's local path pointer.
    let stores = descriptor
        .iter()
        .enumerate()
        .chain(binding.records().iter().enumerate().map(|(i, value)| (i + 16, value)))
        .map(|(index, value)| {
            format!("push.{} locaddr.{index} mem_store", value.as_canonical_u64())
        })
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        "use miden::core::sys::environment::paths use miden::core::sys
         @locals(64) proc run {stores} locaddr.16 loc_store.8
             push.{TAIL} {} {} locaddr.0 exec.paths::verify_binding end
         begin exec.run exec.sys::truncate_stack end",
        masm_push_word(binding.key().as_word()),
        masm_push_word(root.as_word()),
    );
    build_test!(source, &[]).expect_stack(&expected_stack(&[
        binding.implementation.into_word(),
        binding.namespace().into_word(),
    ]));
}
