use super::*;

// Complete native fixtures for later MASM consumers. Digests were frozen with the independent
// portable seven-round BLAKE3/Eidos reference after checking existing generic and domain vectors.
const CONFIGURATION_VECTORS: [(&[u64], [u64; 4]); 3] = [
    (
        &[2, 1, 2, 3, 4, 5, 6, 7, 8, 0, 9, 10, 11, 12],
        [0x0d6127ffae6b9711, 0x1f14f10ceca2f563, 0x446b997553ff121a, 0x5daf09ff386b0156],
    ),
    (
        &[2, 1, 2, 3, 4, 5, 6, 7, 8, 1, 13, 14, 15, 16, 17, 18, 19, 20, 9, 10, 11, 12],
        [0x04837f0654ef8bcc, 0x0e250b83ed753b99, 0x20d8b637365137dc, 0x074254776c3c06c0],
    ),
    (
        &[
            2, 1, 2, 3, 4, 5, 6, 7, 8, 2, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
            27, 28, 9, 10, 11, 12,
        ],
        [0x10e18040ea041dc6, 0x2b8d9e6ef3f828ed, 0x04f5d622e1dc5339, 0x5f6a1bc5d33f5c8c],
    ),
];

#[test]
fn configurations_match_complete_frozen_vectors() {
    let mounts = [
        mount([13, 14, 15, 16], [17, 18, 19, 20]),
        mount([21, 22, 23, 24], [25, 26, 27, 28]),
    ];
    for (count, (expected_payload, expected_digest)) in CONFIGURATION_VECTORS.iter().enumerate() {
        let mut input = mounts[..count].to_vec();
        input.reverse();
        let config = configuration(input);
        let payload = config.preimage_elements().unwrap();
        assert_eq!(payload.len(), 14 + 8 * count);
        assert_eq!(
            payload,
            expected_payload.iter().copied().map(Felt::new_unchecked).collect::<Vec<_>>()
        );
        assert_eq!(config.commitment().unwrap().into_word(), word(*expected_digest));
        assert_eq!(config.entry_implementation(), ImplementationRoot::new(word([1, 2, 3, 4])));
        assert_eq!(config.kernel_namespace(), Namespace::new(word([5, 6, 7, 8])));
        assert_eq!(config.resource_inventory(), word([9, 10, 11, 12]));
        assert_eq!(config.mounts(), &mounts[..count]);
    }
}

#[test]
fn typed_commitment_preserves_its_word() {
    let value = word([1, 2, 3, 4]);
    let commitment = VerifierConfigurationCommitment::new(value);
    assert_eq!(commitment.as_word(), &value);
    assert_eq!(commitment.into_word(), value);
}

#[test]
fn identity_matches_frozen_vector_and_exact_field_order() {
    let relation_id = word([1, 2, 3, 4]);
    let entry = ProcedureKey::new(word([5, 6, 7, 8]));
    let config = VerifierConfigurationCommitment::new(word([9, 10, 11, 12]));
    let payload = VerifierIdentity::preimage_elements(relation_id, entry, config);
    assert_eq!(payload.len(), 12);
    assert_eq!(payload, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].map(Felt::new_unchecked));

    // Frozen independently before the native identity API, alongside the domain vectors.
    let expected =
        word([0x70478a6f4d5cee97, 0x3142c3b5ecb6e152, 0x169528d9edd6ce56, 0x096ea99f5a42c4fb]);
    let identity = VerifierIdentity::derive(relation_id, entry, config);
    assert_eq!(identity.as_word(), &expected);
    assert_eq!(identity.into_word(), expected);
}

#[test]
fn every_identity_coordinate_changes_the_identity() {
    let original = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]];
    let from_words = |values: [[u64; 4]; 3]| {
        VerifierIdentity::derive(
            word(values[0]),
            ProcedureKey::new(word(values[1])),
            VerifierConfigurationCommitment::new(word(values[2])),
        )
    };
    let expected = from_words(original);
    for field in 0..original.len() {
        for coordinate in 0..WORD_SIZE {
            let mut changed = original;
            changed[field][coordinate] += 100;
            assert_ne!(from_words(changed), expected);
        }
    }
}

#[test]
fn identity_domain_substitutions_change_the_commitment() {
    let relation_id = word([1, 2, 3, 4]);
    let entry = ProcedureKey::new(word([5, 6, 7, 8]));
    let config = VerifierConfigurationCommitment::new(word([9, 10, 11, 12]));
    let payload = VerifierIdentity::preimage_elements(relation_id, entry, config);
    let expected = VerifierIdentity::derive(relation_id, entry, config).into_word();
    assert_ne!(
        hasher::hash_elements_in_domain(&payload, domain::EXEC_VERIFIER_CONFIG),
        expected
    );
    assert_ne!(hasher::hash_elements_in_domain(&payload, domain::ENV_PROCEDURE), expected);
}

#[test]
fn every_mount_permutation_has_the_same_canonical_configuration() {
    let mounts = [
        mount([13, 14, 15, 16], [17, 18, 19, 20]),
        mount([21, 22, 23, 24], [25, 26, 27, 28]),
        mount([29, 30, 31, 32], [33, 34, 35, 36]),
    ];
    let expected = configuration(mounts.to_vec());
    for indices in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
        let config = configuration(indices.map(|index| mounts[index]).to_vec());
        assert_eq!(config, expected);
        assert_eq!(config.preimage_elements(), expected.preimage_elements());
        assert_eq!(config.commitment(), expected.commitment());
    }
}

#[test]
fn mount_order_compares_forward_canonical_coordinates() {
    let first = mount([1, 0, 0, 9], [9, 9, 9, 9]);
    let second = mount([2, 0, 0, 0], [0, 0, 0, 0]);
    // Word::Ord uses the last coordinate first and gives the opposite order.
    assert!(first.namespace().as_word() > second.namespace().as_word());
    assert_eq!(configuration(vec![second, first]).mounts(), &[first, second]);

    // Canonical-u64 ordering also differs from little-endian byte ordering.
    let small = mount([1, 0, 0, 0], [0, 0, 0, 0]);
    let large = mount([256, 0, 0, 0], [0, 0, 0, 0]);
    assert_eq!(configuration(vec![large, small]).mounts(), &[small, large]);
}

#[test]
fn equal_namespaces_sort_by_forward_fragment_coordinates() {
    let first = mount([1, 2, 3, 4], [1, 0, 0, 9]);
    let second = mount([1, 2, 3, 4], [2, 0, 0, 0]);
    assert!(first.fragment().as_word() > second.fragment().as_word());
    // These opaque fragments are accepted without claiming that their executable paths are
    // disjoint.
    let config = configuration(vec![second, first]);
    assert_eq!(config.mounts(), &[first, second]);
    assert_eq!(config.preimage_elements().unwrap().len(), 30);
}

#[test]
fn duplicate_mount_pairs_reject_even_when_initially_separated() {
    let first = mount([13, 14, 15, 16], [17, 18, 19, 20]);
    let second = mount([21, 22, 23, 24], [25, 26, 27, 28]);
    for mounts in [vec![first, first], vec![first, second, first], vec![second, first, second]] {
        assert_eq!(
            VerifierConfiguration::new(
                ImplementationRoot::new(word([1, 2, 3, 4])),
                Namespace::new(word([5, 6, 7, 8])),
                mounts,
                word([9, 10, 11, 12]),
            ),
            Err(VerifierConfigurationError::DuplicateMount),
        );
    }
}

#[test]
fn every_configuration_word_coordinate_changes_the_commitment() {
    // D_v, N_kernel, mount namespace, mount fragment, and resource inventory.
    let original =
        [[1, 2, 3, 4], [5, 6, 7, 8], [13, 14, 15, 16], [17, 18, 19, 20], [9, 10, 11, 12]];
    let from_words = |values: [[u64; 4]; 5]| {
        VerifierConfiguration::new(
            ImplementationRoot::new(word(values[0])),
            Namespace::new(word(values[1])),
            vec![mount(values[2], values[3])],
            word(values[4]),
        )
        .unwrap()
    };
    let expected = from_words(original).commitment().unwrap();
    for field in 0..original.len() {
        for coordinate in 0..WORD_SIZE {
            let mut changed = original;
            changed[field][coordinate] += 100;
            assert_ne!(from_words(changed).commitment().unwrap(), expected);
        }
    }
    // Adding a mount changes both the committed count and the logical framing length.
    assert_ne!(
        configuration(vec![
            mount(original[2], original[3]),
            mount([21, 22, 23, 24], [25, 26, 27, 28])
        ])
        .commitment()
        .unwrap(),
        expected,
    );
}

#[test]
fn version_count_and_domain_substitutions_change_the_commitment() {
    let config = configuration(vec![mount([13, 14, 15, 16], [17, 18, 19, 20])]);
    let payload = config.preimage_elements().unwrap();
    let expected = config.commitment().unwrap().into_word();
    for index in [0, 9] {
        let mut changed = payload.clone();
        changed[index] += Felt::ONE;
        assert_ne!(
            hasher::hash_elements_in_domain(&changed, domain::EXEC_VERIFIER_CONFIG),
            expected
        );
    }
    assert_ne!(
        hasher::hash_elements_in_domain(&payload, domain::EXEC_VERIFIER_IDENTITY),
        expected
    );
    assert_ne!(hasher::hash_elements_in_domain(&payload, domain::ENV_LIST), expected);
}

#[test]
fn configuration_length_bounds_reject_without_allocating() {
    assert_eq!(checked_configuration_element_len(0), Ok(14));
    assert_eq!(checked_configuration_element_len(1), Ok(22));
    assert_eq!(checked_configuration_element_len(2), Ok(30));
    for count in [usize::MAX, usize::MAX / 8 + 1, u32::MAX as usize] {
        assert_eq!(
            checked_configuration_element_len(count),
            Err(VerifierConfigurationError::LengthOverflow)
        );
    }

    // Framing bounds dominate on wide targets; contiguous Felt layout dominates on narrow ones.
    let max_elements = (u32::MAX as usize).min(isize::MAX as usize / size_of::<Felt>());
    let max_mounts = (max_elements - 14) / 8;
    assert_eq!(checked_configuration_element_len(max_mounts), Ok(14 + 8 * max_mounts));
    assert_eq!(
        checked_configuration_element_len(max_mounts + 1),
        Err(VerifierConfigurationError::LengthOverflow)
    );
}

fn configuration(mounts: Vec<VerifierMount>) -> VerifierConfiguration {
    VerifierConfiguration::new(
        ImplementationRoot::new(word([1, 2, 3, 4])),
        Namespace::new(word([5, 6, 7, 8])),
        mounts,
        word([9, 10, 11, 12]),
    )
    .unwrap()
}

fn mount(namespace: [u64; 4], fragment: [u64; 4]) -> VerifierMount {
    VerifierMount::new(Namespace::new(word(namespace)), EnvironmentRoot::new(word(fragment)))
}

fn word(values: [u64; 4]) -> Word {
    Word::new(values.map(Felt::new_unchecked))
}
