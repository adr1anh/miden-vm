//! Owned environment objects and their typed commitments.

use alloc::vec::Vec;
use core::alloc::Layout;

use super::{EnvironmentRoot, ImplementationRoot, LabelCommitment};
use crate::{Felt, WORD_SIZE, Word, ZERO, chiplets::hasher, program::domain};

mod encoding;

/// An environment object whose children are opaque object or subtree commitments.
///
/// Labeled and list objects use their registered Eidos domains. Binary collections use the
/// reserved native Merkle frame, compatible with the VM's Merkle instructions. A commitment
/// does not validate referenced preimages, establish a complete environment, prove global
/// executable-path uniqueness, or grant authority to the resulting root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvNode {
    /// A labeled child whose authenticated traversal extends the inherited namespace.
    Env {
        label: LabelCommitment,
        child: EnvironmentRoot,
    },
    /// A local procedure label bound to an executable implementation root.
    ///
    /// This environment leaf is distinct from an executable [`crate::mast::MastNode`] and from
    /// a structural [`crate::mast::ExternalNode`] that omits a concrete code subtree.
    Mast {
        label: LabelCommitment,
        implementation: ImplementationRoot,
    },
    /// Opaque typed application data, which never emits an executable binding.
    Data {
        kind: u32,
        label: LabelCommitment,
        value: Word,
    },
    /// An ordered binary collection preserving the inherited namespace.
    ///
    /// Its commitment is the native Eidos Merkle merge of the two children, so a consecutive
    /// binary path can be authenticated by the VM's Merkle instructions.
    Merkle {
        left: EnvironmentRoot,
        right: EnvironmentRoot,
    },
    /// An ordered collection preserving the inherited namespace, including the empty collection.
    List(Vec<EnvironmentRoot>),
}

impl EnvNode {
    /// Commits to this object's fields using its selected Eidos framing.
    ///
    /// Binary collections use native Merkle-node compression, with all four injected frame
    /// lanes zero. Every other variant uses registered standard Felt-sequence framing.
    ///
    /// Lists hash the concatenated child words, with their Felt count in the standard framing;
    /// no additional count or header enters the payload. This operation checks the list's
    /// current length and fallibly allocates its flattened payload, even for directly
    /// constructed [`Self::List`] values. All other variants use fixed stack payloads.
    ///
    /// Returns an error if a list's payload exceeds the framing or allocation bounds, or its
    /// allocation fails. Success does not establish completeness or authority of the root.
    pub fn commitment(&self) -> Result<EnvironmentRoot, EnvNodeError> {
        let commitment = match self {
            Self::Env { label, child } => {
                let payload = [label.into_word(), child.into_word()];
                hasher::hash_elements_in_domain(
                    Word::words_as_elements(&payload),
                    domain::ENV_ENVIRONMENT,
                )
            },
            Self::Mast { label, implementation } => {
                let payload = [label.into_word(), implementation.into_word()];
                hasher::hash_elements_in_domain(Word::words_as_elements(&payload), domain::ENV_MAST)
            },
            Self::Data { kind, label, value } => {
                let mut payload = [ZERO; 9];
                payload[0] = Felt::from_u32(*kind);
                payload[1..5].copy_from_slice(label.as_word().as_slice());
                payload[5..].copy_from_slice(value.as_slice());
                hasher::hash_elements_in_domain(&payload, domain::ENV_DATA)
            },
            Self::Merkle { left, right } => hasher::merge(&[left.into_word(), right.into_word()]),
            Self::List(children) => {
                let element_len = checked_list_element_len(children.len())?;
                let mut payload = Vec::<Felt>::new();
                payload
                    .try_reserve_exact(element_len)
                    .map_err(|_| EnvNodeError::AllocationFailed)?;
                for child in children {
                    payload.extend_from_slice(child.as_word().as_slice());
                }
                hasher::hash_elements_in_domain(&payload, domain::ENV_LIST)
            },
        };
        Ok(EnvironmentRoot::new(commitment))
    }
}

/// An environment object's hash payload or encoded record cannot be represented or allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvNodeError {
    #[error("environment object payload length exceeds the framing or allocation bounds")]
    LengthOverflow,
    #[error("environment object payload allocation failed")]
    AllocationFailed,
}

/// Checks list flattening arithmetic, framing, and layout before allocating the Felt payload.
fn checked_list_element_len(child_count: usize) -> Result<usize, EnvNodeError> {
    let element_len = child_count.checked_mul(WORD_SIZE).ok_or(EnvNodeError::LengthOverflow)?;
    u32::try_from(element_len).map_err(|_| EnvNodeError::LengthOverflow)?;
    Layout::array::<Felt>(element_len).map_err(|_| EnvNodeError::LengthOverflow)?;
    Ok(element_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::test_vectors::vector;

    #[test]
    fn fixed_object_commitments_match_frozen_vectors() {
        // Synthetic role inputs keep object vectors independent of canonical-label encoding.
        let label = LabelCommitment::new(word([1, 2, 3, 4]));
        let child = root([5, 6, 7, 8]);
        assert_commitment(EnvNode::Env { label, child }, "object_env");
        assert_commitment(
            EnvNode::Mast {
                label,
                implementation: ImplementationRoot::new(word([9, 10, 11, 12])),
            },
            "object_mast",
        );
        assert_commitment(
            EnvNode::Mast {
                label,
                implementation: ImplementationRoot::new(child.into_word()),
            },
            "object_mast_same_payload_as_env",
        );
        assert_commitment(
            EnvNode::Merkle {
                left: child,
                right: root([17, 18, 19, 20]),
            },
            "object_merkle",
        );
    }

    #[test]
    fn merkle_collections_match_native_paths_and_reject_legacy_framing() {
        let left = root([5, 6, 7, 8]);
        let right = root([17, 18, 19, 20]);
        let commitment = EnvNode::Merkle { left, right }.commitment().unwrap();
        let path = crate::crypto::merkle::MerklePath::new(alloc::vec![right.into_word()]);
        path.verify(0, left.into_word(), commitment.as_word()).unwrap();
        assert!(path.verify(1, left.into_word(), commitment.as_word()).is_err());

        let legacy_commitment = word(vector("legacy_object_merkle").digest);
        assert!(path.verify(0, left.into_word(), &legacy_commitment).is_err());
    }

    #[test]
    fn data_commitments_match_frozen_zero_and_maximum_kind_vectors() {
        let label = LabelCommitment::new(word([1, 2, 3, 4]));
        let value = word([13, 14, 15, 16]);
        assert_commitment(EnvNode::Data { kind: 0, label, value }, "object_data_zero");
        assert_commitment(EnvNode::Data { kind: u32::MAX, label, value }, "object_data_max");
    }

    #[test]
    fn list_commitments_match_frozen_empty_partial_and_full_block_vectors() {
        let children = [
            root([5, 6, 7, 8]),
            root([17, 18, 19, 20]),
            root([21, 22, 23, 24]),
            root([25, 26, 27, 28]),
        ];
        for (len, id) in [
            "object_list_0",
            "object_list_1",
            "object_list_2",
            "object_list_3",
            "object_list_4",
        ]
        .into_iter()
        .enumerate()
        {
            assert_commitment(EnvNode::List(children[..len].to_vec()), id);
        }
    }

    #[test]
    fn object_domains_and_field_order_are_distinct() {
        let left = root([1, 2, 3, 4]);
        let right = root([5, 6, 7, 8]);
        let label = LabelCommitment::new(left.into_word());
        let swapped_label = LabelCommitment::new(right.into_word());
        let objects = [
            EnvNode::Env { label, child: right },
            EnvNode::Mast {
                label,
                implementation: ImplementationRoot::new(right.into_word()),
            },
            EnvNode::Merkle { left, right },
            EnvNode::List(vec![left, right]),
        ];
        let swapped_objects = [
            EnvNode::Env { label: swapped_label, child: left },
            EnvNode::Mast {
                label: swapped_label,
                implementation: ImplementationRoot::new(left.into_word()),
            },
            EnvNode::Merkle { left: right, right: left },
            EnvNode::List(vec![right, left]),
        ];

        for (index, object) in objects.iter().enumerate() {
            let commitment = object.commitment().unwrap();
            assert_ne!(commitment, swapped_objects[index].commitment().unwrap());
            for other in &objects[index + 1..] {
                assert_ne!(commitment, other.commitment().unwrap());
            }
        }

        let data = EnvNode::Data { kind: 0, label, value: right.into_word() };
        assert_ne!(
            data.commitment().unwrap(),
            EnvNode::Data { kind: 1, label, value: right.into_word() }.commitment().unwrap(),
        );
        assert_ne!(
            data.commitment().unwrap(),
            EnvNode::Data {
                kind: 0,
                label: swapped_label,
                value: left.into_word()
            }
            .commitment()
            .unwrap(),
        );
    }

    #[test]
    fn list_length_boundaries_reject_without_allocation() {
        assert_eq!(checked_list_element_len(0), Ok(0));
        assert_eq!(checked_list_element_len(1), Ok(4));
        assert_eq!(checked_list_element_len(4), Ok(16));
        assert_eq!(checked_list_element_len(usize::MAX), Err(EnvNodeError::LengthOverflow));
        assert_eq!(
            checked_list_element_len(usize::MAX / WORD_SIZE + 1),
            Err(EnvNodeError::LengthOverflow),
        );
        assert_eq!(
            checked_list_element_len(u32::MAX as usize / WORD_SIZE + 1),
            Err(EnvNodeError::LengthOverflow),
        );

        // Test the tightest framing/layout boundary on this target using arithmetic only. On
        // narrower targets the contiguous Felt allocation layout is the tighter bound.
        let max_elements = (u32::MAX as usize).min(isize::MAX as usize / size_of::<Felt>());
        let max_children = max_elements / WORD_SIZE;
        assert_eq!(checked_list_element_len(max_children), Ok(max_children * WORD_SIZE));
        assert_eq!(checked_list_element_len(max_children + 1), Err(EnvNodeError::LengthOverflow),);
    }

    fn word(values: [u64; 4]) -> Word {
        Word::new(values.map(Felt::new_unchecked))
    }

    fn root(values: [u64; 4]) -> EnvironmentRoot {
        EnvironmentRoot::new(word(values))
    }

    fn assert_commitment(object: EnvNode, id: &str) {
        assert_eq!(object.commitment().unwrap().into_word(), word(vector(id).digest));
    }
}
