//! Exact, budgeted v1 preimages for the owned environment objects.

use alloc::vec::Vec;
use core::alloc::Layout;

use super::{
    EnvNode, EnvNodeError, EnvironmentRoot, ImplementationRoot, LabelCommitment,
    checked_list_element_len,
};
use crate::{
    Word,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader, validate_bounded_len,
    },
};

const VERSION: u8 = 1;
const ENV: u8 = 0;
const MAST: u8 = 1;
const DATA: u8 = 2;
const MERKLE: u8 = 3;
const LIST: u8 = 4;
const HEADER_LEN: usize = 2;
const LIST_HEADER_LEN: usize = HEADER_LEN + size_of::<u32>();

impl EnvNode {
    /// Returns the v1 preimage's byte length without allocating.
    ///
    /// Includes the record header and any List count. Returns an error if a directly
    /// constructed List exceeds the hash framing or allocation bounds.
    pub fn encoded_len(&self) -> Result<usize, EnvNodeError> {
        Ok(match self {
            Self::Env { .. } | Self::Mast { .. } | Self::Merkle { .. } => {
                HEADER_LEN + 2 * Word::SERIALIZED_SIZE
            },
            Self::Data { .. } => LIST_HEADER_LEN + 2 * Word::SERIALIZED_SIZE,
            Self::List(children) => checked_list_record_len(children.len())?,
        })
    }

    /// Encodes one v1 environment-node preimage, preserving the selected commitment payload.
    ///
    /// The record is `1 || kind:u8 || payload`, with Env=0, Mast=1, Data=2, Merkle=3, and
    /// List=4. Words use their canonical 32-byte encoding. Data's type and List's child count
    /// are little-endian u32 values. The wire header and List count do not enter the hash.
    ///
    /// Returns an error if a directly constructed List exceeds the hash framing or allocation
    /// bounds, if the encoded record exceeds allocation bounds, or if allocation fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvNodeError> {
        let byte_len = self.encoded_len()?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(byte_len).map_err(|_| EnvNodeError::AllocationFailed)?;
        bytes.write_u8(VERSION);
        match self {
            Self::Env { label, child } => {
                bytes.write_u8(ENV);
                label.write_into(&mut bytes);
                child.write_into(&mut bytes);
            },
            Self::Mast { label, implementation } => {
                bytes.write_u8(MAST);
                label.write_into(&mut bytes);
                implementation.write_into(&mut bytes);
            },
            Self::Data { kind, label, value } => {
                bytes.write_u8(DATA);
                bytes.write_u32(*kind);
                label.write_into(&mut bytes);
                value.write_into(&mut bytes);
            },
            Self::Merkle { left, right } => {
                bytes.write_u8(MERKLE);
                left.write_into(&mut bytes);
                right.write_into(&mut bytes);
            },
            Self::List(children) => {
                bytes.write_u8(LIST);
                // checked_list_record_len already checked the tighter hash Felt-count bound.
                bytes.write_u32(children.len() as u32);
                for child in children {
                    child.write_into(&mut bytes);
                }
            },
        }
        Ok(bytes)
    }

    /// Decodes exactly one v1 environment-node preimage within the caller's byte budget.
    ///
    /// The budget includes the entire record, including its header and any List count. Unknown
    /// versions or kinds, noncanonical Word fields, truncated records, and trailing bytes are
    /// rejected. List length, hash framing, input, and allocation bounds are checked before
    /// allocation. Successful decoding does not authenticate referenced children or establish
    /// a complete environment.
    pub fn from_bytes(bytes: &[u8], byte_budget: usize) -> Result<Self, DeserializationError> {
        // BudgetedReader::has_more_bytes returns false once its budget is exhausted, even when
        // the underlying input has a suffix. Bound the complete input before wrapping it.
        if bytes.len() > byte_budget {
            return Err(DeserializationError::InvalidValue(
                "environment node input exceeds byte budget".into(),
            ));
        }
        let mut source = BudgetedReader::new(SliceReader::new(bytes), byte_budget);
        if source.read_u8()? != VERSION {
            return Err(DeserializationError::InvalidValue(
                "unknown environment node version".into(),
            ));
        }
        let node = match source.read_u8()? {
            ENV => Self::Env {
                label: LabelCommitment::read_from(&mut source)?,
                child: EnvironmentRoot::read_from(&mut source)?,
            },
            MAST => Self::Mast {
                label: LabelCommitment::read_from(&mut source)?,
                implementation: ImplementationRoot::read_from(&mut source)?,
            },
            DATA => Self::Data {
                kind: source.read_u32()?,
                label: LabelCommitment::read_from(&mut source)?,
                value: Word::read_from(&mut source)?,
            },
            MERKLE => Self::Merkle {
                left: EnvironmentRoot::read_from(&mut source)?,
                right: EnvironmentRoot::read_from(&mut source)?,
            },
            LIST => {
                let count = usize::try_from(source.read_u32()?).map_err(|_| list_length_error())?;
                let byte_len = checked_list_record_len(count).map_err(|_| list_length_error())?;
                validate_bounded_len(&source, "environment List", count, Word::SERIALIZED_SIZE)?;
                if bytes.len() != byte_len {
                    return Err(DeserializationError::InvalidValue(
                        "invalid environment List record length".into(),
                    ));
                }
                let mut children = Vec::new();
                children.try_reserve_exact(count).map_err(|_| {
                    DeserializationError::InvalidValue("environment List allocation failed".into())
                })?;
                for _ in 0..count {
                    children.push(EnvironmentRoot::read_from(&mut source)?);
                }
                Self::List(children)
            },
            _ => {
                return Err(DeserializationError::InvalidValue(
                    "unknown environment node kind".into(),
                ));
            },
        };
        if source.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "trailing bytes after environment node".into(),
            ));
        }
        Ok(node)
    }
}

/// Checks both the public List's commitment bounds and its complete wire/allocation layouts.
fn checked_list_record_len(child_count: usize) -> Result<usize, EnvNodeError> {
    checked_list_element_len(child_count)?;
    Layout::array::<EnvironmentRoot>(child_count).map_err(|_| EnvNodeError::LengthOverflow)?;
    let byte_len = child_count
        .checked_mul(Word::SERIALIZED_SIZE)
        .and_then(|len| len.checked_add(LIST_HEADER_LEN))
        .ok_or(EnvNodeError::LengthOverflow)?;
    Layout::array::<u8>(byte_len).map_err(|_| EnvNodeError::LengthOverflow)?;
    Ok(byte_len)
}

fn list_length_error() -> DeserializationError {
    DeserializationError::InvalidValue(
        "environment List length exceeds framing or allocation bounds".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt,
        program::test_vectors::{Vector, vector},
    };

    #[test]
    fn node_bytes_match_frozen_vectors_and_roundtrips_preserve_commitments() {
        for (node, expected) in fixtures() {
            let expected_bytes = expected.bytes.unwrap();
            assert_eq!(node.encoded_len().unwrap(), expected_bytes.len());
            let bytes = node.to_bytes().unwrap();
            assert_eq!(bytes, expected_bytes);
            assert_eq!(node.commitment().unwrap().into_word(), word(expected.digest));
            let decoded = EnvNode::from_bytes(&bytes, bytes.len()).unwrap();
            assert_eq!(decoded, node);
            assert_eq!(decoded.commitment().unwrap(), node.commitment().unwrap());
            assert_eq!(decoded.to_bytes().unwrap(), bytes);
        }
    }

    #[test]
    fn every_truncation_and_suffix_is_rejected() {
        for (node, _) in fixtures() {
            let bytes = node.to_bytes().unwrap();
            for len in 0..bytes.len() {
                assert!(EnvNode::from_bytes(&bytes[..len], bytes.len()).is_err());
            }
            let mut suffixed = bytes.clone();
            suffixed.push(0);
            assert!(EnvNode::from_bytes(&suffixed, suffixed.len()).is_err());
            // Exhausting the budget on the valid prefix must never hide trailing data.
            assert!(EnvNode::from_bytes(&suffixed, bytes.len()).is_err());
            let mut concatenated = bytes.clone();
            concatenated.extend_from_slice(&bytes);
            assert!(EnvNode::from_bytes(&concatenated, concatenated.len()).is_err());
        }
    }

    #[test]
    fn byte_budget_bounds_the_complete_record() {
        for (node, _) in fixtures() {
            let bytes = node.to_bytes().unwrap();
            for budget in 0..bytes.len() {
                assert!(EnvNode::from_bytes(&bytes, budget).is_err());
            }
            for budget in [bytes.len(), bytes.len() + 1, usize::MAX] {
                assert_eq!(EnvNode::from_bytes(&bytes, budget).unwrap(), node);
            }
        }
    }

    #[test]
    fn unknown_versions_and_kinds_are_rejected() {
        let mut bytes = fixtures()[0].0.to_bytes().unwrap();
        for version in [0, 2, u8::MAX] {
            bytes[0] = version;
            assert!(EnvNode::from_bytes(&bytes, bytes.len()).is_err());
        }
        bytes[0] = VERSION;
        for kind in 5..=u8::MAX {
            bytes[1] = kind;
            assert!(EnvNode::from_bytes(&bytes, bytes.len()).is_err());
        }
    }

    #[test]
    fn noncanonical_felts_are_rejected_in_every_word_role() {
        for (node, _) in fixtures() {
            let bytes = node.to_bytes().unwrap();
            let word_start = match &node {
                EnvNode::Data { .. } | EnvNode::List(_) => LIST_HEADER_LEN,
                _ => HEADER_LEN,
            };
            // Corrupt every limb of every label/root/implementation/value/child Word.
            for offset in (word_start..bytes.len()).step_by(size_of::<u64>()) {
                for invalid in [Felt::ORDER, u64::MAX] {
                    let mut malformed = bytes.clone();
                    malformed[offset..offset + size_of::<u64>()]
                        .copy_from_slice(&invalid.to_le_bytes());
                    assert!(EnvNode::from_bytes(&malformed, malformed.len()).is_err());
                }
            }
        }
    }

    #[test]
    fn malicious_list_counts_reject_before_allocation() {
        for count in [1, u32::MAX / 4, u32::MAX / 4 + 1, u32::MAX] {
            let mut bytes = vec![VERSION, LIST];
            bytes.extend_from_slice(&count.to_le_bytes());
            assert!(EnvNode::from_bytes(&bytes, bytes.len()).is_err());
            assert!(EnvNode::from_bytes(&bytes, usize::MAX).is_err());
        }
        // A count smaller than the actual payload is also a malformed exact record.
        let mut bytes = fixtures().pop().unwrap().0.to_bytes().unwrap();
        bytes[HEADER_LEN..LIST_HEADER_LEN].copy_from_slice(&3_u32.to_le_bytes());
        assert!(EnvNode::from_bytes(&bytes, bytes.len()).is_err());
    }

    #[test]
    fn list_framing_and_record_layout_boundaries_use_arithmetic_only() {
        assert_eq!(checked_list_record_len(0), Ok(6));
        assert_eq!(checked_list_record_len(1), Ok(38));
        assert_eq!(checked_list_record_len(4), Ok(134));
        for count in [
            usize::MAX,
            usize::MAX / Word::SERIALIZED_SIZE + 1,
            usize::MAX / Word::NUM_ELEMENTS + 1,
            u32::MAX as usize / Word::NUM_ELEMENTS + 1,
        ] {
            assert_eq!(checked_list_record_len(count), Err(EnvNodeError::LengthOverflow));
        }
        let max_children = (u32::MAX as usize / Word::NUM_ELEMENTS)
            .min(isize::MAX as usize / size_of::<EnvironmentRoot>())
            .min((isize::MAX as usize - LIST_HEADER_LEN) / Word::SERIALIZED_SIZE);
        assert_eq!(
            checked_list_record_len(max_children),
            Ok(LIST_HEADER_LEN + max_children * Word::SERIALIZED_SIZE),
        );
        assert_eq!(checked_list_record_len(max_children + 1), Err(EnvNodeError::LengthOverflow));
    }

    fn word(values: [u64; 4]) -> Word {
        Word::new(values.map(Felt::new_unchecked))
    }

    fn root(values: [u64; 4]) -> EnvironmentRoot {
        EnvironmentRoot::new(word(values))
    }

    fn fixtures() -> Vec<(EnvNode, Vector)> {
        // The same tracked rows supply exact D1 bytes, Felt preimages, and commitments.
        let label = LabelCommitment::new(word([1, 2, 3, 4]));
        let child = root([5, 6, 7, 8]);
        let children =
            [child, root([17, 18, 19, 20]), root([21, 22, 23, 24]), root([25, 26, 27, 28])];
        vec![
            (EnvNode::Env { label, child }, vector("object_env")),
            (
                EnvNode::Mast {
                    label,
                    implementation: ImplementationRoot::new(word([9, 10, 11, 12])),
                },
                vector("object_mast"),
            ),
            (
                EnvNode::Mast {
                    label,
                    implementation: ImplementationRoot::new(child.into_word()),
                },
                vector("object_mast_same_payload_as_env"),
            ),
            (
                EnvNode::Data {
                    kind: 0,
                    label,
                    value: word([13, 14, 15, 16]),
                },
                vector("object_data_zero"),
            ),
            (
                EnvNode::Data {
                    kind: u32::MAX,
                    label,
                    value: word([13, 14, 15, 16]),
                },
                vector("object_data_max"),
            ),
            (EnvNode::Merkle { left: child, right: children[1] }, vector("object_merkle")),
            (EnvNode::List(vec![]), vector("object_list_0")),
            (EnvNode::List(children[..1].to_vec()), vector("object_list_1")),
            (EnvNode::List(children[..2].to_vec()), vector("object_list_2")),
            (EnvNode::List(children[..3].to_vec()), vector("object_list_3")),
            (EnvNode::List(children.to_vec()), vector("object_list_4")),
        ]
    }
}
