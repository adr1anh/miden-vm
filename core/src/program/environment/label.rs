//! Canonical local-label preimages and their environment commitments.

use alloc::vec::Vec;
use core::{alloc::Layout, num::NonZeroU32};

use super::LabelCommitment;
use crate::{Felt, Word, chiplets::hasher, program::domain, utils::bytes_to_packed_u32_elements};

const VERSION: u8 = 1;
const TEXT: u8 = 0;
const LIBRARY_ID: u8 = 1;
const REVISION: u8 = 2;
const HEADER_LEN: usize = 6;

/// A typed local label retaining its complete canonical byte preimage.
///
/// The envelope is `1 || tag:u8 || payload_len:u32_le || payload`. Its commitment hashes
/// `[envelope_len, packed_u32_0, ...]` under [`domain::ENV_LABEL`], packing the envelope bytes
/// little-endian in groups of four and zero-padding only the final partial group.
///
/// These constructors encode generic labels. Source namespace/procedure validation, including
/// rejecting empty components or reserved paths, belongs to the caller. Constructing a label does
/// not authenticate an environment binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalLabel {
    bytes: Vec<u8>,
}

impl CanonicalLabel {
    /// Encodes an already decoded and unescaped string as an exact UTF-8 Text label.
    ///
    /// Case, whitespace, NUL bytes, Unicode spelling, and `::` are preserved. Empty text is valid
    /// here; this method does not parse source syntax or validate a source component.
    ///
    /// Returns an error if the canonical envelope or hash payload length cannot be represented.
    pub fn text(text: &str) -> Result<Self, LabelError> {
        Self::from_payload(TEXT, text.as_bytes())
    }

    /// Encodes a LibraryId using the word's canonical 32-byte encoding.
    pub fn library_id(id: Word) -> Self {
        Self::from_payload(LIBRARY_ID, &id.as_bytes())
            .expect("a LibraryId label has a fixed representable length")
    }

    /// Encodes a nonzero Revision as exactly four little-endian bytes.
    pub fn revision(revision: NonZeroU32) -> Self {
        Self::from_payload(REVISION, &revision.get().to_le_bytes())
            .expect("a Revision label has a fixed representable length")
    }

    /// Returns the complete canonical envelope, including its version, tag, and payload length.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Commits to the label type and exact canonical bytes under the registered label domain.
    pub fn commitment(&self) -> LabelCommitment {
        // The constructor checked both the byte length and the hash-payload allocation layout.
        let mut elements = Vec::with_capacity(1 + self.bytes.len().div_ceil(4));
        elements.push(Felt::from_u32(self.bytes.len() as u32));
        elements.extend(bytes_to_packed_u32_elements(&self.bytes));
        LabelCommitment::new(hasher::hash_elements_in_domain(&elements, domain::ENV_LABEL))
    }

    fn from_payload(tag: u8, payload: &[u8]) -> Result<Self, LabelError> {
        let byte_len = checked_envelope_len(payload.len())?;
        let mut bytes = Vec::with_capacity(byte_len);
        bytes.extend_from_slice(&[VERSION, tag]);
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        Ok(Self { bytes })
    }
}

/// A canonical label length cannot be represented by the codec or its allocation layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error("canonical label length exceeds the codec or allocation bounds")]
    LengthOverflow,
}

/// Checks all length arithmetic before allocating either the envelope or its Felt hash payload.
fn checked_envelope_len(payload_len: usize) -> Result<usize, LabelError> {
    let byte_len = payload_len.checked_add(HEADER_LEN).ok_or(LabelError::LengthOverflow)?;
    u32::try_from(byte_len).map_err(|_| LabelError::LengthOverflow)?;
    let element_len = byte_len.div_ceil(4).checked_add(1).ok_or(LabelError::LengthOverflow)?;
    u32::try_from(element_len).map_err(|_| LabelError::LengthOverflow)?;
    Layout::array::<u8>(byte_len).map_err(|_| LabelError::LengthOverflow)?;
    Layout::array::<Felt>(element_len).map_err(|_| LabelError::LengthOverflow)?;
    Ok(byte_len)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn built_in_labels_retain_exact_canonical_envelopes() {
        assert_eq!(CanonicalLabel::text("").unwrap().as_bytes(), [1, 0, 0, 0, 0, 0]);
        assert_eq!(
            CanonicalLabel::text("a::β\n").unwrap().as_bytes(),
            [1, 0, 6, 0, 0, 0, b'a', b':', b':', 0xce, 0xb2, b'\n'],
        );
        let library_id = Word::new([
            Felt::new_unchecked(0),
            Felt::new_unchecked(1),
            Felt::new_unchecked(0x0807_0605_0403_0201),
            Felt::new_unchecked(Felt::ORDER - 1),
        ]);
        assert_eq!(
            CanonicalLabel::library_id(library_id).as_bytes(),
            [
                1, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5,
                6, 7, 8, 0, 0, 0, 0, 255, 255, 255, 255,
            ],
        );
        for (revision, payload) in [(1, [1, 0, 0, 0]), (u32::MAX, [255; 4])] {
            let label = CanonicalLabel::revision(NonZeroU32::new(revision).unwrap());
            assert_eq!(&label.as_bytes()[..HEADER_LEN], &[1, 2, 4, 0, 0, 0]);
            assert_eq!(&label.as_bytes()[HEADER_LEN..], &payload);
        }
        assert!(NonZeroU32::new(0).is_none());
    }

    #[test]
    fn generic_text_preserves_source_sensitive_bytes() {
        for text in ["", " ", "\0", "a::b", "\"a\"", "\\n", "\n", "é", "e\u{301}", "🦀"] {
            let label = CanonicalLabel::text(text).unwrap();
            assert_eq!(&label.as_bytes()[HEADER_LEN..], text.as_bytes());
        }
        for (left, right) in [("a", "A"), ("a", "a\0"), ("é", "e\u{301}"), ("\\n", "\n")] {
            assert_ne!(
                CanonicalLabel::text(left).unwrap().commitment(),
                CanonicalLabel::text(right).unwrap().commitment(),
            );
        }
        assert_ne!(
            CanonicalLabel::text("1").unwrap().commitment(),
            CanonicalLabel::revision(NonZeroU32::MIN).commitment(),
        );
        assert_ne!(
            CanonicalLabel::text("\u{1}\0\0\0").unwrap().commitment(),
            CanonicalLabel::revision(NonZeroU32::MIN).commitment(),
        );
        assert_ne!(
            CanonicalLabel::text(&Word::default().to_string()).unwrap().commitment(),
            CanonicalLabel::library_id(Word::default()).commitment(),
        );
        assert_ne!(
            CanonicalLabel::text(&"\0".repeat(32)).unwrap().commitment(),
            CanonicalLabel::library_id(Word::default()).commitment(),
        );
    }

    #[test]
    fn label_hash_payload_binds_byte_length_and_packing() {
        let label = CanonicalLabel::text("a::β\n").unwrap();
        let payload = [12, 0x0006_0001, 0x3a61_0000, 0x0ab2_ce3a].map(Felt::from_u32);
        assert_eq!(
            label.commitment().into_word(),
            hasher::hash_elements_in_domain(&payload, domain::ENV_LABEL),
        );
        assert_ne!(
            label.commitment().into_word(),
            hasher::hash_elements_in_domain(&payload, domain::ENV_NAMESPACE),
        );
        assert_ne!(label.commitment().into_word(), hasher::hash_elements(&payload));
        assert_ne!(
            label.commitment().into_word(),
            hasher::hash_elements_in_domain(&payload[1..], domain::ENV_LABEL),
        );
    }

    #[test]
    fn frozen_builtin_label_vectors() {
        // Frozen from the independent portable Eidos reference calibrated against the existing
        // generic empty/three/nine-Felt vectors. Literal Felt preimages can also be used by MASM.
        assert_vector(
            CanonicalLabel::text("").unwrap(),
            &[6, 1, 0],
            [0x528bd307c5940f1a, 0x40ab78c8d3413fce, 0x786f4695ab72fd74, 0x4145380cf8c98bfc],
        );
        assert_vector(
            CanonicalLabel::text("a::b").unwrap(),
            &[10, 262145, 979435520, 25146],
            [0x5bf3b80228ab38de, 0x287aad7cb8069073, 0x531e815abb592e63, 0x510d0ed33d8a0c96],
        );
        assert_vector(
            CanonicalLabel::text("é").unwrap(),
            &[8, 131073, 2848129024],
            [0x2108c70c2283b5f0, 0x44145cec36e8b778, 0x171dc1d567c34aa7, 0x51d4e4fc382bc069],
        );
        assert_vector(
            CanonicalLabel::text("e\u{301}").unwrap(),
            &[9, 196609, 3429171200, 129],
            [0x111fac8a69e982f1, 0x154e91a036117a9d, 0x0ee07620b63a9370, 0x69c0301702ce100d],
        );
        assert_vector(
            CanonicalLabel::library_id(Word::new([1, 2, 3, 4].map(Felt::from_u32))),
            &[38, 2097409, 65536, 0, 131072, 0, 196608, 0, 262144, 0, 0],
            [0x4b55d12bdf2165ea, 0x316d86db813259e0, 0x4ea45ff06fcd68c5, 0x72ff8d97db29d730],
        );
        assert_vector(
            CanonicalLabel::revision(NonZeroU32::MIN),
            &[10, 262657, 65536, 0],
            [0x60e8408255f38871, 0x51b340bd48ea58ee, 0x02eb98142c198577, 0x2eeefd3c97619b5d],
        );
        assert_vector(
            CanonicalLabel::revision(NonZeroU32::MAX),
            &[10, 262657, 4294901760, 65535],
            [0x1f991e0fe2e19968, 0x0241e73c0038e125, 0x7cf1505f52cfa037, 0x76bb1d381404b2c3],
        );
        // Eight payload Felts require exactly one compression; nine require a partial second.
        assert_vector(
            CanonicalLabel::text("aaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            &[
                28, 1441793, 1633746944, 1633771873, 1633771873, 1633771873, 1633771873, 1633771873,
            ],
            [0x62f83e7828db2365, 0x608f94735a4e7b0a, 0x6752b84c2438d755, 0x3074332575b88406],
        );
        assert_vector(
            CanonicalLabel::text("aaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            &[
                29, 1507329, 1633746944, 1633771873, 1633771873, 1633771873, 1633771873,
                1633771873, 97,
            ],
            [0x61c39a4e23988124, 0x69bf3302e482c78d, 0x12e2c2109a66ec8b, 0x5dcf962871fae51f],
        );
    }

    fn assert_vector(label: CanonicalLabel, expected_payload: &[u32], expected_digest: [u64; 4]) {
        let mut payload = vec![Felt::from_u32(label.as_bytes().len() as u32)];
        payload.extend(bytes_to_packed_u32_elements(label.as_bytes()));
        assert_eq!(
            payload,
            expected_payload.iter().copied().map(Felt::from_u32).collect::<Vec<_>>()
        );
        assert_eq!(
            label.commitment().into_word(),
            Word::new(expected_digest.map(Felt::new_unchecked)),
        );
    }

    #[test]
    fn length_overflow_rejects_before_allocation() {
        assert_eq!(checked_envelope_len(0), Ok(6));
        assert_eq!(checked_envelope_len(4), Ok(10));
        assert_eq!(checked_envelope_len(usize::MAX), Err(LabelError::LengthOverflow));
        assert_eq!(checked_envelope_len(u32::MAX as usize), Err(LabelError::LengthOverflow));
        assert_eq!(
            checked_envelope_len(u32::MAX as usize - HEADER_LEN + 1),
            Err(LabelError::LengthOverflow),
        );
        // These boundaries are checked without allocating giant labels. On narrower targets,
        // the contiguous Felt payload's allocation layout is the first representability bound.
        let largest_envelope =
            (u32::MAX as usize).min((isize::MAX as usize / size_of::<Felt>() - 1) * 4);
        assert_eq!(checked_envelope_len(largest_envelope - HEADER_LEN), Ok(largest_envelope),);
        assert_eq!(
            checked_envelope_len(largest_envelope - HEADER_LEN + 1),
            Err(LabelError::LengthOverflow),
        );
    }
}
