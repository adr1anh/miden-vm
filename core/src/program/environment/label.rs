//! Canonical local-label preimages and their environment commitments.

use alloc::vec::Vec;
use core::{alloc::Layout, num::NonZeroU32};

use super::LabelCommitment;
use crate::{
    Felt, Word,
    chiplets::hasher,
    program::domain,
    serde::{ByteReader, DeserializationError, SliceReader},
    utils::bytes_to_packed_u32_elements,
};

const VERSION: u8 = 1;
const TEXT: u8 = 0;
const LIBRARY_ID: u8 = 1;
const REVISION: u8 = 2;
const TYPED_ID: u8 = 3;
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

    /// Encodes an opaque TypedId after the caller validates its codec and canonical bytes.
    ///
    /// The validator must reject unknown codecs and noncanonical or incomplete ID encodings. It
    /// receives the exact ID bytes, excluding the type ID, which are retained without rewriting.
    /// Type ID 1 is reserved for the Protocol's AccountId codec; this module does not implement
    /// that codec or recognize any TypedId codecs itself. Codec recognition and validation
    /// belong to the responsible builder or publication layer.
    ///
    /// Length and allocation-layout checks precede validation and allocation.
    pub fn typed_id<F>(
        type_id: u32,
        canonical_id_bytes: &[u8],
        validate: F,
    ) -> Result<Self, DeserializationError>
    where
        F: FnOnce(u32, &[u8]) -> Result<(), DeserializationError>,
    {
        let payload_len = canonical_id_bytes
            .len()
            .checked_add(size_of::<u32>())
            .ok_or_else(label_length_error)?;
        let byte_len = checked_envelope_len(payload_len).map_err(|_| label_length_error())?;
        validate(type_id, canonical_id_bytes)?;

        let mut bytes = Vec::with_capacity(byte_len);
        bytes.extend_from_slice(&[VERSION, TYPED_ID]);
        bytes.extend_from_slice(&(payload_len as u32).to_le_bytes());
        bytes.extend_from_slice(&type_id.to_le_bytes());
        bytes.extend_from_slice(canonical_id_bytes);
        Ok(Self { bytes })
    }

    /// Decodes one complete built-in label, rejecting trailing bytes.
    ///
    /// Text retains its exact UTF-8 bytes, including empty text; source-component validation
    /// belongs to the caller. TypedId labels require
    /// [`Self::from_bytes_with_typed_id_validator`]; this method rejects them because it has no
    /// external codec validator.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::from_bytes_with_typed_id_validator(bytes, |_, _| {
            Err(DeserializationError::InvalidValue(
                "TypedId labels require an external codec validator".into(),
            ))
        })
    }

    /// Decodes one complete label, using the caller's validator for opaque TypedId payloads.
    ///
    /// The validator has the same obligations as in [`Self::typed_id`]. It is called once for a
    /// structurally valid TypedId envelope, after length and trailing-data checks, and is not
    /// called for built-in tags. Its ID slice excludes the type ID. Successful decoding retains
    /// the entire original envelope without normalization or re-encoding.
    pub fn from_bytes_with_typed_id_validator<F>(
        bytes: &[u8],
        validate: F,
    ) -> Result<Self, DeserializationError>
    where
        F: FnOnce(u32, &[u8]) -> Result<(), DeserializationError>,
    {
        let mut source = SliceReader::new(bytes);
        if source.read_u8()? != VERSION {
            return Err(DeserializationError::InvalidValue(
                "unknown canonical label version".into(),
            ));
        }
        let tag = source.read_u8()?;
        let payload_len = source.read_u32()? as usize;
        checked_envelope_len(payload_len).map_err(|_| label_length_error())?;
        source.read_slice(payload_len)?;
        if source.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "trailing bytes after canonical label".into(),
            ));
        }
        let payload = &bytes[HEADER_LEN..];
        match tag {
            TEXT => {
                core::str::from_utf8(payload).map_err(|_| {
                    DeserializationError::InvalidValue("invalid UTF-8 Text label".into())
                })?;
            },
            LIBRARY_ID => {
                Word::try_from(payload).map_err(|_| {
                    DeserializationError::InvalidValue("invalid canonical LibraryId Word".into())
                })?;
            },
            REVISION => {
                let revision: [u8; 4] = payload.try_into().map_err(|_| {
                    DeserializationError::InvalidValue("Revision payload must be four bytes".into())
                })?;
                if u32::from_le_bytes(revision) == 0 {
                    return Err(DeserializationError::InvalidValue(
                        "Revision must be nonzero".into(),
                    ));
                }
            },
            TYPED_ID => {
                let mut source = SliceReader::new(payload);
                let type_id = source.read_u32()?;
                validate(type_id, &payload[size_of::<u32>()..])?;
            },
            _ => {
                return Err(DeserializationError::InvalidValue(
                    "unknown canonical label tag".into(),
                ));
            },
        }
        Ok(Self { bytes: bytes.to_vec() })
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

fn label_length_error() -> DeserializationError {
    DeserializationError::InvalidValue(
        "canonical label length exceeds the codec or allocation bounds".into(),
    )
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
    use core::cell::Cell;

    use super::*;
    use crate::program::test_vectors::vector;

    // A synthetic fixture codec, unrelated to the Protocol's AccountId codec (type 1).
    const SYNTHETIC_TYPE_ID: u32 = 0x0403_0201;
    const SYNTHETIC_ID: &[u8] = &[0xa5, 0, 0xff, 0x7e, 0x81];
    fn synthetic_envelope() -> Vec<u8> {
        vector("label_synthetic_typed_id").bytes.unwrap()
    }

    #[test]
    fn exact_decoding_preserves_builtin_bytes() {
        let mut labels = ["", " ", "\0", "a::b", "\"a\"", "\\n", "\n", "é", "e\u{301}", "🦀"]
            .into_iter()
            .map(|text| CanonicalLabel::text(text).unwrap())
            .collect::<Vec<_>>();
        labels.extend([
            CanonicalLabel::library_id(Word::new([
                Felt::new_unchecked(0),
                Felt::new_unchecked(1),
                Felt::new_unchecked(0x0807_0605_0403_0201),
                Felt::new_unchecked(Felt::ORDER - 1),
            ])),
            CanonicalLabel::revision(NonZeroU32::MIN),
            CanonicalLabel::revision(NonZeroU32::MAX),
        ]);
        for label in labels {
            assert_eq!(CanonicalLabel::from_bytes(label.as_bytes()).unwrap(), label);
            assert_eq!(
                CanonicalLabel::from_bytes_with_typed_id_validator(label.as_bytes(), |_, _| {
                    panic!("built-in labels must not invoke the TypedId validator")
                })
                .unwrap(),
                label,
            );
        }
    }

    #[test]
    fn exact_decoding_rejects_bad_framing_before_external_validation() {
        let envelopes = [
            CanonicalLabel::text("a::β\n").unwrap().as_bytes().to_vec(),
            CanonicalLabel::library_id(Word::default()).as_bytes().to_vec(),
            CanonicalLabel::revision(NonZeroU32::MIN).as_bytes().to_vec(),
            synthetic_envelope(),
        ];
        for envelope in envelopes {
            for end in 0..envelope.len() {
                assert_rejected_without_validator(&envelope[..end]);
            }
            for version in [0, 2, u8::MAX] {
                let mut bad = envelope.clone();
                bad[0] = version;
                assert_rejected_without_validator(&bad);
            }
            for tag in [4, u8::MAX] {
                let mut bad = envelope.clone();
                bad[1] = tag;
                assert_rejected_without_validator(&bad);
            }
            for suffix in [&[0][..], &[1, 2, 3][..]] {
                let mut bad = envelope.clone();
                bad.extend_from_slice(suffix);
                assert_rejected_without_validator(&bad);
            }
            let payload_len = (envelope.len() - HEADER_LEN) as u32;
            for bad_len in [payload_len - 1, payload_len + 1, u32::MAX] {
                let mut bad = envelope.clone();
                bad[2..HEADER_LEN].copy_from_slice(&bad_len.to_le_bytes());
                assert_rejected_without_validator(&bad);
            }
        }
    }

    #[test]
    fn builtin_decoding_rejects_noncanonical_payloads() {
        for text in [&[0x80][..], &[0xff][..], &[0xc0, 0xaf][..], &[0xed, 0xa0, 0x80][..]] {
            assert_rejected_without_validator(&envelope(TEXT, text));
        }
        for len in [0, Word::SERIALIZED_SIZE - 1, Word::SERIALIZED_SIZE + 1] {
            assert_rejected_without_validator(&envelope(LIBRARY_ID, &vec![0; len]));
        }
        for lane in 0..4 {
            let mut payload = [0; Word::SERIALIZED_SIZE];
            payload[lane * 8..(lane + 1) * 8].copy_from_slice(&Felt::ORDER.to_le_bytes());
            assert_rejected_without_validator(&envelope(LIBRARY_ID, &payload));
        }
        for revision in [&[][..], &[1, 0, 0][..], &[1, 0, 0, 0, 0][..], &[0; 4][..]] {
            assert_rejected_without_validator(&envelope(REVISION, revision));
        }
    }

    #[test]
    fn typed_id_validation_receives_exact_borrowed_bytes() {
        let calls = Cell::new(0);
        let id_bytes = SYNTHETIC_ID.to_vec();
        let label = CanonicalLabel::typed_id(SYNTHETIC_TYPE_ID, &id_bytes, |type_id, bytes| {
            calls.set(calls.get() + 1);
            assert_eq!(bytes.as_ptr(), id_bytes.as_ptr());
            validate_synthetic_id(type_id, bytes)
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(label.as_bytes(), synthetic_envelope().as_slice());
        let envelope_bytes = synthetic_envelope();
        let decoded = CanonicalLabel::from_bytes_with_typed_id_validator(
            &envelope_bytes,
            |type_id, bytes| {
                calls.set(calls.get() + 1);
                assert_eq!(bytes.as_ptr(), envelope_bytes[HEADER_LEN + 4..].as_ptr());
                validate_synthetic_id(type_id, bytes)
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(decoded, label);
        assert_eq!(decoded.as_bytes(), synthetic_envelope().as_slice());
        assert!(CanonicalLabel::from_bytes(&synthetic_envelope()).is_err());
    }

    #[test]
    fn typed_id_codec_recognition_and_canonicality_are_external() {
        for type_id in [0, 1, u32::MAX] {
            let error = DeserializationError::InvalidValue("unknown synthetic codec".into());
            assert_eq!(
                CanonicalLabel::typed_id(type_id, SYNTHETIC_ID, validate_synthetic_id),
                Err(error.clone()),
            );
            let mut bad = synthetic_envelope();
            bad[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&type_id.to_le_bytes());
            assert_eq!(
                CanonicalLabel::from_bytes_with_typed_id_validator(&bad, validate_synthetic_id),
                Err(error),
            );
        }
        for id in [&[][..], &SYNTHETIC_ID[..SYNTHETIC_ID.len() - 1], &[0; 5][..]] {
            let error = DeserializationError::InvalidValue("noncanonical synthetic ID".into());
            assert_eq!(
                CanonicalLabel::typed_id(SYNTHETIC_TYPE_ID, id, validate_synthetic_id),
                Err(error.clone()),
            );
            let mut payload = SYNTHETIC_TYPE_ID.to_le_bytes().to_vec();
            payload.extend_from_slice(id);
            assert_eq!(
                CanonicalLabel::from_bytes_with_typed_id_validator(
                    &envelope(TYPED_ID, &payload),
                    validate_synthetic_id,
                ),
                Err(error),
            );
        }
        for len in 0..4 {
            assert_rejected_without_validator(&envelope(TYPED_ID, &vec![0; len]));
        }
        // Core imposes no extra codec-specific length requirement: another validator may recognize
        // this synthetic codec's empty encoding. The actual Protocol codec remains external.
        let empty = CanonicalLabel::typed_id(SYNTHETIC_TYPE_ID, &[], |_, bytes| {
            assert!(bytes.is_empty());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            CanonicalLabel::from_bytes_with_typed_id_validator(empty.as_bytes(), |_, bytes| {
                assert!(bytes.is_empty());
                Ok(())
            })
            .unwrap(),
            empty,
        );
    }

    #[test]
    fn frozen_synthetic_typed_id_vector() {
        // Independent portable Eidos reference, using a synthetic codec rather than AccountId.
        let label =
            CanonicalLabel::typed_id(SYNTHETIC_TYPE_ID, SYNTHETIC_ID, validate_synthetic_id)
                .unwrap();
        assert_eq!(label.as_bytes(), synthetic_envelope().as_slice());
        assert_vector(label, "label_synthetic_typed_id");
        let typed_text = CanonicalLabel::typed_id(SYNTHETIC_TYPE_ID, b"alice", |_, bytes| {
            assert_eq!(bytes, b"alice");
            Ok(())
        })
        .unwrap();
        assert_ne!(typed_text.commitment(), CanonicalLabel::text("alice").unwrap().commitment());
    }

    fn validate_synthetic_id(type_id: u32, bytes: &[u8]) -> Result<(), DeserializationError> {
        if type_id != SYNTHETIC_TYPE_ID {
            return Err(DeserializationError::InvalidValue("unknown synthetic codec".into()));
        }
        if bytes != SYNTHETIC_ID {
            return Err(DeserializationError::InvalidValue("noncanonical synthetic ID".into()));
        }
        Ok(())
    }

    fn envelope(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![VERSION, tag];
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn assert_rejected_without_validator(bytes: &[u8]) {
        assert!(CanonicalLabel::from_bytes(bytes).is_err());
        assert!(
            CanonicalLabel::from_bytes_with_typed_id_validator(bytes, |_, _| {
                panic!("malformed framing or built-in payload must not invoke external validation")
            })
            .is_err(),
        );
    }

    #[test]
    fn built_in_labels_retain_exact_canonical_envelopes() {
        assert_eq!(
            CanonicalLabel::text("").unwrap().as_bytes(),
            vector("label_text_empty").bytes.unwrap(),
        );
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
        for (revision, id) in [(1, "label_revision_1"), (u32::MAX, "label_revision_max")] {
            let label = CanonicalLabel::revision(NonZeroU32::new(revision).unwrap());
            assert_eq!(label.as_bytes(), vector(id).bytes.unwrap());
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
        for (label, id) in [
            (CanonicalLabel::text("").unwrap(), "label_text_empty"),
            (CanonicalLabel::text("a::b").unwrap(), "label_text_component"),
            (CanonicalLabel::text("é").unwrap(), "label_text_composed"),
            (CanonicalLabel::text("e\u{301}").unwrap(), "label_text_decomposed"),
            (
                CanonicalLabel::library_id(Word::new([1, 2, 3, 4].map(Felt::from_u32))),
                "label_library_id_1_2_3_4",
            ),
            (CanonicalLabel::revision(NonZeroU32::MIN), "label_revision_1"),
            (CanonicalLabel::revision(NonZeroU32::MAX), "label_revision_max"),
            // Eight payload Felts require exactly one compression; nine require a partial second.
            (CanonicalLabel::text("aaaaaaaaaaaaaaaaaaaaaa").unwrap(), "label_text_22"),
            (CanonicalLabel::text("aaaaaaaaaaaaaaaaaaaaaaa").unwrap(), "label_text_23"),
        ] {
            assert_vector(label, id);
        }
    }

    fn assert_vector(label: CanonicalLabel, id: &str) {
        let expected = vector(id);
        assert_eq!(label.as_bytes(), expected.bytes.unwrap());
        assert_eq!(
            domain::domain_tag(domain::ENV_LABEL).as_canonical_u64(),
            u64::from(expected.domain_tag),
        );
        let mut payload = vec![Felt::from_u32(label.as_bytes().len() as u32)];
        payload.extend(bytes_to_packed_u32_elements(label.as_bytes()));
        assert_eq!(
            payload,
            expected.payload.into_iter().map(Felt::new_unchecked).collect::<Vec<_>>()
        );
        assert_eq!(
            label.commitment().into_word(),
            Word::new(expected.digest.map(Felt::new_unchecked)),
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
