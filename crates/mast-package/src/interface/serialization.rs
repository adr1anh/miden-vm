//! Explicit resource bounds and external profile contracts for interface/home interchange.
//!
//! These helpers do not recognize a Protocol identity codec or confer authority. There is no
//! default profile or resource policy, and context-free `Deserializable` is intentionally absent.

use alloc::vec::Vec;
use core::{alloc::Layout, fmt};

use miden_core::{Felt, program::CanonicalLabel, serde::DeserializationError};

/// Caller-selected finite logical resource bounds for one complete encode/decode operation.
///
/// `max_bytes` bounds the complete wire input/output, including framing. `max_records` bounds
/// aggregate records (home labels, public declarations, and direct/closure IDs). `max_components`
/// bounds aggregate canonical labels in homes and public paths. `max_blob_bytes` bounds aggregate
/// label payload bytes, publisher descriptor bytes, and present ABI bytes; label headers and
/// length prefixes are charged only to `max_bytes`. Thus a home label charges both a record and a
/// component, and its complete payload (including a TypedId codec number) charges blob bytes.
///
/// All four limits are explicit finite u32 values. Zero is permitted and there is no unlimited
/// sentinel or default. These are logical work/size bounds, not an allocator or RSS guarantee:
/// decoded models and intermediate data have overhead, and the reused core label decoder copies
/// each validated envelope with an infallible allocation after budget/layout checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecLimits {
    max_bytes: u32,
    max_records: u32,
    max_components: u32,
    max_blob_bytes: u32,
}

impl CodecLimits {
    pub const fn new(
        max_bytes: u32,
        max_records: u32,
        max_components: u32,
        max_blob_bytes: u32,
    ) -> Self {
        Self {
            max_bytes,
            max_records,
            max_components,
            max_blob_bytes,
        }
    }

    pub const fn max_bytes(self) -> u32 {
        self.max_bytes
    }

    pub const fn max_records(self) -> u32 {
        self.max_records
    }

    pub const fn max_components(self) -> u32 {
        self.max_components
    }

    pub const fn max_blob_bytes(self) -> u32 {
        self.max_blob_bytes
    }
}

/// Recognition and canonical validation of every externally owned TypedId codec.
///
/// Implementations must reject unknown codecs and noncanonical or incomplete encodings. Type 1
/// remains externally owned; this crate provides no AccountId parser or permissive fallback.
pub trait TypedIdProfile {
    type Context: ?Sized;
    type Error: fmt::Debug + fmt::Display;

    fn validate_typed_id(
        &self,
        context: &Self::Context,
        codec: u32,
        canonical_bytes: &[u8],
    ) -> Result<(), Self::Error>;
}

/// External policy and association checks for an explicit complete namespace home.
///
/// This mandatory check must establish that the complete home is permitted and correctly
/// associated with the caller's context/evidence. In particular, generic label validity and an
/// explicit empty N0 path do not establish permission, publisher authority, or a kernel home.
pub trait HomeProfile: TypedIdProfile {
    fn validate_home(
        &self,
        context: &Self::Context,
        home: &[CanonicalLabel],
    ) -> Result<(), Self::Error>;
}

/// The external validation which rejected otherwise structurally valid data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileOperation {
    TypedId,
    Home,
}

impl fmt::Display for ProfileOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypedId => f.write_str("TypedId"),
            Self::Home => f.write_str("home"),
        }
    }
}

/// Structural/resource failures are distinct from external profile/context rejection.
#[derive(Debug, thiserror::Error)]
pub enum CodecError<E> {
    #[error("unsupported {kind} version {version}")]
    UnsupportedVersion { kind: &'static str, version: u8 },
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("trailing bytes after {0}")]
    TrailingBytes(&'static str),
    #[error("invalid canonical label: {0}")]
    InvalidLabel(DeserializationError),
    #[error("{resource} limit exceeded: {actual} > {limit}")]
    LimitExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("{0} exceeds codec or allocation-layout bounds")]
    LengthOverflow(&'static str),
    #[error("allocation failed for {0}")]
    AllocationFailed(&'static str),
    #[error("external {operation} validation rejected the value: {error}")]
    ProfileRejected { operation: ProfileOperation, error: E },
}

pub(crate) struct Budget {
    limits: CodecLimits,
    records: usize,
    components: usize,
    blob_bytes: usize,
}

impl Budget {
    pub(crate) fn new(limits: CodecLimits) -> Self {
        Self {
            limits,
            records: 0,
            components: 0,
            blob_bytes: 0,
        }
    }

    pub(crate) fn wire_bytes<E>(&self, actual: usize) -> Result<(), CodecError<E>> {
        check_limit("wire bytes", actual, self.limits.max_bytes)
    }

    pub(crate) fn records<E>(&mut self, count: usize) -> Result<(), CodecError<E>> {
        charge("records", &mut self.records, count, self.limits.max_records)
    }

    pub(crate) fn components<E>(&mut self, count: usize) -> Result<(), CodecError<E>> {
        charge("components", &mut self.components, count, self.limits.max_components)
    }

    pub(crate) fn blob_bytes<E>(&mut self, count: usize) -> Result<(), CodecError<E>> {
        charge("blob bytes", &mut self.blob_bytes, count, self.limits.max_blob_bytes)
    }
}

fn check_limit<E>(resource: &'static str, actual: usize, limit: u32) -> Result<(), CodecError<E>> {
    let limit = usize::try_from(limit).map_err(|_| CodecError::LengthOverflow(resource))?;
    if actual > limit {
        return Err(CodecError::LimitExceeded { resource, actual, limit });
    }
    Ok(())
}

fn charge<E>(
    resource: &'static str,
    used: &mut usize,
    count: usize,
    limit: u32,
) -> Result<(), CodecError<E>> {
    let total = used.checked_add(count).ok_or(CodecError::LengthOverflow(resource))?;
    check_limit(resource, total, limit)?;
    *used = total;
    Ok(())
}

pub(crate) fn wire_len<E>(len: usize, kind: &'static str) -> Result<u32, CodecError<E>> {
    u32::try_from(len).map_err(|_| CodecError::LengthOverflow(kind))
}

pub(crate) fn checked_add<E>(
    left: usize,
    right: usize,
    kind: &'static str,
) -> Result<usize, CodecError<E>> {
    left.checked_add(right).ok_or(CodecError::LengthOverflow(kind))
}

pub(crate) fn reserve<T, E>(
    target: &mut Vec<T>,
    additional: usize,
    kind: &'static str,
) -> Result<(), CodecError<E>> {
    let total = checked_add(target.len(), additional, kind)?;
    Layout::array::<T>(total).map_err(|_| CodecError::LengthOverflow(kind))?;
    target.try_reserve(additional).map_err(|_| CodecError::AllocationFailed(kind))
}

/// A borrowed reader whose visible input is always the complete, already budget-checked slice.
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new<E>(bytes: &'a [u8], budget: &Budget) -> Result<Self, CodecError<E>> {
        budget.wire_bytes(bytes.len())?;
        Ok(Self { bytes, position: 0 })
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub(crate) fn bytes<E>(
        &mut self,
        len: usize,
        kind: &'static str,
    ) -> Result<&'a [u8], CodecError<E>> {
        let end = checked_add(self.position, len, kind)?;
        let value = self.bytes.get(self.position..end).ok_or(CodecError::Truncated(kind))?;
        self.position = end;
        Ok(value)
    }

    pub(crate) fn u8<E>(&mut self, kind: &'static str) -> Result<u8, CodecError<E>> {
        Ok(self.bytes(1, kind)?[0])
    }

    pub(crate) fn u32<E>(&mut self, kind: &'static str) -> Result<u32, CodecError<E>> {
        let bytes = self.bytes(4, kind)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Check a count's allocation layout and remaining-wire lower bound before loops/reservation.
    pub(crate) fn count<T, E>(
        &self,
        count: u32,
        minimum_bytes: usize,
        kind: &'static str,
    ) -> Result<usize, CodecError<E>> {
        let count = usize::try_from(count).map_err(|_| CodecError::LengthOverflow(kind))?;
        Layout::array::<T>(count).map_err(|_| CodecError::LengthOverflow(kind))?;
        let minimum = count.checked_mul(minimum_bytes).ok_or(CodecError::LengthOverflow(kind))?;
        if minimum > self.remaining() {
            return Err(CodecError::Truncated(kind));
        }
        Ok(count)
    }

    pub(crate) fn finish<E>(self, kind: &'static str) -> Result<(), CodecError<E>> {
        if self.remaining() != 0 {
            return Err(CodecError::TrailingBytes(kind));
        }
        Ok(())
    }

    /// Extract exactly one complete envelope before calling the core decoder/external validator.
    pub(crate) fn label<P: TypedIdProfile + ?Sized>(
        &mut self,
        budget: &mut Budget,
        profile: &P,
        context: &P::Context,
    ) -> Result<CanonicalLabel, CodecError<P::Error>> {
        let start = self.position;
        let header = self.bytes(6, "canonical label header")?;
        let payload = u32::from_le_bytes([header[2], header[3], header[4], header[5]]);
        let payload = usize::try_from(payload)
            .map_err(|_| CodecError::LengthOverflow("canonical label payload"))?;
        budget.blob_bytes(payload)?;
        check_label_layout(payload)?;
        self.bytes(payload, "canonical label payload")?;
        let envelope = &self.bytes[start..self.position];
        let mut rejected = None;
        let result =
            CanonicalLabel::from_bytes_with_typed_id_validator(envelope, |codec, bytes| {
                profile.validate_typed_id(context, codec, bytes).map_err(|error| {
                    rejected = Some(error);
                    DeserializationError::InvalidValue(
                        "external TypedId validation rejected".into(),
                    )
                })
            });
        if let Some(error) = rejected {
            return Err(CodecError::ProfileRejected {
                operation: ProfileOperation::TypedId,
                error,
            });
        }
        result.map_err(CodecError::InvalidLabel)
    }
}

/// Mirrors the core decoder's representability checks before its known envelope-copy allocation.
pub(crate) fn check_label_layout<E>(payload_len: usize) -> Result<(), CodecError<E>> {
    let envelope = checked_add(payload_len, 6, "canonical label envelope")?;
    wire_len(envelope, "canonical label envelope")?;
    Layout::array::<u8>(envelope)
        .map_err(|_| CodecError::LengthOverflow("canonical label envelope"))?;
    let elements = checked_add(envelope.div_ceil(4), 1, "canonical label hash payload")?;
    wire_len(elements, "canonical label hash payload")?;
    Layout::array::<Felt>(elements)
        .map_err(|_| CodecError::LengthOverflow("canonical label hash payload"))?;
    Ok(())
}

/// Revalidate externally owned TypedIds when encoding a previously constructed immutable label.
pub(crate) fn validate_label<P: TypedIdProfile + ?Sized>(
    label: &CanonicalLabel,
    budget: &mut Budget,
    profile: &P,
    context: &P::Context,
) -> Result<(), CodecError<P::Error>> {
    let bytes = label.as_bytes();
    // CanonicalLabel has private immutable bytes; its constructors/decoder already established
    // canonical framing and built-in payload validity. Only the external context can have changed.
    let payload = bytes.len() - 6;
    budget.blob_bytes(payload)?;
    check_label_layout(payload)?;
    if bytes[1] == 3 {
        let codec = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        profile.validate_typed_id(context, codec, &bytes[10..]).map_err(|error| {
            CodecError::ProfileRejected {
                operation: ProfileOperation::TypedId,
                error,
            }
        })?;
    }
    Ok(())
}

pub(crate) struct Writer {
    bytes: Vec<u8>,
    max_bytes: usize,
}

impl Writer {
    pub(crate) fn new<E>(capacity: usize, budget: &Budget) -> Result<Self, CodecError<E>> {
        budget.wire_bytes(capacity)?;
        let mut bytes = Vec::new();
        reserve(&mut bytes, capacity, "wire output")?;
        Ok(Self { bytes, max_bytes: capacity })
    }

    pub(crate) fn bytes<E>(&mut self, bytes: &[u8]) -> Result<(), CodecError<E>> {
        let length = checked_add(self.bytes.len(), bytes.len(), "wire output")?;
        if length > self.max_bytes {
            return Err(CodecError::LengthOverflow("precomputed wire output"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn u8<E>(&mut self, value: u8) -> Result<(), CodecError<E>> {
        self.bytes(&[value])
    }

    pub(crate) fn u32<E>(&mut self, value: u32) -> Result<(), CodecError<E>> {
        self.bytes(&value.to_le_bytes())
    }

    pub(crate) fn finish<E>(self) -> Result<Vec<u8>, CodecError<E>> {
        if self.bytes.len() != self.max_bytes {
            return Err(CodecError::LengthOverflow("precomputed wire output"));
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests;
