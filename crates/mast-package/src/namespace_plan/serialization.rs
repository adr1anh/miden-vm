//! Profile-bound HomeV1 interchange: `1:u8 || count:u32_le || CanonicalLabel[count]`.

use alloc::vec::Vec;

use miden_core::program::CanonicalLabel;

use super::NamespacePlan;
use crate::interface::serialization::{
    Budget, CodecError, CodecLimits, HomeProfile, ProfileOperation, Reader, Writer, checked_add,
    count_with_tail, decode_label, preflight_label, reserve, validate_label,
    validate_label_context, wire_len,
};

impl NamespacePlan {
    /// Preflights a complete embedded HomeV1 without interpreting labels or invoking policy.
    /// The caller retains mandatory following framing in `tail` and completes its entire
    /// enclosing preflight before calling `decode_preflighted_home_v1`.
    pub(crate) fn preflight_home_v1<E>(
        reader: &mut Reader<'_>,
        budget: &mut Budget,
        tail: usize,
    ) -> Result<(), CodecError<E>> {
        let version = reader.u8("HomeV1 version")?;
        if version != 1 {
            return Err(CodecError::UnsupportedVersion { kind: "home", version });
        }
        let count = reader.u32("HomeV1 component count")?;
        let count =
            count_with_tail::<CanonicalLabel, E>(reader, count, 6, tail, "HomeV1 components")?;
        budget.records(count)?;
        budget.components(count)?;
        for _ in 0..count {
            reader.label_envelope(budget)?;
        }
        Ok(())
    }

    /// Decodes a previously preflighted embedded home using the actual external profile.
    /// No resource is charged a second time.
    pub(crate) fn decode_preflighted_home_v1<P: HomeProfile + ?Sized>(
        reader: &mut Reader<'_>,
        profile: &P,
        context: &P::Context,
    ) -> Result<Self, CodecError<P::Error>> {
        let version = reader.u8("HomeV1 version")?;
        if version != 1 {
            return Err(CodecError::UnsupportedVersion { kind: "home", version });
        }
        let count = reader.u32("HomeV1 component count")?;
        let count = reader.count::<CanonicalLabel, _>(count, 6, "HomeV1 components")?;
        let mut home = Vec::new();
        reserve(&mut home, count, "HomeV1 components")?;
        for _ in 0..count {
            home.push(decode_label(reader.preflighted_label_envelope()?, profile, context)?);
        }
        profile
            .validate_home(context, &home)
            .map_err(|error| CodecError::ProfileRejected {
                operation: ProfileOperation::Home,
                error,
            })?;
        Ok(Self::new(home))
    }

    /// Charges embedded home records/components/payloads, returning its complete wire length.
    pub(crate) fn preflight_home_v1_encoding<E>(
        &self,
        budget: &mut Budget,
    ) -> Result<usize, CodecError<E>> {
        wire_len(self.home().len(), "HomeV1 component count")?;
        budget.records(self.home().len())?;
        budget.components(self.home().len())?;
        core::alloc::Layout::array::<CanonicalLabel>(self.home().len())
            .map_err(|_| CodecError::LengthOverflow("HomeV1 components"))?;
        let mut byte_len = 5;
        for label in self.home() {
            preflight_label(label, budget)?;
            byte_len = checked_add(byte_len, label.as_bytes().len(), "HomeV1 bytes")?;
        }
        Ok(byte_len)
    }

    /// Writes an already preflighted and context-validated home into the enclosing writer.
    pub(crate) fn write_home_v1<E>(&self, writer: &mut Writer) -> Result<(), CodecError<E>> {
        writer.u8(1)?;
        writer.u32(wire_len(self.home().len(), "HomeV1 component count")?)?;
        for label in self.home() {
            writer.bytes(label.as_bytes())?;
        }
        Ok(())
    }

    /// Revalidates current policy without recharging an enclosing operation's completed preflight.
    pub(crate) fn validate_home_context<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
    ) -> Result<(), CodecError<P::Error>> {
        for label in self.home() {
            validate_label_context(label, profile, context)?;
        }
        profile
            .validate_home(context, self.home())
            .map_err(|error| CodecError::ProfileRejected {
                operation: ProfileOperation::Home,
                error,
            })
    }

    /// Decodes exactly one complete HomeV1 with explicit external policy, evidence and budgets.
    ///
    /// The input includes its outer version and complete typed path. An explicit count of zero
    /// denotes N0, but still requires external permission/association validation. Successful
    /// decoding validates only this home under the supplied context; it grants no binding or
    /// code authority. There is intentionally no context-free `Deserializable` implementation.
    pub fn decode_home_v1<P: HomeProfile + ?Sized>(
        bytes: &[u8],
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Self, CodecError<P::Error>> {
        let mut budget = Budget::new(limits);
        let mut reader = Reader::new(bytes, &budget)?;
        let version = reader.u8("HomeV1 version")?;
        if version != 1 {
            return Err(CodecError::UnsupportedVersion { kind: "home", version });
        }
        let count = reader.u32("HomeV1 component count")?;
        let count = reader.count::<CanonicalLabel, _>(count, 6, "HomeV1 components")?;
        budget.records(count)?;
        budget.components(count)?;
        let mut home = Vec::new();
        reserve(&mut home, count, "HomeV1 components")?;
        for _ in 0..count {
            home.push(reader.label(&mut budget, profile, context)?);
        }
        reader.finish("HomeV1")?;
        profile
            .validate_home(context, &home)
            .map_err(|error| CodecError::ProfileRejected {
                operation: ProfileOperation::Home,
                error,
            })?;
        Ok(Self::new(home))
    }

    /// Encodes the complete explicit home after revalidating external codecs and home authority.
    ///
    /// A previously built plan does not retain validation under a particular external context.
    /// Both policy checks and the caller's complete logical budgets apply on every encoding.
    pub fn encode_home_v1<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Vec<u8>, CodecError<P::Error>> {
        let mut budget = Budget::new(limits);
        let count = wire_len(self.home().len(), "HomeV1 component count")?;
        budget.records(self.home().len())?;
        budget.components(self.home().len())?;
        let mut byte_len = 5;
        for label in self.home() {
            byte_len = checked_add(byte_len, label.as_bytes().len(), "HomeV1 bytes")?;
        }
        budget.wire_bytes(byte_len)?;
        self.validate_home_contents_with_budget(profile, context, &mut budget)?;
        let mut writer = Writer::new(byte_len, &budget)?;
        writer.u8(1)?;
        writer.u32(count)?;
        for label in self.home() {
            writer.bytes(label.as_bytes())?;
        }
        writer.finish()
    }

    /// Revalidates label payloads and the complete home using the caller's ongoing budget.
    ///
    /// The caller accounts for records, components and its operation's outer byte measure. Each
    /// home-label payload is charged here exactly once, including a TypedId's codec number.
    pub(crate) fn validate_home_contents_with_budget<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        budget: &mut Budget,
    ) -> Result<(), CodecError<P::Error>> {
        for label in self.home() {
            validate_label(label, budget, profile, context)?;
        }
        profile
            .validate_home(context, self.home())
            .map_err(|error| CodecError::ProfileRejected {
                operation: ProfileOperation::Home,
                error,
            })
    }
}

#[cfg(test)]
mod tests;
