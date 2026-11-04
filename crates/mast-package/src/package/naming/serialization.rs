//! Generic naming transport: `1:u8 || HomeV1 || entry_tag:u8 || [K:32] || PackageCallablesV1`.
//!
//! The container supplies its own length prefix. Raw transport is structurally bounded, but only
//! explicit profile admission produces canonical owned metadata with validated home associations.

use alloc::vec::Vec;
use core::{alloc::Layout, convert::Infallible};

use miden_core::{Word, program::ProcedureKey};

use super::{PackageSymbols, PackageSymbolsError};
use crate::{
    NamespacePath,
    interface::serialization::{
        Budget, CodecError, CodecLimits, HomeProfile, Reader, Writer, checked_add, reserve,
        wire_len,
    },
    package::callables::serialization::{self as callables, CallablesCodecError},
};

/// Naming transport, resource, inventory and explicit home-admission failures.
#[derive(Debug, thiserror::Error)]
pub enum NamingCodecError<E> {
    #[error(transparent)]
    Codec(#[from] CodecError<E>),
    #[error(transparent)]
    Callables(#[from] CallablesCodecError<E>),
    #[error(transparent)]
    InvalidNaming(#[from] PackageSymbolsError),
    #[error("invalid naming entry tag {tag}")]
    InvalidEntryTag { tag: u8 },
    #[error("invalid canonical Word for naming entry key")]
    InvalidEntryKey,
}

/// Structurally bounded naming bytes which carry no canonical binding or home authority.
///
/// This type intentionally exposes no namespace, callable or entry getters. Unknown TypedId codecs
/// and malformed label contents can remain opaque in transport; [`Self::decode`] must validate
/// them under the caller's current explicit profile before yielding [`PackageSymbols`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedPackageSymbols {
    bytes: Vec<u8>,
}

impl UnverifiedPackageSymbols {
    /// Retains trusted immutable owned metadata as bounded transport without profile admission.
    /// The encoder completes structural/resource preflight, so its output needs no second scan.
    pub(crate) fn from_owned(
        naming: &PackageSymbols,
        limits: CodecLimits,
    ) -> Result<Self, NamingCodecError<Infallible>> {
        Ok(Self {
            bytes: naming.encode_unverified_v1(limits)?,
        })
    }

    /// Retains an owned payload after complete structural/resource preflight, without callbacks.
    pub fn new(bytes: Vec<u8>, limits: CodecLimits) -> Result<Self, NamingCodecError<Infallible>> {
        preflight_decoding::<Infallible>(&bytes, &mut Budget::new(limits))?;
        Ok(Self { bytes })
    }

    /// Copies a complete structurally bounded payload without interpreting home-label contents.
    pub fn from_bytes_with_limits(
        bytes: &[u8],
        limits: CodecLimits,
    ) -> Result<Self, NamingCodecError<Infallible>> {
        preflight_decoding::<Infallible>(bytes, &mut Budget::new(limits))?;
        let mut owned = Vec::new();
        reserve(&mut owned, bytes.len(), "unverified naming bytes")?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    /// Returns opaque transport bytes, without asserting canonical metadata or home permission.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Admits the payload using current explicit policy, context and complete aggregate limits.
    pub fn decode<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<PackageSymbols, NamingCodecError<P::Error>> {
        PackageSymbols::decode_v1(&self.bytes, profile, context, limits)
    }
}

impl PackageSymbols {
    /// Encodes complete required naming after revalidating its own home and every binding home.
    ///
    /// One enclosing budget includes all callable inventory resources and the package's own home.
    /// An entry additionally charges one record and 32 logical bytes. `max_bytes` bounds the entire
    /// wire payload, including every version/count/tag byte. Every complete wire, logical-resource
    /// and allocation-layout bound is checked before any external profile callback.
    pub fn encode_v1<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Vec<u8>, NamingCodecError<P::Error>> {
        let mut budget = Budget::new(limits);
        let plan = self.preflight_encoding::<P::Error>(&mut budget)?;
        self.namespace_plan().validate_home_context(profile, context)?;
        plan.callables.validate(profile, context)?;
        plan.write(&budget)
    }

    /// Decodes exactly one complete payload with explicit current home policy and context.
    ///
    /// An allocation-free first pass preflights the complete payload and aggregate resource bounds
    /// before interpreting any labels or calling external policy. All inventory references and
    /// the entry declaration are checked before any home policy callback. TypedId/home validation
    /// applies to the package's own home and every retained binding, including unused declarations.
    pub fn decode_v1<P: HomeProfile + ?Sized>(
        bytes: &[u8],
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Self, NamingCodecError<P::Error>> {
        let mut budget = Budget::new(limits);
        let plan = preflight_decoding::<P::Error>(bytes, &mut budget)?;
        let prepared = plan.callables.prepare::<P::Error>(&budget)?;
        if let Some(key) = plan.entry_key
            && !prepared.contains_binding_key(key)
        {
            return Err(PackageSymbolsError::UnknownEntryKey { key }.into());
        }
        let mut home_reader = Reader::new(plan.home, &budget)?;
        let namespace_plan =
            NamespacePath::decode_preflighted_home_v1(&mut home_reader, profile, context)?;
        home_reader.finish("HomeV1")?;
        let callables = prepared.decode(profile, context, &budget)?;
        Ok(Self::new(namespace_plan, callables, plan.entry_key)?)
    }

    /// Trusted owned-container transport, without asserting admission under any home profile.
    ///
    /// Immutable constructors establish structural bindings. This reuses the complete bounded
    /// preflight/write path; it neither invents a permissive profile nor confers home authority.
    pub(crate) fn encode_unverified_v1(
        &self,
        limits: CodecLimits,
    ) -> Result<Vec<u8>, NamingCodecError<Infallible>> {
        let mut budget = Budget::new(limits);
        self.preflight_encoding::<Infallible>(&mut budget)?.write(&budget)
    }

    fn preflight_encoding<E>(
        &self,
        budget: &mut Budget,
    ) -> Result<EncodingPlan<'_>, NamingCodecError<E>> {
        let home_bytes = self.namespace_plan().preflight_home_v1_encoding(budget)?;
        preflight_entry(self.entry_key(), budget)?;
        let callables = self.callables().preflight_v1_encoding::<E>(budget)?;
        let mut byte_len = checked_add(2, home_bytes, "naming payload bytes")?;
        if self.entry_key().is_some() {
            byte_len = checked_add(byte_len, 32, "naming payload bytes")?;
        }
        byte_len = checked_add(byte_len, callables.byte_len, "naming payload bytes")?;
        preflight_wire_layout(byte_len)?;
        budget.wire_bytes(byte_len)?;
        Ok(EncodingPlan { naming: self, callables, byte_len })
    }
}

struct EncodingPlan<'a> {
    naming: &'a PackageSymbols,
    callables: callables::EncodingPlan<'a>,
    byte_len: usize,
}

impl EncodingPlan<'_> {
    fn write<E>(&self, budget: &Budget) -> Result<Vec<u8>, NamingCodecError<E>> {
        let mut writer = Writer::new(self.byte_len, budget)?;
        writer.u8(1)?;
        self.naming.namespace_plan().write_home_v1(&mut writer)?;
        match self.naming.entry_key() {
            None => writer.u8(0)?,
            Some(key) => {
                writer.u8(1)?;
                writer.bytes(&key.as_word().as_bytes())?;
            },
        }
        self.callables.write(&mut writer)?;
        Ok(writer.finish()?)
    }
}

struct DecodingPlan<'a> {
    home: &'a [u8],
    entry_key: Option<ProcedureKey>,
    callables: callables::DecodingPlan<'a>,
}

fn preflight_decoding<'a, E>(
    bytes: &'a [u8],
    budget: &mut Budget,
) -> Result<DecodingPlan<'a>, NamingCodecError<E>> {
    preflight_wire_layout(bytes.len())?;
    let mut reader = Reader::new(bytes, budget)?;
    let version = reader.u8("NamingV1 version")?;
    if version != 1 {
        return Err(CodecError::UnsupportedVersion { kind: "naming", version }.into());
    }
    let start = reader.remaining_bytes();
    // Retain the entry tag and the minimum complete callable inventory framing.
    NamespacePath::preflight_home_v1(&mut reader, budget, 14)?;
    let home = &start[..start.len() - reader.remaining()];
    let entry_key = match reader.u8("naming entry tag")? {
        0 => None,
        1 => {
            let word = Word::try_from(reader.bytes(32, "naming entry key")?)
                .map_err(|_| NamingCodecError::InvalidEntryKey)?;
            Some(ProcedureKey::new(word))
        },
        tag => return Err(NamingCodecError::InvalidEntryTag { tag }),
    };
    preflight_entry(entry_key, budget)?;
    let callables = callables::preflight_v1_decoding(&mut reader, budget)?;
    reader.finish("NamingV1")?;
    Ok(DecodingPlan { home, entry_key, callables })
}

fn preflight_entry<E>(
    entry_key: Option<ProcedureKey>,
    budget: &mut Budget,
) -> Result<(), CodecError<E>> {
    if entry_key.is_some() {
        budget.records(1)?;
        budget.logical_bytes(32)?;
    }
    Ok(())
}

fn preflight_wire_layout<E>(byte_len: usize) -> Result<(), CodecError<E>> {
    wire_len(byte_len, "naming payload bytes")?;
    Layout::array::<u8>(byte_len)
        .map_err(|_| CodecError::LengthOverflow("naming payload bytes"))?;
    Ok(())
}

#[cfg(test)]
mod tests;
