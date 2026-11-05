//! Canonical VM-owned callable inventory payload, independent of package/container admission.
//!
//! `1:u8 || bindings:u32 || (K:32 || HomeV1 || TextPath)* || visible:u32 ||
//! (TextPath || K:32)* || selections:u32 || (K:32 || D:32)*`.
//! A TextPath is a u32 component count followed by complete canonical Text-label envelopes.

use alloc::{string::String, vec::Vec};
use core::{alloc::Layout, cmp::Ordering};

use miden_core::{
    Word,
    program::{CanonicalLabel, ImplementationRoot, LabelError, ProcedureKey},
};

use super::{PackageCallables, PackageCallablesError};
use crate::{
    CallableBinding, CallableProcedurePath, DeclarationError, NamespacePlan,
    interface::serialization::{
        Budget, CodecError, CodecLimits, HomeProfile, Reader, Writer, check_label_layout,
        checked_add, compare_text_paths, count_with_tail, reserve, wire_len,
    },
};

/// Structural callable-payload failures, distinct from caller resource and home-policy failures.
#[derive(Debug, thiserror::Error)]
pub enum CallablesCodecError<E> {
    #[error(transparent)]
    Codec(#[from] CodecError<E>),
    #[error(transparent)]
    InvalidInventory(#[from] PackageCallablesError),
    #[error(transparent)]
    InvalidPath(#[from] DeclarationError),
    #[error("cannot derive callable binding: {0}")]
    InvalidBinding(LabelError),
    #[error("invalid canonical Word for {kind}")]
    InvalidWord { kind: &'static str },
    #[error("{kind} must be strictly increasing in canonical byte order")]
    NonCanonicalOrder { kind: &'static str },
    #[error("callable procedure components require Text labels, found tag {tag}")]
    NonTextPathLabel { tag: u8 },
    #[error("stored callable key {stored:?} differs from derived key {derived:?}")]
    KeyMismatch {
        stored: ProcedureKey,
        derived: ProcedureKey,
    },
}

impl PackageCallables {
    /// Encodes one canonical v1 inventory using explicit current home policy and finite limits.
    ///
    /// `max_bytes` bounds the complete wire payload, including framing. Records count bindings,
    /// aliases, selections and owned home labels; components count home labels and every canonical
    /// and visible path component; blob bytes count home payloads and exact path UTF-8 bytes.
    /// Every complete aggregate/layout/length bound is checked before any profile callback.
    /// Each owned home is revalidated, including N0 and declarations without aliases or code.
    /// This payload establishes no package identity, entry/kernel selection, release or authority.
    pub fn encode_v1<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Vec<u8>, CallablesCodecError<P::Error>> {
        let mut budget = Budget::new(limits);
        let plan = self.preflight_v1_encoding(&mut budget)?;
        plan.validate(profile, context)?;
        let mut writer = Writer::new(plan.byte_len, &budget)?;
        plan.write(&mut writer)?;
        Ok(writer.finish()?)
    }

    /// Decodes exactly one canonical v1 payload and verifies every stored K from its home/path.
    ///
    /// No context-free decoder or default home/profile exists. An allocation-free first scan
    /// bounds the complete input and aggregate records/components/payloads/layouts before actual
    /// TypedId/home validation. Previously encoded data is revalidated under the supplied context.
    pub fn decode_v1<P: HomeProfile + ?Sized>(
        bytes: &[u8],
        profile: &P,
        context: &P::Context,
        limits: CodecLimits,
    ) -> Result<Self, CallablesCodecError<P::Error>> {
        let mut budget = Budget::new(limits);
        let mut reader = Reader::new(bytes, &budget)?;
        let plan = preflight_v1_decoding(&mut reader, &mut budget)?;
        reader.finish("PackageCallablesV1")?;
        plan.decode(profile, context, &budget)
    }

    /// Charges only this field's aggregate resources into an enclosing operation's ongoing budget.
    /// The enclosing operation must preflight all other fields and its complete wire length before
    /// calling `validate`; neither contextual validation nor writing recharges these resources.
    pub(crate) fn preflight_v1_encoding<E>(
        &self,
        budget: &mut Budget,
    ) -> Result<EncodingPlan<'_>, CallablesCodecError<E>> {
        wire_len(self.bindings.len(), "callable binding count")?;
        wire_len(self.visible_paths.len(), "visible callable path count")?;
        wire_len(self.selected_implementations.len(), "implementation selection count")?;
        budget.records(self.bindings.len())?;
        budget.records(self.visible_paths.len())?;
        budget.records(self.selected_implementations.len())?;
        check_array::<(&ProcedureKey, &CallableBinding), E>(
            self.bindings.len(),
            "callable ordering",
        )?;
        check_array::<(&CallableProcedurePath, &ProcedureKey), E>(
            self.visible_paths.len(),
            "visible path ordering",
        )?;
        check_array::<(&ProcedureKey, &ImplementationRoot), E>(
            self.selected_implementations.len(),
            "selection ordering",
        )?;
        let mut byte_len = 13;
        for binding in self.bindings.values() {
            byte_len = checked_add(byte_len, 32, "callable payload bytes")?;
            byte_len = checked_add(
                byte_len,
                binding.namespace_plan().preflight_home_v1_encoding(budget)?,
                "callable payload bytes",
            )?;
            byte_len = checked_add(
                byte_len,
                preflight_path_encoding(binding.path(), budget)?,
                "callable payload bytes",
            )?;
        }
        for path in self.visible_paths.keys() {
            byte_len = checked_add(byte_len, 32, "callable payload bytes")?;
            byte_len = checked_add(
                byte_len,
                preflight_path_encoding(path, budget)?,
                "callable payload bytes",
            )?;
        }
        let selection_bytes = self
            .selected_implementations
            .len()
            .checked_mul(64)
            .ok_or(CodecError::LengthOverflow("implementation selection bytes"))?;
        byte_len = checked_add(byte_len, selection_bytes, "callable payload bytes")?;
        wire_len(byte_len, "callable payload bytes")?;
        budget.wire_bytes(byte_len)?;
        Ok(EncodingPlan { callables: self, byte_len })
    }
}

pub(crate) struct EncodingPlan<'a> {
    callables: &'a PackageCallables,
    pub(crate) byte_len: usize,
}

impl EncodingPlan<'_> {
    pub(crate) fn validate<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
    ) -> Result<(), CallablesCodecError<P::Error>> {
        for binding in self.callables.bindings.values() {
            binding.namespace_plan().validate_home_context(profile, context)?;
            let derived = binding
                .namespace_plan()
                .callable_procedure_key(binding.path())
                .map_err(CallablesCodecError::InvalidBinding)?;
            if derived != binding.key() {
                return Err(CallablesCodecError::KeyMismatch { stored: binding.key(), derived });
            }
        }
        Ok(())
    }

    /// Append only after the entire enclosing operation has preflighted and validated policy.
    pub(crate) fn write<E>(&self, writer: &mut Writer) -> Result<(), CallablesCodecError<E>> {
        let mut bindings = Vec::new();
        reserve(&mut bindings, self.callables.bindings.len(), "callable ordering")?;
        bindings.extend(self.callables.bindings.iter());
        bindings.sort_unstable_by_key(|(key, _)| key.as_word().as_bytes());
        let mut visible = Vec::new();
        reserve(&mut visible, self.callables.visible_paths.len(), "visible path ordering")?;
        visible.extend(self.callables.visible_paths.iter());
        visible.sort_unstable_by(|(left, _), (right, _)| {
            compare_text_paths(left.components(), right.components())
        });
        let mut selections = Vec::new();
        reserve(
            &mut selections,
            self.callables.selected_implementations.len(),
            "selection ordering",
        )?;
        selections.extend(self.callables.selected_implementations.iter());
        selections.sort_unstable_by_key(|(key, _)| key.as_word().as_bytes());

        writer.u8(1)?;
        writer.u32(wire_len(bindings.len(), "callable binding count")?)?;
        for (key, binding) in bindings {
            writer.bytes(&key.as_word().as_bytes())?;
            binding.namespace_plan().write_home_v1(writer)?;
            write_path(binding.path(), writer)?;
        }
        writer.u32(wire_len(visible.len(), "visible callable path count")?)?;
        for (path, key) in visible {
            write_path(path, writer)?;
            writer.bytes(&key.as_word().as_bytes())?;
        }
        writer.u32(wire_len(selections.len(), "implementation selection count")?)?;
        for (key, implementation) in selections {
            writer.bytes(&key.as_word().as_bytes())?;
            writer.bytes(&implementation.as_word().as_bytes())?;
        }
        Ok(())
    }
}

/// Borrowed proof that one field has completed resource/layout/wire preflight, without callbacks.
/// An enclosing manifest can retain this while scanning every later field with the same budget.
pub(crate) struct DecodingPlan<'a> {
    bytes: &'a [u8],
}

pub(crate) fn preflight_v1_decoding<'a, E>(
    reader: &mut Reader<'a>,
    budget: &mut Budget,
) -> Result<DecodingPlan<'a>, CallablesCodecError<E>> {
    let start = reader.remaining_bytes();
    let version = reader.u8("PackageCallablesV1 version")?;
    if version != 1 {
        return Err(CodecError::UnsupportedVersion { kind: "callables", version }.into());
    }
    let count = reader.u32("callable binding count")?;
    let count = count_with_tail::<CallableBinding, E>(reader, count, 48, 8, "callable bindings")?;
    check_array::<(ProcedureKey, &[u8], CallableProcedurePath), E>(
        count,
        "borrowed callable bindings",
    )?;
    budget.records(count)?;
    let mut previous = None;
    for index in 0..count {
        let key = decode_word(reader, "callable binding key")?;
        check_word_order(&mut previous, key, "callable bindings")?;
        let rest = remaining_tail(count - index - 1, 48, 8, "callable bindings")?;
        NamespacePlan::preflight_home_v1(
            reader,
            budget,
            checked_add(rest, 11, "callable path framing")?,
        )?;
        preflight_path_decoding(reader, budget, rest)?;
    }
    let count = reader.u32("visible callable path count")?;
    let count = count_with_tail::<(CallableProcedurePath, ProcedureKey), E>(
        reader,
        count,
        43,
        4,
        "visible callable paths",
    )?;
    budget.records(count)?;
    let mut previous = None;
    for index in 0..count {
        let tail = remaining_tail(count - index - 1, 43, 36, "visible callable paths")?;
        let path = preflight_path_decoding(reader, budget, tail)?;
        if previous.is_some_and(|prior| compare_wire_paths(prior, path) != Ordering::Less) {
            return Err(CallablesCodecError::NonCanonicalOrder { kind: "visible callable paths" });
        }
        previous = Some(path);
        decode_word(reader, "visible callable key")?;
    }
    let count = reader.u32("implementation selection count")?;
    let count = reader.count::<(ProcedureKey, ImplementationRoot), E>(
        count,
        64,
        "implementation selections",
    )?;
    budget.records(count)?;
    let mut previous = None;
    for _ in 0..count {
        let key = decode_word(reader, "selected callable key")?;
        check_word_order(&mut previous, key, "implementation selections")?;
        decode_word(reader, "selected implementation root")?;
    }
    let length = start.len() - reader.remaining();
    wire_len(length, "callable payload bytes")?;
    budget.wire_bytes(length)?;
    Ok(DecodingPlan { bytes: &start[..length] })
}

impl<'a> DecodingPlan<'a> {
    /// Runs actual label/home policy only after the enclosing operation's complete preflight.
    /// `budget` is used for the wire bound only; every aggregate resource was already charged.
    pub(crate) fn decode<P: HomeProfile + ?Sized>(
        &self,
        profile: &P,
        context: &P::Context,
        budget: &Budget,
    ) -> Result<PackageCallables, CallablesCodecError<P::Error>> {
        self.prepare::<P::Error>(budget)?.decode(profile, context, budget)
    }

    /// Prepares bounded paths and borrowed homes, validating all references without callbacks.
    /// Enclosing operations can check their own references before any home policy is invoked.
    /// The entire enclosing resource/layout/wire preflight must already have completed.
    pub(crate) fn prepare<E>(
        &self,
        budget: &Budget,
    ) -> Result<PreparedCallables<'a>, CallablesCodecError<E>> {
        let mut reader = Reader::new(self.bytes, budget)?;
        reader.u8("PackageCallablesV1 version")?;
        let count = reader.u32("callable binding count")? as usize;
        // Retain bounded borrowed home envelopes and decoded Text paths first. This permits
        // reference checks by canonical-key binary search before any external policy callback.
        let mut borrowed_bindings = Vec::new();
        reserve(&mut borrowed_bindings, count, "borrowed callable bindings")?;
        for _ in 0..count {
            let stored = ProcedureKey::new(decode_word(&mut reader, "callable binding key")?);
            let home = borrow_preflighted_home(&mut reader)?;
            let path = decode_preflighted_path(&mut reader)?;
            borrowed_bindings.push((stored, home, path));
        }
        let count = reader.u32("visible callable path count")? as usize;
        let mut visible = Vec::new();
        reserve(&mut visible, count, "visible callable paths")?;
        for _ in 0..count {
            let path = decode_preflighted_path(&mut reader)?;
            let key = ProcedureKey::new(decode_word(&mut reader, "visible callable key")?);
            if !declares_key(&borrowed_bindings, key) {
                return Err(PackageCallablesError::UnknownVisiblePathTarget { path, key }.into());
            }
            visible.push((path, key));
        }
        let count = reader.u32("implementation selection count")? as usize;
        let mut selections = Vec::new();
        reserve(&mut selections, count, "implementation selections")?;
        for _ in 0..count {
            let key = ProcedureKey::new(decode_word(&mut reader, "selected callable key")?);
            let implementation =
                ImplementationRoot::new(decode_word(&mut reader, "selected implementation root")?);
            if !declares_key(&borrowed_bindings, key) {
                return Err(PackageCallablesError::UnknownImplementationTarget { key }.into());
            }
            selections.push((key, implementation));
        }
        reader.finish("PackageCallablesV1")?;
        Ok(PreparedCallables { borrowed_bindings, visible, selections })
    }
}

/// Bounded decoded paths and validated references, retaining home envelopes without authority.
pub(crate) struct PreparedCallables<'a> {
    borrowed_bindings: Vec<(ProcedureKey, &'a [u8], CallableProcedurePath)>,
    visible: Vec<(CallableProcedurePath, ProcedureKey)>,
    selections: Vec<(ProcedureKey, ImplementationRoot)>,
}

impl PreparedCallables<'_> {
    pub(crate) fn contains_binding_key(&self, key: ProcedureKey) -> bool {
        declares_key(&self.borrowed_bindings, key)
    }

    /// Applies actual label/home policy after all enclosing references have been checked.
    /// Resources were charged by the first scan and are not charged again here.
    pub(crate) fn decode<P: HomeProfile + ?Sized>(
        self,
        profile: &P,
        context: &P::Context,
        budget: &Budget,
    ) -> Result<PackageCallables, CallablesCodecError<P::Error>> {
        let Self { borrowed_bindings, visible, selections } = self;
        let mut bindings = Vec::new();
        reserve(&mut bindings, borrowed_bindings.len(), "callable bindings")?;
        for (stored, bytes, path) in borrowed_bindings {
            let mut home_reader = Reader::new(bytes, budget)?;
            let home =
                NamespacePlan::decode_preflighted_home_v1(&mut home_reader, profile, context)?;
            home_reader.finish("HomeV1")?;
            let binding =
                CallableBinding::new(home, path).map_err(CallablesCodecError::InvalidBinding)?;
            if binding.key() != stored {
                return Err(CallablesCodecError::KeyMismatch { stored, derived: binding.key() });
            }
            bindings.push(binding);
        }
        Ok(PackageCallables::new(bindings, visible, selections)?)
    }
}

fn borrow_preflighted_home<'a, E>(reader: &mut Reader<'a>) -> Result<&'a [u8], CodecError<E>> {
    let start = reader.remaining_bytes();
    reader.u8("HomeV1 version")?;
    let count = reader.u32("HomeV1 component count")?;
    for _ in 0..count {
        reader.preflighted_label_envelope()?;
    }
    Ok(&start[..start.len() - reader.remaining()])
}

fn declares_key(
    bindings: &[(ProcedureKey, &[u8], CallableProcedurePath)],
    key: ProcedureKey,
) -> bool {
    bindings
        .binary_search_by(|(candidate, ..)| {
            candidate.as_word().as_bytes().cmp(&key.as_word().as_bytes())
        })
        .is_ok()
}

fn preflight_path_encoding<E>(
    path: &CallableProcedurePath,
    budget: &mut Budget,
) -> Result<usize, CodecError<E>> {
    wire_len(path.components().len(), "callable path component count")?;
    check_array::<String, E>(path.components().len(), "callable path components")?;
    budget.components(path.components().len())?;
    let mut length = 4;
    for component in path.components() {
        budget.blob_bytes(component.len())?;
        check_label_layout(component.len())?;
        length = checked_add(
            length,
            checked_add(6, component.len(), "callable Text label")?,
            "callable path bytes",
        )?;
    }
    Ok(length)
}

fn preflight_path_decoding<'a, E>(
    reader: &mut Reader<'a>,
    budget: &mut Budget,
    tail: usize,
) -> Result<&'a [u8], CallablesCodecError<E>> {
    let count = reader.u32("callable path component count")?;
    let count = count_with_tail::<String, E>(reader, count, 7, tail, "callable path components")?;
    budget.components(count)?;
    let start = reader.remaining_bytes();
    for _ in 0..count {
        let envelope = reader.label_envelope(budget)?;
        if envelope[1] != 0 {
            return Err(CallablesCodecError::NonTextPathLabel { tag: envelope[1] });
        }
    }
    Ok(&start[..start.len() - reader.remaining()])
}

fn decode_preflighted_path<E>(
    reader: &mut Reader<'_>,
) -> Result<CallableProcedurePath, CallablesCodecError<E>> {
    let count = reader.u32("callable path component count")? as usize;
    let mut components = Vec::new();
    reserve(&mut components, count, "callable path components")?;
    for _ in 0..count {
        let label = CanonicalLabel::from_bytes(reader.preflighted_label_envelope()?)
            .map_err(CodecError::InvalidLabel)?;
        let text = core::str::from_utf8(&label.as_bytes()[6..])
            .expect("the core Text decoder validated these exact UTF-8 bytes");
        components.push(String::from(text));
    }
    Ok(CallableProcedurePath::from_semantic_components(components)?)
}

fn write_path<E>(path: &CallableProcedurePath, writer: &mut Writer) -> Result<(), CodecError<E>> {
    writer.u32(wire_len(path.components().len(), "callable path component count")?)?;
    for component in path.components() {
        let label = CanonicalLabel::text(component)
            .map_err(|_| CodecError::LengthOverflow("callable Text label"))?;
        writer.bytes(label.as_bytes())?;
    }
    Ok(())
}

fn decode_word<E>(
    reader: &mut Reader<'_>,
    kind: &'static str,
) -> Result<Word, CallablesCodecError<E>> {
    Word::try_from(reader.bytes(32, kind)?).map_err(|_| CallablesCodecError::InvalidWord { kind })
}

fn check_word_order<E>(
    previous: &mut Option<Word>,
    word: Word,
    kind: &'static str,
) -> Result<(), CallablesCodecError<E>> {
    if previous.is_some_and(|prior| prior.as_bytes() >= word.as_bytes()) {
        return Err(CallablesCodecError::NonCanonicalOrder { kind });
    }
    *previous = Some(word);
    Ok(())
}

fn check_array<T, E>(count: usize, kind: &'static str) -> Result<(), CodecError<E>> {
    Layout::array::<T>(count).map_err(|_| CodecError::LengthOverflow(kind))?;
    Ok(())
}

fn remaining_tail<E>(
    count: usize,
    minimum: usize,
    tail: usize,
    kind: &'static str,
) -> Result<usize, CodecError<E>> {
    checked_add(count.checked_mul(minimum).ok_or(CodecError::LengthOverflow(kind))?, tail, kind)
}

/// Both inputs contain only complete envelopes previously bounded by the first scan.
fn compare_wire_paths(mut left: &[u8], mut right: &[u8]) -> Ordering {
    while !left.is_empty() && !right.is_empty() {
        let left_len =
            6 + u32::from_le_bytes(left[2..6].try_into().expect("preflighted label header"))
                as usize;
        let right_len =
            6 + u32::from_le_bytes(right[2..6].try_into().expect("preflighted label header"))
                as usize;
        let ordering = left[..left_len].cmp(&right[..right_len]);
        if ordering != Ordering::Equal {
            return ordering;
        }
        left = &left[left_len..];
        right = &right[right_len..];
    }
    left.len().cmp(&right.len())
}

#[cfg(test)]
mod tests;
