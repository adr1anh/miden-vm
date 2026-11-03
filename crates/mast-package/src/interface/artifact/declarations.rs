//! Private canonical declaration-byte codec. Source-map iteration does not define wire order.

use alloc::{string::String, vec::Vec};
use core::{alloc::Layout, cmp::Ordering};

use miden_core::program::CanonicalLabel;

use super::{ArtifactError, EncodingPlan, LibraryId, borrow_blob, decode_word};
use crate::interface::{
    DeclarationSet, ProcedureDeclaration, PublicProcedurePath,
    serialization::{
        Budget, CodecError, Reader, Writer, check_label_layout, checked_add, compare_text_paths,
        count_with_tail, reserve, wire_len,
    },
};

pub(super) fn preflight<E>(
    declarations: &DeclarationSet,
    direct: &[LibraryId],
    closure: &[LibraryId],
    budget: &mut Budget,
) -> Result<usize, CodecError<E>> {
    let public_count = declarations.iter().len();
    wire_len(public_count, "public declaration count")?;
    wire_len(direct.len(), "direct requirement count")?;
    wire_len(closure.len(), "closure requirement count")?;
    let id_count = checked_add(direct.len(), closure.len(), "requirement count")?;
    budget.records(checked_add(public_count, id_count, "declaration record count")?)?;
    Layout::array::<&ProcedureDeclaration>(public_count)
        .map_err(|_| CodecError::LengthOverflow("public declarations"))?;
    let id_bytes = id_count
        .checked_mul(32)
        .ok_or(CodecError::LengthOverflow("requirement bytes"))?;
    // Public/direct/closure each have an explicit u32 count, including empty sets.
    let mut db_len = checked_add(12, id_bytes, "declaration bytes")?;
    for declaration in declarations.iter() {
        let components = declaration.path().components();
        wire_len(components.len(), "public path component count")?;
        budget.components(components.len())?;
        db_len = checked_add(db_len, 5, "public declaration bytes")?; // P count and ABI tag
        for text in components {
            budget.blob_bytes(text.len())?;
            check_label_layout(text.len())?;
            db_len = checked_add(
                db_len,
                checked_add(6, text.len(), "public Text label")?,
                "declaration bytes",
            )?;
        }
        if let Some(abi) = declaration.abi_metadata() {
            wire_len(abi.len(), "ABI metadata")?;
            budget.blob_bytes(abi.len())?;
            db_len = checked_add(
                db_len,
                checked_add(4, abi.len(), "ABI metadata")?,
                "declaration bytes",
            )?;
        }
    }
    wire_len(db_len, "declaration bytes")?;
    Ok(db_len)
}

pub(super) fn encode<E>(
    declarations: &DeclarationSet,
    direct: &[LibraryId],
    closure: &[LibraryId],
    plan: &EncodingPlan,
) -> Result<Vec<u8>, CodecError<E>> {
    let mut public = Vec::new();
    reserve(&mut public, declarations.iter().len(), "public declaration ordering")?;
    public.extend(declarations.iter());
    public.sort_unstable_by(|left, right| compare_paths(left, right));
    let mut writer = Writer::new(plan.db_len, &plan.budget)?;
    writer.u32(wire_len(public.len(), "public declaration count")?)?;
    for declaration in public {
        let components = declaration.path().components();
        writer.u32(wire_len(components.len(), "public path component count")?)?;
        for text in components {
            // The shared core encoder supplies the exact complete Text envelope. The preceding
            // preflight bounds its known infallible allocation and hash-layout representability.
            let label = CanonicalLabel::text(text)
                .map_err(|_| CodecError::LengthOverflow("public Text label"))?;
            writer.bytes(label.as_bytes())?;
        }
        match declaration.abi_metadata() {
            None => writer.u8(0)?,
            Some(abi) => {
                writer.u8(1)?;
                writer.u32(wire_len(abi.len(), "ABI metadata")?)?;
                writer.bytes(abi.as_bytes())?;
            },
        }
    }
    for ids in [direct, closure] {
        writer.u32(wire_len(ids.len(), "requirement count")?)?;
        for id in ids {
            writer.bytes(&id.as_word().as_bytes())?;
        }
    }
    writer.finish()
}

pub(super) struct DecodedDeclarations {
    pub(super) declarations: DeclarationSet,
    pub(super) direct: Vec<LibraryId>,
    pub(super) closure: Vec<LibraryId>,
}

pub(super) fn decode<E>(
    bytes: &[u8],
    budget: &mut Budget,
) -> Result<DecodedDeclarations, ArtifactError<E>> {
    let mut reader = Reader::new(bytes, budget)?;
    let public_count = reader.u32("public declaration count")?;
    // A nonempty Text path needs P's count, one seven-byte label, and an ABI discriminator.
    // Both requirement counts remain mandatory even when every set is empty.
    let public_count = count_with_tail::<ProcedureDeclaration, E>(
        &reader,
        public_count,
        12,
        8,
        "public declarations",
    )?;
    budget.records(public_count)?;
    let mut public = Vec::new();
    reserve(&mut public, public_count, "public declarations")?;
    let mut previous: Option<Vec<&[u8]>> = None;
    for index in 0..public_count {
        let component_count = reader.u32("public path component count")?;
        let remaining_public = (public_count - index - 1)
            .checked_mul(12)
            .ok_or(CodecError::LengthOverflow("public declarations"))?;
        let tail = checked_add(remaining_public, 9, "public declaration framing")?;
        let component_count = count_with_tail::<String, E>(
            &reader,
            component_count,
            7,
            tail,
            "public path components",
        )?;
        budget.components(component_count)?;
        let mut components = Vec::new();
        reserve(&mut components, component_count, "public path components")?;
        let mut envelopes = Vec::new();
        reserve(&mut envelopes, component_count, "public path ordering")?;
        for _ in 0..component_count {
            let envelope = reader.label_envelope(budget)?;
            // Reject TypedId and every other non-Text tag before invoking any core TypedId
            // validator. The core decoder remains the single authority for label framing/UTF-8.
            if envelope[1] != 0 {
                return Err(ArtifactError::NonTextPublicLabel { tag: envelope[1] });
            }
            let label = CanonicalLabel::from_bytes(envelope).map_err(CodecError::InvalidLabel)?;
            let text = core::str::from_utf8(&label.as_bytes()[6..])
                .expect("the core Text decoder validated these exact UTF-8 bytes");
            // label_envelope checked the complete envelope's layout and charged this payload.
            components.push(String::from(text));
            envelopes.push(envelope);
        }
        let path = PublicProcedurePath::from_semantic_components(components)?;
        if previous.as_ref().is_some_and(|previous| previous >= &envelopes) {
            return Err(ArtifactError::NonCanonicalPublicPathOrder);
        }
        previous = Some(envelopes);
        let abi_metadata = match reader.u8("ABI presence discriminator")? {
            0 => None,
            1 => {
                let bytes = borrow_blob(&mut reader, "ABI metadata")?;
                budget.blob_bytes(bytes.len())?;
                let text = core::str::from_utf8(bytes).map_err(ArtifactError::InvalidAbiUtf8)?;
                Some(String::from(text))
            },
            tag => return Err(ArtifactError::InvalidAbiDiscriminator { tag }),
        };
        public.push(ProcedureDeclaration::new(path, abi_metadata));
    }
    let direct = decode_ids(&mut reader, budget, "direct", 4)?;
    let closure = decode_ids(&mut reader, budget, "closure", 0)?;
    reader.finish("declaration bytes")?;
    // The native map clones paths and allocates nodes infallibly. All record/component/string
    // counts and layouts above are finite and bounded; this is not an RSS/OOM guarantee.
    let declarations = DeclarationSet::new(public)?;
    Ok(DecodedDeclarations { declarations, direct, closure })
}

fn decode_ids<E>(
    reader: &mut Reader<'_>,
    budget: &mut Budget,
    kind: &'static str,
    tail: usize,
) -> Result<Vec<LibraryId>, ArtifactError<E>> {
    let count = reader.u32("requirement count")?;
    let count = count_with_tail::<LibraryId, E>(reader, count, 32, tail, "requirements")?;
    budget.records(count)?;
    let mut ids: Vec<LibraryId> = Vec::new();
    reserve(&mut ids, count, "requirements")?;
    for _ in 0..count {
        let id = LibraryId::new(decode_word(reader, "requirement LibraryId")?);
        if let Some(previous) = ids.last() {
            match previous.as_word().as_bytes().cmp(&id.as_word().as_bytes()) {
                Ordering::Less => (),
                Ordering::Equal => return Err(ArtifactError::DuplicateLibraryId { kind, id }),
                Ordering::Greater => {
                    return Err(ArtifactError::NonCanonicalLibraryIdOrder { kind });
                },
            }
        }
        ids.push(id);
    }
    Ok(ids)
}

fn compare_paths(left: &ProcedureDeclaration, right: &ProcedureDeclaration) -> Ordering {
    compare_text_paths(left.path().components(), right.path().components())
}
