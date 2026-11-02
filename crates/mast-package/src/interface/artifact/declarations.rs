//! Private canonical declaration-byte encoding. Source-map iteration does not define wire order.

use alloc::vec::Vec;
use core::{alloc::Layout, cmp::Ordering};

use miden_core::program::CanonicalLabel;

use super::{EncodingPlan, LibraryId};
use crate::interface::{
    DeclarationSet, ProcedureDeclaration,
    serialization::{
        Budget, CodecError, Writer, check_label_layout, checked_add, reserve, wire_len,
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

fn compare_paths(left: &ProcedureDeclaration, right: &ProcedureDeclaration) -> Ordering {
    let left = left.path().components();
    let right = right.path().components();
    for (left, right) in left.iter().zip(right) {
        // All envelopes start [1, Text=0]. Compare their little-endian payload lengths, then
        // exact payload bytes. This is full-envelope order, not String or numeric-length order.
        let ordering = (left.len() as u32)
            .to_le_bytes()
            .cmp(&(right.len() as u32).to_le_bytes())
            .then_with(|| left.as_bytes().cmp(right.as_bytes()));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}
