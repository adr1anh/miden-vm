//! Exact keyed code/source occurrences retained independently from public export aliases.

use alloc::{boxed::Box, vec::Vec};
use core::convert::Infallible;

use miden_core::{
    Word,
    mast::{MastForest, MastNodeId},
    program::ProcedureKey,
    serde::ByteWriter,
};

use super::{FORMAT_NAMING_LIMITS, ManifestValidationError, Package, PackageSymbols};
use crate::{
    debug_info::{DebugSourceNodeId, PackageDebugInfo},
    interface::serialization::{Budget, CodecError, CodecLimits, Reader, checked_add, reserve},
};

const MIN_ROW_BYTES: usize = 37;
const COUNT_BYTES: usize = 4;

/// An exact retained occurrence of the code selected for a callable key.
///
/// This is a code/source supply hint, not an authenticated execution binding. The execution caller
/// still supplies the expected target and the host must authenticate its environment opening.
/// An explicit `External(D)` procedure root may be recorded, but does not supply executable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageProcedureOccurrence {
    key: ProcedureKey,
    exec_node: MastNodeId,
    source_node: Option<DebugSourceNodeId>,
}

impl PackageProcedureOccurrence {
    pub const fn new(
        key: ProcedureKey,
        exec_node: MastNodeId,
        source_node: Option<DebugSourceNodeId>,
    ) -> Self {
        Self { key, exec_node, source_node }
    }

    pub const fn key(&self) -> ProcedureKey {
        self.key
    }

    pub const fn exec_node(&self) -> MastNodeId {
        self.exec_node
    }

    pub const fn source_node(&self) -> Option<DebugSourceNodeId> {
        self.source_node
    }

    fn wire_len(&self) -> usize {
        MIN_ROW_BYTES + if self.source_node.is_some() { 4 } else { 0 }
    }
}

/// Invalid exact code/source transport or a mismatch with the package's checked symbols.
#[derive(Debug, thiserror::Error)]
pub enum PackageProcedureOccurrencesError {
    #[error(transparent)]
    Codec(#[from] CodecError<Infallible>),
    #[error("invalid canonical procedure occurrence key")]
    InvalidKey,
    #[error("procedure occurrences must have strictly increasing canonical key bytes: {key:?}")]
    UnsortedOrDuplicateKey { key: ProcedureKey },
    #[error("invalid procedure occurrence source tag {tag}")]
    InvalidSourceTag { tag: u8 },
    #[error("procedure occurrence {key:?} references missing or non-root execution node {node:?}")]
    InvalidExecutionNode { key: ProcedureKey, node: MastNodeId },
    #[error("procedure occurrence key {key:?} is not declared by the package symbols")]
    UnknownKey { key: ProcedureKey },
    #[error("procedure occurrence key {key:?} has no selected implementation")]
    MissingImplementation { key: ProcedureKey },
    #[error(
        "procedure occurrence {key:?} execution node {node:?} differs from its selected implementation"
    )]
    ImplementationMismatch { key: ProcedureKey, node: MastNodeId },
    #[error("package symbols do not match the package: {0}")]
    InvalidSymbols(#[source] Box<ManifestValidationError>),
    #[error(transparent)]
    DebugInfo(#[from] super::PackageDebugInfoError),
}

impl Package {
    /// Attaches exact compiled occurrences using the package format's representability bounds.
    ///
    /// Rows must be strictly sorted by lexicographic canonical key bytes
    /// (`key.as_word().as_bytes()`); duplicates are rejected. Empty tables and declaration-only
    /// packages are permitted. No row is inferred from an implementation digest. Source
    /// references may be attached before the optional debug section; whenever that section is
    /// decoded its exact execution mapping is checked.
    pub fn with_procedure_occurrences(
        self,
        occurrences: impl IntoIterator<Item = PackageProcedureOccurrence>,
        symbols: &PackageSymbols,
    ) -> Result<Self, PackageProcedureOccurrencesError> {
        self.with_procedure_occurrences_with_limits(occurrences, symbols, FORMAT_NAMING_LIMITS)
    }

    /// Attaches occurrences with explicit finite row and complete wire-byte limits.
    ///
    /// Each next row is charged before allocating or retaining it; an iterator's size hint does not
    /// control allocation. Components and blob bytes are not used by this scalar-only transport.
    pub fn with_procedure_occurrences_with_limits(
        mut self,
        occurrences: impl IntoIterator<Item = PackageProcedureOccurrence>,
        symbols: &PackageSymbols,
        limits: CodecLimits,
    ) -> Result<Self, PackageProcedureOccurrencesError> {
        self.check_naming(symbols)
            .map_err(|error| PackageProcedureOccurrencesError::InvalidSymbols(Box::new(error)))?;
        let mut budget = Budget::new(limits);
        budget.wire_bytes(COUNT_BYTES)?;
        let mut byte_len = COUNT_BYTES;
        let mut rows = Vec::new();
        for occurrence in occurrences {
            budget.records(1)?;
            byte_len = checked_add(byte_len, occurrence.wire_len(), "procedure occurrence bytes")?;
            budget.wire_bytes(byte_len)?;
            check_next(&rows, &occurrence)?;
            validate_node(&occurrence, &self.mast)?;
            validate_symbols(&occurrence, &self.mast, symbols)?;
            reserve(&mut rows, 1, "procedure occurrences")?;
            rows.push(occurrence);
        }
        self.procedure_occurrences = rows;
        // Optional debug sections may be attached after this construction step. Existing sections
        // are checked now; normal readers and debug_info() also validate the final source graph.
        if self.sections.iter().any(|section| section.id == super::SectionId::DEBUG_INFO) {
            self.debug_info()?;
        }
        Ok(self)
    }

    /// Returns exact code/source supply hints, sorted by canonical key bytes.
    pub fn procedure_occurrences(&self) -> &[PackageProcedureOccurrence] {
        &self.procedure_occurrences
    }

    /// Looks up an exact supplied occurrence without inferring a key or source occurrence from D.
    pub fn procedure_occurrence(&self, key: ProcedureKey) -> Option<&PackageProcedureOccurrence> {
        let bytes = key.as_word().as_bytes();
        self.procedure_occurrences
            .binary_search_by(|occurrence| occurrence.key.as_word().as_bytes().cmp(&bytes))
            .ok()
            .map(|index| &self.procedure_occurrences[index])
    }

    /// Checks supplied occurrence rows against the package's exact checked symbol inventory.
    ///
    /// Success does not authenticate an environment or authorize execution. Optional debug metadata
    /// is validated separately by debug_info(), preserving trusted-reader deferred validation.
    pub fn check_procedure_occurrences(
        &self,
        symbols: &PackageSymbols,
    ) -> Result<(), PackageProcedureOccurrencesError> {
        self.check_naming(symbols)
            .map_err(|error| PackageProcedureOccurrencesError::InvalidSymbols(Box::new(error)))
    }

    // Package-level profile admission shares its caller's byte/record budget with required
    // occurrence transport. Charge this scalar table before naming preflight or profile callbacks.
    pub(super) fn symbols_limits_after_occurrences(
        &self,
        limits: CodecLimits,
    ) -> Result<CodecLimits, PackageProcedureOccurrencesError> {
        let budget = &mut Budget::new(limits);
        budget.records(self.procedure_occurrences.len())?;
        let byte_len = payload_len(&self.procedure_occurrences)?;
        budget.wire_bytes(byte_len)?;
        let byte_len = u32::try_from(byte_len)
            .map_err(|_| CodecError::LengthOverflow("procedure occurrence bytes"))?;
        let records = u32::try_from(self.procedure_occurrences.len())
            .map_err(|_| CodecError::LengthOverflow("procedure occurrence records"))?;
        Ok(CodecLimits::new(
            limits.max_bytes() - byte_len,
            limits.max_records() - records,
            limits.max_components(),
            limits.max_blob_bytes(),
        ))
    }

    pub(super) fn validate_procedure_occurrences(
        &self,
        symbols: &PackageSymbols,
        limits: CodecLimits,
    ) -> Result<(), PackageProcedureOccurrencesError> {
        let mut budget = Budget::new(limits);
        budget.records(self.procedure_occurrences.len())?;
        budget.wire_bytes(payload_len(&self.procedure_occurrences)?)?;
        let mut previous = None;
        for occurrence in &self.procedure_occurrences {
            check_order(previous, occurrence)?;
            validate_node(occurrence, &self.mast)?;
            validate_symbols(occurrence, &self.mast, symbols)?;
            previous = Some(occurrence.key);
        }
        Ok(())
    }

    pub(super) fn validate_occurrence_sources(
        &self,
        debug_info: &PackageDebugInfo,
    ) -> Result<(), super::PackageDebugInfoError> {
        for occurrence in &self.procedure_occurrences {
            let Some(source_id) = occurrence.source_node else {
                continue;
            };
            let Some(source) = debug_info.source_node(source_id) else {
                return Err(super::PackageDebugInfoError::InvalidReference {
                    message: format!(
                        "procedure occurrence {:?} references missing source node {source_id:?}",
                        occurrence.key,
                    ),
                });
            };
            if source.exec_node != occurrence.exec_node {
                return Err(super::PackageDebugInfoError::InvalidReference {
                    message: format!(
                        "procedure occurrence {:?} source node {source_id:?} maps to {:?}, expected {:?}",
                        occurrence.key, source.exec_node, occurrence.exec_node,
                    ),
                });
            }
        }
        Ok(())
    }

    pub(super) fn strip_occurrence_sources(&mut self) {
        for occurrence in &mut self.procedure_occurrences {
            occurrence.source_node = None;
        }
    }
}

fn validate_node(
    occurrence: &PackageProcedureOccurrence,
    mast: &MastForest,
) -> Result<(), PackageProcedureOccurrencesError> {
    if !mast.is_procedure_root(occurrence.exec_node) {
        return Err(PackageProcedureOccurrencesError::InvalidExecutionNode {
            key: occurrence.key,
            node: occurrence.exec_node,
        });
    }
    Ok(())
}

fn validate_symbols(
    occurrence: &PackageProcedureOccurrence,
    mast: &MastForest,
    symbols: &PackageSymbols,
) -> Result<(), PackageProcedureOccurrencesError> {
    if symbols.callables().binding(occurrence.key).is_none() {
        return Err(PackageProcedureOccurrencesError::UnknownKey { key: occurrence.key });
    }
    let selected = symbols
        .callables()
        .selected_implementation(occurrence.key)
        .ok_or(PackageProcedureOccurrencesError::MissingImplementation { key: occurrence.key })?;
    if !mast.is_procedure_root_with_exact_digest(occurrence.exec_node, selected.into_word()) {
        return Err(PackageProcedureOccurrencesError::ImplementationMismatch {
            key: occurrence.key,
            node: occurrence.exec_node,
        });
    }
    Ok(())
}

fn check_next(
    rows: &[PackageProcedureOccurrence],
    occurrence: &PackageProcedureOccurrence,
) -> Result<(), PackageProcedureOccurrencesError> {
    check_order(rows.last().map(|row| row.key), occurrence)
}

fn check_order(
    previous: Option<ProcedureKey>,
    occurrence: &PackageProcedureOccurrence,
) -> Result<(), PackageProcedureOccurrencesError> {
    if previous.is_some_and(|previous| {
        previous.as_word().as_bytes() >= occurrence.key.as_word().as_bytes()
    }) {
        return Err(PackageProcedureOccurrencesError::UnsortedOrDuplicateKey {
            key: occurrence.key,
        });
    }
    Ok(())
}

pub(super) fn payload_len(
    rows: &[PackageProcedureOccurrence],
) -> Result<usize, PackageProcedureOccurrencesError> {
    rows.iter().try_fold(COUNT_BYTES, |bytes, row| {
        Ok(checked_add(bytes, row.wire_len(), "procedure occurrence bytes")?)
    })
}

pub(super) fn write_payload<W: ByteWriter>(rows: &[PackageProcedureOccurrence], target: &mut W) {
    target.write_u32(u32::try_from(rows.len()).expect("preflighted occurrence count"));
    for row in rows {
        target.write_bytes(&row.key.as_word().as_bytes());
        target.write_u32(row.exec_node.into());
        match row.source_node {
            None => target.write_u8(0),
            Some(source) => {
                target.write_u8(1);
                target.write_u32(source.into());
            },
        }
    }
}

/// The code-supply identity excludes optional source IDs, so stripping debug data preserves it.
pub(super) fn write_code_supply<W: ByteWriter>(
    rows: &[PackageProcedureOccurrence],
    target: &mut W,
) {
    target.write_u32(u32::try_from(rows.len()).expect("preflighted occurrence count"));
    for row in rows {
        target.write_bytes(&row.key.as_word().as_bytes());
        target.write_u32(row.exec_node.into());
    }
}

pub(super) fn read_payload(
    bytes: &[u8],
    mast: &MastForest,
    limits: CodecLimits,
) -> Result<Vec<PackageProcedureOccurrence>, PackageProcedureOccurrencesError> {
    let mut budget = Budget::new(limits);
    let mut reader = Reader::new(bytes, &budget)?;
    let count = reader.u32("procedure occurrence count")?;
    budget.records(count as usize)?;
    let count = reader.count::<PackageProcedureOccurrence, Infallible>(
        count,
        MIN_ROW_BYTES,
        "procedure occurrences",
    )?;
    // Validate the complete borrowed payload, including strict order and exact roots, before the
    // first collection allocation. A hostile count cannot reserve memory ahead of its input.
    let mut previous = None;
    for _ in 0..count {
        let occurrence = read_row(&mut reader)?;
        check_order(previous, &occurrence)?;
        validate_node(&occurrence, mast)?;
        previous = Some(occurrence.key);
    }
    reader.finish("procedure occurrences")?;

    let mut rows = Vec::new();
    reserve(&mut rows, count, "procedure occurrences")?;
    let mut reader = Reader::new(bytes, &budget)?;
    reader.u32::<Infallible>("procedure occurrence count")?;
    for _ in 0..count {
        rows.push(read_row(&mut reader)?);
    }
    Ok(rows)
}

fn read_row(
    reader: &mut Reader<'_>,
) -> Result<PackageProcedureOccurrence, PackageProcedureOccurrencesError> {
    let key = Word::try_from(reader.bytes::<Infallible>(32, "procedure occurrence key")?)
        .map(ProcedureKey::new)
        .map_err(|_| PackageProcedureOccurrencesError::InvalidKey)?;
    let exec_node =
        MastNodeId::new_unchecked(reader.u32::<Infallible>("occurrence execution node")?);
    let source_node = match reader.u8::<Infallible>("procedure occurrence source tag")? {
        0 => None,
        1 => Some(DebugSourceNodeId::from(reader.u32::<Infallible>("occurrence source node")?)),
        tag => return Err(PackageProcedureOccurrencesError::InvalidSourceTag { tag }),
    };
    Ok(PackageProcedureOccurrence::new(key, exec_node, source_node))
}

#[cfg(test)]
mod tests;
