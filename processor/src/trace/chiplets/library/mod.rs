//! Borrowed native witness writer for the future packed Library prefix.
//!
//! This module does not activate Library or capture live execution. Its input is the immutable,
//! completed native session; native completion does not establish Core-row or proof completion.
//! The caller admits and allocates the combined trace and supplies this writer's exact prefix.

use core::borrow::BorrowMut;

use miden_air_definitions::vm::{
    LibraryCols,
    trace::{
        CHIPLETS_CLK_COL, CHIPLETS_WIDTH,
        chiplets::library::{
            EMPTY_LIST, ENV, LIBRARY_COL_RANGE, LIST_CONTINUE, LIST_START, MAST, MERKLE,
        },
    },
};
use miden_core::{
    chiplets::hasher::{
        BLOCK_HI_RANGE, BLOCK_LO_RANGE, CV_RANGE, DIGEST_RANGE, STATE_WIDTH, compress_state,
    },
    crypto::hash::Eidos,
    program::{EnvNode, EnvironmentRoot, Namespace, domain},
};

use crate::{
    ExecutionError, Felt, ONE, Word, ZERO,
    environment::{OpeningId, OpeningOccurrence, ResolutionSession, SessionBinding},
    trace::limits::MAX_TRACE_LEN,
};

#[cfg(test)]
mod tests;

/// A checked, allocation-free view of a completed session, without a second row/request planner.
pub(crate) struct LibraryTrace<'a> {
    session: &'a ResolutionSession,
    prefix_len: usize,
    prefix_cells: usize,
}

impl<'a> LibraryTrace<'a> {
    pub(crate) fn new(session: &'a ResolutionSession) -> Result<Self, ExecutionError> {
        let counters = session.finalize().map_err(ExecutionError::EnvironmentSession)?;
        let ledger = session.ledger();
        let occurrences = ledger.occurrences();
        let totals = ledger.counters();
        let prefix_len = checked_prefix_len(totals.library_rows)?;
        let prefix_cells = prefix_len.checked_mul(CHIPLETS_WIDTH).ok_or_else(length_error)?;
        core::alloc::Layout::array::<Felt>(prefix_cells).map_err(|_| length_error())?;
        if occurrences.is_empty()
            || occurrences.len() != totals.occurrences
            || totals.root_seed_count() != 1
            || ledger.root().map(OpeningId::index) != Some(0)
            || ledger.expected_root() != session.descriptor().environment_root()
            || occurrences[0].commitment() != session.descriptor().environment_root()
            || occurrences[0].namespace() != Namespace::initial()
            || counters.cached_keys != session.bindings().len()
            || counters.reserved_requests != 0
            || counters.committed_requests > MAX_TRACE_LEN
            || totals.compression_requests > MAX_TRACE_LEN
        {
            return Err(inconsistent());
        }

        let mut edges = 0usize;
        let mut list_children = 0usize;
        let mut bindings = session.bindings().iter().peekable();
        let mut previous_binding = None;
        let mut requests = 0usize;
        for (index, occurrence) in occurrences.iter().enumerate() {
            validate_occurrence(occurrences, index, occurrence, &mut edges)?;
            if let EnvNode::List(children) = occurrence.node() {
                list_children =
                    list_children.checked_add(children.len()).ok_or_else(length_error)?;
            }
            if let EnvNode::Mast { label, implementation } = occurrence.node() {
                let binding = bindings.next().ok_or_else(inconsistent)?;
                let opening = binding.opening_id().index();
                let counts = binding.counts();
                if opening != index
                    || previous_binding.is_some_and(|previous| previous >= opening)
                    || binding.namespace() != occurrence.namespace()
                    || binding.implementation_root() != *implementation
                    || binding.procedure_key() != occurrence.namespace().procedure_key(*label)
                    || counts.normal > MAX_TRACE_LEN
                    || counts.syscall > MAX_TRACE_LEN
                    || (counts.syscall != 0 && binding.namespace() != Namespace::initial())
                {
                    return Err(inconsistent());
                }
                previous_binding = Some(opening);
                requests = requests
                    .checked_add(counts.normal)
                    .and_then(|sum| sum.checked_add(counts.syscall))
                    .ok_or_else(length_error)?;
            } else if bindings.peek().is_some_and(|binding| binding.opening_id().index() <= index) {
                return Err(inconsistent());
            }
        }
        if bindings.next().is_some()
            || requests != counters.committed_requests
            || edges != totals.selected_edge_count()
            || list_children != totals.total_list_children
            || session.bindings().first().map(|binding| binding.procedure_key())
                != Some(session.descriptor().entry_key())
        {
            return Err(inconsistent());
        }
        Ok(Self { session, prefix_len, prefix_cells })
    }

    pub(crate) fn prefix_len(&self) -> usize {
        self.prefix_len
    }

    pub(crate) fn prefix_cells(&self) -> usize {
        self.prefix_cells
    }

    /// Streams every raw packed compression request before the caller allocates the prefix.
    ///
    /// The traversal uses only one stack pair and never stores rows or requests. On callback
    /// failure the caller must discard its partially updated state; no rollback is promised.
    /// The callback may merge requests into the existing Hasher interner, but must not append
    /// Controller rows. The authoritative session is never changed.
    pub(crate) fn visit_compression_requests(
        &self,
        request: impl FnMut(&[Felt; STATE_WIDTH]) -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        self.walk(|_, _| Ok(()), request)
    }

    /// Writes an exact caller-allocated prefix without registering compression requests again.
    ///
    /// Combined height, PCS and proving-memory admission remain the caller's responsibility before
    /// allocation. A failed write leaves a disposable, partially written destination; no rollback
    /// is promised. The authoritative session is never changed.
    pub(crate) fn write(&self, prefix: &mut [Felt]) -> Result<(), ExecutionError> {
        if prefix.len() != self.prefix_cells {
            return Err(ExecutionError::Internal(
                "Library destination must be the exact prefix size",
            ));
        }
        prefix.fill(ZERO);
        for (index, row) in prefix.as_chunks_mut::<CHIPLETS_WIDTH>().0.iter_mut().enumerate() {
            row[0] = ONE;
            row[CHIPLETS_CLK_COL] = bounded_felt(index.checked_add(1).ok_or_else(length_error)?)?;
        }
        self.walk(
            |offset, pair| {
                let start = offset.checked_mul(CHIPLETS_WIDTH).ok_or_else(length_error)?;
                let end = start.checked_add(pair.len()).ok_or_else(length_error)?;
                let rows = prefix.get_mut(start..end).ok_or_else(inconsistent)?;
                for (destination, source) in rows
                    .as_chunks_mut::<CHIPLETS_WIDTH>()
                    .0
                    .iter_mut()
                    .zip(pair.as_chunks::<CHIPLETS_WIDTH>().0)
                {
                    destination[LIBRARY_COL_RANGE].copy_from_slice(&source[LIBRARY_COL_RANGE]);
                }
                Ok(())
            },
            |_| Ok(()),
        )?;
        // The initialized zero overlay is PAD on every remaining complete pair, including at
        // least one mandatory pair. Its final B row has global AEAD phase seven.
        Ok(())
    }

    /// The sole node/hash/row traversal for request admission and final materialization.
    fn walk(
        &self,
        mut emit: impl FnMut(usize, &[Felt; 2 * CHIPLETS_WIDTH]) -> Result<(), ExecutionError>,
        mut request: impl FnMut(&[Felt; STATE_WIDTH]) -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        let totals = self.session.ledger().counters();
        let mut requests = Requests {
            callback: &mut request,
            count: 0,
            limit: totals.compression_requests,
        };
        let mut cursor = 0usize;
        let mut bindings = self.session.bindings().iter();
        for occurrence in self.session.ledger().occurrences() {
            let pairs = match occurrence.node() {
                EnvNode::List(children) => children.len().div_ceil(2).max(1),
                _ => 1,
            };
            let end = cursor
                .checked_add(pairs.checked_mul(2).ok_or_else(length_error)?)
                .ok_or_else(length_error)?;
            if end > totals.library_rows {
                return Err(inconsistent());
            }
            match occurrence.node() {
                EnvNode::List(children) => visit_list(
                    children,
                    occurrence.selected_children(),
                    occurrence.namespace(),
                    occurrence.depth(),
                    occurrence.commitment(),
                    &mut requests,
                    &mut |offset, pair| {
                        emit(cursor.checked_add(offset).ok_or_else(length_error)?, pair)
                    },
                )?,
                _ => visit_object(occurrence, &mut bindings, &mut requests, &mut |pair| {
                    emit(cursor, pair)
                })?,
            }
            cursor = end;
        }
        if cursor != totals.library_rows
            || requests.count != totals.compression_requests
            || bindings.next().is_some()
        {
            return Err(inconsistent());
        }
        Ok(())
    }
}

fn validate_occurrence(
    occurrences: &[OpeningOccurrence],
    index: usize,
    occurrence: &OpeningOccurrence,
    edges: &mut usize,
) -> Result<(), ExecutionError> {
    let slots = occurrence.selected_children();
    let child_count = match occurrence.node() {
        EnvNode::Env { .. } => 1,
        EnvNode::Merkle { .. } => 2,
        EnvNode::List(children) => children.len(),
        EnvNode::Mast { .. } => 0,
        EnvNode::Data { .. } => return Err(inconsistent()),
    };
    if slots.len() != child_count || occurrence.depth() > MAX_TRACE_LEN {
        return Err(inconsistent());
    }
    if index == 0 {
        if occurrence.parent().is_some() || occurrence.depth() != 0 {
            return Err(inconsistent());
        }
    } else {
        let parent = occurrence.parent().ok_or_else(inconsistent)?;
        let parent_index = parent.opening().index();
        if parent_index >= index
            || occurrences[parent_index]
                .selected_children()
                .get(parent.child_slot())
                .and_then(|id| *id)
                .map(OpeningId::index)
                != Some(index)
        {
            return Err(inconsistent());
        }
    }
    let namespace = match occurrence.node() {
        EnvNode::Env { label, .. } => occurrence.namespace().child(*label),
        _ => occurrence.namespace(),
    };
    let mut selected = 0;
    for (slot, child) in slots.iter().enumerate() {
        let Some(child) = child else { continue };
        let child_index = child.index();
        let child = occurrences.get(child_index).ok_or_else(inconsistent)?;
        let parent = child.parent().ok_or_else(inconsistent)?;
        let commitment = match occurrence.node() {
            EnvNode::Env { child, .. } => *child,
            EnvNode::Merkle { left, right } => {
                if slot == 0 {
                    *left
                } else {
                    *right
                }
            },
            EnvNode::List(children) => children[slot],
            _ => return Err(inconsistent()),
        };
        if child_index <= index
            || parent.opening().index() != index
            || parent.child_slot() != slot
            || child.commitment() != commitment
            || child.namespace() != namespace
            || child.depth() != occurrence.depth().checked_add(1).ok_or_else(length_error)?
        {
            return Err(inconsistent());
        }
        selected += 1;
        *edges = edges.checked_add(1).ok_or_else(length_error)?;
    }
    // Every retained nonterminal opening lies on a path to at least one retained Mast.
    if child_count != 0 && selected == 0 {
        return Err(inconsistent());
    }
    Ok(())
}

fn visit_object<'a>(
    occurrence: &OpeningOccurrence,
    bindings: &mut impl Iterator<Item = &'a SessionBinding>,
    requests: &mut Requests<'_, impl FnMut(&[Felt; STATE_WIDTH]) -> Result<(), ExecutionError>>,
    emit: &mut impl FnMut(&[Felt; 2 * CHIPLETS_WIDTH]) -> Result<(), ExecutionError>,
) -> Result<(), ExecutionError> {
    let (kind, x, y, frame) = match occurrence.node() {
        EnvNode::Env { label, child } => (
            ENV,
            label.into_word(),
            child.into_word(),
            Eidos::init_chaining_word(domain::ENV_ENVIRONMENT, 8),
        ),
        EnvNode::Merkle { left, right } => (
            MERKLE,
            left.into_word(),
            right.into_word(),
            Eidos::init_chaining_word(domain::ENV_MERKLE, 8),
        ),
        EnvNode::Mast { label, implementation } => (
            MAST,
            label.into_word(),
            implementation.into_word(),
            Eidos::init_chaining_word(domain::ENV_MAST, 8),
        ),
        _ => return Err(inconsistent()),
    };
    if requests.compress(x, y, frame)? != occurrence.commitment().into_word() {
        return Err(inconsistent());
    }
    let mut rows = [ZERO; 2 * CHIPLETS_WIDTH];
    let (a, b) = pair(&mut rows, kind, occurrence.namespace(), occurrence.depth())?;
    a.x = x.into_elements();
    a.y = y.into_elements();
    a.z = occurrence.commitment().into_word().into_elements();
    if kind == MERKLE {
        b.x = a.x;
        b.y = a.y;
        b.b = selection(occurrence.selected_children(), 0);
    } else {
        b.x = a.w;
        b.y = a.x;
        b.w = a.y;
        b.z = match occurrence.node() {
            EnvNode::Env { label, .. } => {
                let output = occurrence.namespace().child(*label).into_word();
                if requests.compress(
                    occurrence.namespace().into_word(),
                    x,
                    Eidos::init_chaining_word(domain::ENV_NAMESPACE, 8),
                )? != output
                {
                    return Err(inconsistent());
                }
                output.into_elements()
            },
            EnvNode::Mast { .. } => {
                let binding = bindings.next().ok_or_else(inconsistent)?;
                let output = binding.procedure_key().into_word();
                if requests.compress(
                    occurrence.namespace().into_word(),
                    x,
                    Eidos::init_chaining_word(domain::ENV_PROCEDURE, 8),
                )? != output
                {
                    return Err(inconsistent());
                }
                b.a = bounded_felt(binding.counts().normal)?;
                b.b = bounded_felt(binding.counts().syscall)?;
                output.into_elements()
            },
            _ => return Err(inconsistent()),
        };
    }
    emit(&rows)
}

fn visit_list(
    children: &[EnvironmentRoot],
    selected: &[Option<OpeningId>],
    namespace: Namespace,
    depth: usize,
    commitment: EnvironmentRoot,
    requests: &mut Requests<'_, impl FnMut(&[Felt; STATE_WIDTH]) -> Result<(), ExecutionError>>,
    emit: &mut impl FnMut(usize, &[Felt; 2 * CHIPLETS_WIDTH]) -> Result<(), ExecutionError>,
) -> Result<(), ExecutionError> {
    let felt_len = children.len().checked_mul(4).ok_or_else(length_error)?;
    let felt_len = u32::try_from(felt_len).map_err(|_| length_error())?;
    let pairs = children.len().div_ceil(2).max(1);
    let mut cv = Eidos::init_chaining_word(domain::ENV_LIST, felt_len);
    for block in 0..pairs {
        let slot = block.checked_mul(2).ok_or_else(length_error)?;
        let x = children.get(slot).map_or(Word::default(), |child| child.into_word());
        let y = children.get(slot + 1).map_or(Word::default(), |child| child.into_word());
        let output = requests.compress(x, y, cv)?;
        let reverse = pairs - 1 - block;
        let kind = if children.is_empty() {
            EMPTY_LIST
        } else if reverse == 0 {
            LIST_START
        } else {
            LIST_CONTINUE
        };
        let mut rows = [ZERO; 2 * CHIPLETS_WIDTH];
        let (a, b) = pair(&mut rows, kind, namespace, depth)?;
        a.x = x.into_elements();
        a.y = y.into_elements();
        a.z = output.into_elements();
        a.a = if children.is_empty() {
            ZERO
        } else {
            let length = (reverse + 1)
                .checked_mul(8)
                .and_then(|length| length.checked_sub(4 * (children.len() % 2)))
                .ok_or_else(length_error)?;
            Felt::from_u32(u32::try_from(length).map_err(|_| length_error())?)
        };
        a.b = if reverse == 0 {
            Felt::from_u8((children.len() % 2) as u8)
        } else {
            ZERO
        };
        b.x = a.x;
        b.y = a.y;
        b.z = cv.into_elements();
        b.a = a.a;
        b.b = selection(selected, slot);
        let destination = reverse.checked_mul(2).ok_or_else(length_error)?;
        emit(destination, &rows)?;
        cv = output;
    }
    if cv != commitment.into_word() {
        return Err(inconsistent());
    }
    Ok(())
}

fn pair(
    rows: &mut [Felt],
    kind: [Felt; 3],
    namespace: Namespace,
    depth: usize,
) -> Result<(&mut LibraryCols<Felt>, &mut LibraryCols<Felt>), ExecutionError> {
    let depth = bounded_felt(depth)?;
    let (a, b) = rows.split_at_mut(CHIPLETS_WIDTH);
    let a: &mut LibraryCols<Felt> = a[LIBRARY_COL_RANGE].borrow_mut();
    let b: &mut LibraryCols<Felt> = b[LIBRARY_COL_RANGE].borrow_mut();
    for row in [&mut *a, &mut *b] {
        row.k = kind;
        row.w = namespace.into_word().into_elements();
        row.d = depth;
    }
    Ok((a, b))
}

fn selection(selected: &[Option<OpeningId>], slot: usize) -> Felt {
    let lo = selected.get(slot).is_some_and(Option::is_some);
    let hi = selected.get(slot + 1).is_some_and(Option::is_some);
    Felt::from_u8(u8::from(lo) + 2 * u8::from(hi))
}

struct Requests<'a, F> {
    callback: &'a mut F,
    count: usize,
    limit: usize,
}

impl<F: FnMut(&[Felt; STATE_WIDTH]) -> Result<(), ExecutionError>> Requests<'_, F> {
    fn compress(&mut self, x: Word, y: Word, cv: Word) -> Result<Word, ExecutionError> {
        let count = self.count.checked_add(1).ok_or_else(length_error)?;
        if count > self.limit {
            return Err(inconsistent());
        }
        let mut state = [ZERO; STATE_WIDTH];
        state[BLOCK_LO_RANGE].copy_from_slice(x.as_slice());
        state[BLOCK_HI_RANGE].copy_from_slice(y.as_slice());
        state[CV_RANGE].copy_from_slice(cv.as_slice());
        (self.callback)(&state)?;
        self.count = count;
        compress_state(&mut state);
        Ok(Word::new(core::array::from_fn(|i| state[DIGEST_RANGE.start + i])))
    }
}

fn checked_prefix_len(active_rows: usize) -> Result<usize, ExecutionError> {
    if !active_rows.is_multiple_of(2) {
        return Err(inconsistent());
    }
    let prefix = active_rows
        .checked_add(2)
        .and_then(|rows| rows.checked_add(7))
        .map(|rows| rows / 8)
        .and_then(|blocks| blocks.checked_mul(8))
        .ok_or_else(length_error)?;
    if prefix > MAX_TRACE_LEN {
        return Err(length_error());
    }
    Ok(prefix)
}

fn bounded_felt(value: usize) -> Result<Felt, ExecutionError> {
    if value > MAX_TRACE_LEN {
        return Err(length_error());
    }
    Ok(Felt::from_u32(u32::try_from(value).map_err(|_| length_error())?))
}

fn length_error() -> ExecutionError {
    ExecutionError::TraceLenExceeded(MAX_TRACE_LEN)
}

fn inconsistent() -> ExecutionError {
    ExecutionError::Internal("inconsistent completed Library session")
}
