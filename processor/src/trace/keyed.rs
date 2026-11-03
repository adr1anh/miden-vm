//! Compact keyed replay witnesses and explicitly bounded native revalidation.
//!
//! Serialized records are observations, not resolution authority. Only a native session can
//! populate their private invocation uses. This module does not establish the packed proof
//! relation or authenticate sparse MAST forests against their source commitments.

use alloc::{collections::VecDeque, vec::Vec};
use core::{
    alloc::Layout,
    sync::atomic::{AtomicUsize, Ordering},
};

use miden_core::{
    program::{
        EnvNode, EnvNodeError, ExecutionDescriptor, ImplementationRoot, Namespace, ProcedureKey,
    },
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

use super::{limits::MAX_TRACE_LEN, trace_state::CoreTraceFragmentContext};
use crate::{
    EnvironmentTraceLimits, ExecutionEnvironment, InvocationTag, InvocationUse, OpeningError,
    OpeningLimits, OpeningOccurrence, OpeningResource, OpeningStep, ResolutionSession,
    ResolutionWitness, SessionBinding, SessionError, SessionPhase,
    mast::{MastForestId, MastNodeId},
    trace::RowIndex,
    tracer::{KeyedEvent, KeyedEventKind, KeyedMode},
};

const RECORD_WIRE_BYTES: usize = 150;
const ENVIRONMENT_HEADER_BYTES: usize = 144;
const OCCURRENCE_HEADER_BYTES: usize = 24;
const NO_PARENT: u64 = u64::MAX;
// A native reservation identity, unrelated to the wire, opening identity or authority. Allocation
// and address reuse cannot alias queues; exhaustion rejects preparation before publication.
static NEXT_QUEUE_ID: AtomicUsize = AtomicUsize::new(1);

/// Explicit transport and combined keyed-revalidation policies. No defaults are provided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayReadLimits {
    /// Maximum complete witness input. The outer witness reader must enforce this limit too.
    pub max_wire_bytes: usize,
    /// Accounted combined raw keyed storage, native session, temporary path and codec-buffer peak.
    ///
    /// Allocator metadata, fixed stack storage and process RSS are excluded. Existing non-keyed
    /// replay structures remain subject to their own reader bounds. Native policies' allocation
    /// exclusions still apply, including allocator excess in internal hashing scratch requests.
    pub max_validation_peak_bytes: usize,
}

/// An explicit resource bounded during keyed capture or replay validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayResource {
    Events,
    RetainedBytes,
    PreparePeakBytes,
    ValidationPeakBytes,
    ValidationWork,
    WireBytes,
}

/// Failure while preparing keyed trace data or revalidating an execution witness.
#[derive(Debug, thiserror::Error)]
pub enum KeyedReplayError {
    #[error("invalid keyed replay: {0}")]
    Invalid(&'static str),
    #[error("keyed replay {resource:?} limit {limit} is below requested {requested}")]
    LimitExceeded {
        resource: ReplayResource,
        limit: usize,
        requested: usize,
    },
    #[error("keyed replay exceeds arithmetic or allocation-layout bounds")]
    LengthOverflow,
    #[error("keyed replay allocation failed")]
    AllocationFailed,
    #[error(transparent)]
    Node(#[from] EnvNodeError),
    #[error(transparent)]
    Opening(#[from] OpeningError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Wire(#[from] DeserializationError),
}

/// Shared explicit accounting while reading the keyed portions of one witness.
pub(crate) struct ReplayReadBudget {
    trace: EnvironmentTraceLimits,
    read: ReplayReadLimits,
    wire_bytes: usize,
    retained_bytes: usize,
    events: usize,
}

impl ReplayReadBudget {
    pub(crate) const fn new(trace: EnvironmentTraceLimits, read: ReplayReadLimits) -> Self {
        Self {
            trace,
            read,
            wire_bytes: 0,
            retained_bytes: 0,
            events: 0,
        }
    }

    fn wire(&mut self, bytes: usize) -> Result<(), KeyedReplayError> {
        let requested = add(self.wire_bytes, bytes)?;
        limit(ReplayResource::WireBytes, requested, self.read.max_wire_bytes)?;
        self.wire_bytes = requested;
        Ok(())
    }

    fn storage(&mut self, bytes: usize) -> Result<(), KeyedReplayError> {
        let requested = add(self.retained_bytes, bytes)?;
        limit(ReplayResource::RetainedBytes, requested, self.trace.max_retained_bytes)?;
        limit(
            ReplayResource::ValidationPeakBytes,
            requested,
            self.read.max_validation_peak_bytes,
        )?;
        self.retained_bytes = requested;
        Ok(())
    }

    fn event_count(&mut self, count: usize) -> Result<(), KeyedReplayError> {
        let requested = add(self.events, count)?;
        limit(ReplayResource::Events, requested, self.trace.max_events)?;
        self.events = requested;
        Ok(())
    }
}

/// Primitive entry metadata. The entry itself consumes no execution row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayEntry {
    namespace: Namespace,
    implementation: ImplementationRoot,
    opening: usize,
}

impl ReplayEntry {
    fn from_binding(binding: SessionBinding) -> Self {
        Self {
            namespace: binding.namespace(),
            implementation: binding.implementation_root(),
            opening: binding.opening_id().index(),
        }
    }

    pub(crate) const fn implementation_root(self) -> ImplementationRoot {
        self.implementation
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ReplayOccurrence {
    parent: Option<(usize, usize)>,
    node_bytes: Vec<u8>,
}

/// Each selected occurrence is stored once, with only its incoming parent edge and core v1 bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EnvironmentReplay {
    descriptor: ExecutionDescriptor,
    entry: ReplayEntry,
    occurrences: Vec<ReplayOccurrence>,
    validated: bool,
}

/// Owned snapshot staging. Publication performs no allocation or fallible work.
#[derive(Debug)]
pub(crate) struct PreparedEnvironmentReplay {
    replay: EnvironmentReplay,
    retained_bytes: usize,
    native_retained_bytes: usize,
    validation_work: usize,
}

impl PreparedEnvironmentReplay {
    pub(crate) const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub(crate) const fn native_retained_bytes(&self) -> usize {
        self.native_retained_bytes
    }

    pub(crate) const fn validation_work(&self) -> usize {
        self.validation_work
    }

    /// The adapter commits this only alongside the already-prepared actual root END.
    /// This marker authenticates native replay data, not VM or proof completion.
    pub(crate) fn commit(mut self) -> EnvironmentReplay {
        self.replay.validated = true;
        self.replay
    }
}

impl EnvironmentReplay {
    pub(crate) const fn descriptor(&self) -> ExecutionDescriptor {
        self.descriptor
    }

    pub(crate) fn entry(&self) -> Result<ReplayEntry, KeyedReplayError> {
        self.require_validated()?;
        Ok(self.entry)
    }

    pub(crate) fn require_validated(&self) -> Result<(), KeyedReplayError> {
        if self.validated {
            Ok(())
        } else {
            Err(KeyedReplayError::Invalid("environment has not been natively revalidated"))
        }
    }

    /// Checks the retained native input without decoding a second authority or copying its ledger.
    pub(crate) fn require_completed_session(
        &self,
        session: &ResolutionSession,
    ) -> Result<(), KeyedReplayError> {
        self.require_validated()?;
        session.finalize()?;
        let entry = session
            .bindings()
            .first()
            .copied()
            .ok_or(KeyedReplayError::Invalid("session entry is absent"))?;
        if session.descriptor() != self.descriptor
            || entry.procedure_key() != self.descriptor.entry_key()
            || ReplayEntry::from_binding(entry) != self.entry
        {
            return Err(KeyedReplayError::Invalid(
                "completed native session differs from environment replay",
            ));
        }
        Ok(())
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize, KeyedReplayError> {
        let mut bytes = add(
            size_of::<ExecutionDescriptor>(),
            add(
                size_of::<ReplayEntry>(),
                array_bytes::<ReplayOccurrence>(self.occurrences.capacity())?,
            )?,
        )?;
        for occurrence in &self.occurrences {
            bytes = add(bytes, occurrence.node_bytes.capacity())?;
        }
        Ok(bytes)
    }

    /// Encodes the session's selected ledger once, before publishing its root-END discharge.
    pub(crate) fn prepare_capture(
        session: &ResolutionSession,
        entry: SessionBinding,
        policies: EnvironmentTraceLimits,
        other_retained_bytes: usize,
        other_preparation_bytes: usize,
        work_before: usize,
    ) -> Result<PreparedEnvironmentReplay, KeyedReplayError> {
        if session.phase() != SessionPhase::PendingEntry {
            return Err(KeyedReplayError::Invalid("capture requires the pending entry"));
        }
        let descriptor = session.descriptor();
        let expected_entry = session
            .bindings()
            .first()
            .copied()
            .ok_or(KeyedReplayError::Invalid("session entry is absent"))?;
        if entry.procedure_key() != descriptor.entry_key()
            || expected_entry.procedure_key() != descriptor.entry_key()
            || ReplayEntry::from_binding(entry) != ReplayEntry::from_binding(expected_entry)
        {
            return Err(KeyedReplayError::Invalid("capture entry differs from the native session"));
        }
        // Root-END preparation reserves no new native buffers. These exact capacities are also
        // retained after the original completed session moves into TraceReplay.
        let native_retained_bytes = session.counters().retained_bytes;
        let other_retained_bytes = add(other_retained_bytes, native_retained_bytes)?;
        let count = session.ledger().occurrences().len();
        let inline_bytes = add(size_of::<ExecutionDescriptor>(), size_of::<ReplayEntry>())?;
        let requested = add(inline_bytes, array_bytes::<ReplayOccurrence>(count)?)?;
        check_capture_storage(policies, other_retained_bytes, other_preparation_bytes, requested)?;
        let mut occurrences = reserve_vec::<ReplayOccurrence>(count)?;
        let mut retained =
            add(inline_bytes, array_bytes::<ReplayOccurrence>(occurrences.capacity())?)?;
        check_capture_storage(policies, other_retained_bytes, other_preparation_bytes, retained)?;
        let mut work = Work::new(work_before, policies.max_validation_work)?;
        for occurrence in session.ledger().occurrences() {
            let encoded_len = occurrence.node().encoded_len()?;
            work.charge(add(encoded_len, usize::from(occurrence.parent().is_some()))?)?;
            // The codec's new buffer is the final retained buffer, not a duplicate staging copy.
            check_capture_storage(
                policies,
                other_retained_bytes,
                other_preparation_bytes,
                add(retained, encoded_len)?,
            )?;
            let node_bytes = occurrence.node().to_bytes()?;
            retained = add(retained, node_bytes.capacity())?;
            check_capture_storage(
                policies,
                other_retained_bytes,
                other_preparation_bytes,
                retained,
            )?;
            occurrences.push(ReplayOccurrence {
                parent: occurrence
                    .parent()
                    .map(|parent| (parent.opening().index(), parent.child_slot())),
                node_bytes,
            });
        }
        Ok(PreparedEnvironmentReplay {
            replay: Self {
                descriptor,
                entry: ReplayEntry::from_binding(entry),
                occurrences,
                validated: false,
            },
            retained_bytes: retained,
            native_retained_bytes,
            validation_work: work.used,
        })
    }

    pub(crate) fn read_with_limits<R: ByteReader>(
        source: &mut R,
        budget: &mut ReplayReadBudget,
    ) -> Result<Self, KeyedReplayError> {
        budget.wire(ENVIRONMENT_HEADER_BYTES)?;
        source.check_eor(ENVIRONMENT_HEADER_BYTES)?;
        let descriptor = ExecutionDescriptor::new(
            ProcedureKey::read_from(source)?,
            miden_core::program::EnvironmentRoot::read_from(source)?,
        );
        let entry = ReplayEntry {
            namespace: Namespace::read_from(source)?,
            implementation: ImplementationRoot::read_from(source)?,
            opening: read_index(source)?,
        };
        let count = read_index(source)?;
        if count == 0 || entry.opening >= count {
            return Err(KeyedReplayError::Invalid("invalid entry occurrence"));
        }
        let minimum_wire = count
            .checked_mul(OCCURRENCE_HEADER_BYTES + 2)
            .ok_or(KeyedReplayError::LengthOverflow)?;
        source.check_eor(minimum_wire)?;
        limit(
            ReplayResource::WireBytes,
            add(budget.wire_bytes, minimum_wire)?,
            budget.read.max_wire_bytes,
        )?;
        let requested = add(
            add(size_of::<ExecutionDescriptor>(), size_of::<ReplayEntry>())?,
            array_bytes::<ReplayOccurrence>(count)?,
        )?;
        budget.storage(requested)?;
        let mut occurrences = reserve_vec::<ReplayOccurrence>(count)?;
        budget.storage(array_bytes::<ReplayOccurrence>(occurrences.capacity() - count)?)?;
        for index in 0..count {
            budget.wire(OCCURRENCE_HEADER_BYTES)?;
            source.check_eor(OCCURRENCE_HEADER_BYTES)?;
            let parent_index = source.read_u64()?;
            let slot = read_index(source)?;
            let parent = if parent_index == NO_PARENT {
                if index != 0 || slot != 0 {
                    return Err(KeyedReplayError::Invalid("invalid root occurrence parent"));
                }
                None
            } else {
                let parent =
                    usize::try_from(parent_index).map_err(|_| KeyedReplayError::LengthOverflow)?;
                if index == 0 || parent >= index {
                    return Err(KeyedReplayError::Invalid("occurrence parent must precede child"));
                }
                Some((parent, slot))
            };
            let len = read_index(source)?;
            if len < 2 {
                return Err(KeyedReplayError::Invalid("environment node record is too short"));
            }
            budget.wire(len)?;
            source.check_eor(len)?;
            budget.storage(len)?;
            // Borrow complete input first: truncated payloads never trigger a payload allocation.
            let bytes = source.read_slice(len)?;
            let mut node_bytes = reserve_vec::<u8>(len)?;
            budget.storage(node_bytes.capacity() - len)?;
            node_bytes.extend_from_slice(bytes);
            occurrences.push(ReplayOccurrence { parent, node_bytes });
        }
        Ok(Self {
            descriptor,
            entry,
            occurrences,
            validated: false,
        })
    }

    /// Recreates authority through the native APIs, leaving the environment untrusted on failure.
    pub(crate) fn revalidate(
        &mut self,
        environment: &ExecutionEnvironment,
        contexts: &mut [CoreTraceFragmentContext],
        policies: EnvironmentTraceLimits,
        read: ReplayReadLimits,
        fragment_size: usize,
    ) -> Result<ResolutionSession, KeyedReplayError> {
        self.validated = false;
        // Nonabortable trust revocation is security cleanup, before fallible accounting. It
        // visits only context headers, never event queues. Subsequent validation scans are
        // charged normally. Old private native uses remain inaccessible on every early error.
        for context in contexts.iter_mut() {
            context.replay.keyed.validated = false;
        }
        let mut work = Work::new(0, policies.max_validation_work)?;
        work.charge(add(contexts.len(), self.occurrences.len())?)?;
        let mut raw_bytes = self.retained_bytes()?;
        let mut events = 0usize;
        for context in contexts.iter() {
            if context.replay.keyed.invalidated {
                return Err(KeyedReplayError::Invalid("keyed queue was terminally invalidated"));
            }
            raw_bytes = add(raw_bytes, context.replay.keyed.retained_bytes()?)?;
            events = add(events, context.replay.keyed.len())?;
        }
        work.charge(events)?;
        for context in contexts.iter_mut() {
            context.replay.keyed.bump_generation()?;
            for record in &mut context.replay.keyed.records {
                record.native_use = None;
            }
        }
        if self.descriptor != environment.descriptor() {
            return Err(KeyedReplayError::Invalid("descriptor differs from caller authority"));
        }
        limit(ReplayResource::Events, events, policies.max_events)?;
        limit(ReplayResource::RetainedBytes, raw_bytes, policies.max_retained_bytes)?;
        limit(ReplayResource::ValidationPeakBytes, raw_bytes, read.max_validation_peak_bytes)?;
        validate_fragment_rows(contexts, fragment_size, events, &mut work)?;
        let peak_available = read.max_validation_peak_bytes - raw_bytes;
        let retained_available = policies.max_retained_bytes - raw_bytes;
        // Clamp before any native allocation: the native owner survives validation and must fit
        // both retained and peak allowance. Temporary paths/replacement buffers consume peak only.
        // Native preparation includes full Lists, old native buffers and staged replacements.
        let mut session_limits = environment.session_limits();
        session_limits.max_prepare_peak_bytes =
            session_limits.max_prepare_peak_bytes.min(peak_available);
        session_limits.max_retained_bytes =
            session_limits.max_retained_bytes.min(retained_available).min(peak_available);
        let mut ledger_limits = environment.ledger_limits();
        ledger_limits.max_peak_bytes = ledger_limits.max_peak_bytes.min(peak_available);
        ledger_limits.max_retained_bytes =
            ledger_limits.max_retained_bytes.min(retained_available).min(peak_available);
        let mut session = ResolutionSession::new(self.descriptor, ledger_limits, session_limits);
        let binding = self.resolve_path(
            self.entry.opening,
            self.descriptor.entry_key(),
            environment.opening_limits(),
            raw_bytes,
            session.counters().retained_bytes,
            read,
            &mut work,
        )?;
        if binding.namespace() != self.entry.namespace
            || binding.implementation_root() != self.entry.implementation
        {
            return Err(KeyedReplayError::Invalid("entry binding metadata differs"));
        }
        let prepared = session.prepare_entry(binding)?;
        if ReplayEntry::from_binding(prepared.binding()) != self.entry {
            return Err(KeyedReplayError::Invalid("entry opening identity differs"));
        }
        prepared.commit();
        let mut previous_row = None;
        for context in contexts.iter() {
            for record in &context.replay.keyed.records {
                work.charge(1)?;
                record.check_mode()?;
                if previous_row.is_some_and(|row| row >= record.row) {
                    return Err(KeyedReplayError::Invalid(
                        "keyed rows are not strictly chronological",
                    ));
                }
                previous_row = Some(record.row);
                // Native APIs scan cached metadata and may replace exact-sized buffers. Charge
                // conservative metadata visits and copied bytes before those operations too.
                charge_native_metadata(&session, &mut work)?;
                let native_use = match record.kind {
                    KeyedEventKind::Invoke(_) => {
                        if session
                            .bindings()
                            .iter()
                            .any(|binding| binding.procedure_key() == record.key)
                        {
                            let prepared =
                                session.prepare_cached(record.key, record.tag, record.row)?;
                            record.check_native(prepared.use_record())?;
                            prepared.commit()
                        } else {
                            let binding = self.resolve_path(
                                record.opening,
                                record.key,
                                environment.opening_limits(),
                                raw_bytes,
                                session.counters().retained_bytes,
                                read,
                                &mut work,
                            )?;
                            charge_native_opening(&session, &binding, &mut work)?;
                            let prepared =
                                session.prepare(record.key, binding, record.tag, record.row)?;
                            record.check_native(prepared.use_record())?;
                            prepared.commit()
                        }
                    },
                    KeyedEventKind::RootEnd => {
                        let prepared =
                            session.prepare_root_end(record.implementation, record.row)?;
                        record.check_native(prepared.use_record())?;
                        prepared.commit()
                    },
                };
                record.check_native(native_use)?;
            }
        }
        session.finalize()?;
        self.check_topology(&session, raw_bytes, read, &mut work)?;
        if session.uses().count() != events {
            return Err(KeyedReplayError::Invalid("unused native invocation uses"));
        }
        // The original completed native owner will be retained with the replay. Admit its actual
        // capacities before publishing any native uses or validation flags.
        let retained_bytes = add(raw_bytes, session.counters().retained_bytes)?;
        limit(ReplayResource::RetainedBytes, retained_bytes, policies.max_retained_bytes)?;
        limit(
            ReplayResource::ValidationPeakBytes,
            retained_bytes,
            read.max_validation_peak_bytes,
        )?;
        // No authority is copied into records until every event, final occurrence, completion
        // and retained-storage check has succeeded.
        {
            let mut uses = session.uses();
            for context in contexts.iter_mut() {
                for record in &mut context.replay.keyed.records {
                    record.native_use = Some(*uses.next().expect("validated native use count"));
                }
                context.replay.keyed.validated = true;
            }
            let extra_use = uses.next();
            debug_assert!(extra_use.is_none());
        }
        self.validated = true;
        Ok(session)
    }

    fn resolve_path(
        &self,
        terminal: usize,
        key: ProcedureKey,
        mut limits: OpeningLimits,
        raw_bytes: usize,
        native_bytes: usize,
        read: ReplayReadLimits,
        work: &mut Work,
    ) -> Result<crate::ResolvedBinding, KeyedReplayError> {
        let mut index = terminal;
        let mut count = 0usize;
        loop {
            work.charge(1)?;
            let occurrence = self
                .occurrences
                .get(index)
                .ok_or(KeyedReplayError::Invalid("opening index is outside occurrence tree"))?;
            count = add(count, 1)?;
            if count > limits.max_nodes || count.saturating_sub(1) > limits.max_depth {
                return Err(KeyedReplayError::Invalid("opening exceeds caller path limits"));
            }
            match occurrence.parent {
                Some((parent, _)) if parent < index => index = parent,
                None if index == 0 => break,
                _ => return Err(KeyedReplayError::Invalid("invalid occurrence ancestry")),
            }
        }
        let base = add(raw_bytes, native_bytes)?;
        let available = read
            .max_validation_peak_bytes
            .checked_sub(base)
            .ok_or(KeyedReplayError::LengthOverflow)?;
        limits.max_storage_bytes = limits.max_storage_bytes.min(available);
        let path_request = array_bytes::<OpeningStep>(count)?;
        check_opening_limit(OpeningResource::StorageBytes, path_request, limits.max_storage_bytes)?;
        check_validation_peak(base, path_request, read)?;
        let mut path = reserve_vec::<OpeningStep>(count)?;
        let mut path_bytes = array_bytes::<OpeningStep>(path.capacity())?;
        check_opening_limit(OpeningResource::StorageBytes, path_bytes, limits.max_storage_bytes)?;
        check_validation_peak(base, path_bytes, read)?;
        let mut encoded_bytes = 0usize;
        let mut total_list_children = 0usize;
        index = terminal;
        let mut selected_child = None;
        loop {
            work.charge(1)?;
            let occurrence = &self.occurrences[index];
            let byte_len = occurrence.node_bytes.len();
            encoded_bytes = add(encoded_bytes, byte_len)?;
            if encoded_bytes > limits.max_encoded_bytes {
                return Err(KeyedReplayError::Invalid("opening exceeds caller encoded byte limit"));
            }
            // This is only a resource preflight for a recognized v1 List header. The core
            // decoder remains the sole authority for versions, kinds, exact lengths and Words.
            // Unknown or truncated framing still reaches that decoder unchanged.
            let children = framed_list_children(&occurrence.node_bytes);
            if let Some(children) = children {
                check_opening_limit(
                    OpeningResource::ListChildren,
                    children,
                    limits.max_list_children,
                )?;
                total_list_children = add(total_list_children, children)?;
                check_opening_limit(
                    OpeningResource::TotalListChildren,
                    total_list_children,
                    limits.max_total_list_children,
                )?;
            }
            // Only a recognized List frame can allocate in the core decoder. Check both native
            // candidate storage and the combined outer budget before that allocation request.
            let node_allocation = children
                .map(array_bytes::<miden_core::program::EnvironmentRoot>)
                .transpose()?
                .unwrap_or(0);
            let requested = add(path_bytes, node_allocation)?;
            check_opening_limit(
                OpeningResource::StorageBytes,
                requested,
                limits.max_storage_bytes,
            )?;
            check_validation_peak(base, requested, read)?;
            work.charge(byte_len)?;
            let node = EnvNode::from_bytes(&occurrence.node_bytes, limits.max_encoded_bytes)?;
            if let EnvNode::List(children) = &node {
                let list_bytes =
                    array_bytes::<miden_core::program::EnvironmentRoot>(children.capacity())?;
                path_bytes = add(path_bytes, list_bytes)?;
                check_opening_limit(
                    OpeningResource::StorageBytes,
                    path_bytes,
                    limits.max_storage_bytes,
                )?;
                check_validation_peak(base, path_bytes, read)?;
            }
            path.push(OpeningStep { node, selected_child });
            match occurrence.parent {
                Some((parent, slot)) => {
                    index = parent;
                    selected_child = Some(slot);
                },
                None => break,
            }
        }
        work.charge(count)?;
        path.reverse();
        // Native verification recomputes commitments and derives namespaces/procedure keys.
        // Twice the canonical byte count conservatively covers these payload bytes, including
        // complete Lists. Work units do not claim literal CPU or internal hash-framing accounting.
        // Its own preflight adds and bounds hashing scratch before performing any hashing.
        work.charge(encoded_bytes.checked_mul(2).ok_or(KeyedReplayError::LengthOverflow)?)?;
        Ok(ResolutionWitness { path }.verify(self.descriptor.environment_root(), key, limits)?)
    }

    fn check_topology(
        &self,
        session: &ResolutionSession,
        raw_bytes: usize,
        read: ReplayReadLimits,
        work: &mut Work,
    ) -> Result<(), KeyedReplayError> {
        let native = session.ledger().occurrences();
        if native.len() != self.occurrences.len() {
            return Err(KeyedReplayError::Invalid("unused or missing opening occurrences"));
        }
        let base = add(raw_bytes, session.counters().retained_bytes)?;
        for (raw, occurrence) in self.occurrences.iter().zip(native) {
            work.charge(1)?;
            let parent = occurrence
                .parent()
                .map(|parent| (parent.opening().index(), parent.child_slot()));
            if raw.parent != parent {
                return Err(KeyedReplayError::Invalid(
                    "occurrence topology differs from native ledger",
                ));
            }
            let len = occurrence.node().encoded_len()?;
            check_validation_peak(base, len, read)?;
            work.charge(len)?;
            let canonical = occurrence.node().to_bytes()?;
            check_validation_peak(base, canonical.capacity(), read)?;
            if canonical != raw.node_bytes {
                return Err(KeyedReplayError::Invalid(
                    "occurrence preimage differs from native ledger",
                ));
            }
        }
        Ok(())
    }
}

impl Serializable for EnvironmentReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.descriptor.entry_key().write_into(target);
        self.descriptor.environment_root().write_into(target);
        self.entry.namespace.write_into(target);
        self.entry.implementation.write_into(target);
        target.write_u64(self.entry.opening as u64);
        target.write_u64(self.occurrences.len() as u64);
        for occurrence in &self.occurrences {
            let (parent, slot) = occurrence
                .parent
                .map_or((NO_PARENT, 0), |(parent, slot)| (parent as u64, slot as u64));
            target.write_u64(parent);
            target.write_u64(slot);
            target.write_u64(occurrence.node_bytes.len() as u64);
            target.write_bytes(&occurrence.node_bytes);
        }
    }
}

/// One primitive wire record, with private native authority installed only after revalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyedReplayRecord {
    kind: KeyedEventKind,
    tag: InvocationTag,
    key: ProcedureKey,
    implementation: ImplementationRoot,
    opening: usize,
    row: RowIndex,
    principal_before: ProcedureKey,
    principal_after: ProcedureKey,
    target_forest: MastForestId,
    target_root: MastNodeId,
    native_use: Option<InvocationUse>,
}

impl KeyedReplayRecord {
    fn from_event(event: KeyedEvent, target_forest: MastForestId, target_root: MastNodeId) -> Self {
        Self {
            kind: event.kind,
            tag: event.use_record.tag(),
            key: event.use_record.procedure_key(),
            implementation: event.use_record.implementation_root(),
            opening: event.use_record.opening_id().index(),
            row: event.use_record.row(),
            principal_before: event.principal_before,
            principal_after: event.principal_after,
            target_forest,
            target_root,
            native_use: Some(event.use_record),
        }
    }

    pub(crate) fn event(self) -> Result<KeyedEvent, KeyedReplayError> {
        Ok(KeyedEvent {
            kind: self.kind,
            use_record: self
                .native_use
                .ok_or(KeyedReplayError::Invalid("record has no native authority"))?,
            principal_before: self.principal_before,
            principal_after: self.principal_after,
        })
    }

    pub(crate) const fn target_forest(self) -> MastForestId {
        self.target_forest
    }

    pub(crate) const fn target_root(self) -> MastNodeId {
        self.target_root
    }

    pub(crate) fn matches(
        self,
        event: KeyedEvent,
        forest: MastForestId,
        root: MastNodeId,
    ) -> Result<(), KeyedReplayError> {
        if self.event()? != event || self.target_forest != forest || self.target_root != root {
            return Err(KeyedReplayError::Invalid(
                "actual keyed transition differs from replay observation",
            ));
        }
        Ok(())
    }

    fn check_mode(self) -> Result<(), KeyedReplayError> {
        let expected_tag = match self.kind {
            KeyedEventKind::Invoke(KeyedMode::Syscall) => InvocationTag::Syscall,
            _ => InvocationTag::Normal,
        };
        if self.tag != expected_tag {
            return Err(KeyedReplayError::Invalid("mode and native invocation tag differ"));
        }
        match self.kind {
            KeyedEventKind::Invoke(KeyedMode::Call | KeyedMode::DynCall) => {
                if self.principal_after != self.key {
                    return Err(KeyedReplayError::Invalid(
                        "call does not establish the requested principal",
                    ));
                }
            },
            KeyedEventKind::Invoke(_) => {
                if self.principal_before != self.principal_after {
                    return Err(KeyedReplayError::Invalid("same-principal mode changes principal"));
                }
            },
            // Actual Core replay checks both observations. A root Call/DynCall END may restore
            // a saved principal; the native resolution session cannot infer that return behavior.
            KeyedEventKind::RootEnd => {},
        }
        Ok(())
    }

    fn check_native(self, record: InvocationUse) -> Result<(), KeyedReplayError> {
        if self.tag != record.tag()
            || self.key != record.procedure_key()
            || self.implementation != record.implementation_root()
            || self.opening != record.opening_id().index()
            || self.row != record.row()
        {
            return Err(KeyedReplayError::Invalid(
                "record differs from natively reconstructed use",
            ));
        }
        Ok(())
    }

    fn read<R: ByteReader>(source: &mut R) -> Result<Self, KeyedReplayError> {
        let kind = match source.read_u8()? {
            0 => KeyedEventKind::Invoke(KeyedMode::Exec),
            1 => KeyedEventKind::Invoke(KeyedMode::Call),
            2 => KeyedEventKind::Invoke(KeyedMode::Syscall),
            3 => KeyedEventKind::Invoke(KeyedMode::Dyn),
            4 => KeyedEventKind::Invoke(KeyedMode::DynCall),
            5 => KeyedEventKind::RootEnd,
            _ => return Err(KeyedReplayError::Invalid("unknown keyed event kind")),
        };
        let tag = match source.read_u8()? {
            0 => InvocationTag::Normal,
            1 => InvocationTag::Syscall,
            _ => return Err(KeyedReplayError::Invalid("unknown invocation tag")),
        };
        let record = Self {
            kind,
            tag,
            key: ProcedureKey::read_from(source)?,
            implementation: ImplementationRoot::read_from(source)?,
            opening: read_index(source)?,
            row: RowIndex::from(source.read_u32()?),
            principal_before: ProcedureKey::read_from(source)?,
            principal_after: ProcedureKey::read_from(source)?,
            target_forest: MastForestId::from(source.read_u32()?),
            target_root: MastNodeId::new_unchecked(source.read_u32()?),
            native_use: None,
        };
        record.check_mode()?;
        Ok(record)
    }
}

/// Fragment-local keyed observations, consumed only after native environment revalidation.
#[derive(Debug)]
pub(crate) struct KeyedReplay {
    records: VecDeque<KeyedReplayRecord>,
    identity: usize,
    generation: usize,
    invalidated: bool,
    validated: bool,
}

impl Default for KeyedReplay {
    fn default() -> Self {
        Self {
            records: VecDeque::new(),
            identity: 0,
            generation: 0,
            invalidated: false,
            validated: true,
        }
    }
}

impl PartialEq for KeyedReplay {
    fn eq(&self, other: &Self) -> bool {
        self.records == other.records
            && self.invalidated == other.invalidated
            && self.validated == other.validated
    }
}

impl Eq for KeyedReplay {}

#[derive(Debug, Clone, Copy)]
struct QueueStamp {
    identity: usize,
    generation: usize,
    len: usize,
    capacity: usize,
}

impl QueueStamp {
    fn matches(self, queue: &KeyedReplay) -> bool {
        !queue.invalidated
            && queue.validated
            && self.identity != 0
            && self.identity == queue.identity
            && self.generation == queue.generation
            && self.len == queue.records.len()
            && self.capacity == queue.records.capacity()
    }
}

/// Unpublished event and optional replacement queue. Dropping it changes no queue or capacity.
#[derive(Debug)]
pub(crate) struct PreparedKeyedRecord {
    record: KeyedReplayRecord,
    replacement: Option<VecDeque<KeyedReplayRecord>>,
    retained_bytes_delta: usize,
    event_count: usize,
    source: QueueStamp,
    next_generation: usize,
}

impl PreparedKeyedRecord {
    pub(crate) const fn retained_bytes_delta(&self) -> usize {
        self.retained_bytes_delta
    }

    pub(crate) const fn event_count(&self) -> usize {
        self.event_count
    }

    /// The adapter checks this against the exclusive target queue immediately before publication.
    pub(crate) fn check_queue(&self, queue: &KeyedReplay) -> Result<(), KeyedReplayError> {
        if self.source.matches(queue) {
            Ok(())
        } else {
            Err(KeyedReplayError::Invalid("stale or cross-queue keyed reservation"))
        }
    }

    /// The tracer commits this once against the same unchanged queue used for preparation.
    pub(crate) fn commit(self, queue: &mut KeyedReplay) {
        if !self.source.matches(queue) {
            // An unexpected late adapter violation must not overwrite records or allocate. The
            // tracer observes this flag in the same cycle and terminally invalidates execution.
            queue.invalidated = true;
            return;
        }
        if let Some(replacement) = self.replacement {
            queue.records = replacement;
        }
        queue.generation = self.next_generation;
        queue.records.push_back(self.record);
    }
}

impl KeyedReplay {
    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize, KeyedReplayError> {
        array_bytes::<KeyedReplayRecord>(self.records.capacity())
    }

    pub(crate) fn require_validated(&self) -> Result<(), KeyedReplayError> {
        if !self.invalidated
            && self.validated
            && self.records.iter().all(|record| record.native_use.is_some())
        {
            Ok(())
        } else {
            Err(KeyedReplayError::Invalid("queue has not been natively revalidated"))
        }
    }

    pub(crate) fn peek(&self) -> Result<KeyedReplayRecord, KeyedReplayError> {
        if self.invalidated {
            return Err(KeyedReplayError::Invalid("keyed queue was terminally invalidated"));
        }
        if !self.validated {
            return Err(KeyedReplayError::Invalid("queue has not been natively revalidated"));
        }
        let record =
            *self.records.front().ok_or(KeyedReplayError::Invalid("missing keyed event"))?;
        record.event()?;
        Ok(record)
    }

    pub(crate) fn pop_front(&mut self) -> Result<KeyedReplayRecord, KeyedReplayError> {
        let record = self.peek()?;
        self.bump_generation()?;
        self.records.pop_front();
        Ok(record)
    }

    /// `retained_bytes` separates trace-owned storage from the retained native owner, so native
    /// capacities enter retained admission without changing the trace-only preparation-peak cap.
    pub(crate) fn prepare_record(
        &mut self,
        event: KeyedEvent,
        forest: MastForestId,
        root: MastNodeId,
        policies: EnvironmentTraceLimits,
        total_events: usize,
        retained_bytes: (usize, usize),
    ) -> Result<PreparedKeyedRecord, KeyedReplayError> {
        if self.invalidated {
            return Err(KeyedReplayError::Invalid("keyed queue was terminally invalidated"));
        }
        if !self.validated {
            return Err(KeyedReplayError::Invalid("queue has not been natively revalidated"));
        }
        let next_generation =
            self.generation.checked_add(1).ok_or(KeyedReplayError::LengthOverflow)?;
        if self.identity == 0 {
            self.identity = NEXT_QUEUE_ID
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |identity| {
                    identity.checked_add(1)
                })
                .map_err(|_| KeyedReplayError::Invalid("keyed queue identities exhausted"))?;
        }
        let source = QueueStamp {
            identity: self.identity,
            generation: self.generation,
            len: self.records.len(),
            capacity: self.records.capacity(),
        };
        let record = KeyedReplayRecord::from_event(event, forest, root);
        record.check_mode()?;
        let event_count = add(total_events, 1)?;
        limit(ReplayResource::Events, event_count, policies.max_events)?;
        let (total_retained_bytes, native_retained_bytes) = retained_bytes;
        let combined_retained_bytes = add(total_retained_bytes, native_retained_bytes)?;
        let old_bytes = self.retained_bytes()?;
        let mut replacement = None;
        let mut retained_bytes_delta = 0;
        if self.records.len() == self.records.capacity() {
            let capacity = add(self.records.len(), 1)?
                .checked_next_power_of_two()
                .ok_or(KeyedReplayError::LengthOverflow)?;
            let requested = array_bytes::<KeyedReplayRecord>(capacity)?;
            limit(
                ReplayResource::PreparePeakBytes,
                add(total_retained_bytes, requested)?,
                policies.max_prepare_peak_bytes,
            )?;
            limit(
                ReplayResource::RetainedBytes,
                add(combined_retained_bytes, requested - old_bytes)?,
                policies.max_retained_bytes,
            )?;
            let mut buffer = VecDeque::new();
            buffer
                .try_reserve_exact(capacity)
                .map_err(|_| KeyedReplayError::AllocationFailed)?;
            let bytes = array_bytes::<KeyedReplayRecord>(buffer.capacity())?;
            limit(
                ReplayResource::PreparePeakBytes,
                add(total_retained_bytes, bytes)?,
                policies.max_prepare_peak_bytes,
            )?;
            retained_bytes_delta =
                bytes.checked_sub(old_bytes).ok_or(KeyedReplayError::LengthOverflow)?;
            limit(
                ReplayResource::RetainedBytes,
                add(combined_retained_bytes, retained_bytes_delta)?,
                policies.max_retained_bytes,
            )?;
            buffer.extend(self.records.iter().copied());
            replacement = Some(buffer);
        } else {
            limit(
                ReplayResource::PreparePeakBytes,
                total_retained_bytes,
                policies.max_prepare_peak_bytes,
            )?;
            limit(
                ReplayResource::RetainedBytes,
                combined_retained_bytes,
                policies.max_retained_bytes,
            )?;
        }
        Ok(PreparedKeyedRecord {
            record,
            replacement,
            retained_bytes_delta,
            event_count,
            source,
            next_generation,
        })
    }

    pub(crate) const fn is_invalidated(&self) -> bool {
        self.invalidated
    }

    fn bump_generation(&mut self) -> Result<(), KeyedReplayError> {
        self.generation = self.generation.checked_add(1).ok_or(KeyedReplayError::LengthOverflow)?;
        Ok(())
    }

    pub(crate) fn read_with_limits<R: ByteReader>(
        source: &mut R,
        budget: &mut ReplayReadBudget,
    ) -> Result<Self, KeyedReplayError> {
        budget.wire(8)?;
        source.check_eor(8)?;
        let count = read_index(source)?;
        budget.event_count(count)?;
        let wire = count.checked_mul(RECORD_WIRE_BYTES).ok_or(KeyedReplayError::LengthOverflow)?;
        budget.wire(wire)?;
        source.check_eor(wire)?;
        budget.storage(array_bytes::<KeyedReplayRecord>(count)?)?;
        let mut records = VecDeque::new();
        records
            .try_reserve_exact(count)
            .map_err(|_| KeyedReplayError::AllocationFailed)?;
        budget.storage(array_bytes::<KeyedReplayRecord>(records.capacity() - count)?)?;
        for _ in 0..count {
            records.push_back(KeyedReplayRecord::read(source)?);
        }
        Ok(Self {
            records,
            validated: false,
            ..Self::default()
        })
    }
}

impl Serializable for KeyedReplay {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u64(self.records.len() as u64);
        for record in &self.records {
            target.write_u8(match record.kind {
                KeyedEventKind::Invoke(KeyedMode::Exec) => 0,
                KeyedEventKind::Invoke(KeyedMode::Call) => 1,
                KeyedEventKind::Invoke(KeyedMode::Syscall) => 2,
                KeyedEventKind::Invoke(KeyedMode::Dyn) => 3,
                KeyedEventKind::Invoke(KeyedMode::DynCall) => 4,
                KeyedEventKind::RootEnd => 5,
            });
            target.write_u8(record.tag as u8);
            record.key.write_into(target);
            record.implementation.write_into(target);
            target.write_u64(record.opening as u64);
            target.write_u32(record.row.as_u32());
            record.principal_before.write_into(target);
            record.principal_after.write_into(target);
            target.write_u32(u32::from(record.target_forest));
            target.write_u32(u32::from(record.target_root));
        }
    }
}

struct Work {
    used: usize,
    maximum: usize,
}

fn validate_fragment_rows(
    contexts: &[CoreTraceFragmentContext],
    fragment_size: usize,
    events: usize,
    work: &mut Work,
) -> Result<(), KeyedReplayError> {
    if fragment_size == 0 || fragment_size > MAX_TRACE_LEN || contexts.is_empty() {
        return Err(KeyedReplayError::Invalid("invalid keyed fragment geometry"));
    }
    work.charge(add(
        contexts.len().checked_mul(2).ok_or(KeyedReplayError::LengthOverflow)?,
        events,
    )?)?;
    let last = contexts
        .iter()
        .rev()
        .find_map(|context| context.replay.keyed.records.back())
        .ok_or(KeyedReplayError::Invalid("missing root-END record"))?;
    if last.kind != KeyedEventKind::RootEnd {
        return Err(KeyedReplayError::Invalid("last keyed record is not root END"));
    }
    let final_clock =
        last.row.as_u32().checked_add(1).ok_or(KeyedReplayError::LengthOverflow)? as usize;
    if final_clock > MAX_TRACE_LEN {
        return Err(KeyedReplayError::Invalid("root-END row exceeds trace ceiling"));
    }
    let mut expected_start = 0usize;
    let mut previous_row = None;
    for context in contexts {
        let start = context.state.system.clk.as_usize();
        let bound = start.checked_add(fragment_size).ok_or(KeyedReplayError::LengthOverflow)?;
        if start != expected_start || bound > MAX_TRACE_LEN || start >= final_clock {
            return Err(KeyedReplayError::Invalid("noncontiguous or unused keyed trace fragment"));
        }
        let end = bound.min(final_clock);
        if context.replay.keyed.len() > end - start {
            return Err(KeyedReplayError::Invalid(
                "fragment has more keyed events than execution rows",
            ));
        }
        for record in &context.replay.keyed.records {
            let row = record.row.as_usize();
            if row < start || row >= end || previous_row.is_some_and(|previous| previous >= row) {
                return Err(KeyedReplayError::Invalid(
                    "keyed record lies outside its chronological fragment",
                ));
            }
            previous_row = Some(row);
        }
        expected_start = bound;
    }
    if final_clock > expected_start {
        return Err(KeyedReplayError::Invalid("root END lies outside the final fragment"));
    }
    Ok(())
}

/// Work units are parent/metadata visits and bytes decoded, hashed, encoded or conservatively
/// copied by native replay preparation. Complete immediate Lists enter every applicable charge.
fn charge_native_metadata(
    session: &ResolutionSession,
    work: &mut Work,
) -> Result<(), KeyedReplayError> {
    let bindings = session.bindings().len();
    let visits = bindings.checked_mul(3).ok_or(KeyedReplayError::LengthOverflow)?;
    let copies = add(
        array_bytes::<SessionBinding>(bindings)?,
        array_bytes::<InvocationUse>(session.counters().committed_requests)?,
    )?;
    work.charge(add(visits, copies)?)
}

fn charge_native_opening(
    session: &ResolutionSession,
    binding: &crate::ResolvedBinding,
    work: &mut Work,
) -> Result<(), KeyedReplayError> {
    work.charge(array_bytes::<OpeningOccurrence>(session.ledger().occurrences().len())?)?;
    for step in binding.opening().path() {
        // Native shared-prefix equality can inspect every child of a complete List again.
        work.charge(step.node.encoded_len()?)?;
    }
    Ok(())
}

fn framed_list_children(bytes: &[u8]) -> Option<usize> {
    if bytes.get(..2)? != [1, 4] {
        return None;
    }
    let count = u32::from_le_bytes(bytes.get(2..6)?.try_into().ok()?);
    usize::try_from(count).ok()
}

fn check_opening_limit(
    resource: OpeningResource,
    requested: usize,
    maximum: usize,
) -> Result<(), KeyedReplayError> {
    if requested > maximum {
        Err(OpeningError::LimitExceeded { resource, limit: maximum, requested }.into())
    } else {
        Ok(())
    }
}

impl Work {
    fn new(used: usize, maximum: usize) -> Result<Self, KeyedReplayError> {
        limit(ReplayResource::ValidationWork, used, maximum)?;
        Ok(Self { used, maximum })
    }

    fn charge(&mut self, amount: usize) -> Result<(), KeyedReplayError> {
        let requested = add(self.used, amount)?;
        limit(ReplayResource::ValidationWork, requested, self.maximum)?;
        self.used = requested;
        Ok(())
    }
}

fn check_capture_storage(
    policies: EnvironmentTraceLimits,
    other_retained_bytes: usize,
    other_preparation_bytes: usize,
    staged_bytes: usize,
) -> Result<(), KeyedReplayError> {
    limit(
        ReplayResource::RetainedBytes,
        add(other_retained_bytes, staged_bytes)?,
        policies.max_retained_bytes,
    )?;
    limit(
        ReplayResource::PreparePeakBytes,
        add(other_preparation_bytes, staged_bytes)?,
        policies.max_prepare_peak_bytes,
    )
}

fn check_validation_peak(
    base: usize,
    staging: usize,
    policies: ReplayReadLimits,
) -> Result<(), KeyedReplayError> {
    limit(
        ReplayResource::ValidationPeakBytes,
        add(base, staging)?,
        policies.max_validation_peak_bytes,
    )
}

fn read_index<R: ByteReader>(source: &mut R) -> Result<usize, KeyedReplayError> {
    usize::try_from(source.read_u64()?).map_err(|_| KeyedReplayError::LengthOverflow)
}

fn reserve_vec<T>(count: usize) -> Result<Vec<T>, KeyedReplayError> {
    array_bytes::<T>(count)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| KeyedReplayError::AllocationFailed)?;
    Ok(result)
}

fn array_bytes<T>(count: usize) -> Result<usize, KeyedReplayError> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| KeyedReplayError::LengthOverflow)
}

fn add(left: usize, right: usize) -> Result<usize, KeyedReplayError> {
    left.checked_add(right).ok_or(KeyedReplayError::LengthOverflow)
}

fn limit(
    resource: ReplayResource,
    requested: usize,
    maximum: usize,
) -> Result<(), KeyedReplayError> {
    if requested > maximum {
        Err(KeyedReplayError::LimitExceeded { resource, limit: maximum, requested })
    } else {
        Ok(())
    }
}
