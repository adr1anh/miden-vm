//! Descriptor-scoped native resolution and invocation-use staging.
//!
//! This module does not load code or change VM state. An adapter must finish every fallible code
//! and VM preflight before committing a guard, and may discharge entry only at the actual root END.
//! Its row markers still require binding to real execution rows by transition/Core/replay work.

use alloc::vec::Vec;
use core::alloc::Layout;

use miden_core::program::{
    EnvironmentRoot, ExecutionTarget, ImplementationRoot, Namespace, ProcedureKey,
};

use super::{
    LedgerError, LedgerLimits, OpeningId, OpeningLedger, PreparedOpening, ResolvedBinding,
};
use crate::trace::{RowIndex, limits::MAX_TRACE_LEN};

/// Explicit finite native session policies. No deployment defaults exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    pub max_cached_keys: usize,
    /// Committed invocation uses plus the separately reserved normal entry demand.
    pub max_requests: usize,
    /// Ledger storage plus all retained binding and use-record Vec capacities.
    pub max_retained_bytes: usize,
    /// Simultaneous ledger preparation peak, old session buffers and replacement/reserved buffers.
    ///
    /// Requests are checked before reservation and returned capacities before publication. As with
    /// the ledger, allocator metadata, excess beyond allocation requests, fixed stack storage and
    /// process RSS are excluded. This does not bound prior caller allocations.
    pub max_prepare_peak_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionResource {
    CachedKeys,
    Requests,
    RetainedBytes,
    PreparePeakBytes,
}

/// Native lifecycle only; Completed does not itself establish VM or proof completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    Unentered,
    PendingEntry,
    Completed,
}

/// The native request tags. Execution-mode/context/principal changes belong to the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InvocationTag {
    Normal = 0,
    Syscall = 1,
}

/// Checked native frequencies for one accepted terminal opening, without an AIR frequency range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpeningUseCounts {
    pub normal: usize,
    pub syscall: usize,
}

impl OpeningUseCounts {
    fn increment(self, tag: InvocationTag) -> Result<Self, SessionError> {
        match tag {
            InvocationTag::Normal => Ok(Self {
                normal: checked_add(self.normal, 1)?,
                ..self
            }),
            InvocationTag::Syscall => Ok(Self {
                syscall: checked_add(self.syscall, 1)?,
                ..self
            }),
        }
    }
}

/// An immutable observation of a binding retained privately under this session's fixed root.
///
/// Its opening identity is local bookkeeping, never authority accepted by preparation APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBinding {
    key: ProcedureKey,
    namespace: Namespace,
    implementation: ImplementationRoot,
    opening: OpeningId,
    counts: OpeningUseCounts,
}

impl SessionBinding {
    pub const fn procedure_key(self) -> ProcedureKey {
        self.key
    }

    pub const fn namespace(self) -> Namespace {
        self.namespace
    }

    pub const fn implementation_root(self) -> ImplementationRoot {
        self.implementation
    }

    pub const fn opening_id(self) -> OpeningId {
        self.opening
    }

    pub const fn counts(self) -> OpeningUseCounts {
        self.counts
    }
}

/// One committed native demand and its adapter-supplied source-row occurrence marker.
///
/// Package debug context remains diagnostic. This record defines neither an authenticated source
/// API nor a serialized witness; actual-row/Core/replay binding remains a later obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvocationUse {
    tag: InvocationTag,
    key: ProcedureKey,
    implementation: ImplementationRoot,
    opening: OpeningId,
    row: RowIndex,
}

impl InvocationUse {
    pub const fn tag(self) -> InvocationTag {
        self.tag
    }

    pub const fn procedure_key(self) -> ProcedureKey {
        self.key
    }

    pub const fn implementation_root(self) -> ImplementationRoot {
        self.implementation
    }

    pub const fn opening_id(self) -> OpeningId {
        self.opening
    }

    pub const fn row(self) -> RowIndex {
        self.row
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCounters {
    pub cached_keys: usize,
    pub committed_requests: usize,
    pub reserved_requests: usize,
    /// Combined published ledger and session capacity storage.
    pub retained_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("resolution session requires phase {expected:?}, rather than {actual:?}")]
    InvalidPhase {
        expected: SessionPhase,
        actual: SessionPhase,
    },
    #[error("resolution session expects root {expected:?}, rather than {actual:?}")]
    WrongRoot {
        expected: EnvironmentRoot,
        actual: EnvironmentRoot,
    },
    #[error("resolution session expects key {expected:?}, rather than {actual:?}")]
    WrongKey {
        expected: ProcedureKey,
        actual: ProcedureKey,
    },
    #[error("syscall requires immediate namespace {expected:?}, rather than {actual:?}")]
    UnauthorizedSyscall { expected: Namespace, actual: Namespace },
    #[error("resolution session has no cached binding for {key:?}")]
    MissingCachedBinding { key: ProcedureKey },
    #[error("resolution session observed inconsistent binding metadata or provenance for {key:?}")]
    InconsistentBinding { key: ProcedureKey },
    #[error("root END expects implementation {expected:?}, rather than {actual:?}")]
    WrongEntryImplementation {
        expected: ImplementationRoot,
        actual: ImplementationRoot,
    },
    #[error("resolution session {resource:?} limit {limit} is below requested {requested}")]
    LimitExceeded {
        resource: SessionResource,
        limit: usize,
        requested: usize,
    },
    #[error("resolution session exceeds arithmetic or allocation-layout bounds")]
    LengthOverflow,
    #[error("resolution session native allocation failed")]
    AllocationFailed,
    #[error("native requests {requested} exceed the necessary trace-row ceiling")]
    TraceRequestLimitExceeded { requested: usize },
}

/// Native resolution authority scoped by an immutable execution descriptor.
///
/// The private binding cache is logically keyed by (R_E, K); it is distinct from any D-indexed code
/// cache. Selective membership does not establish global executable-key uniqueness or admission.
#[derive(Debug)]
pub struct ResolutionSession {
    descriptor: ExecutionTarget,
    limits: SessionLimits,
    ledger: OpeningLedger,
    state: SessionState,
}

impl ResolutionSession {
    pub const fn new(
        descriptor: ExecutionTarget,
        ledger_limits: LedgerLimits,
        limits: SessionLimits,
    ) -> Self {
        Self {
            descriptor,
            limits,
            ledger: OpeningLedger::new(descriptor.environment_root(), ledger_limits),
            state: SessionState {
                phase: SessionPhase::Unentered,
                bindings: Vec::new(),
                uses: Vec::new(),
                root_use: Vec::new(),
                counters: SessionCounters {
                    cached_keys: 0,
                    committed_requests: 0,
                    reserved_requests: 0,
                    retained_bytes: 0,
                },
            },
        }
    }

    pub const fn descriptor(&self) -> ExecutionTarget {
        self.descriptor
    }

    pub const fn limits(&self) -> SessionLimits {
        self.limits
    }

    pub const fn phase(&self) -> SessionPhase {
        self.state.phase
    }

    pub const fn counters(&self) -> SessionCounters {
        self.state.counters
    }

    pub const fn ledger(&self) -> &OpeningLedger {
        &self.ledger
    }

    pub fn bindings(&self) -> &[SessionBinding] {
        &self.state.bindings
    }

    /// Committed invocations in order, followed by the root-END entry use when completed.
    pub fn uses(&self) -> impl DoubleEndedIterator<Item = &InvocationUse> {
        self.state.uses.iter().chain(self.state.root_use.iter())
    }

    /// Diagnostic lookup for live execution, whose invocation rows are strictly chronological.
    /// The returned ordinal refers to `uses()` and never authorizes a transition.
    pub(crate) fn invocation_use_at_row(&self, row: RowIndex) -> Option<(usize, InvocationUse)> {
        let index = self.state.uses.binary_search_by_key(&row, |record| record.row).ok()?;
        Some((index, self.state.uses[index]))
    }

    /// Stages entry authentication and a separately owned normal entry demand/use-record capacity.
    ///
    /// Inspect the binding before transferring it so subsequent host/code preflights can proceed
    /// safely. The consumed witness is not returned on failure or drop. The adapter must finish
    /// every fallible code/VM preflight before commit; this session rolls back no external work.
    pub fn prepare_entry(
        &mut self,
        binding: ResolvedBinding,
    ) -> Result<PreparedEntry<'_>, SessionError> {
        require_phase(self.state.phase, SessionPhase::Unentered)?;
        check_binding(self.descriptor, self.descriptor.entry_key(), &binding)?;
        check_keys(1, self.limits)?;
        check_requests(0, 1, self.limits)?;
        let metadata = BindingMetadata::from_binding(&binding);
        let available = ledger_peak_available(&self.state, self.limits)?;
        let opening = self.ledger.prepare_with_peak_limit(binding, available)?;
        let binding = metadata.with_opening(opening.opening_id());
        let buffers = PreparedBuffers::prepare(
            &self.state,
            self.limits,
            opening.counters().retained_bytes,
            opening.requested_peak_bytes(),
            true,
            false,
            true,
        )?;
        let counters = SessionCounters {
            cached_keys: 1,
            committed_requests: 0,
            reserved_requests: 1,
            retained_bytes: buffers.retained_bytes,
        };
        Ok(PreparedEntry {
            opening,
            native: PreparedNative {
                state: &mut self.state,
                binding,
                binding_index: 0,
                insert_binding: true,
                counters,
                buffers,
            },
        })
    }

    /// Stages an invocation authenticated by a verified binding, without publishing native state.
    ///
    /// As for entry, transfer the witness only once subsequent host/code preflights can safely
    /// proceed, and commit only after every fallible VM preflight succeeds. Repeated bindings must
    /// preserve both metadata and exact opening provenance. Recursion and same-D aliases are valid.
    pub fn prepare(
        &mut self,
        key: ProcedureKey,
        binding: ResolvedBinding,
        tag: InvocationTag,
        row: RowIndex,
    ) -> Result<PreparedInvocation<'_>, SessionError> {
        require_phase(self.state.phase, SessionPhase::PendingEntry)?;
        check_binding(self.descriptor, key, &binding)?;
        check_tag(binding.namespace(), tag)?;
        let metadata = BindingMetadata::from_binding(&binding);
        let existing = self.state.bindings.iter().position(|binding| binding.key == key);
        if let Some(index) = existing
            && !metadata.matches(self.state.bindings[index])
        {
            return Err(SessionError::InconsistentBinding { key });
        }
        let insert_binding = existing.is_none();
        let mut counters = self.state.counters;
        counters.cached_keys = checked_add(counters.cached_keys, usize::from(insert_binding))?;
        check_keys(counters.cached_keys, self.limits)?;
        counters.committed_requests = checked_add(counters.committed_requests, 1)?;
        check_requests(counters.committed_requests, counters.reserved_requests, self.limits)?;
        let available = ledger_peak_available(&self.state, self.limits)?;
        let opening = self.ledger.prepare_with_peak_limit(binding, available)?;
        let mut binding = metadata.with_opening(opening.opening_id());
        if let Some(index) = existing {
            if self.state.bindings[index].opening != binding.opening {
                return Err(SessionError::InconsistentBinding { key });
            }
            binding.counts = self.state.bindings[index].counts;
        } else if self.state.bindings.iter().any(|cached| cached.opening == binding.opening) {
            return Err(SessionError::InconsistentBinding { key });
        }
        binding.counts = binding.counts.increment(tag)?;
        let record = invocation_use(binding, tag, row);
        let buffers = PreparedBuffers::prepare(
            &self.state,
            self.limits,
            opening.counters().retained_bytes,
            opening.requested_peak_bytes(),
            insert_binding,
            true,
            false,
        )?;
        counters.retained_bytes = buffers.retained_bytes;
        let binding_index = existing.unwrap_or(self.state.bindings.len());
        Ok(PreparedInvocation {
            opening: Some(opening),
            native: PreparedNative {
                state: &mut self.state,
                binding,
                binding_index,
                insert_binding,
                counters,
                buffers,
            },
            record,
        })
    }

    /// Stages another use of a private session binding without reopening or charging its path.
    ///
    /// Cache hits still check syscall authorization and record/count each committed invocation.
    /// No caller-supplied opening handle is accepted as authority.
    pub fn prepare_cached(
        &mut self,
        key: ProcedureKey,
        tag: InvocationTag,
        row: RowIndex,
    ) -> Result<PreparedInvocation<'_>, SessionError> {
        require_phase(self.state.phase, SessionPhase::PendingEntry)?;
        let index = self
            .state
            .bindings
            .iter()
            .position(|binding| binding.key == key)
            .ok_or(SessionError::MissingCachedBinding { key })?;
        let mut binding = self.state.bindings[index];
        check_tag(binding.namespace, tag)?;
        binding.counts = binding.counts.increment(tag)?;
        let mut counters = self.state.counters;
        counters.committed_requests = checked_add(counters.committed_requests, 1)?;
        check_requests(counters.committed_requests, counters.reserved_requests, self.limits)?;
        let buffers = PreparedBuffers::prepare(
            &self.state,
            self.limits,
            self.ledger.counters().retained_bytes,
            self.ledger.counters().retained_bytes,
            false,
            true,
            false,
        )?;
        counters.retained_bytes = buffers.retained_bytes;
        Ok(PreparedInvocation {
            opening: None,
            native: PreparedNative {
                state: &mut self.state,
                binding,
                binding_index: index,
                insert_binding: false,
                counters,
                buffers,
            },
            record: invocation_use(binding, tag, row),
        })
    }

    /// Stages the one reserved normal entry use, only for the exact entry implementation.
    ///
    /// Only the transition adapter at the real root END may invoke this operation. The native
    /// session cannot establish that its supplied implementation/row came from actual execution.
    pub fn prepare_root_end(
        &mut self,
        actual_root: ImplementationRoot,
        row: RowIndex,
    ) -> Result<PreparedRootEnd<'_>, SessionError> {
        require_phase(self.state.phase, SessionPhase::PendingEntry)?;
        let mut binding = self.state.bindings[0];
        if actual_root != binding.implementation {
            return Err(SessionError::WrongEntryImplementation {
                expected: binding.implementation,
                actual: actual_root,
            });
        }
        binding.counts = binding.counts.increment(InvocationTag::Normal)?;
        let mut counters = self.state.counters;
        counters.committed_requests = checked_add(counters.committed_requests, 1)?;
        counters.reserved_requests =
            counters.reserved_requests.checked_sub(1).ok_or(SessionError::LengthOverflow)?;
        check_requests(counters.committed_requests, counters.reserved_requests, self.limits)?;
        let buffers = PreparedBuffers::prepare(
            &self.state,
            self.limits,
            self.ledger.counters().retained_bytes,
            self.ledger.counters().retained_bytes,
            false,
            false,
            false,
        )?;
        counters.retained_bytes = buffers.retained_bytes;
        Ok(PreparedRootEnd {
            native: PreparedNative {
                state: &mut self.state,
                binding,
                binding_index: 0,
                insert_binding: false,
                counters,
                buffers,
            },
            record: invocation_use(binding, InvocationTag::Normal, row),
        })
    }

    /// Returns completed native counters without changing state or claiming VM/proof completion.
    pub fn finalize(&self) -> Result<SessionCounters, SessionError> {
        require_phase(self.state.phase, SessionPhase::Completed)?;
        Ok(self.state.counters)
    }
}

/// Non-Clone entry staging. Drop preserves published state and every retained capacity.
#[derive(Debug)]
#[must_use = "commit the guard to publish the prepared native entry"]
pub struct PreparedEntry<'a> {
    opening: PreparedOpening<'a>,
    native: PreparedNative<'a>,
}

impl PreparedEntry<'_> {
    pub const fn binding(&self) -> SessionBinding {
        self.native.binding
    }

    pub const fn counters(&self) -> SessionCounters {
        self.native.counters
    }

    pub const fn requested_peak_bytes(&self) -> usize {
        self.native.buffers.peak_bytes
    }

    /// Publishes already-checked native state once, without allocation or fallible operations.
    pub fn commit(self) -> SessionBinding {
        let binding = self.native.binding;
        self.opening.commit();
        self.native.commit(Publication::Entry);
        binding
    }
}

/// Non-Clone invocation staging, including cache hits. Drop publishes nothing.
#[derive(Debug)]
#[must_use = "commit the guard to publish the prepared native invocation"]
pub struct PreparedInvocation<'a> {
    opening: Option<PreparedOpening<'a>>,
    native: PreparedNative<'a>,
    record: InvocationUse,
}

impl PreparedInvocation<'_> {
    pub const fn binding(&self) -> SessionBinding {
        self.native.binding
    }

    pub const fn use_record(&self) -> InvocationUse {
        self.record
    }

    pub const fn counters(&self) -> SessionCounters {
        self.native.counters
    }

    pub const fn requested_peak_bytes(&self) -> usize {
        self.native.buffers.peak_bytes
    }

    /// Publishes already-checked native state once, without allocation or fallible operations.
    pub fn commit(self) -> InvocationUse {
        if let Some(opening) = self.opening {
            opening.commit();
        }
        self.native.commit(Publication::Invocation(self.record));
        self.record
    }
}

/// Non-Clone discharge of the separately reserved normal entry demand. Drop publishes nothing.
#[derive(Debug)]
#[must_use = "commit the guard to discharge the reserved native entry demand"]
pub struct PreparedRootEnd<'a> {
    native: PreparedNative<'a>,
    record: InvocationUse,
}

impl PreparedRootEnd<'_> {
    pub const fn use_record(&self) -> InvocationUse {
        self.record
    }

    pub const fn counters(&self) -> SessionCounters {
        self.native.counters
    }

    pub const fn requested_peak_bytes(&self) -> usize {
        self.native.buffers.peak_bytes
    }

    /// Consumes reserved capacity and marks native bookkeeping completed, without allocation.
    pub fn commit(self) -> InvocationUse {
        self.native.commit(Publication::RootEnd(self.record));
        self.record
    }
}

#[derive(Debug)]
struct SessionState {
    phase: SessionPhase,
    bindings: Vec<SessionBinding>,
    uses: Vec<InvocationUse>,
    // Ordinary calls cannot consume or grow this entry-only record buffer.
    root_use: Vec<InvocationUse>,
    counters: SessionCounters,
}

impl SessionState {
    fn storage_bytes(&self) -> Result<usize, SessionError> {
        checked_add(
            array_bytes::<SessionBinding>(self.bindings.capacity())?,
            checked_add(
                array_bytes::<InvocationUse>(self.uses.capacity())?,
                array_bytes::<InvocationUse>(self.root_use.capacity())?,
            )?,
        )
    }
}

struct BindingMetadata {
    key: ProcedureKey,
    namespace: Namespace,
    implementation: ImplementationRoot,
}

impl BindingMetadata {
    fn from_binding(binding: &ResolvedBinding) -> Self {
        Self {
            key: binding.procedure_key(),
            namespace: binding.namespace(),
            implementation: binding.implementation_root(),
        }
    }

    fn matches(&self, binding: SessionBinding) -> bool {
        self.key == binding.key
            && self.namespace == binding.namespace
            && self.implementation == binding.implementation
    }

    fn with_opening(self, opening: OpeningId) -> SessionBinding {
        SessionBinding {
            key: self.key,
            namespace: self.namespace,
            implementation: self.implementation,
            opening,
            counts: OpeningUseCounts { normal: 0, syscall: 0 },
        }
    }
}

#[derive(Debug)]
struct PreparedNative<'a> {
    state: &'a mut SessionState,
    binding: SessionBinding,
    binding_index: usize,
    insert_binding: bool,
    counters: SessionCounters,
    buffers: PreparedBuffers,
}

impl PreparedNative<'_> {
    fn commit(mut self, publication: Publication) {
        if let Some(mut replacement) = self.buffers.bindings.take() {
            replacement.append(&mut self.state.bindings);
            self.state.bindings = replacement;
        }
        if self.insert_binding {
            self.state.bindings.push(self.binding);
        } else {
            self.state.bindings[self.binding_index] = self.binding;
        }
        if let Some(mut replacement) = self.buffers.uses.take() {
            replacement.append(&mut self.state.uses);
            self.state.uses = replacement;
        }
        if let Some(reserved) = self.buffers.root_use.take() {
            self.state.root_use = reserved;
        }
        match publication {
            Publication::Entry => self.state.phase = SessionPhase::PendingEntry,
            Publication::Invocation(record) => self.state.uses.push(record),
            Publication::RootEnd(record) => {
                self.state.root_use.push(record);
                self.state.phase = SessionPhase::Completed;
            },
        }
        self.state.counters = self.counters;
    }
}

enum Publication {
    Entry,
    Invocation(InvocationUse),
    RootEnd(InvocationUse),
}

#[derive(Debug)]
struct PreparedBuffers {
    bindings: Option<Vec<SessionBinding>>,
    uses: Option<Vec<InvocationUse>>,
    root_use: Option<Vec<InvocationUse>>,
    retained_bytes: usize,
    peak_bytes: usize,
}

impl PreparedBuffers {
    fn prepare(
        state: &SessionState,
        limits: SessionLimits,
        ledger_retained: usize,
        ledger_peak: usize,
        add_binding: bool,
        add_use: bool,
        reserve_root: bool,
    ) -> Result<Self, SessionError> {
        let mut plan = BufferPlan {
            bindings: growth(state.bindings.len(), state.bindings.capacity(), add_binding)?,
            uses: growth(state.uses.len(), state.uses.capacity(), add_use)?,
            root_use: if reserve_root { Some(1) } else { None },
        };
        plan.check(state, limits, ledger_retained, ledger_peak)?;
        let bindings = if let Some(capacity) = plan.bindings {
            let buffer = reserve_vec::<SessionBinding>(capacity)?;
            plan.bindings = Some(buffer.capacity());
            plan.check(state, limits, ledger_retained, ledger_peak)?;
            Some(buffer)
        } else {
            None
        };
        let uses = if let Some(capacity) = plan.uses {
            let buffer = reserve_vec::<InvocationUse>(capacity)?;
            plan.uses = Some(buffer.capacity());
            plan.check(state, limits, ledger_retained, ledger_peak)?;
            Some(buffer)
        } else {
            None
        };
        let root_use = if let Some(capacity) = plan.root_use {
            let buffer = reserve_vec::<InvocationUse>(capacity)?;
            plan.root_use = Some(buffer.capacity());
            plan.check(state, limits, ledger_retained, ledger_peak)?;
            Some(buffer)
        } else {
            None
        };
        let (retained_bytes, peak_bytes) =
            plan.check(state, limits, ledger_retained, ledger_peak)?;
        Ok(Self {
            bindings,
            uses,
            root_use,
            retained_bytes,
            peak_bytes,
        })
    }
}

struct BufferPlan {
    bindings: Option<usize>,
    uses: Option<usize>,
    root_use: Option<usize>,
}

impl BufferPlan {
    fn check(
        &self,
        state: &SessionState,
        limits: SessionLimits,
        ledger_retained: usize,
        ledger_peak: usize,
    ) -> Result<(usize, usize), SessionError> {
        let retained = checked_add(
            ledger_retained,
            checked_add(
                array_bytes::<SessionBinding>(self.bindings.unwrap_or(state.bindings.capacity()))?,
                checked_add(
                    array_bytes::<InvocationUse>(self.uses.unwrap_or(state.uses.capacity()))?,
                    array_bytes::<InvocationUse>(
                        self.root_use.unwrap_or(state.root_use.capacity()),
                    )?,
                )?,
            )?,
        )?;
        let replacements = checked_add(
            array_bytes::<SessionBinding>(self.bindings.unwrap_or(0))?,
            checked_add(
                array_bytes::<InvocationUse>(self.uses.unwrap_or(0))?,
                array_bytes::<InvocationUse>(self.root_use.unwrap_or(0))?,
            )?,
        )?;
        let peak = checked_add(checked_add(ledger_peak, state.storage_bytes()?)?, replacements)?;
        check_limit(SessionResource::RetainedBytes, retained, limits.max_retained_bytes)?;
        check_limit(SessionResource::PreparePeakBytes, peak, limits.max_prepare_peak_bytes)?;
        Ok((retained, peak))
    }
}

fn growth(len: usize, capacity: usize, add: bool) -> Result<Option<usize>, SessionError> {
    let required = checked_add(len, usize::from(add))?;
    Ok(if required > capacity { Some(required) } else { None })
}

fn ledger_peak_available(
    state: &SessionState,
    limits: SessionLimits,
) -> Result<usize, SessionError> {
    let retained = state.storage_bytes()?;
    check_limit(SessionResource::PreparePeakBytes, retained, limits.max_prepare_peak_bytes)?;
    limits
        .max_prepare_peak_bytes
        .checked_sub(retained)
        .ok_or(SessionError::LengthOverflow)
}

fn check_binding(
    descriptor: ExecutionTarget,
    key: ProcedureKey,
    binding: &ResolvedBinding,
) -> Result<(), SessionError> {
    if binding.environment_root() != descriptor.environment_root() {
        return Err(SessionError::WrongRoot {
            expected: descriptor.environment_root(),
            actual: binding.environment_root(),
        });
    }
    if binding.procedure_key() != key {
        return Err(SessionError::WrongKey {
            expected: key,
            actual: binding.procedure_key(),
        });
    }
    Ok(())
}

fn require_phase(actual: SessionPhase, expected: SessionPhase) -> Result<(), SessionError> {
    if actual == expected {
        Ok(())
    } else {
        Err(SessionError::InvalidPhase { expected, actual })
    }
}

fn check_tag(namespace: Namespace, tag: InvocationTag) -> Result<(), SessionError> {
    if tag == InvocationTag::Syscall && namespace != Namespace::initial() {
        return Err(SessionError::UnauthorizedSyscall {
            expected: Namespace::initial(),
            actual: namespace,
        });
    }
    Ok(())
}

fn invocation_use(binding: SessionBinding, tag: InvocationTag, row: RowIndex) -> InvocationUse {
    InvocationUse {
        tag,
        key: binding.key,
        implementation: binding.implementation,
        opening: binding.opening,
        row,
    }
}

fn check_keys(requested: usize, limits: SessionLimits) -> Result<(), SessionError> {
    check_limit(SessionResource::CachedKeys, requested, limits.max_cached_keys)
}

fn check_requests(
    committed: usize,
    reserved: usize,
    limits: SessionLimits,
) -> Result<(), SessionError> {
    let requested = checked_add(committed, reserved)?;
    // The selected Core invocation/root-completion groups are exclusive and emit one request per
    // row. This necessary ceiling does not establish final packed height, degree or no-wrap safety.
    if requested > MAX_TRACE_LEN {
        return Err(SessionError::TraceRequestLimitExceeded { requested });
    }
    check_limit(SessionResource::Requests, requested, limits.max_requests)
}

fn check_limit(
    resource: SessionResource,
    requested: usize,
    limit: usize,
) -> Result<(), SessionError> {
    if requested > limit {
        Err(SessionError::LimitExceeded { resource, limit, requested })
    } else {
        Ok(())
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, SessionError> {
    left.checked_add(right).ok_or(SessionError::LengthOverflow)
}

fn array_bytes<T>(count: usize) -> Result<usize, SessionError> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| SessionError::LengthOverflow)
}

fn reserve_vec<T>(count: usize) -> Result<Vec<T>, SessionError> {
    array_bytes::<T>(count)?;
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(count).map_err(|_| SessionError::AllocationFailed)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests;
