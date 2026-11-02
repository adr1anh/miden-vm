use alloc::{sync::Arc, vec::Vec};

use miden_air_definitions::vm::trace::chiplets::hasher::{
    CONTROLLER_ROWS_PER_HASHER_OP, STATE_WIDTH,
};
use miden_core::{
    FMP_ADDR, FMP_INIT_VALUE,
    operations::Operation,
    program::ProcedureKey,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

use super::{
    block_stack::{BlockInfo, BlockStack, ExecutionContextInfo},
    keyed::{
        EnvironmentReplay, KeyedReplay, KeyedReplayError, PreparedEnvironmentReplay,
        PreparedKeyedRecord, ReplayReadBudget, ReplayReadLimits, ReplayResource,
    },
    stack::{OverflowTable, PreparedOverflowRestore},
    trace_state::{
        AceReplay, AdviceReplay, BitwiseReplay, BlockAddressReplay, BlockStackReplay,
        CoreTraceFragmentContext, CoreTraceState, DecoderState, ExecutionContextReplay,
        ExecutionContextSystemInfo, ExecutionReplay, HasherRequestReplay, HasherResponseReplay,
        KernelReplay, MastForestResolutionReplay, MemoryReadsReplay, MemoryWritesReplay,
        RangeCheckerReplay, StackOverflowReplay, StackState, SystemState,
    },
    utils::split_u32_into_u16,
};
use crate::{
    AceError, ContextId, EMPTY_WORD, EnvironmentTraceLimits, ExecutionEnvironment, ExecutionError,
    FastProcessor, Felt, MIN_STACK_DEPTH, ONE, ResolutionSession, RowIndex, SessionBinding, Word,
    ZERO,
    continuation_stack::{Continuation, ContinuationStack},
    crypto::merkle::MerklePath,
    mast::{
        BasicBlockNode, ExecNode, JoinNode, LoopNode, MastForest, MastForestId, MastNode,
        MastNodeExt, MastNodeId, SparseMastForest, SparseMastForestBuilder, SplitNode, VisitKind,
    },
    processor::{Processor, StackInterface, SystemInterface},
    trace::chiplets::{
        CircuitEvaluation, PTR_OFFSET_ELEM, PTR_OFFSET_WORD,
        layout::{ControllerRow, LogicalControllerAddress},
    },
    tracer::{
        CycleProjection, KeyedEvent, KeyedEventKind, KeyedMode, KeyedTarget,
        OperationHelperRegisters, Tracer,
    },
    utils::Idx,
};

// STATE SNAPSHOT
// ================================================================================================

/// Execution state snapshot, used to record the state at the start of a trace fragment.
#[derive(Debug)]
struct StateSnapshot {
    state: CoreTraceState,
    /// Continuation stack with forest references already translated to [`MastForestId`]s into the
    /// `mast_forest_store` of the [`TraceReplay`] being built.
    continuation_stack: ContinuationStack<MastForestId>,
    /// The active forest at the start of this fragment, in `mast_forest_store`.
    initial_mast_forest_id: MastForestId,
}

// TRACE REPLAY
// ================================================================================================

#[derive(Debug)]
pub(crate) struct TraceReplay {
    pub(crate) environment: EnvironmentReplay,
    /// The original completed native input; native completion does not establish proof completion.
    pub(crate) resolution_session: ResolutionSession,
    /// The list of trace fragment contexts built during execution.
    pub(crate) core_trace_contexts: Vec<CoreTraceFragmentContext>,

    /// Sparse MAST forests, one per source [`MastForest`] visited during execution.
    ///
    /// Each entry contains only the [`MastNode`]s that were actually visited, while preserving the
    /// original [`MastNodeId`]s of the source forest. References from `CoreTraceFragmentContext`,
    /// `MastForestResolutionReplay`, and `HasherOp::HashBasicBlock` are encoded as
    /// [`MastForestId`]s into this vector.
    ///
    /// Serialized entries are trusted sparse replay data. Their node and digest maps are not
    /// checked against a source [`MastForest`] commitment on read; see
    /// <https://github.com/0xMiden/miden-vm/issues/3303>.
    pub(crate) mast_forest_store: Vec<Arc<SparseMastForest>>,

    // Replays that contain additional data needed to generate u32 range-lookup multiplicities and
    // chiplets columns.
    pub(crate) range_checker_replay: RangeCheckerReplay,
    pub(crate) memory_writes: MemoryWritesReplay,
    pub(crate) bitwise_replay: BitwiseReplay,
    pub(crate) hasher_for_chiplet: HasherRequestReplay,
    pub(crate) kernel_replay: KernelReplay,
    pub(crate) ace_replay: AceReplay,

    /// The number of rows per core trace fragment, except for the last fragment which may be
    /// shorter.
    pub(crate) fragment_size: usize,

    /// The maximum number of field elements allowed on the operand stack in an active execution
    /// context.
    pub(crate) max_stack_depth: usize,
}

impl TraceReplay {
    pub(crate) fn validate_export(
        &self,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<(), DeserializationError> {
        self.require_validated()
            .map_err(|e| DeserializationError::InvalidValue(format!("{e}")))?;
        if !self.hasher_for_chiplet.is_buffered() {
            return Err(DeserializationError::InvalidValue(
                "streamed hasher replay cannot be exported".into(),
            ));
        }
        let mut bytes = self
            .environment
            .retained_bytes()
            .and_then(|bytes| {
                bytes
                    .checked_add(self.resolution_session.counters().retained_bytes)
                    .ok_or(super::keyed::KeyedReplayError::LengthOverflow)
            })
            .map_err(|e| DeserializationError::InvalidValue(format!("{e}")))?;
        let mut events = 0usize;
        for fragment in &self.core_trace_contexts {
            bytes = bytes
                .checked_add(
                    fragment
                        .replay
                        .keyed
                        .retained_bytes()
                        .map_err(|e| DeserializationError::InvalidValue(format!("{e}")))?,
                )
                .ok_or_else(|| {
                    DeserializationError::InvalidValue("keyed export size overflow".into())
                })?;
            events = events.checked_add(fragment.replay.keyed.len()).ok_or_else(|| {
                DeserializationError::InvalidValue("keyed event count overflow".into())
            })?;
        }
        if bytes > trace_limits.max_retained_bytes
            || bytes > read_limits.max_validation_peak_bytes
            || events > trace_limits.max_events
        {
            return Err(DeserializationError::InvalidValue(
                "keyed export exceeds caller limits".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn write_payload<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(1);
        self.environment.write_into(target);
        target.write_usize(self.mast_forest_store.len());
        for forest in &self.mast_forest_store {
            forest.write_into(target);
        }
        self.core_trace_contexts.write_into(target);
        self.range_checker_replay.write_into(target);
        self.memory_writes.write_into(target);
        self.bitwise_replay.write_into(target);
        self.hasher_for_chiplet.write_into(target);
        self.kernel_replay.write_into(target);
        self.ace_replay.write_into(target);
        self.fragment_size.write_into(target);
        self.max_stack_depth.write_into(target);
    }
}

impl TraceReplay {
    pub(crate) fn read_with_limits<R: ByteReader>(
        source: &mut R,
        environment: &ExecutionEnvironment,
        trace_limits: EnvironmentTraceLimits,
        read_limits: ReplayReadLimits,
    ) -> Result<Self, DeserializationError> {
        if source.read_u8()? != 1 {
            return Err(DeserializationError::InvalidValue(
                "missing keyed environment metadata".into(),
            ));
        }
        let mut budget = ReplayReadBudget::new(trace_limits, read_limits);
        let environment_replay = EnvironmentReplay::read_with_limits(source, &mut budget)
            .map_err(|e| DeserializationError::InvalidValue(format!("{e}")))?;
        let store_len = source.read_usize()?;
        let max_store_len = source.max_alloc(SparseMastForest::min_serialized_size());
        if store_len > max_store_len {
            return Err(DeserializationError::InvalidValue(format!(
                "MAST forest store length {store_len} exceeds reader allocation bound {max_store_len}"
            )));
        }

        let mut mast_forest_store = Vec::with_capacity(store_len);
        for _ in 0..store_len {
            mast_forest_store.push(Arc::new(SparseMastForest::read_from(source)?));
        }

        let fragment_count = source.read_usize()?;
        if fragment_count > source.max_alloc(CoreTraceFragmentContext::min_serialized_size()) {
            return Err(DeserializationError::InvalidValue(
                "trace fragment count exceeds reader bound".into(),
            ));
        }
        let mut core_trace_contexts = Vec::new();
        core_trace_contexts.try_reserve_exact(fragment_count).map_err(|_| {
            DeserializationError::InvalidValue("trace fragment allocation failed".into())
        })?;
        for _ in 0..fragment_count {
            core_trace_contexts
                .push(CoreTraceFragmentContext::read_with_limits(source, &mut budget)?);
        }
        // Keep decoded fields local until structure and native authority are fully validated.
        let range_checker_replay = RangeCheckerReplay::read_from(source)?;
        let memory_writes = MemoryWritesReplay::read_from(source)?;
        let bitwise_replay = BitwiseReplay::read_from(source)?;
        let hasher_for_chiplet = HasherRequestReplay::read_from(source)?;
        let kernel_replay = KernelReplay::read_from(source)?;
        let ace_replay = AceReplay::read_from(source)?;
        let fragment_size = usize::read_from(source)?;
        let max_stack_depth = usize::read_from(source)?;
        validate_trace_generation_context_invariants(
            fragment_size,
            max_stack_depth,
            &core_trace_contexts,
        )?;
        validate_trace_generation_context_forest_ids(
            mast_forest_store.len(),
            &core_trace_contexts,
            &hasher_for_chiplet,
        )?;
        let mut environment_replay = environment_replay;
        let resolution_session = environment_replay
            .revalidate(
                environment,
                &mut core_trace_contexts,
                trace_limits,
                read_limits,
                fragment_size,
            )
            .map_err(|e| DeserializationError::InvalidValue(format!("{e}")))?;
        Ok(Self {
            environment: environment_replay,
            resolution_session,
            mast_forest_store,
            core_trace_contexts,
            range_checker_replay,
            memory_writes,
            bitwise_replay,
            hasher_for_chiplet,
            kernel_replay,
            ace_replay,
            fragment_size,
            max_stack_depth,
        })
    }
}

impl TraceReplay {
    pub(crate) fn require_validated(&self) -> Result<(), ExecutionError> {
        self.environment
            .require_completed_session(&self.resolution_session)
            .map_err(keyed_error)?;
        for context in &self.core_trace_contexts {
            context.replay.keyed.require_validated().map_err(keyed_error)?;
        }
        Ok(())
    }

    pub(crate) fn entry_implementation(
        &self,
    ) -> Result<miden_core::program::ImplementationRoot, ExecutionError> {
        Ok(self.environment.entry().map_err(keyed_error)?.implementation_root())
    }
}

fn validate_trace_generation_context_invariants(
    fragment_size: usize,
    max_stack_depth: usize,
    core_trace_contexts: &[CoreTraceFragmentContext],
) -> Result<(), DeserializationError> {
    if fragment_size == 0 {
        return Err(DeserializationError::InvalidValue(
            "trace generation fragment_size must be non-zero".into(),
        ));
    }
    if max_stack_depth < MIN_STACK_DEPTH {
        return Err(DeserializationError::InvalidValue(format!(
            "trace generation max_stack_depth {} is below minimum {MIN_STACK_DEPTH}",
            max_stack_depth
        )));
    }
    for (fragment_index, fragment) in core_trace_contexts.iter().enumerate() {
        let stack_depth = fragment.state.stack.stack_depth();
        if stack_depth > max_stack_depth {
            return Err(DeserializationError::InvalidValue(format!(
                "fragment {fragment_index}: stack depth {stack_depth} exceeds max_stack_depth {}",
                max_stack_depth
            )));
        }
    }
    Ok(())
}

fn validate_trace_generation_context_forest_ids(
    store_len: usize,
    core_trace_contexts: &[CoreTraceFragmentContext],
    hasher_for_chiplet: &HasherRequestReplay,
) -> Result<(), DeserializationError> {
    for (fragment_index, fragment) in core_trace_contexts.iter().enumerate() {
        validate_mast_forest_id(
            fragment.initial_mast_forest_id,
            store_len,
            "core trace fragment initial_mast_forest_id",
        )?;
        for forest_id in fragment.continuation.iter_enter_forest_ids() {
            validate_mast_forest_id(
                forest_id,
                store_len,
                "core trace fragment continuation EnterForest",
            )
            .map_err(|err| {
                DeserializationError::InvalidValue(format!("fragment {fragment_index}: {err}"))
            })?;
        }
        for forest_id in fragment.replay.mast_forest_resolution.iter_forest_ids() {
            validate_mast_forest_id(
                forest_id,
                store_len,
                "core trace fragment MastForestResolutionReplay",
            )
            .map_err(|err| {
                DeserializationError::InvalidValue(format!("fragment {fragment_index}: {err}"))
            })?;
        }
    }

    for forest_id in hasher_for_chiplet.iter_hash_basic_block_forest_ids() {
        validate_mast_forest_id(forest_id, store_len, "hasher HashBasicBlock replay")?;
    }

    Ok(())
}

fn validate_mast_forest_id(
    forest_id: MastForestId,
    store_len: usize,
    label: &str,
) -> Result<(), DeserializationError> {
    if forest_id.to_usize() >= store_len {
        return Err(DeserializationError::InvalidValue(format!(
            "{label} id {} is out of range for mast_forest_store length {store_len}",
            u32::from(forest_id)
        )));
    }
    Ok(())
}

/// Builder for recording the context to generate trace fragments during execution.
///
/// Specifically, this records the information necessary to be able to generate the trace in
/// fragments of configurable length. This requires storing state at the very beginning of the
/// fragment before any operations are executed, as well as recording the various values read during
/// execution in the corresponding "replays" (e.g. values read from memory are recorded in
/// `MemoryReadsReplay`, values read from the advice provider are recorded in `AdviceReplay``, etc).
///
/// Then, to generate a trace fragment, we initialize the state of the processor using the stored
/// snapshot from the beginning of the fragment, and replay the recorded values as they are
/// encountered during execution (e.g. when encountering a memory read operation, we will replay the
/// value rather than querying the memory chiplet).
#[derive(Debug)]
pub struct ExecutionTracer {
    trace_limits: EnvironmentTraceLimits,
    entry: Option<(miden_core::program::ExecutionDescriptor, SessionBinding)>,
    environment: Option<EnvironmentReplay>,
    keyed: KeyedReplay,
    keyed_events: usize,
    keyed_retained_bytes: usize,
    validation_work: usize,
    pending_keyed: Option<(PreparedKeyedRecord, KeyedEvent, Option<KeyedReplay>)>,
    prepared_keyed_cycle: Option<(KeyedEventKind, ProcedureKey)>,
    active_keyed_event: Option<KeyedEvent>,
    prepared_fragment_replays: Option<PreparedFragmentReplays>,
    keyed_reservation_pending: bool,
    keyed_invalidated: bool,
    pending_environment: Option<PreparedEnvironmentReplay>,
    prepared_snapshot: Option<StateSnapshot>,
    // State stored at the start of a core trace fragment.
    //
    // This field is only set to `None` at initialization, and is populated when starting a new
    // trace fragment with `Self::start_new_fragment_context()`. Hence, on the first call to
    // `Self::start_new_fragment_context()`, we don't extract a new `TraceFragmentContext`, but in
    // every other call, we do.
    state_snapshot: Option<StateSnapshot>,

    // Replay data aggregated throughout the execution of a core trace fragment
    overflow_table: OverflowTable,
    overflow_replay: StackOverflowReplay,

    block_stack: BlockStack,
    block_stack_replay: BlockStackReplay,
    execution_context_replay: ExecutionContextReplay,

    hasher_chiplet_shim: HasherChipletShim,
    memory_reads: MemoryReadsReplay,
    advice: AdviceReplay,
    external: MastForestResolutionReplay,

    // Replays that contain additional data needed to generate u32 range-lookup multiplicities and
    // chiplets columns.
    range_checker: RangeCheckerReplay,
    memory_writes: MemoryWritesReplay,
    bitwise: BitwiseReplay,
    kernel: KernelReplay,
    hasher_for_chiplet: HasherRequestReplay,
    ace: AceReplay,

    // Output
    fragment_contexts: Vec<CoreTraceFragmentContext>,

    /// Per-source-forest sparse builders, indexed by `mast_forest_indices`.
    ///
    /// Each builder accumulates the [`MastNodeId`]s of nodes visited inside its source forest
    /// during execution, and is finalized into an [`Arc<SparseMastForest>`] in
    /// [`Self::into_trace_replay`].
    mast_forest_builders: Vec<SparseMastForestBuilder>,

    /// Maps a source forest's `Arc::as_ptr` identity to its [`MastForestId`] in
    /// `mast_forest_builders` (and, by construction, the eventual id in
    /// `TraceReplay::mast_forest_store`).
    ///
    /// Pointer identity is sound here because the trace-generation flow never crosses a process
    /// boundary: the tracer builds the store and the replay processor consumes it in the same
    /// run.
    mast_forest_ids: Vec<(*const MastForest, MastForestId)>,

    /// The number of rows per core trace fragment.
    fragment_size: usize,

    /// The maximum number of field elements allowed on the operand stack in an active execution
    /// context.
    max_stack_depth: usize,

    /// Caller overflow frame checked before a Call/Syscall/Dyncall END is published.
    prepared_restore_context: Option<PreparedOverflowRestore>,
    /// Prepared frame moved here at start and consumed after the VM return commits.
    pending_restore_context: Option<PreparedOverflowRestore>,

    /// Flag set in `start_clock_cycle` when an `EvalCircuit` operation is encountered, consumed
    /// in `finalize_clock_cycle` to record the memory reads performed by the operation.
    is_eval_circuit_op: bool,

    /// Infallible Tracer hooks report checked address failures at cycle finalization.
    pending_address_error: Option<ExecutionError>,
}

/// Empty replacement queues reserved for the first row after a fragment drain.
#[derive(Debug, Default)]
struct PreparedFragmentReplays {
    block_addresses: BlockAddressReplay,
    block_stack: BlockStackReplay,
    execution_context: ExecutionContextReplay,
    overflow: StackOverflowReplay,
    memory_reads: MemoryReadsReplay,
}

impl ExecutionTracer {
    /// Creates a tracer whose hasher-chiplet requests stream to `hasher_sender` as they are
    /// recorded, instead of buffering for post-execution replay. Everything else records as in
    /// [`Self::new`].
    #[cfg(feature = "std")]
    pub(crate) fn new_with_streamed_hasher(
        fragment_size: usize,
        max_stack_depth: usize,
        hasher_sender: std::sync::mpsc::Sender<crate::trace::ResolvedHasherOp<'static>>,
        trace_limits: EnvironmentTraceLimits,
    ) -> Result<Self, ExecutionError> {
        let mut tracer = Self::new(fragment_size, max_stack_depth, trace_limits)?;
        tracer.hasher_for_chiplet = HasherRequestReplay::streamed(hasher_sender);
        Ok(tracer)
    }

    /// Creates a new `ExecutionTracer` with the given fragment size.
    #[inline(always)]
    pub fn new(
        fragment_size: usize,
        max_stack_depth: usize,
        trace_limits: EnvironmentTraceLimits,
    ) -> Result<Self, ExecutionError> {
        if fragment_size == 0 || max_stack_depth < MIN_STACK_DEPTH {
            return Err(ExecutionError::Internal("invalid keyed trace configuration"));
        }
        Ok(Self {
            trace_limits,
            entry: None,
            environment: None,
            keyed: KeyedReplay::default(),
            keyed_events: 0,
            keyed_retained_bytes: 0,
            validation_work: 0,
            pending_keyed: None,
            prepared_keyed_cycle: None,
            active_keyed_event: None,
            prepared_fragment_replays: None,
            keyed_reservation_pending: false,
            keyed_invalidated: false,
            pending_environment: None,
            prepared_snapshot: None,
            state_snapshot: None,
            overflow_table: OverflowTable::default(),
            overflow_replay: StackOverflowReplay::default(),
            block_stack: BlockStack::default(),
            block_stack_replay: BlockStackReplay::default(),
            execution_context_replay: ExecutionContextReplay::default(),
            hasher_chiplet_shim: HasherChipletShim::default(),
            memory_reads: MemoryReadsReplay::default(),
            range_checker: RangeCheckerReplay::default(),
            memory_writes: MemoryWritesReplay::default(),
            advice: AdviceReplay::default(),
            bitwise: BitwiseReplay::default(),
            kernel: KernelReplay::default(),
            hasher_for_chiplet: HasherRequestReplay::default(),
            ace: AceReplay::default(),
            external: MastForestResolutionReplay::default(),
            fragment_contexts: Vec::new(),
            mast_forest_builders: Vec::new(),
            mast_forest_ids: Vec::new(),
            fragment_size,
            max_stack_depth,
            prepared_restore_context: None,
            pending_restore_context: None,
            is_eval_circuit_op: false,
            pending_address_error: None,
        })
    }

    /// Returns the [`MastForestId`] of `forest` in [`Self::mast_forest_builders`], creating a new
    /// builder for it on first encounter. Forests are identified by `Arc::as_ptr`.
    #[inline]
    fn forest_id(&mut self, forest: &Arc<MastForest>) -> MastForestId {
        let key = Arc::as_ptr(forest);
        let position =
            match self.mast_forest_ids.binary_search_by_key(&key, |(pointer, _)| *pointer) {
                Ok(position) => return self.mast_forest_ids[position].1,
                Err(position) => position,
            };
        let id = MastForestId::from(self.mast_forest_builders.len() as u32);
        self.mast_forest_builders.push(SparseMastForestBuilder::new(forest.clone()));
        self.mast_forest_ids.insert(position, (key, id));
        id
    }

    /// Records that the node with id `node_id` was visited inside `forest`. Also records the
    /// node's immediate children (if any) as digest-only references.
    ///
    /// The parent is recorded as a [`VisitKind::FullVisit`] so its full [`MastNode`] is available
    /// at replay time. Children are recorded as [`VisitKind::DigestOnly`] because trace
    /// generation only needs their digest when building the parent's trace row (e.g. a Split
    /// node needs the digest of *both* branches even if only one is taken; a Join needs both
    /// children's digests; a Call needs the callee's digest). If a child is later actually
    /// entered, a subsequent `record_visit` call promotes it to a full visit.
    ///
    /// Keeping un-entered children as digest-only means accidental entry into a pruned node
    /// surfaces as a clean `get_node_by_id` miss rather than a partially-populated node.
    #[inline]
    fn record_visit(&mut self, forest: &Arc<MastForest>, node_id: MastNodeId) {
        let id = self.forest_id(forest);
        self.mast_forest_builders[id.to_usize()].record_visit(node_id, VisitKind::FullVisit);

        if let Some(node) = forest.get_node_by_id(node_id) {
            node.for_each_child(|child_id| {
                self.mast_forest_builders[id.to_usize()]
                    .record_visit(child_id, VisitKind::DigestOnly);
            });
        }
    }

    /// Translates a live continuation stack carrying `Arc<MastForest>` references into one carrying
    /// [`MastForestId`]s into `mast_forest_builders`.
    fn translate_continuation_stack(
        &mut self,
        live: ContinuationStack<Arc<MastForest>>,
    ) -> ContinuationStack<MastForestId> {
        let mut translated: ContinuationStack<MastForestId> = ContinuationStack::default();
        for cont in live.into_inner() {
            let translated_cont = match cont {
                Continuation::EnterForest {
                    forest,
                    package_debug_info,
                    inline_context_depth,
                } => Continuation::EnterForest {
                    forest: self.forest_id(&forest),
                    package_debug_info,
                    inline_context_depth,
                },
                Continuation::StartNode(id) => Continuation::StartNode(id),
                Continuation::FinishJoin(id) => Continuation::FinishJoin(id),
                Continuation::FinishSplit(id) => Continuation::FinishSplit(id),
                Continuation::FinishLoop(node_id) => Continuation::FinishLoop(node_id),
                Continuation::FinishCall(id) => Continuation::FinishCall(id),
                Continuation::FinishDyn(id) => Continuation::FinishDyn(id),
                Continuation::FinishExec(id) => Continuation::FinishExec(id),
                Continuation::RootBoundary { implementation, principal } => {
                    Continuation::RootBoundary { implementation, principal }
                },
                Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                    Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch }
                },
                Continuation::Respan { node_id, batch_index } => {
                    Continuation::Respan { node_id, batch_index }
                },
                Continuation::FinishBasicBlock(id) => Continuation::FinishBasicBlock(id),
            };
            translated.push_continuation(translated_cont);
        }
        translated
    }

    /// Converts the `ExecutionTracer` into a [`TraceReplay`] using the data accumulated during
    /// execution.
    #[inline(always)]
    pub(crate) fn into_trace_replay(
        mut self,
        resolution_session: ResolutionSession,
    ) -> Result<TraceReplay, ExecutionError> {
        if self.pending_keyed.is_some()
            || self.pending_environment.is_some()
            || self.keyed_reservation_pending
            || self.keyed_invalidated
            || self.pending_address_error.is_some()
            || self.pending_restore_context.is_some()
            || self.active_keyed_event.is_some()
            || self.prepared_keyed_cycle.is_some()
            || self.prepared_restore_context.is_some()
            || self.prepared_fragment_replays.is_some()
            || self.prepared_snapshot.is_some()
        {
            return Err(ExecutionError::InvalidExecutionState);
        }
        self.environment
            .as_ref()
            .ok_or(ExecutionError::InvalidExecutionState)?
            .require_completed_session(&resolution_session)
            .map_err(keyed_error)?;
        // If there is an ongoing trace state being built, finish it
        self.finish_current_fragment_context();

        // Finalize each per-source-forest builder into a `SparseMastForest`. Indices stored on
        // fragments and replays line up with the position in this vector by construction (the
        // builders were appended in the same order the indices were assigned).
        let mast_forest_store = self
            .mast_forest_builders
            .into_iter()
            .map(|builder| Arc::new(builder.finalize()))
            .collect();

        let environment = self.environment.take().ok_or(ExecutionError::InvalidExecutionState)?;
        for fragment in &self.fragment_contexts {
            fragment.replay.keyed.require_validated().map_err(keyed_error)?;
        }
        Ok(TraceReplay {
            environment,
            resolution_session,
            core_trace_contexts: self.fragment_contexts,
            mast_forest_store,
            range_checker_replay: self.range_checker,
            memory_writes: self.memory_writes,
            bitwise_replay: self.bitwise,
            kernel_replay: self.kernel,
            hasher_for_chiplet: self.hasher_for_chiplet,
            ace_replay: self.ace,
            fragment_size: self.fragment_size,
            max_stack_depth: self.max_stack_depth,
        })
    }

    // HELPERS
    // -------------------------------------------------------------------------------------------

    /// Captures the internal state into a new [TraceFragmentContext] (stored internally), resets
    /// the internal replay state of the builder, and records a new state snapshot, marking the
    /// beginning of the next trace state.
    ///
    /// This must be called at the beginning of a new trace fragment, before executing the first
    /// operation. Internal replay fields are expected to be accessed during execution of this new
    /// fragment to record data to be replayed by the trace fragment generators.
    #[inline(always)]
    fn start_new_fragment_context(
        &mut self,
        system_state: SystemState,
        stack_top: [Felt; MIN_STACK_DEPTH],
        mut continuation_stack: ContinuationStack<Arc<MastForest>>,
        continuation: Continuation<Arc<MastForest>>,
        current_forest: Arc<MastForest>,
    ) {
        // If there is an ongoing snapshot, finish it
        self.finish_current_fragment_context();

        // Start a new snapshot
        let decoder_state = {
            if self.block_stack.is_empty() {
                DecoderState {
                    current_addr: LogicalControllerAddress::ABSENT,
                    parent_addr: LogicalControllerAddress::ABSENT,
                }
            } else {
                let block_info = self.block_stack.peek();

                DecoderState {
                    current_addr: block_info.addr,
                    parent_addr: block_info.parent_addr,
                }
            }
        };
        let stack = {
            let stack_depth = MIN_STACK_DEPTH + self.overflow_table.num_elements_in_current_ctx();
            let last_overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
            StackState::new(stack_top, stack_depth, last_overflow_addr)
        };

        // Push new continuation corresponding to the current execution state
        continuation_stack.push_continuation(continuation);

        // Translate the live `Arc<MastForest>`-bearing continuation stack into one indexed by
        // `MastForestId` into `mast_forest_builders`, registering any newly-encountered forests
        // along the way.
        let initial_mast_forest_id = self.forest_id(&current_forest);
        let translated_stack = self.translate_continuation_stack(continuation_stack);

        self.state_snapshot = Some(StateSnapshot {
            state: CoreTraceState {
                system: system_state,
                decoder: decoder_state,
                stack,
            },
            continuation_stack: translated_stack,
            initial_mast_forest_id,
        });
    }

    #[inline(always)]
    fn record_control_node_start<P: Processor>(
        &mut self,
        node: &MastNode,
        processor: &P,
        current_forest: &MastForest,
    ) {
        let result = self.hasher_chiplet_shim.record_hash_control_block();
        let Some(block_addr) = self.record_address_result(result) else {
            return;
        };
        let ctx_info = match node {
            MastNode::Join(node) => {
                let child1_hash = current_forest
                    .get_node_by_id(node.first())
                    .expect("join node's first child expected to be in the forest")
                    .digest();
                let child2_hash = current_forest
                    .get_node_by_id(node.second())
                    .expect("join node's second child expected to be in the forest")
                    .digest();
                self.hasher_for_chiplet.record_hash_control_block(
                    child1_hash,
                    child2_hash,
                    JoinNode::DOMAIN,
                    node.digest(),
                );

                None
            },
            MastNode::Split(node) => {
                let child1_hash = current_forest
                    .get_node_by_id(node.on_true())
                    .expect("split node's true child expected to be in the forest")
                    .digest();
                let child2_hash = current_forest
                    .get_node_by_id(node.on_false())
                    .expect("split node's false child expected to be in the forest")
                    .digest();
                self.hasher_for_chiplet.record_hash_control_block(
                    child1_hash,
                    child2_hash,
                    SplitNode::DOMAIN,
                    node.digest(),
                );

                None
            },
            MastNode::Loop(node) => {
                let body_hash = current_forest
                    .get_node_by_id(node.body())
                    .expect("loop node's body expected to be in the forest")
                    .digest();

                self.hasher_for_chiplet.record_hash_control_block(
                    body_hash,
                    EMPTY_WORD,
                    LoopNode::DOMAIN,
                    node.digest(),
                );

                None
            },
            MastNode::Exec(node) => {
                self.hasher_for_chiplet.record_hash_control_block(
                    node.target().into_word(),
                    EMPTY_WORD,
                    ExecNode::DOMAIN,
                    node.digest(),
                );
                None
            },
            MastNode::Call(node) => {
                self.hasher_for_chiplet.record_hash_control_block(
                    node.target().into_word(),
                    EMPTY_WORD,
                    node.domain(),
                    node.digest(),
                );

                let overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
                Some(ExecutionContextInfo::new(
                    processor.system().ctx(),
                    processor.system().caller_hash(),
                    processor.stack().depth(),
                    overflow_addr,
                ))
            },
            MastNode::Dyn(dyn_node) => {
                self.hasher_for_chiplet.record_hash_control_block(
                    EMPTY_WORD,
                    EMPTY_WORD,
                    dyn_node.domain(),
                    dyn_node.digest(),
                );

                if dyn_node.is_dyncall() {
                    // DYNCALL drops the top stack element (the memory address holding the
                    // callee hash) and records the stack state *after* the drop as the new
                    // context.
                    //
                    // `record_control_node_start()` is called *before* `decrement_stack_size()`,
                    // so we must compute the post-drop overflow address without actually
                    // performing the pop.  We use `clk_after_pop_in_current_ctx()` which
                    // returns the clock of the second-to-last overflow entry (i.e. what
                    // `last_update_clk_in_current_ctx()` would return after the pop), or ZERO
                    // when the overflow stack has ≤1 entry and would become empty.
                    //
                    // When the stack is already at MIN_STACK_DEPTH the drop does not reduce
                    // the depth and the overflow address is ZERO — mirroring the same guard
                    // already present in the parallel-tracer path.  See #2813 / PR #2904.
                    let (stack_depth_after_drop, overflow_addr) =
                        if Processor::stack(processor).depth() > MIN_STACK_DEPTH as u32 {
                            (
                                processor.stack().depth() - 1,
                                self.overflow_table.clk_after_pop_in_current_ctx(),
                            )
                        } else {
                            (processor.stack().depth(), ZERO)
                        };
                    Some(ExecutionContextInfo::new(
                        processor.system().ctx(),
                        processor.system().caller_hash(),
                        stack_depth_after_drop,
                        overflow_addr,
                    ))
                } else {
                    None
                }
            },
            MastNode::Block(_) => panic!(
                "`ExecutionTracer::record_basic_block_start()` must be called instead for basic blocks"
            ),
            MastNode::External(_) => panic!(
                "External nodes are guaranteed to be resolved before record_control_node_start is called"
            ),
        };

        let parent_addr = self.block_stack.push(block_addr, ctx_info);
        self.block_stack_replay.record_node_start_parent_addr(parent_addr);
    }

    fn record_address_result<T>(&mut self, result: Result<T, ExecutionError>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.pending_address_error.get_or_insert(error);
                None
            },
        }
    }

    /// Records the block address for an END operation based on the block being popped.
    #[inline(always)]
    fn record_node_end(&mut self, block_info: &BlockInfo) {
        let (prev_addr, prev_parent_addr) = if self.block_stack.is_empty() {
            (LogicalControllerAddress::ABSENT, LogicalControllerAddress::ABSENT)
        } else {
            let prev_block = self.block_stack.peek();
            (prev_block.addr, prev_block.parent_addr)
        };
        self.block_stack_replay
            .record_node_end(block_info.addr, prev_addr, prev_parent_addr);
    }

    /// Records the execution context system info for CALL/SYSCALL/DYNCALL operations.
    #[inline(always)]
    fn record_execution_context(&mut self, ctx_info: ExecutionContextSystemInfo) {
        self.execution_context_replay.record_execution_context(ctx_info);
    }

    /// Records the current core trace state, if any.
    ///
    /// Specifically, extracts the stored [SnapshotStart] as well as all the replay data recorded
    /// from the various components (e.g. memory, advice, etc) since the last call to this method.
    /// Resets the internal state to default values to prepare for the next trace fragment.
    ///
    /// Note that the very first time that this is called (at clock cycle 0), the snapshot will not
    /// contain any replay data, and so no core trace state will be recorded.
    #[inline(always)]
    fn finish_current_fragment_context(&mut self) {
        if let Some(snapshot) = self.state_snapshot.take() {
            // Extract the replays
            let (hasher_replay, block_addr_replay) = self.hasher_chiplet_shim.extract_replay();
            let memory_reads_replay = core::mem::take(&mut self.memory_reads);
            let advice_replay = core::mem::take(&mut self.advice);
            let external_replay = core::mem::take(&mut self.external);
            let stack_overflow_replay = core::mem::take(&mut self.overflow_replay);
            let block_stack_replay = core::mem::take(&mut self.block_stack_replay);
            let execution_context_replay = core::mem::take(&mut self.execution_context_replay);

            let trace_state = CoreTraceFragmentContext {
                state: snapshot.state,
                replay: ExecutionReplay {
                    keyed: core::mem::take(&mut self.keyed),
                    hasher: hasher_replay,
                    block_address: block_addr_replay,
                    memory_reads: memory_reads_replay,
                    advice: advice_replay,
                    mast_forest_resolution: external_replay,
                    stack_overflow: stack_overflow_replay,
                    block_stack: block_stack_replay,
                    execution_context: execution_context_replay,
                },
                continuation: snapshot.continuation_stack,
                initial_mast_forest_id: snapshot.initial_mast_forest_id,
            };

            self.fragment_contexts.push(trace_state);
        }
    }

    /// Pushes the value at stack position 15 onto the overflow table. This must be called in
    /// `Tracer::start_clock_cycle()` *before* the processor increments the stack size, where stack
    /// position 15 at the start of the clock cycle corresponds to the element that overflows.
    #[inline(always)]
    fn increment_stack_size(&mut self, processor: &FastProcessor) {
        let new_overflow_value = processor.stack_get(15);
        self.overflow_table.push(new_overflow_value, processor.system().clock());
    }

    /// Pops a value from the overflow table and records it for replay.
    #[inline(always)]
    fn decrement_stack_size(&mut self) {
        if let Some(popped_value) = self.overflow_table.pop() {
            let new_overflow_addr = self.overflow_table.last_update_clk_in_current_ctx();
            self.overflow_replay.record_pop_overflow(popped_value, new_overflow_addr);
        }
    }
}

/// Owned reservations are unpublished until their matching infallible hook consumes them.
pub struct ExecutionTraceReservation(ExecutionTraceReservationKind);

// Keep the unpublished reservation inline: boxing would introduce a separate allocation outside
// trace preparation's checked resource reservations. Its bounded stack footprint is deliberate.
#[allow(clippy::large_enum_variant)]
enum ExecutionTraceReservationKind {
    Entry(miden_core::program::ExecutionDescriptor, SessionBinding),
    Completion,
    Event {
        record: PreparedKeyedRecord,
        forest: Option<(MastForestId, SparseMastForestBuilder)>,
        queue: Option<KeyedReplay>,
    },
}

fn keyed_error(error: super::keyed::KeyedReplayError) -> ExecutionError {
    ExecutionError::KeyedTrace(error)
}

impl Tracer for ExecutionTracer {
    type Processor = FastProcessor;
    type Forest = Arc<MastForest>;
    type KeyedReservation = ExecutionTraceReservation;

    fn prepare_environment(
        &mut self,
        descriptor: &miden_core::program::ExecutionDescriptor,
        entry: SessionBinding,
    ) -> Result<Self::KeyedReservation, ExecutionError> {
        if self.entry.is_some() || entry.procedure_key() != descriptor.entry_key() {
            return Err(ExecutionError::InvalidExecutionState);
        }
        let bytes = size_of::<miden_core::program::ExecutionDescriptor>()
            .checked_add(size_of::<SessionBinding>())
            .ok_or(ExecutionError::InvalidExecutionState)?;
        for (resource, limit) in [
            (ReplayResource::RetainedBytes, self.trace_limits.max_retained_bytes),
            (ReplayResource::PreparePeakBytes, self.trace_limits.max_prepare_peak_bytes),
        ] {
            if bytes > limit {
                return Err(keyed_error(KeyedReplayError::LimitExceeded {
                    resource,
                    limit,
                    requested: bytes,
                }));
            }
        }
        Ok(ExecutionTraceReservation(ExecutionTraceReservationKind::Entry(
            *descriptor,
            entry,
        )))
    }

    fn commit_environment(&mut self, reservation: Self::KeyedReservation) {
        let ExecutionTraceReservationKind::Entry(descriptor, entry) = reservation.0 else {
            unreachable!("entry reservation kind");
        };
        self.keyed_retained_bytes =
            size_of::<miden_core::program::ExecutionDescriptor>() + size_of::<SessionBinding>();
        self.entry = Some((descriptor, entry));
    }

    fn prepare_environment_completion(
        &mut self,
        environment: &ExecutionEnvironment,
        session: &ResolutionSession,
    ) -> Result<Self::KeyedReservation, ExecutionError> {
        if self.keyed_reservation_pending || self.pending_keyed.is_some() || self.keyed_invalidated
        {
            return Err(ExecutionError::InvalidExecutionState);
        }
        self.pending_environment = None;
        let (descriptor, entry) = self.entry.ok_or(ExecutionError::InvalidExecutionState)?;
        if descriptor != environment.descriptor() || self.environment.is_some() {
            return Err(ExecutionError::InvalidExecutionState);
        }
        let staged = EnvironmentReplay::prepare_capture(
            session,
            entry,
            self.trace_limits,
            self.keyed_retained_bytes,
            self.keyed_retained_bytes,
            self.validation_work,
        )
        .map_err(keyed_error)?;
        self.pending_environment = Some(staged);
        Ok(ExecutionTraceReservation(ExecutionTraceReservationKind::Completion))
    }

    fn commit_environment_completion(&mut self, reservation: Self::KeyedReservation) {
        let ExecutionTraceReservationKind::Completion = reservation.0 else {
            unreachable!("completion reservation kind");
        };
        let staged = self.pending_environment.take().expect("prepared environment snapshot");
        self.keyed_retained_bytes += staged.retained_bytes();
        self.validation_work = staged.validation_work();
        self.environment = Some(staged.commit());
    }

    fn prepare_keyed_transition(
        &mut self,
        processor: &FastProcessor,
        event: &KeyedEvent,
        target: KeyedTarget<'_, Arc<MastForest>>,
        projection: CycleProjection,
    ) -> Result<Self::KeyedReservation, ExecutionError> {
        if self.pending_keyed.is_some()
            || self.keyed_reservation_pending
            || self.keyed_invalidated
            || event.use_record.row() != projection.row
            || processor.system().clock() != projection.row
            || event.use_record.implementation_root() != target.implementation
            || processor.system().caller_hash() != *event.principal_before.as_word()
            || target.forest.get_node_by_id(target.root).is_none_or(|node| {
                node.is_external() || node.digest() != *target.implementation.as_word()
            })
            || !target
                .forest
                .is_procedure_root_with_exact_digest(target.root, *target.implementation.as_word())
        {
            return Err(ExecutionError::Internal(
                "keyed trace target or row differs from activation",
            ));
        }
        if self.prepared_keyed_cycle != Some((event.kind, event.use_record.procedure_key()))
            || match event.kind {
                KeyedEventKind::Invoke(KeyedMode::Call | KeyedMode::DynCall) => {
                    event.principal_after != event.use_record.procedure_key()
                },
                KeyedEventKind::Invoke(_) => event.principal_before != event.principal_after,
                KeyedEventKind::RootEnd => {
                    Some(event.principal_after)
                        != self.prepared_keyed_cycle.map(|(_, principal)| principal)
                },
            }
        {
            return Err(ExecutionError::Internal("keyed event differs from actual trace mode"));
        }
        if matches!(event.kind, KeyedEventKind::RootEnd) != self.pending_environment.is_some() {
            return Err(ExecutionError::InvalidExecutionState);
        }
        let existing_forest = self
            .mast_forest_ids
            .binary_search_by_key(&Arc::as_ptr(target.forest), |(pointer, _)| *pointer)
            .ok()
            .map(|position| self.mast_forest_ids[position].1);
        let (forest, staged_forest) = if let Some(id) = existing_forest {
            (id, None)
        } else {
            let id = u32::try_from(self.mast_forest_builders.len())
                .map(MastForestId::from)
                .map_err(|_| ExecutionError::Internal("MAST forest ID exhausted"))?;
            self.mast_forest_builders
                .try_reserve(1)
                .map_err(|_| ExecutionError::Internal("forest builder allocation failed"))?;
            self.mast_forest_ids
                .try_reserve(1)
                .map_err(|_| ExecutionError::Internal("forest index allocation failed"))?;
            (id, Some((id, SparseMastForestBuilder::new(target.forest.clone()))))
        };
        let staged_bytes = self.pending_environment.as_ref().map_or(0, |p| p.retained_bytes());
        let native_retained_bytes =
            self.pending_environment.as_ref().map_or(0, |p| p.native_retained_bytes());
        let total_bytes = self
            .keyed_retained_bytes
            .checked_add(staged_bytes)
            .ok_or(ExecutionError::InvalidExecutionState)?;
        let mut prospective_queue = projection
            .row
            .as_usize()
            .is_multiple_of(self.fragment_size)
            .then(KeyedReplay::default);
        let queue = prospective_queue.as_mut().unwrap_or(&mut self.keyed);
        let reservation = queue
            .prepare_record(
                *event,
                forest,
                target.root,
                self.trace_limits,
                self.keyed_events,
                (total_bytes, native_retained_bytes),
            )
            .map_err(keyed_error)?;
        reservation.check_queue(queue).map_err(keyed_error)?;
        self.keyed_reservation_pending = true;
        Ok(ExecutionTraceReservation(ExecutionTraceReservationKind::Event {
            record: reservation,
            forest: staged_forest,
            queue: prospective_queue,
        }))
    }

    fn commit_keyed_transition(&mut self, reservation: Self::KeyedReservation, event: KeyedEvent) {
        let ExecutionTraceReservationKind::Event { record, forest, queue } = reservation.0 else {
            unreachable!("event reservation kind");
        };
        if !self.keyed_reservation_pending
            || self.pending_keyed.is_some()
            || record.check_queue(queue.as_ref().unwrap_or(&self.keyed)).is_err()
        {
            self.keyed_invalidated = true;
            self.keyed_reservation_pending = false;
            return;
        }
        self.keyed_reservation_pending = false;
        if let Some((id, builder)) = forest {
            let pointer = Arc::as_ptr(builder.source());
            let position = self
                .mast_forest_ids
                .binary_search_by_key(&pointer, |(pointer, _)| *pointer)
                .expect_err("prepared forest is absent until commit");
            self.mast_forest_ids.insert(position, (pointer, id));
            self.mast_forest_builders.push(builder);
        }
        self.keyed_events = record.event_count();
        self.keyed_retained_bytes += record.retained_bytes_delta();
        self.pending_keyed = Some((record, event, queue));
    }

    fn prepare_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        continuation: &Continuation<Arc<MastForest>>,
        continuation_stack: &ContinuationStack<Arc<MastForest>>,
        current_forest: &Arc<MastForest>,
        projection: CycleProjection,
    ) -> Result<(), ExecutionError> {
        if projection.row != processor.system().clock()
            || projection.row.as_usize().checked_add(1) != Some(projection.next_clock.as_usize())
        {
            return Err(ExecutionError::Internal("trace cycle projection does not match clock"));
        }
        if self.fragment_size == 0 {
            return Err(ExecutionError::Internal("trace fragment size must be non-zero"));
        }
        if self.keyed_invalidated
            || self.keyed_reservation_pending
            || self.pending_keyed.is_some()
            || self.pending_address_error.is_some()
            || self.pending_restore_context.is_some()
            || self.active_keyed_event.is_some()
        {
            return Err(ExecutionError::Internal("previous trace cycle was not finalized"));
        }
        let mut prepared_keyed_cycle = None;
        let mut prepared_restore_context = None;
        let mut prepared_fragment_replays = projection
            .row
            .as_usize()
            .is_multiple_of(self.fragment_size)
            .then(PreparedFragmentReplays::default);
        if projection.row.as_usize().is_multiple_of(self.fragment_size) {
            self.fragment_contexts
                .try_reserve(1)
                .map_err(|_| ExecutionError::Internal("trace fragment allocation failed"))?;
        }
        if matches!(continuation, Continuation::FinishLoop(_))
            && Processor::stack(processor).depth() > MIN_STACK_DEPTH as u32
        {
            prepared_fragment_replays
                .as_mut()
                .map(|replays| &mut replays.overflow)
                .unwrap_or(&mut self.overflow_replay)
                .prepare_record_pop()?;
        }
        match continuation {
            Continuation::StartNode(node_id) => {
                let node = current_forest
                    .get_node_by_id(*node_id)
                    .ok_or(ExecutionError::Internal("trace start node is missing"))?;
                if matches!(node, MastNode::External(_)) {
                    return Err(ExecutionError::Internal("external trace node was not resolved"));
                }
                let mut missing_child = false;
                node.for_each_child(|child| {
                    missing_child |= current_forest.get_node_by_id(child).is_none();
                });
                if missing_child {
                    return Err(ExecutionError::Internal("trace control child is missing"));
                }
                let count = match node {
                    MastNode::Block(block) => {
                        if block.op_batches().is_empty() {
                            return Err(ExecutionError::Internal(
                                "trace basic block has no batches",
                            ));
                        }
                        block.num_op_batches()
                    },
                    _ => 1,
                };
                self.hasher_chiplet_shim.preflight_rows(count, CONTROLLER_ROWS_PER_HASHER_OP)?;
                self.block_stack.prepare_push()?;
                let mode_and_key = match node {
                    MastNode::Exec(node) => Some((KeyedMode::Exec, node.target())),
                    MastNode::Call(node) => Some((
                        if node.is_syscall() {
                            KeyedMode::Syscall
                        } else {
                            KeyedMode::Call
                        },
                        node.target(),
                    )),
                    MastNode::Dyn(node) => {
                        let word = processor
                            .memory()
                            .read_word(
                                processor.system().ctx(),
                                processor.stack_get(0),
                                projection.row,
                            )
                            .map_err(ExecutionError::MemoryErrorNoCtx)?;
                        Some((
                            if node.is_dyncall() {
                                KeyedMode::DynCall
                            } else {
                                KeyedMode::Dyn
                            },
                            ProcedureKey::new(word),
                        ))
                    },
                    _ => None,
                };
                if let Some((mode, key)) = mode_and_key {
                    prepared_keyed_cycle = Some((KeyedEventKind::Invoke(mode), key));
                    prepared_fragment_replays
                        .as_mut()
                        .map(|replays| &mut replays.block_addresses)
                        .unwrap_or(&mut self.hasher_chiplet_shim.block_addr_replay)
                        .prepare_record()?;
                    self.hasher_for_chiplet.prepare_record_control_block()?;
                    prepared_fragment_replays
                        .as_mut()
                        .map(|replays| &mut replays.block_stack)
                        .unwrap_or(&mut self.block_stack_replay)
                        .prepare_record_start()?;
                    if matches!(mode, KeyedMode::Call | KeyedMode::Syscall | KeyedMode::DynCall) {
                        self.overflow_table.prepare_start_context()?;
                    }
                    if matches!(mode, KeyedMode::Dyn | KeyedMode::DynCall) {
                        prepared_fragment_replays
                            .as_mut()
                            .map(|replays| &mut replays.memory_reads)
                            .unwrap_or(&mut self.memory_reads)
                            .prepare_record_read_word()?;
                        if Processor::stack(processor).depth() > MIN_STACK_DEPTH as u32 {
                            prepared_fragment_replays
                                .as_mut()
                                .map(|replays| &mut replays.overflow)
                                .unwrap_or(&mut self.overflow_replay)
                                .prepare_record_pop()?;
                        }
                    }
                    if matches!(mode, KeyedMode::Call | KeyedMode::DynCall) {
                        self.memory_writes.prepare_record_write_element()?;
                    }
                }
            },
            Continuation::Respan { .. } => {
                self.block_stack
                    .prepare_pop()?
                    .addr
                    .checked_advance(CONTROLLER_ROWS_PER_HASHER_OP)?;
            },
            Continuation::FinishLoop(_) if processor.stack_get(0) == ONE => {},
            Continuation::FinishJoin(_)
            | Continuation::FinishSplit(_)
            | Continuation::FinishLoop(_)
            | Continuation::FinishCall(_)
            | Continuation::FinishDyn(_)
            | Continuation::FinishExec(_)
            | Continuation::FinishBasicBlock(_) => {
                if self.block_stack.prepare_pop()?.ctx_info.is_some() {
                    prepared_restore_context =
                        Some(self.overflow_table.prepare_restore_context().map_err(|_| {
                            ExecutionError::Internal("trace overflow context cannot be restored")
                        })?);
                    prepared_fragment_replays
                        .as_mut()
                        .map(|replays| &mut replays.execution_context)
                        .unwrap_or(&mut self.execution_context_replay)
                        .prepare_record()?;
                    prepared_fragment_replays
                        .as_mut()
                        .map(|replays| &mut replays.overflow)
                        .unwrap_or(&mut self.overflow_replay)
                        .prepare_record_restore()?;
                }
                prepared_fragment_replays
                    .as_mut()
                    .map(|replays| &mut replays.block_stack)
                    .unwrap_or(&mut self.block_stack_replay)
                    .prepare_record_end()?;
            },
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                let block = current_forest
                    .get_node_by_id(*node_id)
                    .and_then(|node| match node {
                        MastNode::Block(block) => Some(block),
                        _ => None,
                    })
                    .ok_or(ExecutionError::Internal("trace basic block is missing"))?;
                let op = block
                    .op_batches()
                    .get(*batch_index)
                    .and_then(|batch| batch.ops().get(*op_idx_in_batch))
                    .ok_or(ExecutionError::Internal("trace operation index is out of bounds"))?;
                let rows = match op {
                    Operation::Compress | Operation::LogDeferred => 1,
                    Operation::MpVerify(_) => usize::try_from(
                        processor.stack_get(4).as_canonical_u64(),
                    )
                    .map_err(|_| ExecutionError::Internal("Merkle depth is out of bounds"))?,
                    Operation::MrUpdate => {
                        usize::try_from(processor.stack_get(4).as_canonical_u64())
                            .ok()
                            .and_then(|depth| depth.checked_mul(2))
                            .ok_or(ExecutionError::Internal("Merkle depth is out of bounds"))?
                    },
                    _ => 0,
                };
                self.hasher_chiplet_shim.preflight_rows(rows, CONTROLLER_ROWS_PER_HASHER_OP)?;
            },
            Continuation::EnterForest { .. } | Continuation::RootBoundary { .. } => {
                return Err(ExecutionError::Internal("zero-cycle continuation cannot be traced"));
            },
        }
        if matches!(
            continuation,
            Continuation::FinishBasicBlock(_)
                | Continuation::FinishJoin(_)
                | Continuation::FinishSplit(_)
                | Continuation::FinishExec(_)
                | Continuation::FinishLoop(_)
                | Continuation::FinishCall(_)
                | Continuation::FinishDyn(_)
        ) && !matches!(continuation, Continuation::FinishLoop(_)
            if processor.stack_get(0) == ONE)
            && let Some((_, principal)) = continuation_stack.root_boundary_after_next()
        {
            prepared_keyed_cycle = Some((KeyedEventKind::RootEnd, principal));
        }
        // Only actual keyed cycles retain their current continuation on the live stack.
        // SPAN/final-op preflight may see a root END below the current block, but its snapshot
        // must still add the executing block continuation through start_new_fragment_context.
        if projection.row.as_usize().is_multiple_of(self.fragment_size)
            && prepared_keyed_cycle.is_some()
        {
            self.prepared_snapshot = None;
            let mut translated = ContinuationStack::default();
            translated.prepare_push(continuation_stack.len())?;
            for (continuation, _) in continuation_stack.iter_with_source_node_ids() {
                let continuation = match continuation {
                    Continuation::EnterForest {
                        forest,
                        package_debug_info,
                        inline_context_depth,
                    } => Continuation::EnterForest {
                        forest: self.forest_id(forest),
                        package_debug_info: package_debug_info.clone(),
                        inline_context_depth: *inline_context_depth,
                    },
                    Continuation::StartNode(id) => Continuation::StartNode(*id),
                    Continuation::FinishJoin(id) => Continuation::FinishJoin(*id),
                    Continuation::FinishSplit(id) => Continuation::FinishSplit(*id),
                    Continuation::FinishLoop(id) => Continuation::FinishLoop(*id),
                    Continuation::FinishCall(id) => Continuation::FinishCall(*id),
                    Continuation::FinishDyn(id) => Continuation::FinishDyn(*id),
                    Continuation::FinishExec(id) => Continuation::FinishExec(*id),
                    Continuation::FinishBasicBlock(id) => Continuation::FinishBasicBlock(*id),
                    Continuation::RootBoundary { implementation, principal } => {
                        Continuation::RootBoundary {
                            implementation: *implementation,
                            principal: *principal,
                        }
                    },
                    Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                        Continuation::ResumeBasicBlock {
                            node_id: *node_id,
                            batch_index: *batch_index,
                            op_idx_in_batch: *op_idx_in_batch,
                        }
                    },
                    Continuation::Respan { node_id, batch_index } => Continuation::Respan {
                        node_id: *node_id,
                        batch_index: *batch_index,
                    },
                };
                translated.push_continuation(continuation);
            }
            let (current_addr, parent_addr) = if self.block_stack.is_empty() {
                (LogicalControllerAddress::ABSENT, LogicalControllerAddress::ABSENT)
            } else {
                let block = self.block_stack.peek();
                (block.addr, block.parent_addr)
            };
            self.prepared_snapshot = Some(StateSnapshot {
                state: CoreTraceState {
                    system: SystemState::from_processor(processor),
                    decoder: DecoderState { current_addr, parent_addr },
                    stack: StackState::new(
                        processor
                            .stack_top()
                            .try_into()
                            .map_err(|_| ExecutionError::Internal("invalid stack top width"))?,
                        MIN_STACK_DEPTH + self.overflow_table.num_elements_in_current_ctx(),
                        self.overflow_table.last_update_clk_in_current_ctx(),
                    ),
                },
                continuation_stack: translated,
                initial_mast_forest_id: self.forest_id(current_forest),
            });
        }
        self.prepared_keyed_cycle = prepared_keyed_cycle;
        self.prepared_restore_context = prepared_restore_context;
        self.prepared_fragment_replays = prepared_fragment_replays;
        Ok(())
    }

    /// When sufficiently many clock cycles have elapsed, starts a new trace state. Also updates the
    /// internal block stack.
    #[inline(always)]
    fn start_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        continuation: Continuation<Arc<MastForest>>,
        continuation_stack: &ContinuationStack<Arc<MastForest>>,
        current_forest: &Arc<MastForest>,
    ) {
        if matches!(&continuation, Continuation::StartNode(id)
            if matches!(current_forest.get_node_by_id(*id),
                Some(MastNode::Exec(_) | MastNode::Call(_) | MastNode::Dyn(_))))
            && self.pending_keyed.is_none()
        {
            self.keyed_invalidated = true;
            return;
        }
        // check if we need to start a new trace state
        if processor.system().clock().as_usize().is_multiple_of(self.fragment_size) {
            if self.prepared_snapshot.is_some() {
                self.finish_current_fragment_context();
                self.state_snapshot = self.prepared_snapshot.take();
            } else {
                self.start_new_fragment_context(
                    SystemState::from_processor(processor),
                    processor
                        .stack_top()
                        .try_into()
                        .expect("stack_top expected to be MIN_STACK_DEPTH elements"),
                    continuation_stack.clone_for_trace(),
                    continuation.clone(),
                    current_forest.clone(),
                );
            }
            if let Some(replays) = self.prepared_fragment_replays.take() {
                self.hasher_chiplet_shim.block_addr_replay = replays.block_addresses;
                self.block_stack_replay = replays.block_stack;
                self.execution_context_replay = replays.execution_context;
                self.overflow_replay = replays.overflow;
                self.memory_reads = replays.memory_reads;
            }
        }

        let expected_keyed = self.prepared_keyed_cycle.take();
        let pending_keyed = self.pending_keyed.take();
        if expected_keyed.is_some() != pending_keyed.is_some() {
            self.keyed_invalidated = true;
            return;
        }
        if let Some((record, event, queue)) = pending_keyed {
            if expected_keyed != Some((event.kind, event.use_record.procedure_key()))
                || event.use_record.row() != processor.system().clock()
                || *event.principal_before.as_word() != processor.system().caller_hash()
            {
                self.keyed_invalidated = true;
                return;
            }
            if let Some(queue) = queue {
                self.keyed = queue;
            }
            record.commit(&mut self.keyed);
            self.keyed_invalidated |= self.keyed.is_invalidated();
            self.active_keyed_event = Some(event);
        }

        // Record that the node being executed at this cycle was visited inside `current_forest`.
        // This builds up the per-source-forest sparse subset used at trace generation time. Note
        // that an `ExecutionTracer`'s state is invalidated on error, so it is safe to record the
        // visit here even if the operation later fails (per Tracer invariants).
        if let Some(visited_node_id) = node_id_for_visit(&continuation) {
            self.record_visit(current_forest, visited_node_id);
        }

        match continuation {
            Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                // Update overflow table based on whether the operation increments or decrements
                // the stack size.
                let basic_block = current_forest[node_id].unwrap_basic_block();
                let op = &basic_block.op_batches()[batch_index].ops()[op_idx_in_batch];

                if op.increments_stack_size() {
                    self.increment_stack_size(processor);
                } else if op.decrements_stack_size() {
                    self.decrement_stack_size();
                }

                if matches!(op, Operation::EvalCircuit) {
                    self.is_eval_circuit_op = true;
                }
            },
            Continuation::StartNode(mast_node_id) => match &current_forest[mast_node_id] {
                MastNode::Join(_) | MastNode::Loop(_) | MastNode::Exec(_) => {
                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );
                },
                MastNode::Split(_) => {
                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );
                    self.decrement_stack_size();
                },
                MastNode::Call(_) => {
                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );
                    self.overflow_table.start_context();
                },
                MastNode::Dyn(dyn_node) => {
                    self.record_control_node_start(
                        &current_forest[mast_node_id],
                        processor,
                        current_forest,
                    );
                    // DYN and DYNCALL both drop the memory address from the stack.
                    self.decrement_stack_size();

                    if dyn_node.is_dyncall() {
                        // Note: the overflow pop (stack size decrement above) must happen before
                        // starting the new context so that it operates on the old context's
                        // overflow table, per the semantics of dyncall.
                        self.overflow_table.start_context();
                    }
                },
                MastNode::Block(basic_block_node) => {
                    let result =
                        self.hasher_chiplet_shim.record_hash_basic_block(basic_block_node);
                    let Some(block_addr) = self.record_address_result(result) else {
                        return;
                    };
                    let forest_id = self.forest_id(current_forest);
                    self.hasher_for_chiplet.record_hash_basic_block(
                        forest_id,
                        mast_node_id,
                        basic_block_node,
                    );
                    let parent_addr = self.block_stack.push(block_addr, None);
                    self.block_stack_replay.record_node_start_parent_addr(parent_addr);
                },
                MastNode::External(_) => unreachable!(
                    "start_clock_cycle is guaranteed not to be called on external nodes"
                ),
            },
            Continuation::Respan { node_id: _, batch_index: _ } => {
                let result = self
                    .block_stack
                    .peek()
                    .addr
                    .checked_advance(CONTROLLER_ROWS_PER_HASHER_OP);
                if let Some(address) = self.record_address_result(result) {
                    self.block_stack.peek_mut().addr = address;
                }
            },
            Continuation::FinishLoop(_) if processor.stack_get(0) == ONE => {
                // This is a REPEAT operation, which drops the condition (top element) off the stack
                self.decrement_stack_size();
            },
            Continuation::FinishJoin(_)
            | Continuation::FinishSplit(_)
            | Continuation::FinishCall(_)
            | Continuation::FinishDyn(_)
            | Continuation::FinishExec(_)
            | Continuation::FinishLoop(_) // not a REPEAT, which is handled separately above
            | Continuation::FinishBasicBlock(_) => {
                // The END of a loop drops the condition from the stack (the body always pushes it).
                if matches!(
                    &continuation,
                    Continuation::FinishLoop(_)
                ) {
                    self.decrement_stack_size();
                }

                // This is an END operation; pop the block stack and record the node end
                let block_info = self.block_stack.pop();
                self.record_node_end(&block_info);

                if let Some(ctx_info) = block_info.ctx_info {
                    self.record_execution_context(ExecutionContextSystemInfo {
                        parent_ctx: ctx_info.parent_ctx,
                        parent_fn_hash: ctx_info.parent_fn_hash,
                    });

                    self.pending_restore_context = self.prepared_restore_context.take();
                    if self.pending_restore_context.is_none() {
                        self.keyed_invalidated = true;
                    }
                }
            },
            Continuation::EnterForest { .. } | Continuation::RootBoundary { .. } => {
                panic!("EnterForest continuations are guaranteed not to be passed here")
            },
        }
    }

    #[inline(always)]
    fn record_mast_forest_resolution(&mut self, node_id: MastNodeId, forest: &Arc<MastForest>) {
        let forest_id = self.forest_id(forest);
        self.external.record_resolution(node_id, forest_id);
    }

    #[inline(always)]
    fn record_external_node_entered(
        &mut self,
        external_node_id: MastNodeId,
        forest: &Arc<MastForest>,
    ) {
        // External nodes don't go through `start_clock_cycle`, so we record their visit here so
        // the per-source-forest sparse builder includes them. The replay path needs the external
        // node present in the sparse forest because `execute_external_node` indexes the forest by
        // id to fetch the procedure digest.
        self.record_visit(forest, external_node_id);
    }

    #[inline(always)]
    fn record_hasher_compress(
        &mut self,
        input_state: [Felt; STATE_WIDTH],
        output_state: [Felt; STATE_WIDTH],
    ) {
        let result = self.hasher_chiplet_shim.record_compression_output(output_state);
        if self.record_address_result(result).is_some() {
            self.hasher_for_chiplet.record_compress_input(input_state);
        }
    }

    #[inline(always)]
    fn record_hasher_aead_xof(
        &mut self,
        ctx: ContextId,
        clk: RowIndex,
        input_state: [Felt; STATE_WIDTH],
    ) {
        self.hasher_for_chiplet.record_aead_xof_input(ctx, clk, input_state);
    }

    #[inline(always)]
    fn record_hasher_build_merkle_root(
        &mut self,
        node: Word,
        path: Option<&MerklePath>,
        depth: Felt,
        index: Felt,
        output_root: Word,
    ) {
        let path = path.expect("execution tracer expects a valid Merkle path");
        let result = self.hasher_chiplet_shim.record_build_merkle_root(path, output_root);
        if self.record_address_result(result).is_none() {
            return;
        }
        self.hasher_for_chiplet.record_build_merkle_root(node, path.clone(), index);
        self.range_checker.record_merkle_depth(depth);
        self.range_checker.record_merkle_index(index);
    }

    #[inline(always)]
    fn record_hasher_update_merkle_root(
        &mut self,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        depth: Felt,
        index: Felt,
        old_root: Word,
        new_root: Word,
    ) {
        let path = path.expect("execution tracer expects a valid Merkle path");
        let result = self.hasher_chiplet_shim.record_update_merkle_root(path, old_root, new_root);
        if self.record_address_result(result).is_none() {
            return;
        }
        self.hasher_for_chiplet.record_update_merkle_root(
            old_value,
            new_value,
            path.clone(),
            index,
        );
        self.range_checker.record_merkle_depth(depth);
        self.range_checker.record_merkle_index(index);
    }

    #[inline(always)]
    fn record_memory_read_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        self.memory_reads.record_read_element(element, addr, ctx, clk);
    }

    #[inline(always)]
    fn record_memory_read_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex) {
        self.memory_reads.record_read_word(word, addr, ctx, clk);
    }

    #[inline(always)]
    fn record_memory_write_element(
        &mut self,
        element: Felt,
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        self.memory_writes.record_write_element(element, addr, ctx, clk);
    }

    #[inline(always)]
    fn record_memory_write_word(&mut self, word: Word, addr: Felt, ctx: ContextId, clk: RowIndex) {
        self.memory_writes.record_write_word(word, addr, ctx, clk);
    }

    #[inline(always)]
    fn record_memory_read_dword(
        &mut self,
        words: [Word; 2],
        addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        self.memory_reads.record_read_word(words[0], addr, ctx, clk);
        self.memory_reads.record_read_word(words[1], addr + PTR_OFFSET_WORD, ctx, clk);
    }

    #[inline(always)]
    fn record_dyncall_memory(
        &mut self,
        callee_hash: Word,
        read_addr: Felt,
        read_ctx: ContextId,
        fmp_ctx: ContextId,
        clk: RowIndex,
    ) {
        self.memory_reads.record_read_word(callee_hash, read_addr, read_ctx, clk);
        self.memory_writes.record_write_element(FMP_INIT_VALUE, FMP_ADDR, fmp_ctx, clk);
    }

    #[inline(always)]
    fn record_aead_stream(
        &mut self,
        plaintext: [Word; 2],
        src_addr: Felt,
        keystream: [Felt; 16],
        ciphertext: [Felt; 16],
        dst_addr: Felt,
        ctx: ContextId,
        clk: RowIndex,
    ) {
        let ciphertext_words = [
            [ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]].into(),
            [ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7]].into(),
            [ciphertext[8], ciphertext[9], ciphertext[10], ciphertext[11]].into(),
            [ciphertext[12], ciphertext[13], ciphertext[14], ciphertext[15]].into(),
        ];

        // Each 4-row stream half emits a read interaction, so mirror the executor's duplicate
        // source-word reads in the replay consumed by parallel trace generation.
        self.memory_reads.record_read_word(plaintext[0], src_addr, ctx, clk);
        self.memory_reads.record_read_word(plaintext[0], src_addr, ctx, clk);
        self.memory_reads
            .record_read_word(plaintext[1], src_addr + PTR_OFFSET_WORD, ctx, clk);
        self.memory_reads
            .record_read_word(plaintext[1], src_addr + PTR_OFFSET_WORD, ctx, clk);
        for (i, word) in ciphertext_words.into_iter().enumerate() {
            self.memory_writes.record_write_word(
                word,
                dst_addr + Felt::new_unchecked((i * 4) as u64),
                ctx,
                clk,
            );
        }

        let trace_ctx = Felt::new_unchecked(u32::from(ctx) as u64);
        let trace_clk = Felt::from(clk);
        self.bitwise
            .record_aead_stream(crate::trace::trace_state::AeadStreamReplayEntry {
                ctx: trace_ctx,
                clk: trace_clk,
                src_ptr: src_addr,
                dst_ptr: dst_addr,
                lane_base: ZERO,
                plaintext: plaintext[0].into(),
                keystream: keystream[..8].try_into().expect("low keystream chunk has 8 lanes"),
                ciphertext: ciphertext[..8].try_into().expect("low ciphertext chunk has 8 lanes"),
            });
        self.bitwise
            .record_aead_stream(crate::trace::trace_state::AeadStreamReplayEntry {
                ctx: trace_ctx,
                clk: trace_clk,
                src_ptr: src_addr + PTR_OFFSET_WORD,
                dst_ptr: dst_addr + Felt::new_unchecked(8),
                lane_base: Felt::new_unchecked(8),
                plaintext: plaintext[1].into(),
                keystream: keystream[8..].try_into().expect("high keystream chunk has 8 lanes"),
                ciphertext: ciphertext[8..].try_into().expect("high ciphertext chunk has 8 lanes"),
            });
    }

    #[inline(always)]
    fn record_pipe(&mut self, words: [Word; 2], addr: Felt, ctx: ContextId, clk: RowIndex) {
        self.advice.record_pop_stack_dword(words);
        self.memory_writes.record_write_word(words[0], addr, ctx, clk);
        self.memory_writes.record_write_word(words[1], addr + PTR_OFFSET_WORD, ctx, clk);
    }

    #[inline(always)]
    fn record_advice_pop_stack(&mut self, value: Felt) {
        self.advice.record_pop_stack(value);
    }

    #[inline(always)]
    fn record_advice_pop_stack_word(&mut self, word: Word) {
        self.advice.record_pop_stack_word(word);
    }

    #[inline(always)]
    fn record_u32and(&mut self, a: Felt, b: Felt) {
        self.bitwise.record_u32and(a, b);
    }

    #[inline(always)]
    fn record_u32xor(&mut self, a: Felt, b: Felt) {
        self.bitwise.record_u32xor(a, b);
    }

    #[inline(always)]
    fn record_u32_range_checks(&mut self, u32_lo: Felt, u32_hi: Felt) {
        let (t1, t0) = split_u32_into_u16(u32_lo.as_canonical_u64());
        let (t3, t2) = split_u32_into_u16(u32_hi.as_canonical_u64());

        self.range_checker.record_range_check_u32([t0, t1, t2, t3]);
    }

    #[inline(always)]
    fn record_u32div_range_checks(
        &mut self,
        quotient: Felt,
        remainder: Felt,
        remainder_diff: Felt,
    ) {
        self.record_u32_range_checks(quotient, remainder);
        let (d1, d0) = split_u32_into_u16(remainder_diff.as_canonical_u64());
        self.range_checker.record_u32div_remainder_diff([d0, d1]);
    }

    #[inline(always)]
    fn record_kernel_proc_access(&mut self, proc_hash: Word) {
        self.kernel.record_kernel_proc_access(proc_hash);
    }

    #[inline(always)]
    fn record_circuit_evaluation(
        &mut self,
        circuit_evaluation: CircuitEvaluation,
    ) -> Result<(), AceError> {
        self.ace.record_circuit_evaluation(circuit_evaluation)
    }

    #[inline(always)]
    fn finalize_clock_cycle(
        &mut self,
        processor: &FastProcessor,
        _op_helper_registers: OperationHelperRegisters,
        _current_forest: &Arc<MastForest>,
    ) -> Result<(), ExecutionError> {
        if self.keyed_invalidated || self.keyed.is_invalidated() {
            self.keyed_invalidated = true;
            return Err(ExecutionError::InvalidExecutionState);
        }
        if let Some(error) = self.pending_address_error.take() {
            self.keyed_invalidated = true;
            return Err(error);
        }
        if let Some(event) = self.active_keyed_event.take()
            && processor.system().caller_hash() != *event.principal_after.as_word()
        {
            self.keyed_invalidated = true;
            return Err(ExecutionError::InvalidExecutionState);
        }
        // Restore the checked overflow frame only after the prepared VM return commits.
        if let Some(prepared) = self.pending_restore_context.take() {
            // Restore context for call/syscall/dyncall: pop the current context's
            // (empty) overflow stack and restore the previous context's overflow state.
            if !self.overflow_table.commit_restore_context(prepared) {
                self.keyed_invalidated = true;
                return Err(ExecutionError::InvalidExecutionState);
            }
            self.overflow_replay.record_restore_context_overflow_addr(
                MIN_STACK_DEPTH + self.overflow_table.num_elements_in_current_ctx(),
                self.overflow_table.last_update_clk_in_current_ctx(),
            );
        }

        // Record all memory reads performed during EvalCircuit operations. We run this in
        // `finalize_clock_cycle` to ensure that the memory reads are only recorded if the operation
        // succeeds (and hence the values read from the stack can be assumed to be valid).
        if self.is_eval_circuit_op {
            let ptr = processor.stack_get(0);
            let num_read = processor.stack_get(1).as_canonical_u64();
            let num_eval = processor.stack_get(2).as_canonical_u64();
            let ctx = processor.ctx();
            let clk = processor.clock();

            let num_read_rows = num_read / 2;

            let mut addr = ptr;
            for _ in 0..num_read_rows {
                let word = processor
                    .memory()
                    .read_word(ctx, addr, clk)
                    .expect("EvalCircuit memory read should not fail after successful execution");
                self.memory_reads.record_read_word(word, addr, ctx, clk);
                addr += PTR_OFFSET_WORD;
            }
            for _ in 0..num_eval {
                let element = processor
                    .memory()
                    .read_element(ctx, addr)
                    .expect("EvalCircuit memory read should not fail after successful execution");
                self.memory_reads.record_read_element(element, addr, ctx, clk);
                addr += PTR_OFFSET_ELEM;
            }

            self.is_eval_circuit_op = false;
        }

        Ok(())
    }
}

/// Extracts the [`MastNodeId`] that is being executed at the start of a clock cycle from the given
/// continuation, so that the node can be marked as visited in its source forest's sparse builder.
///
/// Continuations not passed to [`Tracer::start_clock_cycle`] (per the trait contract) are matched
/// pessimistically here, returning `None`.
#[inline]
fn node_id_for_visit<F>(continuation: &Continuation<F>) -> Option<MastNodeId> {
    match *continuation {
        Continuation::StartNode(id)
        | Continuation::FinishJoin(id)
        | Continuation::FinishSplit(id)
        | Continuation::FinishCall(id)
        | Continuation::FinishDyn(id)
        | Continuation::FinishExec(id)
        | Continuation::FinishBasicBlock(id) => Some(id),
        Continuation::FinishLoop(id) => Some(id),
        Continuation::ResumeBasicBlock { node_id, .. } | Continuation::Respan { node_id, .. } => {
            Some(node_id)
        },
        Continuation::EnterForest { .. } | Continuation::RootBoundary { .. } => None,
    }
}

// HASHER CHIPLET SHIM
// ================================================================================================

/// Implements a shim for the hasher chiplet, where the responses of the hasher chiplet are emulated
/// and recorded for later replay.
///
/// This is used to simulate hasher operations in parallel trace generation without needing to
/// actually generate the hasher trace. All hasher operations are recorded during fast execution and
/// then replayed during core trace generation.
#[derive(Debug)]
pub struct HasherChipletShim {
    /// Zero-based position of the next Controller row, retained across replay fragment drains.
    next_row: ControllerRow,
    /// Replay for the hasher chiplet responses, recording only the hasher chiplet responses.
    hasher_replay: HasherResponseReplay,
    block_addr_replay: BlockAddressReplay,
}

impl HasherChipletShim {
    /// Creates a new [HasherChipletShim].
    pub fn new() -> Self {
        Self {
            next_row: ControllerRow::default(),
            hasher_replay: HasherResponseReplay::default(),
            block_addr_replay: BlockAddressReplay::default(),
        }
    }

    fn preflight_rows(&self, count: usize, rows_per_item: usize) -> Result<(), ExecutionError> {
        self.next_row.checked_advance_many(count, rows_per_item)?;
        Ok(())
    }

    /// Records the address returned from a call to `Hasher::hash_control_block()`.
    pub fn record_hash_control_block(
        &mut self,
    ) -> Result<LogicalControllerAddress, ExecutionError> {
        let block_addr = self.reserve_rows(1, CONTROLLER_ROWS_PER_HASHER_OP)?;
        self.block_addr_replay.record_block_address(block_addr);
        Ok(block_addr)
    }

    /// Records the address returned from a call to `Hasher::hash_basic_block()`.
    pub fn record_hash_basic_block(
        &mut self,
        basic_block_node: &BasicBlockNode,
    ) -> Result<LogicalControllerAddress, ExecutionError> {
        let block_addr =
            self.reserve_rows(basic_block_node.num_op_batches(), CONTROLLER_ROWS_PER_HASHER_OP)?;
        self.block_addr_replay.record_block_address(block_addr);
        Ok(block_addr)
    }
    /// Records the output of one Eidos compression request.
    pub fn record_compression_output(
        &mut self,
        hashed_state: [Felt; 12],
    ) -> Result<(), ExecutionError> {
        let address = self.reserve_rows(1, CONTROLLER_ROWS_PER_HASHER_OP)?;
        self.hasher_replay.record_compression(address, hashed_state);
        Ok(())
    }

    /// Records the result of a call to `Hasher::build_merkle_root()`.
    pub fn record_build_merkle_root(
        &mut self,
        path: &MerklePath,
        computed_root: Word,
    ) -> Result<(), ExecutionError> {
        let address = self.reserve_rows(path.len(), CONTROLLER_ROWS_PER_HASHER_OP)?;
        self.hasher_replay.record_build_merkle_root(address, computed_root);
        Ok(())
    }

    /// Records the result of a call to `Hasher::update_merkle_root()`.
    pub fn record_update_merkle_root(
        &mut self,
        path: &MerklePath,
        old_root: Word,
        new_root: Word,
    ) -> Result<(), ExecutionError> {
        // The Merkle path is verified twice: once for the old root and once for the new root.
        let address = self.reserve_rows(path.len(), 2 * CONTROLLER_ROWS_PER_HASHER_OP)?;
        self.hasher_replay.record_update_merkle_root(address, old_root, new_root);
        Ok(())
    }

    fn reserve_rows(
        &mut self,
        count: usize,
        rows_per_item: usize,
    ) -> Result<LogicalControllerAddress, ExecutionError> {
        let end = self.next_row.checked_advance_many(count, rows_per_item)?;
        let address = self.next_row.logical_address();
        self.next_row = end;
        Ok(address)
    }

    pub fn extract_replay(&mut self) -> (HasherResponseReplay, BlockAddressReplay) {
        (
            core::mem::take(&mut self.hasher_replay),
            core::mem::take(&mut self.block_addr_replay),
        )
    }
}

impl Default for HasherChipletShim {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod controller_address_tests {
    use super::*;
    use crate::{StackInputs, trace::parallel::MAX_TRACE_LEN};

    fn assert_limit<T>(result: Result<T, ExecutionError>) {
        assert!(matches!(result, Err(ExecutionError::TraceLenExceeded(MAX_TRACE_LEN))));
    }

    #[test]
    fn shim_preserves_logical_addresses_across_fragment_drains() {
        let mut shim = HasherChipletShim::new();
        assert_eq!(shim.record_hash_control_block().unwrap().to_felt(), ONE);
        let (_, first_blocks) = shim.extract_replay();
        let mut first_blocks =
            BlockAddressReplay::read_from_bytes(&first_blocks.to_bytes()).unwrap();
        assert_eq!(first_blocks.replay_block_address().unwrap().to_felt(), ONE);

        let state = [ONE; STATE_WIDTH];
        shim.record_compression_output(state).unwrap();
        let (responses, blocks) = shim.extract_replay();
        let mut responses = HasherResponseReplay::read_from_bytes(&responses.to_bytes()).unwrap();
        let (address, output) = responses.replay_compression().unwrap();
        assert_eq!((address.to_felt(), output), (Felt::from_u32(2), state));
        assert_eq!(blocks, BlockAddressReplay::default());
        assert_eq!(shim.record_hash_control_block().unwrap().to_felt(), Felt::from_u32(3));
    }

    #[test]
    fn shim_exact_cap_and_span_overflow_are_atomic() {
        let mut shim = HasherChipletShim {
            next_row: ControllerRow::new(MAX_TRACE_LEN - 1).unwrap(),
            ..Default::default()
        };
        let block = crate::mast::BasicBlockNodeBuilder::new(vec![Operation::Noop; 73])
            .build()
            .unwrap();
        assert_limit(shim.record_hash_basic_block(&block));
        assert_limit(shim.reserve_rows(usize::MAX, 2));
        let path = MerklePath::new(vec![[ZERO; 4].into()]);
        assert_limit(shim.record_update_merkle_root(&path, [ZERO; 4].into(), [ONE; 4].into()));
        assert_eq!(shim.next_row.position(), MAX_TRACE_LEN - 1);
        assert_eq!(
            shim.extract_replay(),
            (HasherResponseReplay::default(), BlockAddressReplay::default())
        );

        assert_eq!(
            shim.record_hash_control_block().unwrap().to_felt(),
            Felt::from_u32(MAX_TRACE_LEN as u32),
        );
        assert_eq!(shim.next_row.position(), MAX_TRACE_LEN);
        let (_, mut blocks) = shim.extract_replay();
        assert_eq!(
            blocks.replay_block_address().unwrap().to_felt(),
            Felt::from_u32(MAX_TRACE_LEN as u32)
        );
        assert_limit(shim.record_compression_output([ZERO; STATE_WIDTH]));
        assert_limit(shim.record_build_merkle_root(&path, [ZERO; 4].into()));
        assert_limit(shim.record_hash_control_block());
        assert_eq!(shim.next_row.position(), MAX_TRACE_LEN);
        assert_eq!(
            shim.extract_replay(),
            (HasherResponseReplay::default(), BlockAddressReplay::default())
        );
    }

    #[test]
    fn infallible_hook_reports_address_error_at_cycle_finalization() {
        let mut tracer = ExecutionTracer::new(64, MIN_STACK_DEPTH);
        tracer.hasher_chiplet_shim.next_row = ControllerRow::new(MAX_TRACE_LEN).unwrap();
        tracer.record_hasher_compress([ZERO; STATE_WIDTH], [ZERO; STATE_WIDTH]);
        assert!(tracer.pending_address_error.is_some());
        assert_eq!(
            tracer.hasher_chiplet_shim.extract_replay(),
            (HasherResponseReplay::default(), BlockAddressReplay::default()),
        );
        let forest = Arc::new(MastForest::new());
        let processor = FastProcessor::new(StackInputs::default());
        assert_limit(tracer.finalize_clock_cycle(
            &processor,
            OperationHelperRegisters::Empty,
            &forest,
        ));
        assert!(tracer.pending_address_error.is_none());
    }
}

#[cfg(test)]
mod serialization_tests {
    use miden_core::serde::SliceReader;

    use super::*;
    use crate as processor;
    use crate::mast::BasicBlockNodeBuilder;

    #[allow(dead_code)]
    mod common {
        include!("../../tests/common/keyed_witness.rs");
    }
    use common::{execution_fixture, execution_witness, read_limits, trace_limits};

    fn read_context(context: &TraceReplay) -> Result<TraceReplay, DeserializationError> {
        let mut payload = Vec::new();
        context.write_payload(&mut payload);
        let environment = execution_fixture(vec![Operation::Noop]).environment;
        TraceReplay::read_with_limits(
            &mut SliceReader::new(&payload),
            &environment,
            trace_limits(),
            read_limits(),
        )
    }

    fn empty_trace_generation_context(fragment_size: usize, max_stack_depth: usize) -> TraceReplay {
        let mut context = valid_trace_generation_context();
        context.mast_forest_store.clear();
        context.core_trace_contexts.clear();
        context.fragment_size = fragment_size;
        context.max_stack_depth = max_stack_depth;
        context
    }

    fn valid_trace_generation_context() -> TraceReplay {
        execution_witness(vec![Operation::Noop], crate::StackInputs::default())
            .witness
            .into_parts()
            .0
            .trace
    }

    fn assert_context_read_rejects_bad_forest_id(context: TraceReplay, expected_label: &str) {
        let err = read_context(&context).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected invalid forest id error");
        };
        assert!(message.contains(expected_label), "{message}");
        assert!(message.contains("out of range for mast_forest_store length 1"), "{message}");
    }

    #[test]
    fn bounded_read_retains_completed_native_input_and_exact_entry_frequency() {
        let original = valid_trace_generation_context();
        let restored = read_context(&original).unwrap();
        restored.require_validated().unwrap();
        let live = &original.resolution_session;
        let read = &restored.resolution_session;
        assert_eq!(read.phase(), crate::SessionPhase::Completed);
        assert_eq!(read.descriptor(), live.descriptor());
        assert_eq!(read.finalize().unwrap(), live.finalize().unwrap());
        assert_eq!(read.bindings(), live.bindings());
        assert_eq!(
            read.uses().copied().collect::<Vec<_>>(),
            live.uses().copied().collect::<Vec<_>>()
        );
        assert_eq!(read.bindings()[0].counts().normal, 1);
        assert_eq!(read.bindings()[0].counts().syscall, 0);
        assert_eq!(read.ledger().occurrences().len(), live.ledger().occurrences().len());
        for (actual, expected) in
            read.ledger().occurrences().iter().zip(live.ledger().occurrences())
        {
            assert_eq!(actual.node(), expected.node());
            assert_eq!(actual.parent(), expected.parent());
        }
    }

    #[test]
    fn validated_replay_requires_matching_completed_native_owner() {
        let mut trace = valid_trace_generation_context();
        let environment = execution_fixture(vec![Operation::Noop]).environment;
        trace.resolution_session = ResolutionSession::new(
            environment.descriptor(),
            environment.ledger_limits(),
            environment.session_limits(),
        );
        assert!(trace.require_validated().is_err());

        trace.resolution_session = execution_witness(
            vec![Operation::Push(ONE), Operation::Drop],
            crate::StackInputs::default(),
        )
        .witness
        .into_parts()
        .0
        .trace
        .resolution_session;
        assert!(trace.require_validated().is_err());
    }

    #[test]
    fn root_end_retains_native_capacities_and_admits_its_keyed_record_before_commit() {
        let original = valid_trace_generation_context();
        let environment = execution_fixture(vec![Operation::Noop]).environment;
        let descriptor = environment.descriptor();
        let binding = crate::ResolutionWitness {
            path: vec![crate::OpeningStep {
                node: original.resolution_session.ledger().occurrences()[0].node().clone(),
                selected_child: None,
            }],
        }
        .verify(
            descriptor.environment_root(),
            descriptor.entry_key(),
            environment.opening_limits(),
        )
        .unwrap();
        let mut session = ResolutionSession::new(
            descriptor,
            environment.ledger_limits(),
            environment.session_limits(),
        );
        session.prepare_entry(binding).unwrap().commit();
        let before = session.counters();
        let staged = EnvironmentReplay::prepare_capture(
            &session,
            session.bindings()[0],
            trace_limits(),
            0,
            0,
            0,
        )
        .unwrap();
        assert_eq!(staged.native_retained_bytes(), before.retained_bytes);
        let implementation = session.bindings()[0].implementation_root();
        let prepared = session.prepare_root_end(implementation, RowIndex::from(0u32)).unwrap();
        assert_eq!(prepared.counters().retained_bytes, before.retained_bytes);
        let event = KeyedEvent {
            kind: KeyedEventKind::RootEnd,
            use_record: prepared.use_record(),
            principal_before: descriptor.entry_key(),
            principal_after: descriptor.entry_key(),
        };
        let mut limits = trace_limits();
        // The environment and moved native capacities fit exactly; the root-END queue still
        // needs its own retained allocation, which must reject before either native commit.
        limits.max_retained_bytes = staged.retained_bytes() + before.retained_bytes;
        let mut queue = KeyedReplay::default();
        let error = queue
            .prepare_record(
                event,
                MastForestId::from(0u32),
                MastNodeId::from(0),
                limits,
                0,
                (staged.retained_bytes(), before.retained_bytes),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            super::super::keyed::KeyedReplayError::LimitExceeded {
                resource: super::super::keyed::ReplayResource::RetainedBytes,
                ..
            }
        ));
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.retained_bytes().unwrap(), 0);
        drop(prepared);
        drop(staged);
        assert_eq!(session.phase(), crate::SessionPhase::PendingEntry);
        assert_eq!(session.counters(), before);
        assert_eq!(session.bindings()[0].counts().normal, 0);
        assert!(session.uses().next().is_none());
        session.prepare_root_end(implementation, RowIndex::from(0u32)).unwrap().commit();
        assert_eq!(session.finalize().unwrap().retained_bytes, before.retained_bytes);
        assert_eq!(session.bindings()[0].counts().normal, 1);
    }

    #[test]
    fn retained_native_read_rejection_revokes_replay_trust() {
        let mut trace = valid_trace_generation_context();
        let environment = execution_fixture(vec![Operation::Noop]).environment;
        let mut raw = trace.environment.retained_bytes().unwrap();
        for fragment in &trace.core_trace_contexts {
            raw += fragment.replay.keyed.retained_bytes().unwrap();
        }
        let mut limits = trace_limits();
        limits.max_retained_bytes = raw;
        assert!(
            trace
                .environment
                .revalidate(
                    &environment,
                    &mut trace.core_trace_contexts,
                    limits,
                    read_limits(),
                    trace.fragment_size,
                )
                .is_err()
        );
        assert!(trace.require_validated().is_err());
        assert!(trace.environment.require_validated().is_err());
        for fragment in &trace.core_trace_contexts {
            assert!(fragment.replay.keyed.require_validated().is_err());
        }
    }

    #[test]
    fn trace_generation_context_read_rejects_zero_fragment_size() {
        let context = empty_trace_generation_context(0, MIN_STACK_DEPTH);

        let err = read_context(&context).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected invalid fragment size error");
        };
        assert!(message.contains("fragment_size must be non-zero"));
    }

    #[test]
    fn trace_generation_context_read_rejects_max_stack_depth_below_minimum() {
        let context = empty_trace_generation_context(1, MIN_STACK_DEPTH - 1);

        let err = read_context(&context).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected invalid max stack depth error");
        };
        assert!(message.contains("max_stack_depth"));
    }

    #[test]
    fn trace_generation_context_read_rejects_bad_initial_forest_id() {
        let mut context = valid_trace_generation_context();
        context.core_trace_contexts[0].initial_mast_forest_id = MastForestId::from(1u32);

        assert_context_read_rejects_bad_forest_id(
            context,
            "core trace fragment initial_mast_forest_id",
        );
    }

    #[test]
    fn trace_generation_context_read_rejects_bad_continuation_forest_id() {
        let mut context = valid_trace_generation_context();
        context.core_trace_contexts[0]
            .continuation
            .push_enter_forest(MastForestId::from(1u32));

        assert_context_read_rejects_bad_forest_id(
            context,
            "core trace fragment continuation EnterForest",
        );
    }

    #[test]
    fn trace_generation_context_read_rejects_bad_resolution_replay_forest_id() {
        let mut context = valid_trace_generation_context();
        context.core_trace_contexts[0]
            .replay
            .mast_forest_resolution
            .record_resolution(MastNodeId::from(0), MastForestId::from(1u32));

        assert_context_read_rejects_bad_forest_id(
            context,
            "core trace fragment MastForestResolutionReplay",
        );
    }

    #[test]
    fn trace_generation_context_read_rejects_bad_hasher_replay_forest_id() {
        let mut context = valid_trace_generation_context();
        let basic_block = BasicBlockNodeBuilder::new(vec![Operation::Noop]).build().unwrap();
        context.hasher_for_chiplet.record_hash_basic_block(
            MastForestId::from(1u32),
            MastNodeId::from(0),
            &basic_block,
        );

        assert_context_read_rejects_bad_forest_id(context, "hasher HashBasicBlock replay");
    }
}
