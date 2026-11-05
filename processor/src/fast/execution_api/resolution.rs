//! Owned live resolution driver. Generic execution and replay share only prepared transitions.

use core::ops::ControlFlow;

use miden_core::program::{ImplementationRoot, Namespace, ProcedureKey};

use super::*;
use crate::{
    EnvironmentWitnessRequest, InvocationTag, ResolutionWitness, SessionError, SessionPhase,
    Stopper,
    continuation_stack::Continuation,
    execution::{
        ExecutionState, InternalBreakReason, KeyedRequest, LoadedTarget, RootEndRequest,
        execute_impl, finish_emit_op_execution, finish_keyed_invocation,
        finish_load_mast_forest_from_external, finish_root_end, preflight_keyed_invocation,
        preflight_root_end,
    },
    fast::{
        external::maybe_use_caller_error_context,
        step::{BreakReason, ExecutionLifecycle, PendingBinding, PendingKey, PendingResolution},
    },
    tracer::{KeyedEvent, KeyedEventKind, KeyedMode, KeyedTarget},
};

impl FastProcessor {
    fn invalidate(&mut self, resume: &mut ResumeContext) {
        self.invalid_execution = true;
        resume.lifecycle = ExecutionLifecycle::Invalid;
    }

    fn check_resume(&mut self, resume: &mut ResumeContext) -> Result<(), ExecutionError> {
        if self.invalid_execution
            || resume.lifecycle != ExecutionLifecycle::Active
            || !self
                .execution_identity
                .as_ref()
                .is_some_and(|id| Arc::ptr_eq(id, &resume.identity))
        {
            self.invalidate(resume);
            return Err(ExecutionError::InvalidExecutionState);
        }
        Ok(())
    }

    fn witness_request(resume: &ResumeContext) -> EnvironmentWitnessRequest {
        EnvironmentWitnessRequest {
            root: resume.environment.descriptor().environment_root(),
            key: resume.pending.as_ref().expect("pending resolution").request.key(),
            limits: resume.environment.opening_limits(),
        }
    }

    fn cache_pending_binding(resume: &mut ResumeContext) {
        let pending = resume.pending.as_mut().expect("pending resolution");
        if pending.binding.is_none() && matches!(pending.request, PendingKey::Invoke(_)) {
            pending.binding = resume
                .session
                .bindings()
                .iter()
                .copied()
                .find(|binding| binding.procedure_key() == pending.request.key())
                .map(PendingBinding::Cached);
        }
    }

    fn retain_verified_witness(
        resume: &mut ResumeContext,
        request: EnvironmentWitnessRequest,
        witness: Option<ResolutionWitness>,
    ) -> Result<(), ExecutionError> {
        let witness = witness.ok_or(ExecutionError::EnvironmentWitnessUnavailable {
            root: request.root,
            key: request.key,
        })?;
        let binding =
            witness.verify(request.root, request.key, request.limits).map_err(|error| {
                ExecutionError::InvalidEnvironmentOpening {
                    root: request.root,
                    key: request.key,
                    error: error.into(),
                }
            })?;
        // This publication is private pending evidence, not a native use or VM transition. In
        // particular it happens before the next await for code supply.
        resume.pending.as_mut().expect("pending resolution").binding =
            Some(PendingBinding::Verified(binding));
        Ok(())
    }

    fn pending_implementation(resume: &ResumeContext) -> ImplementationRoot {
        match resume
            .pending
            .as_ref()
            .and_then(|pending| pending.binding.as_ref())
            .expect("authenticated pending binding")
        {
            PendingBinding::Verified(binding) => binding.implementation_root(),
            PendingBinding::Cached(binding) => binding.implementation_root(),
        }
    }

    /// Authorization uses authenticated namespace evidence before any D-indexed code lookup.
    fn authorize_pending_mode(resume: &ResumeContext) -> Result<(), ExecutionError> {
        let pending = resume.pending.as_ref().expect("pending resolution");
        if !matches!(pending.request, PendingKey::Invoke(request) if request.mode == KeyedMode::Syscall)
        {
            return Ok(());
        }
        let actual = match pending.binding.as_ref().expect("authenticated pending binding") {
            PendingBinding::Verified(binding) => binding.namespace(),
            PendingBinding::Cached(binding) => binding.namespace(),
        };
        let expected = Namespace::initial();
        if actual != expected {
            return Err(ExecutionError::EnvironmentSession(SessionError::UnauthorizedSyscall {
                expected,
                actual,
            }));
        }
        Ok(())
    }

    fn has_materialized_root(forest: &MastForest, implementation: ImplementationRoot) -> bool {
        forest.procedure_roots().iter().any(|root| {
            let node = &forest[*root];
            !node.is_external() && node.digest() == *implementation.as_word()
        })
    }

    /// Available code is considered only after the pending key has authenticated its D.
    fn local_code_candidate(
        &self,
        resume: &ResumeContext,
        implementation: ImplementationRoot,
    ) -> Option<LoadedMastForest> {
        if matches!(resume.pending.as_ref()?.request, PendingKey::Invoke(_))
            && Self::has_materialized_root(&resume.current_forest, implementation)
        {
            return Some(LoadedMastForest::with_package_debug_info(
                resume.current_forest.clone(),
                Ok(resume.package_debug_info.as_deref().cloned()),
            ));
        }
        if Self::has_materialized_root(resume.program_hint.mast_forest(), implementation) {
            return Some(resume.program_hint.clone());
        }
        self.loaded_mast_forests.get(implementation.as_word()).cloned()
    }

    fn prepare_pending_code(
        &self,
        resume: &ResumeContext,
        loaded: LoadedMastForest,
        implementation: ImplementationRoot,
        host: &impl BaseHost,
    ) -> Result<PreparedLoadedTarget, ExecutionError> {
        let source = match resume.pending.as_ref().expect("pending resolution").request {
            PendingKey::Entry(_) => None,
            PendingKey::Invoke(request) => request.source_node_id,
        };
        let mut prepared = Self::prepare_loaded_target(
            loaded,
            *implementation.as_word(),
            true,
            resume.package_debug_info.as_deref(),
            source,
            resume.source_aware,
            host,
        )?;
        if matches!(
            resume.pending.as_ref().expect("pending resolution").request,
            PendingKey::Entry(_)
        ) && Arc::ptr_eq(
            prepared.loaded_mast_forest.mast_forest(),
            resume.program_hint.mast_forest(),
        ) && prepared.root_id == resume.entrypoint_hint
            && let Some(source) = resume.entry_source_hint
        {
            let debug = prepared.package_debug_info.as_ref().ok_or(ExecutionError::Internal(
                "program entry source has no owning debug package",
            ))?;
            if debug.source_node(source).is_none_or(|node| node.exec_node != prepared.root_id) {
                return Err(ExecutionError::Internal(
                    "program entry source does not match the resolved root",
                ));
            }
            prepared.source_node_id = Some(source);
        }
        Ok(prepared)
    }

    fn publish_preflighted_code(
        &mut self,
        prepared: &PreparedLoadedTarget,
    ) -> Result<(), ExecutionError> {
        let forest = prepared.loaded_mast_forest.mast_forest();
        let commitment = forest.commitment();
        if !self.merged_mast_forests.contains(&commitment) {
            self.advice.prepare_extend_map(forest.advice_map()).map_exec_err()?.commit();
            self.merged_mast_forests.insert(commitment);
        }
        if prepared.cache_on_publish {
            Self::cache_loaded_mast_forest(
                &mut self.loaded_mast_forests,
                &prepared.loaded_mast_forest,
            );
        }
        Ok(())
    }

    fn pending_code_not_found(
        resume: &ResumeContext,
        implementation: ImplementationRoot,
        host: &impl BaseHost,
    ) -> ExecutionError {
        let source = match resume.pending.as_ref().expect("pending resolution").request {
            PendingKey::Entry(_) => None,
            PendingKey::Invoke(request) => request.source_node_id,
        };
        match (resume.package_debug_info.as_deref(), source) {
            (Some(debug), Some(source)) => {
                crate::errors::procedure_not_found_with_package_source_context(
                    *implementation.as_word(),
                    PackageSourceDebugContext::new(debug, source),
                    host,
                )
            },
            _ => crate::errors::procedure_not_found_with_context(*implementation.as_word()),
        }
    }

    fn resolve_pending_sync<S, T>(
        &mut self,
        host: &mut impl SyncHost,
        tracer: &mut T,
        stopper: &S,
        resume: &mut ResumeContext,
    ) -> Result<ControlFlow<BreakReason<Arc<MastForest>>>, ExecutionError>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        Self::cache_pending_binding(resume);
        if resume.pending.as_ref().expect("pending resolution").binding.is_none() {
            let request = Self::witness_request(resume);
            let witness = host.get_environment_witness(request).map_err(|error| {
                ExecutionError::EnvironmentSourceError {
                    root: request.root,
                    key: request.key,
                    error,
                }
            })?;
            Self::retain_verified_witness(resume, request, witness)?;
        }
        Self::authorize_pending_mode(resume)?;
        let implementation = Self::pending_implementation(resume);
        let loaded = self
            .local_code_candidate(resume, implementation)
            .or_else(|| host.get_mast_forest(implementation.as_word()))
            .ok_or_else(|| Self::pending_code_not_found(resume, implementation, host))?;
        let prepared = self.prepare_pending_code(resume, loaded, implementation, host)?;
        self.finish_pending(host, tracer, stopper, resume, implementation, prepared)
    }

    async fn resolve_pending_async<S, T>(
        &mut self,
        host: &mut impl Host,
        tracer: &mut T,
        stopper: &S,
        resume: &mut ResumeContext,
    ) -> Result<ControlFlow<BreakReason<Arc<MastForest>>>, ExecutionError>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        Self::cache_pending_binding(resume);
        if resume.pending.as_ref().expect("pending resolution").binding.is_none() {
            let request = Self::witness_request(resume);
            let witness = host.get_environment_witness(request).await.map_err(|error| {
                ExecutionError::EnvironmentSourceError {
                    root: request.root,
                    key: request.key,
                    error,
                }
            })?;
            Self::retain_verified_witness(resume, request, witness)?;
        }
        Self::authorize_pending_mode(resume)?;
        let implementation = Self::pending_implementation(resume);
        let loaded = match self.local_code_candidate(resume, implementation) {
            Some(loaded) => loaded,
            None => host
                .get_mast_forest(implementation.as_word())
                .await
                .ok_or_else(|| Self::pending_code_not_found(resume, implementation, host))?,
        };
        let prepared = self.prepare_pending_code(resume, loaded, implementation, host)?;
        self.finish_pending(host, tracer, stopper, resume, implementation, prepared)
    }

    fn finish_pending<H, S, T>(
        &mut self,
        host: &mut H,
        tracer: &mut T,
        stopper: &S,
        resume: &mut ResumeContext,
        implementation: ImplementationRoot,
        prepared: PreparedLoadedTarget,
    ) -> Result<ControlFlow<BreakReason<Arc<MastForest>>>, ExecutionError>
    where
        H: BaseHost,
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let request = resume.pending.as_ref().expect("pending resolution").request;
        let target = LoadedTarget {
            implementation,
            root: prepared.root_id,
            forest: prepared.loaded_mast_forest.mast_forest().clone(),
            package_debug_info: prepared.package_debug_info.clone(),
            source_node_id: prepared.source_node_id,
        };
        let invocation = if let PendingKey::Invoke(request) = request {
            let mut state = ExecutionState {
                processor: self,
                continuation_stack: &mut resume.continuation_stack,
                host,
                tracer,
                stopper,
                source_debug_info: resume.package_debug_info.clone(),
                current_source_node_id: request.source_node_id,
                inline_call_contexts: &mut resume.inline_call_contexts,
            };
            Some(preflight_keyed_invocation(
                &mut state,
                &resume.current_forest,
                request,
                &target,
            )?)
        } else {
            if self.clk.as_u32() != 0
                || resume.session.phase() != SessionPhase::Unentered
                || self.options.max_num_continuations() < 2
            {
                return Err(ExecutionError::Internal(
                    "entry transition has invalid clock or continuation budget",
                ));
            }
            None
        };
        let entry_stack = if matches!(request, PendingKey::Entry(_)) {
            Some(ContinuationStack::for_root(
                target.root,
                implementation,
                resume.environment.descriptor().entry_key(),
                resume.source_aware,
                target.source_node_id,
            )?)
        } else {
            None
        };

        // After moving a verified opening into a native guard, every returned error is terminal.
        // Before this point the owned pending binding survives all host and code failures.
        let binding = resume
            .pending
            .as_mut()
            .expect("pending resolution")
            .binding
            .take()
            .expect("authenticated pending binding");
        let result = (|| {
            match request {
                PendingKey::Entry(key) => {
                    let PendingBinding::Verified(binding) = binding else {
                        return Err(ExecutionError::Internal(
                            "entry cannot use an unentered cache",
                        ));
                    };
                    let native = resume
                        .session
                        .prepare_entry(binding)
                        .map_err(ExecutionError::EnvironmentSession)?;
                    let reservation = tracer
                        .prepare_environment(&resume.environment.descriptor(), native.binding())?;
                    self.publish_preflighted_code(&prepared)?;
                    native.commit();
                    self.caller_hash = *key.as_word();
                    tracer.commit_environment(reservation);
                    resume.current_forest = target.forest;
                    resume.package_debug_info = target.package_debug_info;
                    resume.continuation_stack = entry_stack.expect("prepared entry stack");
                    resume.pending = None;
                    Ok(ControlFlow::Continue(()))
                },
                PendingKey::Invoke(request) => {
                    let tag = if request.mode == KeyedMode::Syscall {
                        InvocationTag::Syscall
                    } else {
                        InvocationTag::Normal
                    };
                    let native = match binding {
                        PendingBinding::Verified(binding) => {
                            resume.session.prepare(request.key, binding, tag, request.row)
                        },
                        PendingBinding::Cached(_) => {
                            resume.session.prepare_cached(request.key, tag, request.row)
                        },
                    }
                    .map_err(ExecutionError::EnvironmentSession)?;
                    let principal = ProcedureKey::new(self.caller_hash);
                    let event = KeyedEvent {
                        kind: KeyedEventKind::Invoke(request.mode),
                        use_record: native.use_record(),
                        principal_before: principal,
                        principal_after: if matches!(
                            request.mode,
                            KeyedMode::Call | KeyedMode::DynCall
                        ) {
                            request.key
                        } else {
                            principal
                        },
                    };
                    let reservation = tracer.prepare_keyed_transition(
                        self,
                        &event,
                        KeyedTarget {
                            forest: &target.forest,
                            root: target.root,
                            implementation,
                        },
                        invocation.as_ref().expect("prepared invocation").projection,
                    )?;
                    self.publish_preflighted_code(&prepared)?;
                    native.commit();
                    resume.pending = None;
                    let mut state = ExecutionState {
                        processor: self,
                        continuation_stack: &mut resume.continuation_stack,
                        host,
                        tracer,
                        stopper,
                        source_debug_info: resume.package_debug_info.clone(),
                        current_source_node_id: request.source_node_id,
                        inline_call_contexts: &mut resume.inline_call_contexts,
                    };
                    let flow = finish_keyed_invocation(
                        &mut state,
                        &mut resume.current_forest,
                        request,
                        target,
                        invocation.expect("prepared invocation"),
                        event,
                        reservation,
                    );
                    // Source ownership switches even when stepping stops on the invocation row.
                    resume.package_debug_info = state.source_debug_info.clone();
                    Ok(flow)
                },
            }
        })();
        if result.is_err() {
            self.invalidate(resume);
        }
        result
    }

    fn complete_root_end<H, S, T>(
        &mut self,
        host: &mut H,
        tracer: &mut T,
        stopper: &S,
        resume: &mut ResumeContext,
        request: RootEndRequest<Arc<MastForest>>,
    ) -> Result<ControlFlow<BreakReason<Arc<MastForest>>>, ExecutionError>
    where
        H: BaseHost,
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let prepared = {
            let mut state = ExecutionState {
                processor: self,
                continuation_stack: &mut resume.continuation_stack,
                host,
                tracer,
                stopper,
                source_debug_info: resume.package_debug_info.clone(),
                current_source_node_id: request.source_node_id,
                inline_call_contexts: &mut resume.inline_call_contexts,
            };
            preflight_root_end(&mut state, &resume.current_forest, &request)?
        };
        let completion =
            tracer.prepare_environment_completion(&resume.environment, &resume.session)?;
        let native = resume
            .session
            .prepare_root_end(request.implementation, request.row)
            .map_err(ExecutionError::EnvironmentSession)?;
        let event = KeyedEvent {
            kind: KeyedEventKind::RootEnd,
            use_record: native.use_record(),
            principal_before: ProcedureKey::new(self.caller_hash),
            principal_after: request.principal,
        };
        let root = request.continuation.exec_node().expect("root preflight checked actual node");
        let reservation = tracer.prepare_keyed_transition(
            self,
            &event,
            KeyedTarget {
                forest: &resume.current_forest,
                root,
                implementation: request.implementation,
            },
            prepared.projection,
        )?;
        native.commit();
        tracer.commit_environment_completion(completion);
        let mut state = ExecutionState {
            processor: self,
            continuation_stack: &mut resume.continuation_stack,
            host,
            tracer,
            stopper,
            source_debug_info: resume.package_debug_info.clone(),
            current_source_node_id: request.source_node_id,
            inline_call_contexts: &mut resume.inline_call_contexts,
        };
        Ok(finish_root_end(
            &mut state,
            &resume.current_forest,
            request,
            prepared,
            event,
            reservation,
        ))
    }

    fn completed(&mut self, resume: &mut ResumeContext) -> Result<bool, ExecutionError> {
        if resume.pending.is_some() || resume.session.phase() != SessionPhase::Completed {
            self.invalidate(resume);
            return Err(ExecutionError::Internal(
                "execution ended before its authenticated root END",
            ));
        }
        if let Err(error) = resume.session.finalize() {
            self.invalidate(resume);
            return Err(ExecutionError::EnvironmentSession(error));
        }
        resume.lifecycle = ExecutionLifecycle::Complete;
        Ok(true)
    }

    fn stopped(
        &mut self,
        resume: &mut ResumeContext,
        reason: BreakReason<Arc<MastForest>>,
    ) -> Result<bool, ExecutionError> {
        match reason {
            BreakReason::Err(error) => {
                // Generic cycle callbacks may fail after native/VM publication. Such execution
                // can never be resumed or exported, regardless of the callback's error kind.
                self.invalidate(resume);
                Err(error)
            },
            BreakReason::Stopped(next) => {
                if let Some((continuation, source)) = next {
                    resume
                        .continuation_stack
                        .push_resumed_with_source_node_id(continuation, source);
                }
                while matches!(
                    resume.continuation_stack.peek_continuation(),
                    Some(Continuation::EnterForest { .. })
                ) {
                    let Some((
                        Continuation::EnterForest {
                            forest,
                            package_debug_info,
                            inline_context_depth,
                        },
                        _,
                    )) = resume.continuation_stack.pop_continuation_with_source_node_id()
                    else {
                        unreachable!("peeked forest restoration exists");
                    };
                    resume.current_forest = forest;
                    resume.package_debug_info = package_debug_info;
                    resume.inline_call_contexts.truncate(inline_context_depth);
                }
                if resume.continuation_stack.len() == 0 {
                    self.completed(resume)
                } else {
                    Ok(false)
                }
            },
        }
    }

    fn retain_key_request(resume: &mut ResumeContext, request: KeyedRequest) {
        debug_assert!(resume.pending.is_none());
        resume.pending = Some(PendingResolution {
            request: PendingKey::Invoke(request),
            binding: None,
        });
    }

    pub(super) fn drive_sync<S, T>(
        &mut self,
        host: &mut impl SyncHost,
        tracer: &mut T,
        stopper: &S,
        resume: &mut ResumeContext,
    ) -> Result<bool, ExecutionError>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.check_resume(resume)?;
        loop {
            if resume.pending.is_some()
                && let ControlFlow::Break(reason) =
                    self.resolve_pending_sync(host, tracer, stopper, resume)?
            {
                return self.stopped(resume, reason);
            }
            let reason = match execute_impl(
                self,
                &mut resume.continuation_stack,
                &mut resume.current_forest,
                host,
                tracer,
                stopper,
                &mut resume.package_debug_info,
                &mut resume.inline_call_contexts,
            ) {
                ControlFlow::Continue(()) => return self.completed(resume),
                ControlFlow::Break(reason) => reason,
            };
            match reason {
                InternalBreakReason::ResolveKey(request) => {
                    Self::retain_key_request(resume, request)
                },
                InternalBreakReason::RootEnd(request) => {
                    if let ControlFlow::Break(reason) =
                        self.complete_root_end(host, tracer, stopper, resume, request)?
                    {
                        return self.stopped(resume, reason);
                    }
                },
                InternalBreakReason::User(reason) => return self.stopped(resume, reason),
                InternalBreakReason::Emit { op_idx, continuation, source_node_id } => {
                    if let ControlFlow::Break(reason) = self.op_emit_sync(
                        host,
                        op_idx,
                        resume.package_debug_info.as_deref(),
                        source_node_id,
                    ) {
                        return self.stopped(resume, reason);
                    }
                    if let ControlFlow::Break(reason) = finish_emit_op_execution(
                        continuation,
                        source_node_id,
                        self,
                        &mut resume.continuation_stack,
                        &resume.current_forest,
                        tracer,
                        stopper,
                    ) {
                        return self.stopped(resume, reason);
                    }
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash,
                    source_node_id,
                } => {
                    let inline = resume.package_debug_info.clone().and_then(|debug| {
                        crate::SourceInlineCallContext::for_source_boundary(debug, source_node_id)
                    });
                    let loaded = self.load_mast_forest_sync(
                        procedure_hash,
                        host,
                        resume.package_debug_info.as_deref(),
                        source_node_id,
                        resume.source_aware,
                    );
                    let (root, forest, debug, source) = match loaded {
                        Ok(loaded) => loaded,
                        Err(error) => {
                            let error = maybe_use_caller_error_context(
                                error,
                                &resume.continuation_stack,
                                resume.package_debug_info.as_deref(),
                                host,
                            );
                            self.invalidate(resume);
                            return Err(error);
                        },
                    };
                    if let ControlFlow::Break(reason) = finish_load_mast_forest_from_external(
                        root,
                        forest,
                        debug,
                        source,
                        inline,
                        (external_node_id, source_node_id),
                        &mut resume.current_forest,
                        &mut resume.package_debug_info,
                        &mut resume.inline_call_contexts,
                        &mut resume.continuation_stack,
                        tracer,
                    ) {
                        return self.stopped(resume, reason);
                    }
                },
            }
        }
    }

    pub(super) async fn drive_async<S, T>(
        &mut self,
        host: &mut impl Host,
        tracer: &mut T,
        stopper: &S,
        resume: &mut ResumeContext,
    ) -> Result<bool, ExecutionError>
    where
        S: Stopper<Processor = Self, Forest = Arc<MastForest>>,
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.check_resume(resume)?;
        loop {
            if resume.pending.is_some()
                && let ControlFlow::Break(reason) =
                    self.resolve_pending_async(host, tracer, stopper, resume).await?
            {
                return self.stopped(resume, reason);
            }
            let reason = match execute_impl(
                self,
                &mut resume.continuation_stack,
                &mut resume.current_forest,
                host,
                tracer,
                stopper,
                &mut resume.package_debug_info,
                &mut resume.inline_call_contexts,
            ) {
                ControlFlow::Continue(()) => return self.completed(resume),
                ControlFlow::Break(reason) => reason,
            };
            match reason {
                InternalBreakReason::ResolveKey(request) => {
                    Self::retain_key_request(resume, request)
                },
                InternalBreakReason::RootEnd(request) => {
                    if let ControlFlow::Break(reason) =
                        self.complete_root_end(host, tracer, stopper, resume, request)?
                    {
                        return self.stopped(resume, reason);
                    }
                },
                InternalBreakReason::User(reason) => return self.stopped(resume, reason),
                InternalBreakReason::Emit { op_idx, continuation, source_node_id } => {
                    // The legacy event boundary has already started its cycle. Cancellation
                    // there is terminal; keyed witness/code awaits above remain retryable.
                    self.invalidate(resume);
                    let emit = self
                        .op_emit(host, op_idx, resume.package_debug_info.as_deref(), source_node_id)
                        .await;
                    if let ControlFlow::Break(reason) = emit {
                        return self.stopped(resume, reason);
                    }
                    self.invalid_execution = false;
                    resume.lifecycle = ExecutionLifecycle::Active;
                    if let ControlFlow::Break(reason) = finish_emit_op_execution(
                        continuation,
                        source_node_id,
                        self,
                        &mut resume.continuation_stack,
                        &resume.current_forest,
                        tracer,
                        stopper,
                    ) {
                        return self.stopped(resume, reason);
                    }
                },
                InternalBreakReason::LoadMastForestFromExternal {
                    external_node_id,
                    procedure_hash,
                    source_node_id,
                } => {
                    let inline = resume.package_debug_info.clone().and_then(|debug| {
                        crate::SourceInlineCallContext::for_source_boundary(debug, source_node_id)
                    });
                    // Structural External(D) is part of already authenticated code, not key
                    // authority. Its legacy sans-IO boundary remains terminal on returned errors.
                    self.invalidate(resume);
                    let loaded = self
                        .load_mast_forest(
                            procedure_hash,
                            host,
                            resume.package_debug_info.as_deref(),
                            source_node_id,
                            resume.source_aware,
                        )
                        .await;
                    let (root, forest, debug, source) = match loaded {
                        Ok(loaded) => loaded,
                        Err(error) => {
                            let error = maybe_use_caller_error_context(
                                error,
                                &resume.continuation_stack,
                                resume.package_debug_info.as_deref(),
                                host,
                            );
                            self.invalidate(resume);
                            return Err(error);
                        },
                    };
                    self.invalid_execution = false;
                    resume.lifecycle = ExecutionLifecycle::Active;
                    if let ControlFlow::Break(reason) = finish_load_mast_forest_from_external(
                        root,
                        forest,
                        debug,
                        source,
                        inline,
                        (external_node_id, source_node_id),
                        &mut resume.current_forest,
                        &mut resume.package_debug_info,
                        &mut resume.inline_call_contexts,
                        &mut resume.continuation_stack,
                        tracer,
                    ) {
                        return self.stopped(resume, reason);
                    }
                },
            }
        }
    }
}
