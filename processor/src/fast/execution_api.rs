use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId},
    program::{ImplementationRoot, MIN_STACK_DEPTH, Program, StackInputs, StackOutputs},
};
use miden_mast_package::{
    PackageProcedureOccurrence,
    debug_info::{DebugSourceGraphLookupError, DebugSourceNodeId, PackageDebugInfo},
};
use tracing::instrument;

use super::{
    FastProcessor, NoopTracer,
    step::{NeverStopper, ResumeContext, StepStopper},
};
#[cfg(feature = "std")]
use crate::PrecompileWitness;
use crate::{
    BaseHost, CodeRequest, ExecutionError, ExecutionOutput, ExecutionWitness, Host,
    LoadedMastForest, SyncHost,
    continuation_stack::ContinuationStack,
    errors::{MapExecErr, PackageSourceDebugContext, malformed_mast_forest_with_context},
    execution::LoadedTarget,
    trace::execution_tracer::ExecutionTracer,
    tracer::Tracer,
};

/// Validated code supply, retained without publishing cache or advice state.
///
/// This is separate from environment authentication: possession of a requested body does not
/// authorize its execution.
#[derive(Debug)]
struct PreparedLoadedTarget {
    request: CodeRequest,
    root_id: MastNodeId,
    loaded_mast_forest: LoadedMastForest,
    package_debug_info: Option<Arc<PackageDebugInfo>>,
    source_node_id: Option<DebugSourceNodeId>,
}

/// Whether source selection may infer a unique root or must retain an explicit occurrence.
enum SourceNodeHint {
    Infer,
    Exact(Option<DebugSourceNodeId>),
}

impl FastProcessor {
    pub(super) fn new_resume_context(
        &mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        debug_info: Option<Arc<PackageDebugInfo>>,
        entry_source_hint: Option<DebugSourceNodeId>,
    ) -> Result<ResumeContext, ExecutionError> {
        if self.invalid_execution || self.execution_identity.is_some() || self.clk.as_u32() != 0 {
            return Err(ExecutionError::InvalidExecutionState);
        }
        let identity = Arc::new(());
        let program_hint = LoadedMastForest::with_package_debug_info(
            program.mast_forest().clone(),
            Ok(debug_info.as_deref().cloned()),
        );
        let descriptor = environment.descriptor();
        let resume = ResumeContext {
            current_forest: program.mast_forest().clone(),
            loaded_owner: None,
            continuation_stack: ContinuationStack::default(),
            package_debug_info: None,
            inline_call_contexts: Vec::new(),
            environment,
            session: crate::ResolutionSession::new(
                descriptor,
                environment.ledger_limits(),
                environment.session_limits(),
            ),
            pending: Some(super::step::PendingResolution {
                request: super::step::PendingKey::Entry(descriptor.entry_key()),
                binding: None,
            }),
            lifecycle: super::step::ExecutionLifecycle::Active,
            identity: identity.clone(),
            program_hint,
            entrypoint_hint: program.entrypoint(),
            entry_source_hint,
            source_aware: debug_info.is_some() || entry_source_hint.is_some(),
        };
        self.execution_identity = Some(identity);
        Ok(resume)
    }

    // EXECUTE
    // -------------------------------------------------------------------------------------------

    /// Executes the given program synchronously and returns the execution output.
    pub fn execute_sync(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_tracer_sync(program, environment, host, &mut NoopTracer)
    }

    /// Executes the given program synchronously with package-owned source/debug context.
    ///
    /// This derives the entrypoint source occurrence from [`PackageDebugInfo`], so the source graph
    /// must contain at most one root for the executable entrypoint. When the package manifest names
    /// the exact entrypoint source occurrence, use
    /// [`Self::execute_with_package_debug_info_at_source_node_sync`] instead.
    pub fn execute_with_package_debug_info_sync(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer_sync(
            program,
            environment,
            package_debug_info,
            None,
            host,
            &mut NoopTracer,
        )
    }

    /// Executes the given program synchronously with package-owned source/debug context rooted at
    /// `entrypoint_source_node_id`.
    ///
    /// Use this when the package manifest names the exact source/debug occurrence for the
    /// executable entrypoint. This preserves source disambiguation when multiple source roots map
    /// to the same executable MAST node.
    pub fn execute_with_package_debug_info_at_source_node_sync(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer_sync(
            program,
            environment,
            package_debug_info,
            Some(entrypoint_source_node_id),
            host,
            &mut NoopTracer,
        )
    }

    /// Async variant of [`Self::execute_sync`] for hosts that need async callbacks.
    #[inline(always)]
    pub async fn execute(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_tracer(program, environment, host, &mut NoopTracer).await
    }

    /// Async variant of [`Self::execute_with_package_debug_info_sync`].
    ///
    /// When the package manifest names the exact entrypoint source occurrence, use
    /// [`Self::execute_with_package_debug_info_at_source_node`] instead.
    #[inline(always)]
    pub async fn execute_with_package_debug_info(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer(
            program,
            environment,
            package_debug_info,
            None,
            host,
            &mut NoopTracer,
        )
        .await
    }

    /// Async variant of [`Self::execute_with_package_debug_info_at_source_node_sync`].
    #[inline(always)]
    pub async fn execute_with_package_debug_info_at_source_node(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl Host,
    ) -> Result<ExecutionOutput, ExecutionError> {
        self.execute_with_package_debug_info_and_tracer(
            program,
            environment,
            package_debug_info,
            Some(entrypoint_source_node_id),
            host,
            &mut NoopTracer,
        )
        .await
    }

    /// Executes the program and builds its execution trace, overlapping the two when a Rayon worker
    /// is available. The hasher chiplet — the dominant serial part of trace building — consumes a
    /// live stream of requests while execution is still running, hiding its cost behind the
    /// (inherently sequential) execution itself. When the caller is Rayon's only worker, this uses
    /// compact buffered replay and builds the trace after execution.
    ///
    /// `budget` applies the same modelled peak-memory bound as
    /// [`crate::trace::build_trace`] does; the streamed hasher builds ahead of that
    /// call, so it needs its own copy of the derived row cap.
    /// The supplied model must satisfy the compatibility requirements documented on
    /// [`crate::trace::build_trace`].
    ///
    /// Produces the same trace as [`Self::execute_for_proving_sync`] followed by
    /// [`ExecutionWitness::into_parts`] and [`crate::trace::build_trace`]. The optional
    /// precompile witness is returned separately because [`crate::trace::VmTrace`] retains only
    /// its authenticated root.
    #[cfg(feature = "std")]
    #[instrument(name = "execute_and_build_trace_sync", skip_all)]
    pub fn execute_and_build_trace_sync(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl SyncHost,
        budget: &miden_stark::memory::ProvingBudget<{ miden_air_definitions::vm::MIDEN_AIR_COUNT }>,
    ) -> Result<(crate::trace::VmTrace, Option<PrecompileWitness>), ExecutionError> {
        use crate::trace::{
            MAX_TRACE_LEN, build_hasher_chiplet, build_trace, build_trace_with_prebuilt_hasher,
        };

        if Self::rayon_has_no_parallel_worker() {
            let (vm_witness, precompiles_witness) =
                self.execute_for_proving_sync(program, environment, host)?.into_parts();
            let trace = build_trace(vm_witness, budget)?;
            return Ok((trace, precompiles_witness));
        }

        let stack_inputs = self.initial_stack_inputs();
        let trace_limits = self
            .options
            .environment_trace_limits()
            .ok_or(ExecutionError::MissingEnvironmentTraceLimits)?;
        let max_trace_len = MAX_TRACE_LEN.min(budget.max_any_height());
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut tracer = ExecutionTracer::new_with_streamed_hasher(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
            sender,
            trace_limits,
        )?;

        let mut hasher = None;
        let hasher_slot = &mut hasher;
        // Keep `tracer` owned by the scope body. If execution unwinds, dropping the body closes the
        // stream before Rayon waits for the builder, so the builder cannot remain blocked on input.
        let execution_output = rayon::in_place_scope(move |scope| {
            // Execution and the host remain on the calling thread. An idle Rayon worker can steal
            // only the builder task.
            let span = tracing::Span::current();
            scope.spawn(move |_| {
                let _span = span.entered();
                let result = build_hasher_chiplet(
                    receiver.into_iter().map(Ok),
                    max_trace_len,
                    max_trace_len,
                );
                *hasher_slot = Some(result);
            });

            let execution_output =
                self.execute_with_tracer_and_session_sync(program, environment, host, &mut tracer);

            match execution_output {
                Ok((output, session)) => {
                    let (mut vm_witness, precompiles_witness) =
                        Self::execution_witness_from_parts(stack_inputs, output, session, tracer)?
                            .into_parts();
                    // End the stream before this scope waits for the builder.
                    drop(vm_witness.take_hasher_replay());
                    Ok((vm_witness, precompiles_witness))
                },
                Err(err) => {
                    // Dropping the tracer closes the stream and lets the builder finish. The
                    // execution error remains the root cause even if the partial replay also
                    // failed.
                    drop(tracer);
                    Err(err)
                },
            }
        });

        let hasher = hasher.expect("hasher builder did not run");
        let (vm_witness, precompiles_witness) = match execution_output {
            Ok(output) => output,
            Err(err) => {
                if let Err(builder_err) = hasher {
                    tracing::debug!(%builder_err, "hasher builder also failed");
                }
                return Err(err);
            },
        };

        let trace = build_trace_with_prebuilt_hasher(vm_witness, hasher?, budget)?;
        Ok((trace, precompiles_witness))
    }

    #[cfg(feature = "std")]
    fn rayon_has_no_parallel_worker() -> bool {
        // `current_num_threads` initializes Rayon's global fallback before the thread-index check.
        rayon::current_num_threads() == 1 && rayon::current_thread_index().is_some()
    }

    /// Executes the given program synchronously and returns its complete post-execution witness.
    ///
    /// # Example
    /// ```
    /// use miden_assembly::Assembler;
    /// use miden_processor::{DefaultHost, FastProcessor, StackInputs};
    ///
    /// let program = Assembler::default()
    ///     .assemble_program("prg", "begin push.1 drop end")
    ///     .unwrap()
    ///     .unwrap_program();
    /// let mut host = DefaultHost::default();
    ///
    /// let execution_witness = FastProcessor::new(StackInputs::default())
    ///     .execute_for_proving_sync(&program, &mut host)
    ///     .unwrap();
    /// let (vm_witness, _) = execution_witness.into_parts();
    /// let trace =
    ///     miden_processor::trace::build_trace(vm_witness, &miden_vm_stark::memory::default_budget())
    ///         .unwrap();
    ///
    /// assert_eq!(*trace.entry_implementation().as_word(), program.hash());
    /// ```
    #[instrument(name = "execute_for_proving_sync", skip_all)]
    pub fn execute_for_proving_sync(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionWitness, ExecutionError> {
        let stack_inputs = self.initial_stack_inputs();
        let trace_limits = self
            .options
            .environment_trace_limits()
            .ok_or(ExecutionError::MissingEnvironmentTraceLimits)?;
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
            trace_limits,
        )?;
        let (execution_output, session) =
            self.execute_with_tracer_and_session_sync(program, environment, host, &mut tracer)?;
        Self::execution_witness_from_parts(stack_inputs, execution_output, session, tracer)
    }

    /// Executes the given program synchronously with package-owned source/debug context and returns
    /// its complete post-execution witness.
    #[instrument(name = "execute_for_proving_with_package_debug_info_sync", skip_all)]
    pub fn execute_for_proving_with_package_debug_info_sync(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionWitness, ExecutionError> {
        let stack_inputs = self.initial_stack_inputs();
        let trace_limits = self
            .options
            .environment_trace_limits()
            .ok_or(ExecutionError::MissingEnvironmentTraceLimits)?;
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
            trace_limits,
        )?;
        let (execution_output, session) = self
            .execute_with_package_debug_info_and_tracer_and_session_sync(
                program,
                environment,
                package_debug_info,
                None,
                host,
                &mut tracer,
            )?;
        Self::execution_witness_from_parts(stack_inputs, execution_output, session, tracer)
    }

    /// Executes the given program synchronously with package-owned source/debug context rooted at
    /// `entrypoint_source_node_id` and returns its complete post-execution witness.
    #[instrument(
        name = "execute_for_proving_with_package_debug_info_at_source_node_sync",
        skip_all
    )]
    pub fn execute_for_proving_with_package_debug_info_at_source_node_sync(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl SyncHost,
    ) -> Result<ExecutionWitness, ExecutionError> {
        let stack_inputs = self.initial_stack_inputs();
        let trace_limits = self
            .options
            .environment_trace_limits()
            .ok_or(ExecutionError::MissingEnvironmentTraceLimits)?;
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
            trace_limits,
        )?;
        let (execution_output, session) = self
            .execute_with_package_debug_info_and_tracer_and_session_sync(
                program,
                environment,
                package_debug_info,
                Some(entrypoint_source_node_id),
                host,
                &mut tracer,
            )?;
        Self::execution_witness_from_parts(stack_inputs, execution_output, session, tracer)
    }

    /// Async variant of [`Self::execute_for_proving_sync`] for async hosts.
    #[inline(always)]
    #[instrument(name = "execute_for_proving", skip_all)]
    pub async fn execute_for_proving(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl Host,
    ) -> Result<ExecutionWitness, ExecutionError> {
        let stack_inputs = self.initial_stack_inputs();
        let trace_limits = self
            .options
            .environment_trace_limits()
            .ok_or(ExecutionError::MissingEnvironmentTraceLimits)?;
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
            trace_limits,
        )?;
        let (execution_output, session) = self
            .execute_with_tracer_and_session(program, environment, host, &mut tracer)
            .await?;
        Self::execution_witness_from_parts(stack_inputs, execution_output, session, tracer)
    }

    /// Async variant of [`Self::execute_for_proving_with_package_debug_info_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    #[instrument(name = "execute_for_proving_with_package_debug_info", skip_all)]
    pub async fn execute_for_proving_with_package_debug_info(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl Host,
    ) -> Result<ExecutionWitness, ExecutionError> {
        let stack_inputs = self.initial_stack_inputs();
        let trace_limits = self
            .options
            .environment_trace_limits()
            .ok_or(ExecutionError::MissingEnvironmentTraceLimits)?;
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
            trace_limits,
        )?;
        let (execution_output, session) = self
            .execute_with_package_debug_info_and_tracer_and_session(
                program,
                environment,
                package_debug_info,
                None,
                host,
                &mut tracer,
            )
            .await?;
        Self::execution_witness_from_parts(stack_inputs, execution_output, session, tracer)
    }

    /// Async variant of
    /// [`Self::execute_for_proving_with_package_debug_info_at_source_node_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    #[instrument(name = "execute_for_proving_with_package_debug_info_at_source_node", skip_all)]
    pub async fn execute_for_proving_with_package_debug_info_at_source_node(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl Host,
    ) -> Result<ExecutionWitness, ExecutionError> {
        let stack_inputs = self.initial_stack_inputs();
        let trace_limits = self
            .options
            .environment_trace_limits()
            .ok_or(ExecutionError::MissingEnvironmentTraceLimits)?;
        let mut tracer = ExecutionTracer::new(
            self.options.core_trace_fragment_size(),
            self.options.max_stack_depth(),
            trace_limits,
        )?;
        let (execution_output, session) = self
            .execute_with_package_debug_info_and_tracer_and_session(
                program,
                environment,
                package_debug_info,
                Some(entrypoint_source_node_id),
                host,
                &mut tracer,
            )
            .await?;
        Self::execution_witness_from_parts(stack_inputs, execution_output, session, tracer)
    }

    /// Executes the given program with the provided tracer using an async host.
    pub async fn execute_with_tracer<T>(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl Host,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.execute_with_tracer_and_session(program, environment, host, tracer)
            .await
            .map(|(output, _)| output)
    }

    async fn execute_with_package_debug_info_and_tracer<T>(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
        host: &mut impl Host,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.execute_with_package_debug_info_and_tracer_and_session(
            program,
            environment,
            package_debug_info,
            entrypoint_source_node_id,
            host,
            tracer,
        )
        .await
        .map(|(output, _)| output)
    }

    /// Executes the given program with the provided tracer using a sync host.
    pub fn execute_with_tracer_sync<T>(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl SyncHost,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.execute_with_tracer_and_session_sync(program, environment, host, tracer)
            .map(|(output, _)| output)
    }

    fn execute_with_package_debug_info_and_tracer_sync<T>(
        self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
        host: &mut impl SyncHost,
        tracer: &mut T,
    ) -> Result<ExecutionOutput, ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        self.execute_with_package_debug_info_and_tracer_and_session_sync(
            program,
            environment,
            package_debug_info,
            entrypoint_source_node_id,
            host,
            tracer,
        )
        .map(|(output, _)| output)
    }

    /// Executes the given program with the provided tracer using an async host.
    async fn execute_with_tracer_and_session<T>(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl Host,
        tracer: &mut T,
    ) -> Result<(ExecutionOutput, crate::ResolutionSession), ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut resume = self.new_resume_context(program, environment, None, None)?;
        if !self.drive_async(host, tracer, &NeverStopper, &mut resume).await? {
            return Err(ExecutionError::Internal("full execution stopped unexpectedly"));
        }
        let stack = self.current_stack_outputs()?;
        let output = self.into_execution_output(stack)?;
        Ok((output, resume.session))
    }

    /// Executes the given program with package-owned source/debug context and the provided tracer
    /// using an async host.
    async fn execute_with_package_debug_info_and_tracer_and_session<T>(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
        host: &mut impl Host,
        tracer: &mut T,
    ) -> Result<(ExecutionOutput, crate::ResolutionSession), ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut resume = self.new_resume_context(
            program,
            environment,
            Some(Arc::new(package_debug_info.clone())),
            entrypoint_source_node_id,
        )?;
        if !self.drive_async(host, tracer, &NeverStopper, &mut resume).await? {
            return Err(ExecutionError::Internal("full execution stopped unexpectedly"));
        }
        let stack = self.current_stack_outputs()?;
        let output = self.into_execution_output(stack)?;
        Ok((output, resume.session))
    }

    /// Executes the given program with the provided tracer using a sync host.
    fn execute_with_tracer_and_session_sync<T>(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl SyncHost,
        tracer: &mut T,
    ) -> Result<(ExecutionOutput, crate::ResolutionSession), ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut resume = self.new_resume_context(program, environment, None, None)?;
        if !self.drive_sync(host, tracer, &NeverStopper, &mut resume)? {
            return Err(ExecutionError::Internal("full execution stopped unexpectedly"));
        }
        let stack = self.current_stack_outputs()?;
        let output = self.into_execution_output(stack)?;
        Ok((output, resume.session))
    }

    /// Executes the given program with package-owned source/debug context and the provided tracer
    /// using a sync host.
    fn execute_with_package_debug_info_and_tracer_and_session_sync<T>(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: Option<DebugSourceNodeId>,
        host: &mut impl SyncHost,
        tracer: &mut T,
    ) -> Result<(ExecutionOutput, crate::ResolutionSession), ExecutionError>
    where
        T: Tracer<Processor = Self, Forest = Arc<MastForest>>,
    {
        let mut resume = self.new_resume_context(
            program,
            environment,
            Some(Arc::new(package_debug_info.clone())),
            entrypoint_source_node_id,
        )?;
        if !self.drive_sync(host, tracer, &NeverStopper, &mut resume)? {
            return Err(ExecutionError::Internal("full execution stopped unexpectedly"));
        }
        let stack = self.current_stack_outputs()?;
        let output = self.into_execution_output(stack)?;
        Ok((output, resume.session))
    }

    /// Executes a single clock cycle synchronously.
    pub fn step_sync(
        &mut self,
        host: &mut impl SyncHost,
        resume_ctx: &mut ResumeContext,
    ) -> Result<bool, ExecutionError> {
        self.drive_sync(host, &mut NoopTracer, &StepStopper, resume_ctx)
    }

    /// Executes a single clock cycle synchronously with package-owned source/debug context.
    pub fn step_with_package_debug_info_sync(
        &mut self,
        host: &mut impl SyncHost,
        resume_ctx: &mut ResumeContext,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<bool, ExecutionError> {
        if !resume_ctx.source_aware {
            if resume_ctx.session.phase() != crate::SessionPhase::Unentered {
                return Err(ExecutionError::Internal(
                    "source-aware stepping must be configured before entry resolution",
                ));
            }
            resume_ctx.program_hint = LoadedMastForest::with_package_debug_info(
                resume_ctx.program_hint.mast_forest().clone(),
                Ok(Some(package_debug_info.clone())),
            );
            resume_ctx.source_aware = true;
        }
        self.drive_sync(host, &mut NoopTracer, &StepStopper, resume_ctx)
    }

    /// Async variant of [`Self::step_sync`].
    #[inline(always)]
    pub async fn step(
        &mut self,
        host: &mut impl Host,
        resume_ctx: &mut ResumeContext,
    ) -> Result<bool, ExecutionError> {
        self.drive_async(host, &mut NoopTracer, &StepStopper, resume_ctx).await
    }

    /// Async variant of [`Self::step_with_package_debug_info_sync`].
    #[inline(always)]
    pub async fn step_with_package_debug_info(
        &mut self,
        host: &mut impl Host,
        resume_ctx: &mut ResumeContext,
        package_debug_info: &PackageDebugInfo,
    ) -> Result<bool, ExecutionError> {
        if !resume_ctx.source_aware {
            if resume_ctx.session.phase() != crate::SessionPhase::Unentered {
                return Err(ExecutionError::Internal(
                    "source-aware stepping must be configured before entry resolution",
                ));
            }
            resume_ctx.program_hint = LoadedMastForest::with_package_debug_info(
                resume_ctx.program_hint.mast_forest().clone(),
                Ok(Some(package_debug_info.clone())),
            );
            resume_ctx.source_aware = true;
        }
        self.drive_async(host, &mut NoopTracer, &StepStopper, resume_ctx).await
    }

    /// Pairs execution output with the initial inputs and replay witness captured during execution.
    #[inline(always)]
    fn execution_witness_from_parts(
        stack_inputs: StackInputs,
        execution_output: ExecutionOutput,
        session: crate::ResolutionSession,
        tracer: ExecutionTracer,
    ) -> Result<ExecutionWitness, ExecutionError> {
        let trace = tracer.into_trace_replay(session)?;
        ExecutionWitness::from_execution(stack_inputs, execution_output, trace)
    }

    /// Returns the current top 16 stack elements in public input order.
    #[inline(always)]
    fn initial_stack_inputs(&self) -> StackInputs {
        core::array::from_fn(|idx| self.stack_get(idx)).into()
    }

    /// Materializes the current stack as public outputs without consuming the processor.
    #[inline(always)]
    fn current_stack_outputs(&self) -> Result<StackOutputs, ExecutionError> {
        StackOutputs::new(
            &self.stack[self.stack_bot_idx..self.stack_top_idx]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<_>>(),
        )
        .map_err(|_| {
            ExecutionError::OutputStackOverflow(
                self.stack_top_idx - self.stack_bot_idx - MIN_STACK_DEPTH,
            )
        })
    }

    // HELPERS
    // ------------------------------------------------------------------------------------------

    fn load_mast_forest_sync(
        &mut self,
        node_digest: Word,
        host: &mut impl SyncHost,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
        source_aware_execution: bool,
    ) -> Result<LoadedTarget<Arc<MastForest>>, ExecutionError> {
        let cached = self
            .loaded_mast_forests
            .get(&node_digest)
            .and_then(|owners| owners.first())
            .cloned();
        let loaded_mast_forest = match cached {
            Some(mast_forest) => mast_forest,
            None => host
                .get_mast_forest(CodeRequest::External {
                    implementation: ImplementationRoot::new(node_digest),
                })
                .ok_or_else(|| match (package_debug_info, source_node_id) {
                    (Some(debug_info), Some(source_node_id)) => {
                        crate::errors::procedure_not_found_with_package_source_context(
                            node_digest,
                            PackageSourceDebugContext::new(debug_info, source_node_id),
                            host,
                        )
                    },
                    _ => crate::errors::procedure_not_found_with_context(node_digest),
                })?,
        };
        let prepared = Self::prepare_loaded_target(
            loaded_mast_forest,
            CodeRequest::External {
                implementation: ImplementationRoot::new(node_digest),
            },
            None,
            package_debug_info,
            source_node_id,
            source_aware_execution,
            host,
        )?;
        self.publish_loaded_target(prepared)
    }

    async fn load_mast_forest(
        &mut self,
        node_digest: Word,
        host: &mut impl Host,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
        source_aware_execution: bool,
    ) -> Result<LoadedTarget<Arc<MastForest>>, ExecutionError> {
        let cached = self
            .loaded_mast_forests
            .get(&node_digest)
            .and_then(|owners| owners.first())
            .cloned();
        let loaded_mast_forest = match cached {
            Some(mast_forest) => mast_forest,
            None => {
                if let Some(mast_forest) = host
                    .get_mast_forest(CodeRequest::External {
                        implementation: ImplementationRoot::new(node_digest),
                    })
                    .await
                {
                    mast_forest
                } else {
                    return Err(match (package_debug_info, source_node_id) {
                        (Some(debug_info), Some(source_node_id)) => {
                            crate::errors::procedure_not_found_with_package_source_context(
                                node_digest,
                                PackageSourceDebugContext::new(debug_info, source_node_id),
                                host,
                            )
                        },
                        _ => crate::errors::procedure_not_found_with_context(node_digest),
                    });
                }
            },
        };
        let prepared = Self::prepare_loaded_target(
            loaded_mast_forest,
            CodeRequest::External {
                implementation: ImplementationRoot::new(node_digest),
            },
            None,
            package_debug_info,
            source_node_id,
            source_aware_execution,
            host,
        )?;
        self.publish_loaded_target(prepared)
    }

    /// An exact keyed offer may improve metadata; generic code keeps the existing local choice.
    fn select_code_offer(
        request: CodeRequest,
        offered: Option<LoadedMastForest>,
        local: Option<LoadedMastForest>,
    ) -> Option<LoadedMastForest> {
        if offered.as_ref().is_some_and(|owner| {
            request.key().is_some_and(|key| {
                owner.materialized_procedure_occurrence(key, request.implementation()).is_some()
            })
        }) {
            return offered;
        }
        local.or(offered)
    }

    /// Resolves the requested local body and its actual package-owned source context without
    /// changing processor state. Keyed transitions can retain this result until their remaining
    /// VM and tracer preflights complete.
    fn prepare_loaded_target(
        loaded_mast_forest: LoadedMastForest,
        request: CodeRequest,
        entry_hint: Option<(MastNodeId, Option<DebugSourceNodeId>)>,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
        source_aware_execution: bool,
        host: &impl BaseHost,
    ) -> Result<PreparedLoadedTarget, ExecutionError> {
        let mast_forest = loaded_mast_forest.mast_forest();
        let implementation = request.implementation();
        let node_digest = *implementation.as_word();
        let occurrence = request.key().and_then(|key| {
            loaded_mast_forest.materialized_procedure_occurrence(key, implementation)
        });
        let root_hint = entry_hint.map(|(root, _)| root);
        let root_id = if let Some(root) =
            occurrence.map(PackageProcedureOccurrence::exec_node).or(root_hint)
        {
            Some(root).filter(|&root| {
                mast_forest.procedure_roots().contains(&root)
                    && !mast_forest[root].is_external()
                    && mast_forest[root].digest() == node_digest
            })
        } else {
            mast_forest.procedure_roots().iter().copied().find(|&root| {
                let node = &mast_forest[root];
                !node.is_external() && node.digest() == node_digest
            })
        }
        .ok_or_else(|| {
            let context = match (package_debug_info, source_node_id) {
                (Some(debug_info), Some(source_node_id)) => {
                    Some(PackageSourceDebugContext::new(debug_info, source_node_id))
                },
                _ => None,
            };
            malformed_mast_forest_with_context(node_digest, context, host)
        })?;
        // A keyed occurrence explicitly carries its source choice, including no source. Never
        // replace that choice with the first equal-D root or an inferred debug source root.
        let source_hint = if let Some(occurrence) = occurrence {
            SourceNodeHint::Exact(occurrence.source_node())
        } else if let Some((_, Some(source))) = entry_hint {
            SourceNodeHint::Exact(Some(source))
        } else {
            SourceNodeHint::Infer
        };
        let (package_debug_info, source_node_id) = Self::loaded_package_source_context(
            &loaded_mast_forest,
            root_id,
            source_hint,
            source_aware_execution,
        )?;

        Ok(PreparedLoadedTarget {
            request,
            root_id,
            loaded_mast_forest,
            package_debug_info,
            source_node_id,
        })
    }

    /// Checks advice conflicts and budgets before publishing any loaded-code state. After this
    /// preflight, publication has no returned execution error; BTree allocation may still abort.
    fn publish_loaded_target(
        &mut self,
        prepared: PreparedLoadedTarget,
    ) -> Result<LoadedTarget<Arc<MastForest>>, ExecutionError> {
        let PreparedLoadedTarget {
            request,
            root_id,
            loaded_mast_forest,
            package_debug_info,
            source_node_id,
        } = prepared;
        let mast_forest = loaded_mast_forest.mast_forest().clone();
        let commitment = mast_forest.commitment();
        let advice_extension = if self.merged_mast_forests.contains(&commitment) {
            None
        } else {
            Some(self.advice.prepare_extend_map(mast_forest.advice_map()).map_exec_err()?)
        };

        if let Some(advice_extension) = advice_extension {
            advice_extension.commit();
            self.merged_mast_forests.insert(commitment);
        }
        Self::cache_loaded_mast_forest(&mut self.loaded_mast_forests, &loaded_mast_forest);
        if request.key().is_some() {
            self.loaded_code_requests.insert(request, loaded_mast_forest.clone());
        }

        Ok(LoadedTarget {
            implementation: request.implementation(),
            root: root_id,
            forest: mast_forest,
            package_debug_info,
            loaded_owner: Some(loaded_mast_forest),
            source_node_id,
        })
    }

    fn cache_loaded_mast_forest(
        loaded_mast_forests: &mut BTreeMap<Word, Vec<LoadedMastForest>>,
        loaded_mast_forest: &LoadedMastForest,
    ) {
        for procedure_digest in loaded_mast_forest.mast_forest().local_procedure_digests() {
            let owners = loaded_mast_forests.entry(procedure_digest).or_default();
            if !owners.iter().any(|owner| owner.same_owner(loaded_mast_forest)) {
                owners.push(loaded_mast_forest.clone());
            }
        }
    }

    fn loaded_package_source_context(
        loaded_mast_forest: &LoadedMastForest,
        root_id: MastNodeId,
        source_hint: SourceNodeHint,
        source_aware_execution: bool,
    ) -> Result<(Option<Arc<PackageDebugInfo>>, Option<DebugSourceNodeId>), ExecutionError> {
        if !source_aware_execution {
            return Ok((None, None));
        }

        let Some(package_debug_info) = loaded_mast_forest
            .package_debug_info()
            .map_err(|_| ExecutionError::Internal("loaded package debug info is malformed"))?
        else {
            if matches!(source_hint, SourceNodeHint::Exact(Some(_))) {
                return Err(ExecutionError::Internal(
                    "loaded procedure source has no owning debug package",
                ));
            }
            return Ok((None, None));
        };

        if let SourceNodeHint::Exact(source_node_id) = source_hint {
            if let Some(source) = source_node_id
                && package_debug_info
                    .source_node(source)
                    .is_none_or(|node| node.exec_node != root_id)
            {
                return Err(ExecutionError::Internal(
                    "loaded procedure source does not match the resolved root",
                ));
            }
            return Ok((Some(package_debug_info), source_node_id));
        }

        let source_node_id = match package_debug_info.unique_source_root_for_exec_node(root_id) {
            Ok(source_node_id) => source_node_id,
            Err(DebugSourceGraphLookupError::AmbiguousRoot { .. }) => None,
            Err(_) => {
                return Err(ExecutionError::Internal(
                    "loaded package debug source graph has malformed entrypoint roots",
                ));
            },
        };

        Ok((Some(package_debug_info), source_node_id))
    }

    /// Executes the given program synchronously one step at a time.
    pub fn execute_by_step_sync(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(program, environment, None, None)?;
        while !self.step_sync(host, &mut resume)? {}
        self.current_stack_outputs()
    }

    /// Executes the given program synchronously one step at a time with package-owned source/debug
    /// context.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_by_step_with_package_debug_info_sync(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(
            program,
            environment,
            Some(Arc::new(package_debug_info.clone())),
            None,
        )?;
        while !self.step_sync(host, &mut resume)? {}
        self.current_stack_outputs()
    }

    /// Executes the given program synchronously one step at a time with package-owned source/debug
    /// context rooted at `entrypoint_source_node_id`.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_by_step_with_package_debug_info_at_source_node_sync(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(
            program,
            environment,
            Some(Arc::new(package_debug_info.clone())),
            Some(entrypoint_source_node_id),
        )?;
        while !self.step_sync(host, &mut resume)? {}
        self.current_stack_outputs()
    }

    /// Async variant of [`Self::execute_by_step_sync`].
    #[inline(always)]
    pub async fn execute_by_step(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(program, environment, None, None)?;
        while !self.step(host, &mut resume).await? {}
        self.current_stack_outputs()
    }

    /// Async variant of [`Self::execute_by_step_with_package_debug_info_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    pub async fn execute_by_step_with_package_debug_info(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(
            program,
            environment,
            Some(Arc::new(package_debug_info.clone())),
            None,
        )?;
        while !self.step(host, &mut resume).await? {}
        self.current_stack_outputs()
    }

    /// Async variant of
    /// [`Self::execute_by_step_with_package_debug_info_at_source_node_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    pub async fn execute_by_step_with_package_debug_info_at_source_node(
        mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node_id: DebugSourceNodeId,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(
            program,
            environment,
            Some(Arc::new(package_debug_info.clone())),
            Some(entrypoint_source_node_id),
        )?;
        while !self.step(host, &mut resume).await? {}
        self.current_stack_outputs()
    }

    /// Similar to [`Self::execute_sync`], but allows mutable access to the processor.
    ///
    /// This is mainly meant to be used in tests.
    #[cfg(any(test, feature = "testing"))]
    pub fn execute_mut_sync(
        &mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl SyncHost,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(program, environment, None, None)?;
        if !self.drive_sync(host, &mut NoopTracer, &NeverStopper, &mut resume)? {
            return Err(ExecutionError::Internal("full execution stopped unexpectedly"));
        }
        self.current_stack_outputs()
    }

    /// Async variant of [`Self::execute_mut_sync`].
    #[cfg(any(test, feature = "testing"))]
    #[inline(always)]
    pub async fn execute_mut(
        &mut self,
        program: &Program,
        environment: crate::ExecutionEnvironment,
        host: &mut impl Host,
    ) -> Result<StackOutputs, ExecutionError> {
        let mut resume = self.new_resume_context(program, environment, None, None)?;
        if !self.drive_async(host, &mut NoopTracer, &NeverStopper, &mut resume).await? {
            return Err(ExecutionError::Internal("full execution stopped unexpectedly"));
        }
        self.current_stack_outputs()
    }
}

mod resolution;

#[cfg(test)]
mod preparation_tests;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::FastProcessor;

    #[test]
    fn sole_rayon_worker_requires_buffered_trace_building() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap()
            .install(|| assert!(FastProcessor::rayon_has_no_parallel_worker()));
    }
}

#[cfg(test)]
mod completed_session_tests {
    use super::*;
    use crate as processor;
    use crate::{ExecutionOptions, SessionPhase};

    #[allow(dead_code)]
    mod common {
        include!("../../tests/common/keyed_witness.rs");
    }

    #[test]
    fn full_execution_moves_the_original_completed_native_owner_into_replay() {
        let common::ExecutionFixture { program, environment, mut host } =
            common::execution_fixture(vec![miden_core::operations::Operation::Noop]);
        let processor = FastProcessor::new(StackInputs::default())
            .with_options(
                ExecutionOptions::default().with_environment_trace_limits(common::trace_limits()),
            )
            .unwrap();
        let mut tracer = ExecutionTracer::new(64, MIN_STACK_DEPTH, common::trace_limits()).unwrap();
        let (_, session) = processor
            .execute_with_tracer_and_session_sync(&program, environment, &mut host, &mut tracer)
            .unwrap();
        assert_eq!(session.phase(), SessionPhase::Completed);
        let counters = session.finalize().unwrap();
        let occurrences = session.ledger().occurrences().as_ptr();
        let bindings = session.bindings().as_ptr();
        let root_use = session.uses().next().unwrap() as *const crate::InvocationUse;
        assert_eq!(session.bindings()[0].counts().normal, 1);
        assert_eq!(session.bindings()[0].counts().syscall, 0);
        assert_eq!(counters.committed_requests, 1);
        assert_eq!(counters.reserved_requests, 0);

        let trace = tracer.into_trace_replay(session).unwrap();
        trace.require_validated().unwrap();
        let retained = &trace.resolution_session;
        assert_eq!(retained.finalize().unwrap(), counters);
        assert_eq!(retained.ledger().occurrences().as_ptr(), occurrences);
        assert_eq!(retained.bindings().as_ptr(), bindings);
        assert_eq!(retained.uses().next().unwrap() as *const crate::InvocationUse, root_use);
        assert_eq!(retained.bindings()[0].counts().normal, 1);
    }
}
