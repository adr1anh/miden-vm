use crate::{
    ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionTarget, FastProcessor,
    FutureMaybeSend, Host, StackInputs,
    advice::{AdviceError, AdviceInputs},
};

// PROGRAM EXECUTOR
// ================================================================================================

/// A pluggable executor used to execute an expected [`ExecutionTarget`] against a [`Host`].
///
/// Defaults to [`FastProcessor`]. Alternative implementations can wrap execution in a debugger,
/// add instrumentation, or redirect to a different backend, while leaving the surrounding
/// executor wiring untouched.
pub trait ProgramExecutor {
    /// Creates a new executor configured with the provided inputs and options.
    ///
    /// In generic code (`E: ProgramExecutor`) this resolves normally. For the concrete
    /// [`FastProcessor`] type, however, the inherent
    /// [`FastProcessor::new`](crate::FastProcessor::new) (which takes only stack inputs)
    /// shadows this trait method by name, so invoke the trait constructor with fully-qualified
    /// syntax: `<FastProcessor as ProgramExecutor>::new(stack_inputs, advice_inputs, options)`.
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Result<Self, AdviceError>
    where
        Self: Sized;

    /// Executes the caller-selected target against the given host.
    fn execute<H: Host + Send>(
        self,
        target: ExecutionTarget,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>>;
}

impl ProgramExecutor for FastProcessor {
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Result<Self, AdviceError> {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
    }

    fn execute<H: Host + Send>(
        self,
        target: ExecutionTarget,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        FastProcessor::execute(self, target, host)
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_utils_testing::Test;

    use super::*;
    use crate::{DefaultHost, StackInputs, test_utils::native_fixture_environment};

    #[tokio::test(flavor = "current_thread")]
    async fn program_executor_default_impl_runs_via_trait() {
        let test = Test::new(
            "program_executor_default_impl_runs_via_trait",
            "begin push.3 swap drop end",
            false,
        );
        let (code, ..) = test.compile().unwrap();
        let (target, resolution_limits, source) =
            native_fixture_environment(&test.fixture_environment().unwrap());
        let mut host = DefaultHost::default()
            .with_source_manager(test.source_manager)
            .with_environment_source(source);
        host.load_library(code).unwrap();

        // Drive execution entirely through the trait, defaulting to `FastProcessor`.
        let processor = <FastProcessor as ProgramExecutor>::new(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default().with_resolution_limits(resolution_limits),
        )
        .unwrap();
        let output = <FastProcessor as ProgramExecutor>::execute(processor, target, &mut host)
            .await
            .unwrap();

        // push.3 leaves 3 on top; `swap drop` restores the operand stack to its
        // fixed depth of 16 so the program ends with a well-formed output stack.
        assert_eq!(output.stack.get_element(0), Some(crate::Felt::from_u32(3)));
    }

    #[test]
    fn program_executor_reports_invalid_advice_inputs() {
        let advice_inputs =
            AdviceInputs::default().with_map([(crate::Word::default(), vec![crate::Felt::ONE])]);
        let options = ExecutionOptions::default().with_max_advice_size_bytes(0);

        let result =
            <FastProcessor as ProgramExecutor>::new(StackInputs::default(), advice_inputs, options);

        assert!(result.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn program_executor_uses_host_owned_source_metadata() {
        let test = Test::new(
            "program_executor_uses_host_owned_source_metadata",
            "begin push.3 swap drop end",
            false,
        );
        let (code, ..) = test.compile().unwrap();
        let (target, resolution_limits, source) =
            native_fixture_environment(&test.fixture_environment().unwrap());
        let mut host = DefaultHost::default()
            .with_source_manager(test.source_manager)
            .with_environment_source(source);
        host.load_library(code).unwrap();

        // Source metadata is supplied by the owning host code package.
        let processor = <FastProcessor as ProgramExecutor>::new(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default().with_resolution_limits(resolution_limits),
        )
        .unwrap();
        let output = <FastProcessor as ProgramExecutor>::execute(processor, target, &mut host)
            .await
            .unwrap();

        assert_eq!(output.stack.get_element(0), Some(crate::Felt::from_u32(3)));
    }
}
