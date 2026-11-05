#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

pub use miden_air_definitions::vm::VmTrace;
use miden_air_definitions::vm::{CoreCols, DecoderCols, StackCols, SystemCols};
use miden_assembly::{Linkage, diagnostics::reporting::PrintDiagnostic};
pub use miden_assembly::{
    Path,
    debuginfo::{DefaultSourceManager, SourceFile, SourceLanguage, SourceManager},
    diagnostics::Report,
};
pub use miden_core::{
    EMPTY_WORD, Felt, ONE, WORD_SIZE, Word, ZERO,
    chiplets::hasher::{STATE_WIDTH, hash_elements},
    field::{Field, PrimeCharacteristicRing, PrimeField64, QuadFelt},
    program::{ExecutionClaim, MIN_STACK_DEPTH, StackInputs, StackOutputs},
    utils::{IntoBytes, ToElements, group_slice_elements},
};
use miden_core::{chiplets::hasher::compress_state, events::EventName};
use miden_mast_package::{Package, debug_info::PackageDebugInfo};
// Unit tests of the processor itself compile a distinct crate instance. Re-export the
// dependency so their test-only adapters can name its native request/policy types without
// guessing identity.
pub use miden_processor as processor;
#[cfg(not(target_family = "wasm"))]
use miden_processor::trace::build_trace;
pub use miden_processor::{
    ContextId, ExecutionError, ProcessorState,
    advice::{AdviceInputs, AdviceProvider, AdviceStack},
};
use miden_processor::{
    DefaultHost, ExecutionEnvironment, ExecutionOptions, ExecutionOutput, ExecutionWitness,
    FastProcessor, Program,
    event::{EventHandler, TraceHandler},
};
pub use miden_prover::Prover;
pub use miden_verifier::Verifier;
pub use pretty_assertions::{assert_eq, assert_ne, assert_str_eq};
#[cfg(all(feature = "arbitrary", not(target_family = "wasm")))]
use proptest::prelude::{Arbitrary, Strategy};
pub use test_case::test_case;

pub mod math {
    pub use miden_core::{
        field::{ExtensionField, Field, PrimeField64, QuadFelt},
        utils::ToElements,
    };
}

pub use miden_core::serde;

pub mod crypto;

#[cfg(not(target_family = "wasm"))]
pub mod rand;

pub mod recursive_verifier;

pub mod librarytree;
mod test_builders;
#[cfg(all(feature = "arbitrary", not(target_family = "wasm")))]
pub use proptest;
pub use test_builders::{IntoAdviceStackInput, advice_stack_from};

pub fn module_source(path: impl AsRef<Path>, source: impl ToString) -> String {
    let source = source.to_string();
    if source.trim_start().starts_with("namespace ") {
        source
    } else {
        let path = path.as_ref().to_string();
        let namespace = path.strip_prefix("::").unwrap_or(&path);
        format!("namespace {namespace}\n\n{source}")
    }
}

#[cfg(not(target_family = "wasm"))]
/// Constructs a processor with the default VM environment.
fn new_vm_default_processor(
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    options: ExecutionOptions,
) -> Result<FastProcessor, ExecutionError> {
    FastProcessor::new_with_options(
        stack_inputs,
        advice_inputs,
        options.with_environment_trace_limits(librarytree::trace_limits()),
    )
    .map_err(ExecutionError::advice_error_no_context)
}

// CONSTANTS
// ================================================================================================

/// A value just over what a [u32] integer can hold.
pub const U32_BOUND: u64 = u32::MAX as u64 + 1;

/// A source code of the `truncate_stack` procedure.
pub const TRUNCATE_STACK_PROC: &str = "
@locals(4)
proc truncate_stack
     loc_storew_be.0 dropw movupw.3
    sdepth neq.16
    while.true
        dropw movupw.3
        sdepth neq.16
    end
    loc_loadw_be.0
end
";

// COMPILE CACHE
// ================================================================================================

/// Key for the process-local compile cache, keyed by all inputs that affect compilation output.
///
/// The source manager identity is included so cached programs keep their debug/source mapping local
/// to the test context that produced them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg(all(feature = "std", not(target_family = "wasm")))]
struct CompileCacheKey {
    source_manager: usize,
    source: SourceCacheKey,
    kernel_source: Option<SourceCacheKey>,
    add_modules: Vec<(String, String)>,
    library_artifacts: Vec<Word>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg(all(feature = "std", not(target_family = "wasm")))]
struct SourceCacheKey {
    uri: String,
    source: String,
}

pub type CompiledTest = (Program, Option<Arc<Package>>, Option<PackageDebugInfo>);

/// Retains exact compiler/admitted names beside the code and its locally validated environment.
#[derive(Clone)]
struct PreparedTest {
    compiled: CompiledTest,
    // Cache keys use this instance's address; retain it so the allocator cannot recycle that
    // identity for another manager while the compiled source/debug mappings remain cached.
    _source_manager: Arc<DefaultSourceManager>,
    _local_naming: miden_mast_package::PackageNaming,
    _kernel_naming: Option<miden_mast_package::PackageNaming>,
    _import_naming: Vec<miden_mast_package::PackageNaming>,
    environment: librarytree::FixtureEnvironment,
}

#[cfg(all(feature = "std", not(target_family = "wasm")))]
type CompileCacheValue = PreparedTest;

#[cfg(all(feature = "std", not(target_family = "wasm")))]
type CompileCache = std::collections::HashMap<CompileCacheKey, CompileCacheValue>;

#[cfg(all(feature = "std", not(target_family = "wasm")))]
static COMPILE_CACHE: std::sync::Mutex<Option<CompileCache>> = std::sync::Mutex::new(None);

// TEST HANDLER
// ================================================================================================

/// Asserts that running the given assembler test will result in the expected error.
#[cfg(all(feature = "std", not(target_family = "wasm")))]
#[macro_export]
macro_rules! expect_assembly_error {
    ($test:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )? $(,)?) => {
        let error = $test.compile().expect_err("expected assembly to fail");
        match error.downcast::<::miden_assembly::AssemblyError>() {
            Ok(error) => {
                ::core::assert_matches!(error, $( $pattern )|+ $( if $guard )?);
            }
            Err(report) => {
                panic!(r#"
assertion failed (expected assembly error, but got a different type):
    left: `{:?}`,
    right: `{}`"#, report, stringify!($($pattern)|+ $(if $guard)?));
            }
        }
    };
}

/// Asserts that running the given execution test will result in the expected error.
#[cfg(all(feature = "std", not(target_family = "wasm")))]
#[macro_export]
macro_rules! expect_exec_error_matches {
    ($test:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )? $(,)?) => {
        match $test.execute() {
            Ok(_) => panic!("expected execution to fail @ {}:{}", file!(), line!()),
            Err(error) => ::core::assert_matches!(error, $( $pattern )|+ $( if $guard )?),
        }
    };
}

/// Like [miden_assembly::testing::assert_diagnostic], but matches each non-empty line of the
/// rendered output to a corresponding pattern.
///
/// Empty lines are ignored, but the remaining line count must match the number of patterns.
#[cfg(not(target_family = "wasm"))]
#[macro_export]
macro_rules! assert_diagnostic_lines {
    ($diagnostic:expr, $($expected:expr),+) => {{
        use $crate::DiagnosticPattern as Pattern;
        let actual = format!("{}", miden_assembly::diagnostics::reporting::PrintDiagnostic::new_without_color($diagnostic));
        let expected = [$(Pattern::from($expected)),*];
        let actual_line_count = actual.lines().filter(|line| !line.trim().is_empty()).count();
        ::core::assert_eq!(
            actual_line_count,
            expected.len(),
            "diagnostic line count mismatch: expected {} non-empty lines, got {}\nactual diagnostic:\n{}",
            expected.len(),
            actual_line_count,
            actual,
        );
        for (actual_line, expected) in actual
            .lines()
            .filter(|line| !line.trim().is_empty())
            .zip(expected.into_iter())
        {
            expected.assert_match_with_context(actual_line, &actual);
        }
    }};
}

#[cfg(not(target_family = "wasm"))]
#[macro_export]
macro_rules! assert_assembler_diagnostic {
    ($test:ident, $($expected:literal),+) => {{
        let error = $test
            .compile()
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};

    ($test:ident, $($expected:expr),+) => {{
        let error = $test
            .compile()
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};
}

/// This is a container for the data required to run tests, which allows for running several
/// different types of tests.
///
/// Types of valid result tests:
/// - Execution test: check that running a program compiled from the given source has the specified
///   results for the given (optional) inputs.
/// - Proptest: run an execution test inside a proptest.
///
/// Types of failure tests:
/// - Assembly error test: check that attempting to compile the given source causes an AssemblyError
///   which contains the specified substring.
/// - Execution error test: check that running a program compiled from the given source causes an
///   ExecutionError which contains the specified substring.
pub struct Test {
    pub source_manager: Arc<DefaultSourceManager>,
    pub source: Arc<SourceFile>,
    pub kernel_source: Option<Arc<SourceFile>>,
    pub stack_inputs: StackInputs,
    pub advice_inputs: AdviceInputs,
    pub in_tracing_mode: bool,
    pub libraries: Vec<Arc<Package>>,
    library_naming: Vec<(usize, Arc<miden_mast_package::PackageNaming>)>,
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
    pub trace_handlers: Vec<(EventName, Arc<dyn TraceHandler>)>,
    pub add_modules: Vec<(Arc<Path>, String)>,
}

impl Test {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates the simplest possible new test, with only a source string and no inputs.
    pub fn new(name: &str, source: &str, in_tracing_mode: bool) -> Self {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let source = source_manager.load(SourceLanguage::Masm, name.into(), source.to_string());
        Self::from_source_parts(
            source_manager,
            source,
            StackInputs::default(),
            AdviceInputs::default(),
            in_tracing_mode,
        )
    }

    /// Creates a test from an already loaded source and its original source manager.
    #[doc(hidden)]
    pub fn from_source_parts(
        source_manager: Arc<DefaultSourceManager>,
        source: Arc<SourceFile>,
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        in_tracing_mode: bool,
    ) -> Self {
        Self {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_tracing_mode,
            libraries: Vec::default(),
            library_naming: Vec::new(),
            handlers: Vec::new(),
            trace_handlers: Vec::new(),
            add_modules: Vec::default(),
        }
    }

    /// Adds kernel source to this test so it is assembled and linked during compilation.
    #[track_caller]
    pub fn with_kernel(self, kernel_source: impl ToString) -> Self {
        self.with_kernel_source(
            format!("kernel{}", core::panic::Location::caller().line()),
            kernel_source,
        )
    }

    /// Adds kernel source to this test so it is assembled and linked during compilation.
    pub fn with_kernel_source(
        mut self,
        kernel_name: impl Into<String>,
        kernel_source: impl ToString,
    ) -> Self {
        self.kernel_source = Some(self.source_manager.load(
            SourceLanguage::Masm,
            kernel_name.into().into(),
            kernel_source.to_string(),
        ));
        self
    }

    /// Sets the stack inputs for this test using stack-ordered values.
    #[track_caller]
    pub fn with_stack_inputs(mut self, stack_inputs: impl AsRef<[u64]>) -> Self {
        self.stack_inputs = stack_inputs_from_ints(stack_inputs.as_ref().iter().copied());
        self
    }

    /// Adds a library to link in during assembly.
    pub fn with_library(mut self, package: Arc<Package>) -> Self {
        // This call selects raw admission. Public vector edits must not let its new slot
        // inherit an earlier owned inventory, or leave removed tail slots attached.
        let index = self.libraries.len();
        self.library_naming.retain(|(slot, _)| *slot < index);
        self.libraries.push(package);
        self
    }

    /// Retains a compiler-owned or independently admitted inventory with its exact package.
    ///
    /// Compilation checks the pair before cache reuse. Unlike [`Self::with_library`], this does
    /// not reinterpret the package under the finite source-test home convention. It grants no
    /// publication or execution authority; the fixture still constructs its explicit environment.
    pub fn with_library_and_naming(
        mut self,
        package: Arc<Package>,
        naming: Arc<miden_mast_package::PackageNaming>,
    ) -> Self {
        let index = self.libraries.len();
        self.library_naming.retain(|(slot, _)| *slot < index);
        self.library_naming.push((index, naming));
        self.libraries.push(package);
        self
    }

    /// Adds a handler for a specific event when running the `Host`.
    pub fn with_event_handler(mut self, event: EventName, handler: impl EventHandler) -> Self {
        self.add_event_handler(event, handler);
        self
    }

    /// Adds handlers for specific events when running the `Host`.
    pub fn with_event_handlers(
        mut self,
        handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
    ) -> Self {
        self.add_event_handlers(handlers);
        self
    }

    /// Adds a trace handler for a specific trace event when running the `Host`.
    pub fn with_trace_handler(mut self, event: EventName, handler: impl TraceHandler) -> Self {
        self.add_trace_handler(event, handler);
        self
    }

    /// Adds trace handlers for specific trace events when running the `Host`.
    pub fn with_trace_handlers(
        mut self,
        handlers: Vec<(EventName, Arc<dyn TraceHandler>)>,
    ) -> Self {
        self.add_trace_handlers(handlers);
        self
    }

    /// Adds an extra module to link in during assembly.
    pub fn with_module(mut self, path: impl AsRef<Path>, source: impl ToString) -> Self {
        self.add_module(path, source);
        self
    }

    /// Add an extra module to link in during assembly
    pub fn add_module(&mut self, path: impl AsRef<Path>, source: impl ToString) {
        let path = path.as_ref();
        let source = module_source(path, source);
        self.add_modules.push((path.into(), source));
    }

    /// Add a handler for a specific event when running the `Host`.
    pub fn add_event_handler(&mut self, event: EventName, handler: impl EventHandler) {
        self.add_event_handlers(vec![(event, Arc::new(handler))]);
    }

    /// Add a handler for a specific event when running the `Host`.
    ///
    /// The host registry applies the event name rules (not empty, not reserved, not a duplicate)
    /// when the test builds the host, so a rejected name panics there.
    pub fn add_event_handlers(&mut self, handlers: Vec<(EventName, Arc<dyn EventHandler>)>) {
        self.handlers.extend(handlers);
    }

    /// Add a trace handler for a specific event when running the `Host`.
    pub fn add_trace_handler(&mut self, event: EventName, handler: impl TraceHandler) {
        self.add_trace_handlers(vec![(event, Arc::new(handler))]);
    }

    /// Add trace handlers for specific events when running the `Host`.
    ///
    /// The host registry applies the event name rules (not empty, not reserved, not a duplicate)
    /// when the test builds the host, so a rejected name panics there.
    pub fn add_trace_handlers(&mut self, handlers: Vec<(EventName, Arc<dyn TraceHandler>)>) {
        self.trace_handlers.extend(handlers);
    }

    // TEST METHODS
    // --------------------------------------------------------------------------------------------

    /// Builds a final stack from the provided stack-ordered array and asserts that executing the
    /// test will result in the expected final stack state.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn expect_stack(&self, final_stack: &[u64]) {
        let result = stack_outputs_as_int_vec(&self.get_last_stack_state());
        let expected = resize_to_min_stack_depth(final_stack);
        assert_eq!(expected, result, "Expected stack to be {:?}, found {:?}", expected, result);
    }

    /// Executes the test and validates that the process memory has the elements of `expected_mem`
    /// at address `mem_start_addr` and that the end of the stack execution trace matches the
    /// `final_stack`.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn expect_stack_and_memory(
        &self,
        final_stack: &[u64],
        mem_start_addr: u32,
        expected_mem: &[u64],
    ) {
        // compile the program
        let (program, environment, host, _debug_info) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());

        // execute the test
        let processor = new_vm_default_processor(
            self.stack_inputs,
            self.advice_inputs.clone(),
            ExecutionOptions::default(),
        )
        .expect("test processor should initialize with default precompiles");
        let execution_output = processor.execute_sync(&program, environment, &mut host).unwrap();

        // validate the memory state
        for (addr, mem_value) in ((mem_start_addr as usize)
            ..(mem_start_addr as usize + expected_mem.len()))
            .zip(expected_mem.iter())
        {
            let mem_state = execution_output
                .memory
                .read_element(ContextId::root(), Felt::from_u32(addr as u32))
                .unwrap();
            assert_eq!(
                *mem_value,
                mem_state.as_canonical_u64(),
                "Expected memory [{}] => {:?}, found {:?}",
                addr,
                mem_value,
                mem_state
            );
        }

        // validate the stack state from the same execution as the memory assertions
        let result = stack_outputs_as_int_vec(&execution_output.stack);
        let expected = resize_to_min_stack_depth(final_stack);
        assert_eq!(expected, result, "Expected stack to be {:?}, found {:?}", expected, result);
    }

    /// Asserts that executing the test inside a proptest results in the expected final stack state.
    /// The proptest will return a test failure instead of panicking if the assertion condition
    /// fails.
    #[cfg(all(feature = "arbitrary", not(target_family = "wasm")))]
    pub fn prop_expect_stack(
        &self,
        final_stack: &[u64],
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let result = stack_outputs_as_int_vec(&self.get_last_stack_state());
        proptest::prop_assert_eq!(resize_to_min_stack_depth(final_stack), result);

        Ok(())
    }

    /// Executes the test with the provided stack inputs and asserts the final stack state.
    ///
    /// This preserves the same execution coverage as [`expect_stack`](Self::expect_stack): traced
    /// execution, step/resume execution comparison, and trace construction are all still run.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn expect_stack_with_inputs(&self, stack_inputs: &[u64], final_stack: &[u64]) {
        let trace = self
            .execute_with_stack_inputs(stack_inputs)
            .inspect_err(|_err| {
                #[cfg(feature = "std")]
                std::eprintln!("{}", PrintDiagnostic::new_without_color(_err))
            })
            .expect("failed to execute");

        let result = stack_outputs_as_int_vec(&trace.last_stack_state());
        let expected = resize_to_min_stack_depth(final_stack);
        assert_eq!(expected, result, "Expected stack to be {:?}, found {:?}", expected, result);
    }

    // UTILITY METHODS
    // --------------------------------------------------------------------------------------------

    /// Compiles a test's source and returns the resulting Program together with the associated
    /// kernel library (when specified).
    ///
    /// # Errors
    /// Returns an error if compilation of the program source or the kernel fails.
    pub fn compile(&self) -> Result<CompiledTest, Report> {
        self.prepare().map(|prepared| prepared.compiled)
    }

    /// Returns the exact environment prepared with this test's canonical entry and code inputs.
    ///
    /// This uses the shared source fixture convention and its finite import-home policy. Callers
    /// executing [`Self::compile`]'s code directly must install this environment's witness source
    /// on their host and pass its explicit execution configuration to the processor.
    pub fn fixture_environment(&self) -> Result<librarytree::FixtureEnvironment, Report> {
        self.prepare().map(|prepared| prepared.environment)
    }

    fn prepare(&self) -> Result<PreparedTest, Report> {
        use miden_assembly::{
            Assembler,
            ast::{Module, ModuleKind},
            testing::{FixtureNamespace, fixture_package_naming},
        };
        use miden_assembly_syntax::Parse;
        use miden_mast_package::TargetType;

        // Revalidate all current input policies before cache lookup. The public library vector
        // may have changed since a paired inventory was supplied, and a previous owned import
        // must not make a later raw import bypass the finite fixture-home admission policy.
        for (index, naming) in &self.library_naming {
            let package = self.libraries.get(*index).ok_or_else(|| {
                Report::msg("retained library naming has no corresponding package")
            })?;
            package.check_naming(naming).map_err(|error| Report::msg(error.to_string()))?;
        }
        let import_naming = self
            .libraries
            .iter()
            .enumerate()
            .map(|(index, package)| {
                match self.library_naming.iter().find(|(slot, _)| *slot == index) {
                    Some((_, naming)) => Ok(naming.as_ref().clone()),
                    None => fixture_package_naming(package),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        #[cfg(all(feature = "std", not(target_family = "wasm")))]
        let cache_key = self.compile_cache_key();

        #[cfg(all(feature = "std", not(target_family = "wasm")))]
        {
            let mut cache_guard = COMPILE_CACHE.lock().unwrap();
            let cache = cache_guard.get_or_insert_with(Default::default);
            if let Some(cached) = cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present.
        #[cfg(not(target_family = "wasm"))]
        {
            let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
        }

        let (mut assembler, kernel_lib, kernel_naming) = if let Some(kernel) =
            self.kernel_source.clone()
        {
            let mut parser = Module::parser(Some(ModuleKind::Kernel));
            let kernel = parser.parse(Some(Path::KERNEL), kernel, self.source_manager.clone())?;
            let base = Assembler::new(self.source_manager.clone());
            let mut fixture = FixtureNamespace::assembly_tests();
            fixture.add_kernel_modules(&base, &[kernel.as_ref()])?;
            let assembler = fixture.configure(base, [kernel.as_ref()])?;
            let product = assembler.assemble_library_modules(
                "kernel".into(),
                kernel,
                [],
                TargetType::Kernel,
            )?;
            let naming = product.naming().clone();
            let package = Arc::<Package>::from(product.into_artifact(true)?);
            (
                Assembler::with_kernel(
                    self.source_manager.clone(),
                    package.clone(),
                    naming.clone(),
                )?,
                Some(package),
                Some(naming),
            )
        } else {
            (Assembler::new(self.source_manager.clone()), None, None)
        };

        let program = self.source.clone().parse(false, self.source_manager.clone())?;
        let modules = self
            .add_modules
            .iter()
            .map(|(path, source)| {
                Module::parser(None).parse_str(
                    Some(path.as_ref()),
                    source,
                    self.source_manager.clone(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (package, naming) in self.libraries.iter().zip(&import_naming) {
            assembler.link_package(package.clone(), Linkage::Dynamic, naming.clone())?;
        }
        let mut fixture = FixtureNamespace::assembly_tests();
        fixture.add_module(&program)?;
        for module in &modules {
            fixture.add_module(module)?;
        }
        assembler = fixture.configure(
            assembler,
            core::iter::once(program.as_ref()).chain(modules.iter().map(|module| module.as_ref())),
        )?;
        for module in modules {
            assembler.compile_and_statically_link(module)?;
        }
        let product = assembler.assemble_executable_modules("program".into(), program, [])?;
        let local_naming = product.naming().clone();
        let package = product.into_artifact(true)?;
        let debug_info = package
            .debug_info()
            .map_err(|err| Report::msg(format!("failed to decode test debug info: {err}")))?;
        let program = package.try_into_program(&local_naming)?;
        let entry = local_naming
            .entry_key()
            .ok_or_else(|| Report::msg("compiled test has no explicit entry key"))?;
        let environment = librarytree::FixtureEnvironment::new(
            entry,
            core::iter::once(&local_naming)
                .chain(kernel_naming.iter())
                .chain(import_naming.iter()),
        )?;
        let result = PreparedTest {
            compiled: (program, kernel_lib, debug_info),
            _source_manager: self.source_manager.clone(),
            _local_naming: local_naming,
            _kernel_naming: kernel_naming,
            _import_naming: import_naming,
            environment,
        };

        #[cfg(all(feature = "std", not(target_family = "wasm")))]
        {
            let mut cache_guard = COMPILE_CACHE.lock().unwrap();
            let cache = cache_guard.get_or_insert_with(Default::default);
            cache.insert(cache_key, result.clone());
        }
        Ok(result)
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs. Returns a
    /// resulting execution trace or error.
    ///
    /// Internally, this also checks that traced execution and step/resume execution agree on the
    /// stack outputs.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn execute(&self) -> Result<VmTrace, ExecutionError> {
        self.execute_with_stack_inputs_inner(self.stack_inputs)
    }

    /// Compiles the test's source and executes it with the provided stack inputs.
    ///
    /// This uses the same traced execution, step/resume comparison, and trace construction path as
    /// [`execute`](Self::execute).
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn execute_with_stack_inputs(
        &self,
        stack_inputs: &[u64],
    ) -> Result<VmTrace, ExecutionError> {
        let stack_inputs = stack_inputs_from_ints(stack_inputs.iter().copied());
        self.execute_with_stack_inputs_inner(stack_inputs)
    }

    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    fn execute_with_stack_inputs_inner(
        &self,
        stack_inputs: StackInputs,
    ) -> Result<VmTrace, ExecutionError> {
        // Note: we fix a large fragment size here, as we're not testing the fragment boundaries
        // with these tests (which are tested separately), but rather only the per-fragment trace
        // generation logic - though not too big so as to over-allocate memory.
        const FRAGMENT_SIZE: usize = 1 << 16;

        let (program, environment, host, debug_info) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());
        let debug_info = self.in_tracing_mode.then_some(debug_info).flatten();

        let fast_stack_result = {
            let fast_processor = new_vm_default_processor(
                stack_inputs,
                self.advice_inputs.clone(),
                ExecutionOptions::default()
                    .with_core_trace_fragment_size(FRAGMENT_SIZE)
                    .unwrap(),
            )?;
            if let Some(debug_info) = debug_info.as_ref() {
                fast_processor.execute_for_proving_with_package_debug_info_sync(
                    &program,
                    environment,
                    debug_info,
                    &mut host,
                )
            } else {
                fast_processor.execute_for_proving_sync(&program, environment, &mut host)
            }
        };

        // Compare traced full execution and step/resume execution stack outputs.
        self.assert_result_with_step_execution(stack_inputs, &fast_stack_result);

        fast_stack_result.and_then(|witness| {
            let (vm_witness, _) = witness.into_parts();
            let trace = build_trace(vm_witness, &miden_vm_stark::memory::default_budget())?;

            assert_eq!(&program.hash(), trace.program_hash(), "inconsistent program hash");
            Ok(trace)
        })
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs.
    ///
    /// Returns the [`ExecutionOutput`] once execution is finished.
    #[cfg(not(target_family = "wasm"))]
    pub fn execute_for_output(&self) -> Result<(ExecutionOutput, DefaultHost), ExecutionError> {
        let (program, environment, host, debug_info) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());
        let debug_info = self.in_tracing_mode.then_some(debug_info).flatten();

        let processor = new_vm_default_processor(
            self.stack_inputs,
            self.advice_inputs.clone(),
            ExecutionOptions::default(),
        )?;

        if let Some(debug_info) = debug_info.as_ref() {
            processor
                .execute_with_package_debug_info_sync(&program, environment, debug_info, &mut host)
                .map(|output| (output, host))
        } else {
            processor
                .execute_sync(&program, environment, &mut host)
                .map(|output| (output, host))
        }
    }

    /// Compiles the test's code into a program, then generates and verifies a STARK proof of
    /// execution. When `test_fail` is true, forces a failure by modifying the first output.
    ///
    /// Prefer [`check_constraints`](Self::check_constraints) for constraint validation — it is
    /// much faster and provides better error diagnostics. Use this method only when you need to
    /// exercise the full STARK prove/verify pipeline (e.g., testing proof serialization,
    /// verifier logic, or precompile request handling).
    #[cfg(not(target_family = "wasm"))]
    pub fn prove_and_verify(&self, pub_inputs: Vec<u64>, test_fail: bool) {
        let (program, environment, mut host, debug_info) = self.get_program_and_host();
        let debug_info = self.in_tracing_mode.then_some(debug_info).flatten();
        let stack_inputs = stack_inputs_from_ints(pub_inputs);
        let processor = new_vm_default_processor(
            stack_inputs,
            self.advice_inputs.clone(),
            ExecutionOptions::default(),
        )
        .unwrap();
        let witness = if let Some(debug_info) = debug_info.as_ref() {
            processor.execute_for_proving_with_package_debug_info_sync(
                &program,
                environment,
                debug_info,
                &mut host,
            )
        } else {
            processor.execute_for_proving_sync(&program, environment, &mut host)
        }
        .unwrap();
        let stack_outputs = *witness.claim().stack_outputs();
        let proof = Prover::new().prove_full(witness).unwrap();
        let claim =
            ExecutionClaim::from_program_info(program.to_info(), stack_inputs, stack_outputs);
        if test_fail {
            let mut elements = [ZERO; MIN_STACK_DEPTH];
            elements.copy_from_slice(&*stack_outputs);
            elements[0] += ONE;
            let stack_outputs =
                StackOutputs::new(&elements).expect("stack outputs should fit the VM stack");
            let invalid_claim = ExecutionClaim::from_program_info(
                claim.to_program_info(),
                stack_inputs,
                stack_outputs,
            );
            assert!(Verifier::new().verify(&invalid_claim, &proof).is_err());
        } else {
            let outcome =
                Verifier::new().verify(&claim, &proof).expect("complete proof should verify");
            assert!(outcome.is_complete(), "prove_full must settle all precompile work");
        }
    }

    /// Executes the test program and checks all AIR constraints without generating a STARK proof.
    ///
    /// This is the recommended way to validate constraints in tests. It delegates to
    /// [`miden_vm_stark::debug::check_constraints`], which is much faster than the
    /// full prove/verify pipeline and provides better error diagnostics. Use
    /// [`prove_and_verify`](Self::prove_and_verify) only when you need to exercise the
    /// complete STARK proof generation and verification flow.
    ///
    /// # Panics
    ///
    /// Panics if execution fails or if any AIR constraint evaluates to nonzero on any row.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn check_constraints(&self) {
        let trace = self
            .execute()
            .inspect_err(|_err| {
                #[cfg(feature = "std")]
                std::eprintln!("{}", PrintDiagnostic::new_without_color(_err))
            })
            .expect("failed to execute");
        miden_vm_stark::debug::check_constraints(&trace);
    }

    /// Returns the last state of the stack after executing a test.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn get_last_stack_state(&self) -> StackOutputs {
        let trace = self
            .execute()
            .inspect_err(|_err| {
                #[cfg(feature = "std")]
                std::eprintln!("{}", PrintDiagnostic::new_without_color(_err))
            })
            .expect("failed to execute");

        trace.last_stack_state()
    }

    // HELPERS
    // ------------------------------------------------------------------------------------------

    /// Returns the program and host for the test.
    ///
    /// The host is initialized with the advice inputs provided in the test, as well as the kernel
    /// and library MAST forests.
    #[cfg(not(target_family = "wasm"))]
    fn get_program_and_host(
        &self,
    ) -> (Program, ExecutionEnvironment, DefaultHost, Option<PackageDebugInfo>) {
        let prepared = self.prepare().expect("Failed to compile test source.");
        let environment = prepared.environment.execution();
        let mut host =
            DefaultHost::default().with_environment_source(prepared.environment.source());
        let (program, kernel, debug_info) = prepared.compiled;
        if let Some(kernel) = kernel {
            host.load_library(kernel.mast_forest()).unwrap();
        }
        for library in &self.libraries {
            host.load_library(library.mast_forest()).unwrap();
        }
        for (event, handler) in &self.handlers {
            host.register_handler(event.clone(), handler.clone()).unwrap_or_else(|err| {
                panic!("Failed to register handler for event '{}': {err}", event.as_str())
            });
        }
        for (event, handler) in &self.trace_handlers {
            host.register_trace_handler(event.clone(), handler.clone())
                .unwrap_or_else(|err| {
                    panic!("Failed to register trace handler for event '{}': {err}", event.as_str())
                });
        }

        (program, environment, host, debug_info)
    }

    #[cfg(not(target_family = "wasm"))]
    fn assert_result_with_step_execution(
        &self,
        stack_inputs: StackInputs,
        fast_result: &Result<ExecutionWitness, ExecutionError>,
    ) {
        fn compare_results(
            left_result: Result<StackOutputs, &ExecutionError>,
            right_result: &Result<StackOutputs, ExecutionError>,
            left_name: &str,
            right_name: &str,
            compare_error_diagnostics: bool,
        ) {
            match (left_result, right_result) {
                (Ok(left_stack_outputs), Ok(right_stack_outputs)) => {
                    assert_eq!(
                        left_stack_outputs, *right_stack_outputs,
                        "stack outputs do not match between {left_name} and {right_name}"
                    );
                },
                (Err(left_err), Err(right_err)) => {
                    if !compare_error_diagnostics {
                        return;
                    }

                    // assert that diagnostics match
                    let right_diagnostic =
                        format!("{}", PrintDiagnostic::new_without_color(right_err));
                    let left_diagnostic =
                        format!("{}", PrintDiagnostic::new_without_color(left_err));

                    assert_eq!(
                        left_diagnostic, right_diagnostic,
                        "diagnostics do not match between {left_name} and {right_name}:\n{left_name}: {}\n{right_name}: {}",
                        left_diagnostic, right_diagnostic
                    );
                },
                (Ok(_), Err(right_err)) => {
                    let right_diagnostic =
                        format!("{}", PrintDiagnostic::new_without_color(right_err));
                    panic!(
                        "expected error, but {left_name} succeeded. {right_name} error:\n{right_diagnostic}"
                    );
                },
                (Err(left_err), Ok(_)) => {
                    panic!(
                        "expected success, but {left_name} failed. {left_name} error:\n{left_err}"
                    );
                },
            }
        }

        let (program, environment, host, debug_info) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());
        let debug_info = self.in_tracing_mode.then_some(debug_info).flatten();
        let compare_error_diagnostics = debug_info.is_none();

        let fast_result_by_step = {
            let fast_process = new_vm_default_processor(
                stack_inputs,
                self.advice_inputs.clone(),
                ExecutionOptions::default(),
            )
            .expect("test processor should initialize with default precompiles");
            if let Some(debug_info) = debug_info.as_ref() {
                fast_process.execute_by_step_with_package_debug_info_sync(
                    &program,
                    environment,
                    debug_info,
                    &mut host,
                )
            } else {
                fast_process.execute_by_step_sync(&program, environment, &mut host)
            }
        };

        compare_results(
            fast_result.as_ref().map(|witness| *witness.claim().stack_outputs()),
            &fast_result_by_step,
            "traced execution",
            "step/resume execution",
            compare_error_diagnostics,
        );
    }

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    fn compile_cache_key(&self) -> CompileCacheKey {
        CompileCacheKey {
            source_manager: Arc::as_ptr(&self.source_manager) as usize,
            source: SourceCacheKey::from_source_file(self.source.as_ref()),
            kernel_source: self.kernel_source.as_deref().map(SourceCacheKey::from_source_file),
            add_modules: self
                .add_modules
                .iter()
                .map(|(path, source)| (path.to_string(), source.clone()))
                .collect(),
            library_artifacts: self
                .libraries
                .iter()
                // This binds code, exact required canonical naming and semantic sections. The
                // Current raw/owned input checks run before cache lookup; this key does not
                // substitute for either admission or exact package/naming correspondence.
                .map(|library| library.commitment())
                .collect(),
        }
    }
}

#[cfg(all(test, feature = "std", not(target_family = "wasm")))]
mod tests {
    use core::num::NonZeroU32;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use miden_assembly::{Assembler, NamespaceInputs, ast::Module};
    use miden_core::program::CanonicalLabel;
    use miden_mast_package::{
        CallableBinding, CallableProcedurePath, NamespacePlan, PackageNaming, TargetType,
    };
    use miden_processor::{advice::AdviceMutation, event::EventError};

    use super::*;

    fn compiler_owned_library(home: &str) -> (Arc<Package>, Arc<PackageNaming>, CallableBinding) {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let module = Module::parser(None)
            .parse_str(
                Some(Path::new("::foreign")),
                "namespace foreign\npub proc answer push.29 swap drop end",
                source_manager.clone(),
            )
            .unwrap();
        let binding = CallableBinding::new(
            NamespacePlan::new(vec![
                CanonicalLabel::text(home).unwrap(),
                CanonicalLabel::revision(NonZeroU32::new(7).unwrap()),
            ]),
            CallableProcedurePath::from_semantic_components(vec![
                "service".into(),
                "response".into(),
            ])
            .unwrap(),
        )
        .unwrap();
        let inputs = NamespaceInputs::new()
            .with_namespace_plan(NamespacePlan::new(vec![
                CanonicalLabel::text("owned-library-compilation-context").unwrap(),
            ]))
            .with_callable_binding(Arc::from(Path::new("::foreign::answer")), binding.clone())
            .unwrap();
        let product = Assembler::new(source_manager)
            .with_namespace_inputs(inputs)
            .assemble_library_modules("owned-library".into(), module, [], TargetType::Library)
            .unwrap();
        let naming = Arc::new(product.naming().clone());
        let package = Arc::from(product.into_artifact(true).unwrap());
        (package, naming, binding)
    }

    #[test]
    fn compile_returns_error_for_invalid_kernel_without_panicking() {
        let test = Test::new("main", "begin push.1 end", false)
            .with_kernel_source("kernel", "export.invalid begin push.1");

        let result = catch_unwind(AssertUnwindSafe(|| test.compile()));

        assert!(result.is_ok(), "invalid kernel source caused Test::compile() to panic");
        assert!(result.unwrap().is_err(), "invalid kernel source should return an error");
    }

    #[test]
    fn compile_returns_error_for_invalid_extra_module_without_panicking() {
        let test = Test::new("main", "use.foo::bar\nbegin\n    exec.foo::bar\nend", false)
            .with_module("foo", "export.bar begin push.1");

        let result = catch_unwind(AssertUnwindSafe(|| test.compile()));

        assert!(result.is_ok(), "invalid extra module source caused Test::compile() to panic");
        assert!(result.unwrap().is_err(), "invalid extra module source should return an error");
    }

    #[test]
    fn compiler_owned_library_retains_foreign_binding_and_environment() {
        let (package, naming, binding) = compiler_owned_library("selected-foreign-owner");
        crate::assert_ne!(naming.namespace_plan(), binding.namespace_plan());
        crate::assert_eq!(naming.callables().binding(binding.key()), Some(&binding));
        assert!(miden_assembly::testing::fixture_package_naming(&package).is_err());
        let implementation = naming.callables().selected_implementation(binding.key()).unwrap();
        let test = Test::new("owned_foreign", "use foreign\nbegin exec.foreign::answer end", false)
            .with_library_and_naming(package, naming);

        test.compile().expect("compiler-owned foreign import should compile");
        let environment = test.fixture_environment().expect("explicit foreign environment");
        let execution = environment.execution();
        let request = miden_processor::EnvironmentWitnessRequest {
            root: execution.descriptor().environment_root(),
            key: binding.key(),
            limits: execution.opening_limits(),
        };
        let resolved = environment
            .source()
            .get(request)
            .unwrap()
            .expect("the exact foreign binding must be mounted")
            .verify(request.root, request.key, request.limits)
            .unwrap();
        crate::assert_eq!(resolved.namespace(), binding.parent_namespace());
        crate::assert_eq!(resolved.implementation_root(), implementation);

        let (output, _) = test.execute_for_output().expect("native foreign import execution");
        crate::assert_eq!(stack_outputs_as_int_vec(&output.stack)[0], 29);
    }

    #[test]
    fn compiler_owned_library_mismatched_pair_rejects_warm_cache() {
        let (package, naming, binding) = compiler_owned_library("selected-foreign-owner");
        let (_, other_naming, other_binding) = compiler_owned_library("different-foreign-owner");
        crate::assert_ne!(binding.key(), other_binding.key());
        crate::assert_eq!(
            naming.callables().selected_implementation(binding.key()),
            other_naming.callables().selected_implementation(other_binding.key()),
            "equal code must not make distinct canonical metadata interchangeable"
        );
        let warmed = Test::new("owned_pair", "use foreign\nbegin exec.foreign::answer end", false)
            .with_library_and_naming(package.clone(), naming);
        warmed.compile().expect("valid pair should warm the compile cache");

        let mut mismatched =
            Test::new("owned_pair", "", false).with_library_and_naming(package, other_naming);
        mismatched.source_manager = warmed.source_manager.clone();
        mismatched.source = warmed.source.clone();
        crate::assert_eq!(mismatched.compile_cache_key(), warmed.compile_cache_key());
        let error = mismatched.compile().expect_err("a cached success cannot validate a new pair");
        assert!(error.to_string().contains("naming transport"));
    }

    #[test]
    fn raw_foreign_library_rejects_after_owned_cache_warm() {
        let (package, naming, _) = compiler_owned_library("selected-foreign-owner");
        let warmed =
            Test::new("owned_then_raw", "use foreign\nbegin exec.foreign::answer end", false)
                .with_library_and_naming(package.clone(), naming);
        warmed.compile().expect("owned import should warm the compile cache");

        let mut raw = Test::new("owned_then_raw", "", false).with_library(package);
        raw.source_manager = warmed.source_manager.clone();
        raw.source = warmed.source.clone();
        crate::assert_eq!(raw.compile_cache_key(), warmed.compile_cache_key());
        let error = raw
            .compile()
            .expect_err("a raw import still requires current fixture admission");
        assert!(error.to_string().contains("unexpected fixture home"));
    }

    #[test]
    fn raw_reselection_after_clear_does_not_inherit_owned_naming_or_cache() {
        let (package, naming, _) = compiler_owned_library("selected-foreign-owner");
        let mut test =
            Test::new("owned_clear_raw", "use foreign\nbegin exec.foreign::answer end", false)
                .with_library_and_naming(package.clone(), naming);
        test.compile().expect("owned import should warm the cache");
        let warmed_key = test.compile_cache_key();

        test.libraries.clear();
        let raw = test.with_library(package);
        crate::assert_eq!(raw.compile_cache_key(), warmed_key);
        let error =
            raw.compile().expect_err("a new raw selection must not inherit owned authority");
        assert!(error.to_string().contains("unexpected fixture home"));
    }

    #[test]
    fn owned_reselection_after_clear_replaces_removed_slot_metadata() {
        let (package, naming, _) = compiler_owned_library("selected-foreign-owner");
        let (replacement, replacement_naming, _) = compiler_owned_library("replacement-owner");
        let mut test =
            Test::new("owned_clear_owned", "use foreign\nbegin exec.foreign::answer end", false)
                .with_library_and_naming(package, naming);
        test.compile().expect("the original owned import should compile");

        test.libraries.clear();
        test.with_library_and_naming(replacement, replacement_naming)
            .compile()
            .expect("the explicit new owned selection must replace removed slot metadata");
    }

    #[test]
    fn compiler_owned_library_dangling_naming_rejects_after_clear() {
        let (package, naming, _) = compiler_owned_library("selected-foreign-owner");
        let mut test = Test::new("removed_owned_library", "begin nop end", false)
            .with_library_and_naming(package, naming);
        test.compile().expect("valid owned import should prepare successfully");

        test.libraries.clear();
        let error = test.compile().expect_err("removed packages must not leave usable naming");
        assert!(
            error
                .to_string()
                .contains("retained library naming has no corresponding package")
        );
    }

    #[test]
    fn explicit_environment_executes_nested_helpers_and_procref() {
        let test = Test::new(
            "keyed_helpers",
            r#"
            proc helper
                push.7
            end
            proc nested
                exec.helper
            end
            begin
                procref.nested mem_storew_le.100 dropw push.100 dynexec swap drop
            end
        "#,
            false,
        );
        let (output, _) = test.execute_for_output().expect("named helper execution");
        crate::assert_eq!(stack_outputs_as_int_vec(&output.stack)[0], 7);
    }

    #[test]
    fn explicit_environment_executes_root_kernel_and_private_helper() {
        let test = Test::new("keyed_kernel", "begin syscall.answer end", true).with_kernel_source(
            "keyed_kernel_source",
            r#"
                proc helper
                    push.9
                end
                pub proc answer
                    exec.helper swap drop
                end
            "#,
        );
        let (output, _) = test.execute_for_output().expect("root kernel/private helper execution");
        crate::assert_eq!(stack_outputs_as_int_vec(&output.stack)[0], 9);
    }

    #[test]
    #[should_panic(expected = "diagnostic line count mismatch")]
    fn assert_diagnostic_lines_rejects_missing_actual_lines() {
        crate::assert_diagnostic_lines!(
            miden_assembly::report!("the error string"),
            "the error string",
            "other",
            "lines"
        );
    }

    #[test]
    #[should_panic(expected = "diagnostic line count mismatch")]
    fn assert_diagnostic_lines_rejects_extra_actual_lines() {
        crate::assert_diagnostic_lines!(
            miden_assembly::report!("the first line\nthe second line"),
            "the first line"
        );
    }

    #[test]
    fn expect_stack_and_memory_executes_once() {
        const EVENT_NAME: EventName = EventName::new("test::expect_stack_and_memory::once");

        let invocations = Arc::new(AtomicUsize::new(0));
        let handler_invocations = invocations.clone();
        let handler = move |_process: &ProcessorState| -> Result<Vec<AdviceMutation>, EventError> {
            handler_invocations.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        };

        let source = alloc::format!(
            r#"
            begin
                emit.event("{EVENT_NAME}")
                push.42.1000 mem_store
            end
            "#
        );

        Test::new("main", &source, false)
            .with_event_handler(EVENT_NAME, handler)
            .expect_stack_and_memory(&[], 1000, &[42]);

        core::assert_eq!(1, invocations.load(Ordering::SeqCst));
    }
}

#[cfg(all(feature = "std", not(target_family = "wasm")))]
impl SourceCacheKey {
    fn from_source_file(source_file: &SourceFile) -> Self {
        Self {
            uri: source_file.uri().as_str().to_string(),
            source: source_file.as_str().to_string(),
        }
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Appends a Word to an operand stack Vec.
pub fn append_word_to_vec(target: &mut Vec<u64>, word: Word) {
    target.extend(word.iter().map(Felt::as_canonical_u64));
}

#[doc(hidden)]
pub use miden_assembly_syntax::testing::Pattern as DiagnosticPattern;

/// Converts a slice of Felts into a vector of u64 values.
pub fn felt_slice_to_ints(values: &[Felt]) -> Vec<u64> {
    values.iter().map(|e| (*e).as_canonical_u64()).collect()
}

#[doc(hidden)]
#[track_caller]
pub fn stack_inputs_from_ints(values: impl IntoIterator<Item = u64>) -> StackInputs {
    let values = values
        .into_iter()
        .map(|value| Felt::new(value).expect("stack input should be a valid field element"))
        .collect::<Vec<_>>();
    StackInputs::new(&values).expect("stack inputs should fit the VM stack")
}

fn stack_outputs_as_int_vec(outputs: &StackOutputs) -> Vec<u64> {
    outputs.iter().map(Felt::as_canonical_u64).collect()
}

pub fn resize_to_min_stack_depth(values: &[u64]) -> Vec<u64> {
    let mut result: Vec<u64> = values.to_vec();
    result.resize(MIN_STACK_DEPTH, 0);
    result
}

/// A proptest strategy for generating a random word with 4 values of type T.
#[cfg(all(feature = "arbitrary", not(target_family = "wasm")))]
pub fn prop_randw<T: Arbitrary>() -> impl Strategy<Value = Vec<T>> {
    use proptest::prelude::{any, prop};
    prop::collection::vec(any::<T>(), 4)
}

/// Computes one expected COMPRESS state transition.
///
/// The block lanes are preserved and the chaining-value lanes are replaced with the
/// Eidos compression output.
pub fn build_expected_compress(values: &[u64]) -> [Felt; STATE_WIDTH] {
    assert!(values.len() >= STATE_WIDTH, "expected at least 12 values for compress test");

    // Reconstruct the internal VM hasher state from the initial stack:
    // stack[0..12] = [v0, ..., v11]
    // => state[0..12] = stack[0..12] in [BLOCK_LO, BLOCK_HI, CV] layout.
    let mut state = [ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        state[i] = Felt::new_unchecked(values[i]);
    }

    compress_state(&mut state);

    // Map internal state back to stack layout [BLOCK_LO, BLOCK_HI, CV'].
    let mut out = [ZERO; STATE_WIDTH];
    out[..STATE_WIDTH].copy_from_slice(&state[..STATE_WIDTH]);

    out
}

pub fn build_expected_hash(values: &[u64]) -> [Felt; 4] {
    let digest = hash_elements(&values.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<_>>());
    digest.into()
}

/// Computes the generic eight-Felt hash used by `hdword`.
pub fn build_expected_hdword(values: &[u64]) -> [Felt; 4] {
    assert!(values.len() >= 2 * WORD_SIZE, "expected at least two words for hdword test");

    let values = values.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<_>>();
    hash_elements(&values[..2 * WORD_SIZE]).into()
}

// Generates the MASM code which pushes the input values during the execution of the program.
#[cfg(all(feature = "std", not(target_family = "wasm")))]
pub fn push_inputs(inputs: &[u64]) -> String {
    let mut result = String::new();

    inputs.iter().for_each(|v| result.push_str(&format!("push.{v}\n")));
    result
}

/// Hierarchical column-name table for the Core AIR row, used by [`get_column_name`].
const CORE_COL_NAMES: CoreCols<&'static str> = CoreCols {
    system: SystemCols {
        clk: "clk",
        ctx: "ctx",
        fn_hash: ["fn_hash[0]", "fn_hash[1]", "fn_hash[2]", "fn_hash[3]"],
    },
    decoder: DecoderCols {
        addr: "decoder_addr",
        op_bits: [
            "op_bits[0]",
            "op_bits[1]",
            "op_bits[2]",
            "op_bits[3]",
            "op_bits[4]",
            "op_bits[5]",
            "op_bits[6]",
        ],
        hasher_state: [
            "hasher_state[0]",
            "hasher_state[1]",
            "hasher_state[2]",
            "hasher_state[3]",
            "hasher_state[4]",
            "hasher_state[5]",
            "hasher_state[6]",
            "hasher_state[7]",
        ],
        in_span: "in_span",
        group_count: "group_count",
        op_index: "op_index",
        full_batch: "full_batch",
        batch_size_code: "batch_size_code",
        extra: ["op_bits_extra[0]", "op_bits_extra[1]"],
        resolved_digest: [
            "resolved_digest[0]",
            "resolved_digest[1]",
            "resolved_digest[2]",
            "resolved_digest[3]",
        ],
    },
    stack: StackCols {
        top: [
            "stack[0]",
            "stack[1]",
            "stack[2]",
            "stack[3]",
            "stack[4]",
            "stack[5]",
            "stack[6]",
            "stack[7]",
            "stack[8]",
            "stack[9]",
            "stack[10]",
            "stack[11]",
            "stack[12]",
            "stack[13]",
            "stack[14]",
            "stack[15]",
        ],
        b0: "stack_b0",
        b1: "stack_b1",
        h0: "stack_h0",
    },
};

/// Helper function to get column name for debugging
pub fn get_column_name(col_idx: usize) -> String {
    let core_names = CORE_COL_NAMES.as_slice();
    if let Some(name) = core_names.get(col_idx) {
        return (*name).to_string();
    }
    format!("unknown_col[{col_idx}]")
}
