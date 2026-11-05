use std::{path::PathBuf, time::Instant};

use clap::Parser;
use miden_assembly::diagnostics::{Report, WrapErr};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor,
    trace::{VmTrace, build_trace},
};
use miden_vm::internal::{InputFile, execution_inputs::AdmittedExecutionInputs};
use miden_vm_stark::memory::{DEFAULT_MAX_PROVER_MEMORY_BYTES, canonical_budget};
use tracing::instrument;

use super::{
    data::{Libraries, OutputFile},
    execution_inputs::ExecutionArgs,
    naming_inputs::NamingArgs,
    precompile_limits::PrecompileArgs,
    utils::{load_program, load_program_libraries, parse_byte_size},
};

#[derive(Debug, Clone, Parser)]
#[command(about = "Run a Miden program")]
pub struct RunCmd {
    /// Path to a .masm assembly file or a .masp package file
    #[arg(value_parser)]
    program_file: PathBuf,

    /// Number of cycles the program is expected to consume
    #[arg(short = 'e', long = "exp-cycles", default_value = "64")]
    expected_cycles: u32,

    /// Path to input file
    #[arg(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,

    /// Library code packages; also provide assembly imports for source programs
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,

    /// Maximum number of cycles a program is allowed to consume
    #[arg(short = 'm', long = "max-cycles", default_value_t = ExecutionOptions::MAX_CYCLES)]
    max_cycles: u32,

    /// Maximum combined logical advice size in bytes, also bounding witness loading
    #[arg(long = "max-advice-size", default_value_t = ExecutionOptions::DEFAULT_MAX_ADVICE_SIZE_BYTES)]
    max_advice_size: usize,

    /// Maximum modelled peak memory for VM trace construction (512M, 32Gi)
    ///
    /// Does not cover precompile proving or total process memory.
    #[arg(
        long = "max-prover-memory",
        default_value_t = DEFAULT_MAX_PROVER_MEMORY_BYTES,
        value_parser = parse_byte_size
    )]
    max_prover_memory: u64,

    #[command(flatten)]
    precompile_limits: PrecompileArgs,

    #[command(flatten)]
    execution: ExecutionArgs,

    #[command(flatten)]
    naming: NamingArgs,

    /// Number of outputs
    #[arg(short = 'n', long = "num-outputs", default_value = "16")]
    num_outputs: usize,

    /// Path to output file
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,

    /// Path to a file (.masm or .masp) containing the kernel to be loaded with the program
    #[arg(long = "kernel", value_parser)]
    kernel_file: Option<PathBuf>,
}

impl RunCmd {
    fn get_execution_options(&self) -> Result<ExecutionOptions, Report> {
        let options = ExecutionOptions::new(
            Some(self.max_cycles),
            self.expected_cycles,
            ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
        )
        .map(|options| options.with_max_advice_size_bytes(self.max_advice_size))
        .map_err(|err| Report::msg(format!("{err}")))?;
        Ok(self.precompile_limits.apply_to(options))
    }

    pub fn execute(&self) -> Result<(), Report> {
        let inputs = self.execution.admit()?;
        let execution_options = self
            .get_execution_options()?
            .with_environment_trace_limits(inputs.trace_limits())
            .with_resolution_limits(inputs.resolution_limits());
        println!("===============================================================================");
        println!("Run program: {}", self.program_file.display());
        println!("-------------------------------------------------------------------------------");

        let now = Instant::now();

        let naming = self.naming.read()?;
        let libraries = Libraries::new(&self.library_paths, &naming)?;
        let trace = run_program(self, execution_options, &inputs, &naming, &libraries)?;

        println!("Entry key: {}", inputs.target().entry_key().as_word());
        println!("Environment root: {}", inputs.target().environment_root().as_word());
        println!("Entry implementation: {}", trace.entry_implementation().as_word());
        println!("Executed the program in {} ms", now.elapsed().as_millis());

        if let Some(output_path) = &self.output_file {
            // write outputs to file if one was specified
            OutputFile::write(trace.stack_outputs(), output_path).map_err(Report::msg)?;
        } else {
            // write the stack outputs to the terminal
            println!("Output: {:?}", trace.stack_outputs().get_num_elements(self.num_outputs));
        }

        let summary = trace.trace_len_summary();
        let chiplets = summary.chiplets();
        let padding_percentage =
            |rows: usize, height: usize| (height.saturating_sub(rows)) * 100 / height;

        // print the required cycles for each component
        println!(
            "VM trace rows:
├── Core rows: {} extended to {} ({}% padding)
├── Chiplets rows: {} extended to {} ({}% padding)
    ├── Library rows: {}
    ├── Controller rows: {}
    ├── AEAD rows: {}
    ├── Memory chiplet rows: {}
    ├── ACE chiplet rows: {}
    └── Bitwise chiplet rows: {}
├── Eidos compression rows: {} extended to {} ({}% padding)
└── Byte-pair lookup rows: {} (fixed table)",
            summary.core_rows(),
            summary.core_height(),
            padding_percentage(summary.core_rows(), summary.core_height()),
            summary.chiplets_rows(),
            summary.chiplets_height(),
            padding_percentage(summary.chiplets_rows(), summary.chiplets_height()),
            chiplets.library_len(),
            chiplets.hash_chiplet_len(),
            chiplets.aead_len(),
            chiplets.memory_chiplet_len(),
            chiplets.ace_chiplet_len(),
            chiplets.bitwise_chiplet_len(),
            summary.eidos_compression_rows(),
            summary.eidos_compression_height(),
            padding_percentage(
                summary.eidos_compression_rows(),
                summary.eidos_compression_height()
            ),
            summary.byte_pair_lookup_rows(),
        );

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[instrument(name = "run_program", skip_all)]
fn run_program(
    params: &RunCmd,
    exec_options: ExecutionOptions,
    inputs: &AdmittedExecutionInputs,
    naming: &miden_vm::internal::naming_inputs::NamingInputs,
    libraries: &Libraries,
) -> Result<VmTrace, Report> {
    let loaded = load_program(
        &params.program_file,
        libraries,
        params.kernel_file.as_deref(),
        naming,
        inputs.target().entry_key(),
    )?;
    let input_data = InputFile::read(&params.input_file, &params.program_file)?;
    let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
    let advice_inputs = input_data
        .parse_advice_inputs_with_options(&exec_options)
        .map_err(Report::msg)?;
    let mut host = DefaultHost::default().with_environment_source(inputs.source());
    if let Some(source_manager) = loaded.source_manager.clone() {
        host = host.with_source_manager(source_manager);
    }
    load_program_libraries(&mut host, &loaded, libraries)?;
    let processor = FastProcessor::new_with_options(stack_inputs, advice_inputs, exec_options)
        .map_err(Report::msg)?;
    let witness = processor
        .execute_for_proving_sync(inputs.target(), &mut host)
        .wrap_err("Failed to execute program")?;
    let (vm_witness, _) = witness.into_parts();
    let trace = build_trace(vm_witness, &canonical_budget(params.max_prover_memory))
        .wrap_err("Failed to build trace")?;
    Ok(trace)
}
