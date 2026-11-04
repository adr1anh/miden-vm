use std::sync::Arc;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use miden_core_lib::CoreLibrary;
use miden_processor::{ExecutionOptions, FastProcessor, advice::AdviceInputs};
use miden_utils_testing::librarytree::assemble_fixture_program;
use miden_vm::{
    Assembler, DefaultHost, StackInputs, assembly::DefaultSourceManager, internal::InputFile,
};
use tokio::runtime::Runtime;
use walkdir::WalkDir;

/// Benchmark the execution of all the masm examples in the `masm-examples` directory.
fn program_execution_fast(c: &mut Criterion) {
    let mut group = c.benchmark_group("program_execution_fast");

    let masm_examples_dir = {
        let mut miden_dir = std::env::current_dir().unwrap();
        miden_dir.push("masm-examples");

        miden_dir
    };

    for entry in WalkDir::new(masm_examples_dir) {
        match &entry {
            Ok(entry) => {
                // if it's not a masm file, skip it.
                if !entry.file_type().is_file() || entry.path().extension().unwrap() != "masm" {
                    continue;
                }

                // if there's a `.inputs` file associated with this `.masm` file, use it as the
                // inputs.
                let (stack_inputs, advice_inputs) = match InputFile::read(&None, entry.path()) {
                    Ok(input_data) => {
                        let stack_inputs = input_data.parse_stack_inputs().unwrap();
                        let advice_inputs = input_data.parse_advice_inputs().unwrap();
                        (stack_inputs, advice_inputs)
                    },
                    Err(_) => (StackInputs::default(), AdviceInputs::default()),
                };

                // the name of the file without the extension
                let source = std::fs::read_to_string(entry.path()).unwrap();

                // Create a benchmark for the masm file
                let file_stem = entry.path().file_stem().unwrap().to_string_lossy();
                group.bench_function(file_stem, |bench| {
                    let source_manager = Arc::new(DefaultSourceManager::default());
                    let core_lib = CoreLibrary::default();
                    let mut assembler = Assembler::new(source_manager.clone());
                    assembler
                        .link_package(
                            core_lib.package(),
                            miden_assembly::Linkage::Dynamic,
                            core_lib.naming().clone(),
                        )
                        .expect("failed to load core library");
                    let (code, environment) = assemble_fixture_program(
                        assembler,
                        "program",
                        source.as_str(),
                        &[core_lib.naming()],
                    );
                    let stack_inputs_vec: Vec<_> = stack_inputs.iter().rev().copied().collect();
                    let stack_inputs = StackInputs::new(&stack_inputs_vec).unwrap();
                    bench.to_async(Runtime::new().unwrap()).iter_batched(
                        || {
                            let host = DefaultHost::default()
                                .with_source_manager(source_manager.clone())
                                .with_library(&core_lib)
                                .unwrap()
                                .with_library(code.clone())
                                .unwrap()
                                .with_environment_source(environment.source());

                            let processor = FastProcessor::new_with_options(
                                stack_inputs,
                                advice_inputs.clone(),
                                ExecutionOptions::default()
                                    .with_resolution_limits(environment.resolution_limits()),
                            )
                            .expect("advice inputs should fit advice map limits");

                            (host, environment.target(), processor)
                        },
                        |(mut host, target, processor)| async move {
                            processor.execute(target, &mut host).await.unwrap();
                        },
                        BatchSize::SmallInput,
                    );
                });
            },
            // If we can't access the entry, just skip it
            Err(err) => {
                eprintln!("Failed to access file: {entry:?} with error {err:?}");
            },
        }
    }

    group.finish();
}

criterion_group!(benchmark, program_execution_fast);
criterion_main!(benchmark);
