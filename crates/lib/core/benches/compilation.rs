use std::{fmt::Write, hint::black_box, path::Path, sync::Arc, time::Duration};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use miden_assembly::{
    Assembler, ProjectTargetSelector, ast::Module, debuginfo::DefaultSourceManager,
    package::NamespacePlan,
};
use miden_package_registry::InMemoryPackageRegistry;

#[path = "../source_naming.rs"]
mod source_naming;

fn core_lib(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_core_lib");
    group.measurement_time(Duration::from_secs(10));

    // Compiles the entire core library
    group.bench_function("all", |bench| {
        bench.iter(|| {
            let assembler = Assembler::default();
            let mut registry = InMemoryPackageRegistry::default();

            let manifest_dir = env!("CARGO_MANIFEST_DIR");
            let manifest_path = Path::new(manifest_dir).join("asm/miden-project.toml");
            let mut project_assembler =
                assembler.for_project_at_path(manifest_path, &mut registry).unwrap();
            project_assembler.with_namespace_inputs_provider(|_, sources, _| {
                source_naming::source_namespace_inputs(
                    NamespacePlan::new(vec![]),
                    core::iter::once(sources.root.as_ref())
                        .chain(sources.support.iter().map(Box::as_ref)),
                )
            });
            black_box(
                project_assembler.assemble_with_naming(ProjectTargetSelector::Library, "release"),
            )
            .unwrap();
        });
    });

    group.finish();
}

fn generated_programs(c: &mut Criterion) {
    bench_generated_programs(
        c,
        "compile_generated_programs",
        &[
            ("deep_control_flow", 16, deep_control_flow_program(16)),
            ("repeated_subtrees", 96, repeated_subtree_program(96)),
            ("error_code_heavy", 160, error_code_heavy_program(160)),
        ],
    );

    if std::env::var_os("MIDEN_MAST_BENCH_STRESS").is_some() {
        bench_generated_programs(
            c,
            "compile_generated_programs_stress",
            &[("deep_control_flow", 64, deep_control_flow_program(64))],
        );
    }
}

fn bench_generated_programs(c: &mut Criterion, group_name: &str, cases: &[(&str, usize, String)]) {
    let mut group = c.benchmark_group(group_name);
    group.measurement_time(Duration::from_secs(10));

    for (name, size, source) in cases {
        group.bench_with_input(BenchmarkId::new(*name, *size), source, |bench, source| {
            bench.iter(|| {
                let source_manager = Arc::new(DefaultSourceManager::default());
                let module =
                    Module::parser(None).parse_str(None, source, source_manager.clone()).unwrap();
                let inputs = source_naming::source_namespace_inputs(
                    NamespacePlan::new(vec![]),
                    core::iter::once(module.as_ref()),
                )
                .unwrap();
                let assembler = Assembler::new(source_manager).with_namespace_inputs(inputs);
                black_box(assembler.assemble_program("bench", module).unwrap());
            });
        });
    }

    group.finish();
}

fn deep_control_flow_program(depth: usize) -> String {
    let mut source = String::from("begin\n    push.1\n");
    for _ in 0..depth {
        source.push_str("    repeat.2\n");
    }
    source.push_str("    push.1 add\n");
    for _ in 0..depth {
        source.push_str("    end\n");
    }
    source.push_str("end\n");
    source
}

fn repeated_subtree_program(num_procedures: usize) -> String {
    let mut source = String::new();
    for idx in 0..num_procedures {
        writeln!(source, "proc repeated_{idx}\n    push.1 add\n    push.2 mul\nend\n").unwrap();
    }

    source.push_str("begin\n    push.0\n");
    for idx in 0..num_procedures {
        writeln!(source, "    exec.repeated_{idx}").unwrap();
    }
    source.push_str("end\n");
    source
}

fn error_code_heavy_program(num_ops: usize) -> String {
    let mut source = String::from("begin\n    push.0\n");
    for idx in 0..num_ops {
        writeln!(source, "    push.1\n    assert.err=\"bench-{idx}\"\n    push.1 add").unwrap();
    }
    source.push_str("end\n");
    source
}

criterion_group!(compilation_group, core_lib, generated_programs);
criterion_main!(compilation_group);
