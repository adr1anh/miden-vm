//! Capture fixed VM producer workloads, then independently validate their synthesized heights.

use std::{collections::BTreeMap, path::Path};

use miden_vm_synthetic_bench::{
    calibrator::{calibrate, measure_program},
    producer::{SNAPSHOT_PATH, VM_WORKLOADS},
    snapshot::TraceSnapshot,
    workload::synthesize,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut captures = Vec::new();
    // Target measurements come from fixed producer sources before any synthesis or calibration.
    for producer in VM_WORKLOADS {
        let measured = measure_program(producer.source)?;
        println!("Captured independent producer {}: {measured:?}", producer.name);
        captures.push((
            producer,
            TraceSnapshot {
                trace: measured.totals,
                shape: measured.breakdown,
            },
        ));
    }
    let calibration = calibrate()?;
    let mut scenarios = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for (producer, snapshot) in &captures {
        println!("Checking synthesized heights for {}", producer.name);
        let generated = synthesize(&calibration, snapshot);
        println!("{}:\n{}", producer.name, generated.report);
        let trace = snapshot.trace;
        let shape = snapshot.shape;
        scenarios.insert(
            producer.name,
            json!({
                "provenance": "current_vm_producer_measured",
                "producer_source": producer.source_path,
                "trace": {
                    "core_rows": trace.core_rows,
                    "chiplets_rows": trace.chiplets_rows,
                    "eidos_compression_rows": trace.eidos_compression_rows,
                    "byte_pair_lookup_rows": trace.byte_pair_lookup_rows,
                    "chiplets_shape": {
                        "library_rows": shape.library_rows,
                        "hasher_rows": shape.hasher_rows,
                        "aead_rows": shape.aead_rows,
                        "memory_rows": shape.memory_rows,
                        "ace_rows": shape.ace_rows,
                        "bitwise_rows": shape.bitwise_rows,
                    },
                },
            }),
        );
        sources.insert(producer.source_path, producer.source);
    }
    // No dataset is written unless every independent capture passes checked synthesis.
    let mut snapshot_json = serde_json::to_string_pretty(&scenarios)?;
    snapshot_json.push('\n');
    std::fs::write(manifest.join(SNAPSHOT_PATH), snapshot_json)?;
    let provenance = json!({
        "schema": "packed-vm-components-v1",
        "producer_command": "cargo +1.99.0 run --offline --locked --profile test-dev -p miden-vm-synthetic-bench --example capture_vm_snapshots",
        "scenario_count": captures.len(),
        "producer_sources": sources,
        "validation": "independent producer trace capture, per-AIR processor formula checks, and calibrated synthesis matching all four padded AIR heights",
    });
    let mut provenance_json = serde_json::to_string_pretty(&provenance)?;
    provenance_json.push('\n');
    std::fs::write(manifest.join("snapshots/provenance/vm-components.json"), provenance_json)?;
    println!("\nCaptured height pins for src/snapshot.rs:");
    for (producer, snapshot) in captures {
        let trace = snapshot.trace;
        println!(
            "        ({:?}, {:?}),",
            producer.name,
            [
                trace.padded_core(),
                trace.padded_chiplets(),
                trace.padded_eidos_compression(),
                trace.padded_and8_lookup()
            ],
        );
    }
    Ok(())
}
