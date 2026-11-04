//! Fixed generic VM workloads measured independently of synthetic workload generation.

/// One checked-in assembly workload used to capture a benchmark target.
pub struct ProducerWorkload {
    pub name: &'static str,
    pub source_path: &'static str,
    pub source: &'static str,
}

/// The default producer dataset. Sources are fixed inputs, never outputs of the solver.
pub const VM_WORKLOADS: &[ProducerWorkload] = &[
    ProducerWorkload {
        name: "VM arithmetic and memory",
        source_path: "snapshots/sources/arithmetic-memory.masm",
        source: include_str!("../snapshots/sources/arithmetic-memory.masm"),
    },
    ProducerWorkload {
        name: "VM bitwise and memory",
        source_path: "snapshots/sources/bitwise-memory.masm",
        source: include_str!("../snapshots/sources/bitwise-memory.masm"),
    },
    ProducerWorkload {
        name: "VM memory and compression",
        source_path: "snapshots/sources/memory-compression.masm",
        source: include_str!("../snapshots/sources/memory-compression.masm"),
    },
    ProducerWorkload {
        name: "VM compression and arithmetic",
        source_path: "snapshots/sources/compression-arithmetic.masm",
        source: include_str!("../snapshots/sources/compression-arithmetic.masm"),
    },
];

pub const SNAPSHOT_PATH: &str = "snapshots/vm-components.json";

/// Representative generic VM workloads selected by the ordinary benchmark entry points.
pub const DEFAULT_SCENARIOS: &[&str] = &[
    VM_WORKLOADS[0].name,
    VM_WORKLOADS[1].name,
    VM_WORKLOADS[2].name,
    VM_WORKLOADS[3].name,
];
