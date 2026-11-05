//! Snapshot selection and checked synthesis shared by MVM and recursive benchmarks.

use std::path::PathBuf;

use crate::{
    calibrator::{Calibration, measure_program},
    snapshot::TraceSnapshot,
    snippets::memory_max_iters,
    solver::{Plan, emit, solve},
    verifier::VerificationReport,
};

/// Producer identity, scenario name, and measured target shape.
pub struct Scenario {
    pub producer: String,
    pub name: String,
    pub snapshot: TraceSnapshot,
}

/// Synthetic source and its measured agreement with the producer's AIR heights.
pub struct SynthesizedProgram {
    pub source: String,
    pub plan: Plan,
    pub report: VerificationReport,
}

/// Loads `SYNTH_SNAPSHOT` or the checked-in snapshots and applies `SYNTH_SCENARIO`.
/// Without a scenario filter, selects the supplied default scenario names.
pub fn load_scenarios(default_scenarios: &[&str]) -> Vec<Scenario> {
    let paths = if let Ok(path) = std::env::var("SYNTH_SNAPSHOT") {
        let mut path = PathBuf::from(path);
        if path.is_relative() && !path.is_file() {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path = root
                .parent()
                .and_then(std::path::Path::parent)
                .expect("workspace root")
                .join(path);
        }
        vec![path]
    } else {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("snapshots");
        let mut paths: Vec<_> = std::fs::read_dir(&directory)
            .expect("read synthetic snapshots directory")
            .map(|entry| entry.expect("snapshot directory entry").path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
            .collect();
        paths.sort();
        paths
    };
    let filter = std::env::var("SYNTH_SCENARIO").ok().map(|filter| slugify(&filter));
    let mut scenarios = Vec::new();
    for path in paths {
        let producer = path.file_stem().and_then(|name| name.to_str()).expect("producer name");
        for (name, snapshot) in TraceSnapshot::load_all(&path)
            .unwrap_or_else(|error| panic!("load {}: {error}", path.display()))
        {
            let selected = filter.as_ref().map_or_else(
                || default_scenarios.contains(&name.as_str()),
                |filter| slugify(&name).contains(filter),
            );
            if selected {
                scenarios.push(Scenario {
                    producer: producer.to_string(),
                    name,
                    snapshot,
                });
            }
        }
    }
    assert!(!scenarios.is_empty(), "no synthetic scenarios matched {filter:?}");
    scenarios
}

/// Solves a plan from measured snippet costs and requires every emitted AIR height to match.
pub fn synthesize(calibration: &Calibration, snapshot: &TraceSnapshot) -> SynthesizedProgram {
    let target = snapshot.shape();
    let plan = solve(calibration, &target);
    assert!(
        plan.iters("memory") <= memory_max_iters(),
        "memory address counter would overflow"
    );
    let source = emit(&plan);
    let actual = measure_program(&source).expect("measure synthesized program");
    let report = VerificationReport::new(target, actual);
    assert!(report.brackets_match(), "synthetic AIR heights differ from producer:\n{report}");
    SynthesizedProgram { source, plan, report }
}

/// Lower-case ASCII identifier with punctuation collapsed to single hyphens.
pub fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_end_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use crate::{
        calibrator::{calibrate, measure_program},
        producer::{DEFAULT_SCENARIOS, SNAPSHOT_PATH, VM_WORKLOADS},
        snapshot::TraceSnapshot,
    };

    #[test]
    fn default_vm_workloads_match_all_four_air_heights() {
        let calibration = calibrate().expect("calibrate snippets");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(SNAPSHOT_PATH);
        let scenarios = TraceSnapshot::load_all(path).expect("load measured VM snapshots");
        assert_eq!(scenarios.len(), DEFAULT_SCENARIOS.len());
        assert_eq!(VM_WORKLOADS.len(), DEFAULT_SCENARIOS.len());
        for producer in VM_WORKLOADS {
            assert!(DEFAULT_SCENARIOS.contains(&producer.name));
            let (_, snapshot) = scenarios
                .iter()
                .find(|(name, _)| name == producer.name)
                .unwrap_or_else(|| panic!("missing producer workload: {}", producer.name));
            // Re-execute the independent source. A solver-generated target cannot satisfy this
            // assertion merely by agreeing with its own synthesized output.
            let measured = measure_program(producer.source).expect("measure producer source");
            assert_eq!(snapshot.shape(), measured, "{}: producer capture changed", producer.name);
            super::synthesize(&calibration, snapshot);
        }
    }
}
