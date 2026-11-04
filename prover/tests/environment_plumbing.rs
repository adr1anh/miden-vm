#![cfg(feature = "std")]

use std::sync::Arc;

use miden_core::{
    Felt, Word,
    mast::{BasicBlockNodeBuilder, MastForest},
    operations::Operation,
    program::{CanonicalLabel, EnvironmentRoot, ExecutionTarget, Namespace},
};
use miden_processor::{
    DefaultHost, EnvironmentTraceLimits, ExecutionEnvironment, ExecutionError, ExecutionOptions,
    LedgerLimits, OpeningLimits, Program, SessionLimits, StackInputs, advice::AdviceInputs,
};
use miden_prover::{Prover, prove_sync};

// A caller-selected descriptor with no available opening. Code possession must not supply either
// the entry identity or its authority, regardless of the proving execution/trace scheduling mode.
#[test]
fn proving_preserves_the_caller_environment_in_sequential_and_overlapped_execution() {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);
    let program = Program::new(Arc::new(forest), root);
    let entry = Namespace::initial()
        .child(CanonicalLabel::text("caller-selected").unwrap().commitment())
        .procedure_key(CanonicalLabel::text("start").unwrap().commitment());
    let authorized_root = EnvironmentRoot::new(Word::new([83u32; 4].map(Felt::from_u32)));
    let environment = ExecutionEnvironment::new(
        ExecutionTarget::new(entry, authorized_root),
        OpeningLimits {
            max_nodes: 8,
            max_depth: 7,
            max_list_children: 8,
            max_total_list_children: 16,
            max_encoded_bytes: 4096,
            max_storage_bytes: 16_384,
        },
        LedgerLimits {
            max_occurrences: 8,
            max_total_list_children: 16,
            max_encoded_bytes: 8192,
            max_library_rows: 128,
            max_compression_requests: 128,
            max_retained_bytes: 65_536,
            max_peak_bytes: 131_072,
        },
        SessionLimits {
            max_cached_keys: 8,
            max_requests: 8,
            max_retained_bytes: 131_072,
            max_prepare_peak_bytes: 262_144,
        },
    );
    for overlapped in [false, true] {
        let options = ExecutionOptions::default()
            .with_overlapped_trace_build(overlapped)
            .with_environment_trace_limits(EnvironmentTraceLimits {
                max_events: 64,
                max_retained_bytes: 1_048_576,
                max_prepare_peak_bytes: 2_097_152,
                max_validation_work: 1_048_576,
            });
        let result = prove_sync(
            &Prover::new(),
            &program,
            environment,
            StackInputs::default(),
            AdviceInputs::default(),
            &mut DefaultHost::default(),
            options,
        );
        assert!(
            matches!(result,
                Err(ExecutionError::EnvironmentWitnessUnavailable { root, key })
                    if root == authorized_root && key == entry
            ),
            "proving mode {overlapped} must request exactly the caller's root/key: {result:?}"
        );
    }
}
