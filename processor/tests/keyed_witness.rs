//! Public replay-v4 transport and native trace-reconstruction regressions.
//!
//! The single-Mast environment and finite budgets are fixtures, not a Protocol policy. These
//! programs have no retained invocations: native reconstruction uses the current zero Library
//! prefix pending PR 06 and does not establish proof acceptance.

use miden_core::operations::Operation;
use miden_processor::{self as processor, ExecutionWitness, Felt, StackInputs, trace::build_trace};

#[path = "common/keyed_witness.rs"]
mod common;

use common::{aead_stream_witness, deferred_witness, execution_witness, read_limits, trace_limits};

#[test]
fn witness_reports_precompile_state() {
    let plain = execution_witness(
        vec![Operation::Push(Felt::new_unchecked(1)), Operation::Drop],
        StackInputs::default(),
    );
    assert!(!plain.witness.has_precompiles());
    assert!(!plain.witness.into_parts().0.has_precompiles());

    let deferred = deferred_witness();
    assert!(deferred.witness.has_precompiles());
    let (vm, precompile) = deferred.witness.into_parts();
    assert!(vm.has_precompiles());
    assert!(precompile.is_some());
}

#[test]
fn witness_wire_rejects_unsupported_version() {
    let fixture = deferred_witness();
    let mut bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    assert_eq!(bytes[0], 4, "keyed replay witnesses must use wire version 4");
    assert!(
        ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &fixture.environment,
            trace_limits(),
            read_limits(),
        )
        .is_ok()
    );

    // Versions reject before any replay or precompile payload is decoded.
    for version in [0, 1, 2, 3, 5] {
        bytes[0] = version;
        let error = ExecutionWitness::read_from_bytes_with_limits(
            &bytes,
            &fixture.environment,
            trace_limits(),
            read_limits(),
        )
        .expect_err("unsupported witness format must be rejected");
        assert!(error.to_string().contains("unsupported execution witness wire version"));
    }
}

#[test]
fn witness_wire_rejects_trailing_bytes() {
    let fixture = deferred_witness();
    let mut bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    bytes.push(0);
    let error = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &fixture.environment,
        trace_limits(),
        read_limits(),
    )
    .expect_err("witness payload with trailing bytes should be rejected");
    assert!(
        error.to_string().contains("extra bytes after execution witness payload"),
        "unexpected error: {error}"
    );
}

#[test]
fn deferred_witness_round_trip_preserves_claim_descriptor_and_precompile() {
    let fixture = deferred_witness();
    let bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &fixture.environment,
        trace_limits(),
        read_limits(),
    )
    .expect("deferred witness should round trip");
    assert_eq!(restored.claim(), fixture.witness.claim());
    assert_eq!(restored.execution_descriptor(), fixture.environment.descriptor());
    assert!(restored.has_precompiles());
    assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
    let (vm, precompile) = restored.into_parts();
    assert!(vm.has_precompiles());
    assert!(precompile.is_some());
}

#[test]
fn aead_stream_witness_round_trip_rebuilds_the_same_native_trace() {
    let fixture = aead_stream_witness();
    let bytes = fixture.witness.to_bytes_with_limits(trace_limits(), read_limits()).unwrap();
    let claim = fixture.witness.claim();
    let (original_vm, original_precompile) = fixture.witness.into_parts();
    assert!(original_precompile.is_none());
    let original_trace = build_trace(original_vm, &miden_vm_stark::memory::default_budget())
        .expect("original native trace should build");

    let restored = ExecutionWitness::read_from_bytes_with_limits(
        &bytes,
        &fixture.environment,
        trace_limits(),
        read_limits(),
    )
    .expect("AEAD witness should round trip");
    assert_eq!(restored.claim(), claim);
    assert_eq!(restored.execution_descriptor(), fixture.environment.descriptor());
    assert_eq!(restored.to_bytes_with_limits(trace_limits(), read_limits()).unwrap(), bytes);
    let (restored_vm, restored_precompile) = restored.into_parts();
    assert!(restored_precompile.is_none());
    let restored_trace = build_trace(restored_vm, &miden_vm_stark::memory::default_budget())
        .expect("restored native trace should build");

    assert_eq!(restored_trace.public_inputs(), original_trace.public_inputs());
    assert_eq!(restored_trace.trace_len_summary(), original_trace.trace_len_summary());
    assert_eq!(
        restored_trace.main_trace().clone_air_matrices(),
        original_trace.main_trace().clone_air_matrices()
    );
}
