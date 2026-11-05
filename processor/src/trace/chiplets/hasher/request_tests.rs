use super::{
    CompressionOutput, CompressionRequestKey, ContextId, EIDOS_COMPRESSION_CYCLE_LEN,
    ExecutionError, Hasher, HasherState, MAX_TRACE_LEN, ONE, RowIndex, ZERO,
    checked_compression_request_counts, state_to_key,
};

fn key(state: &HasherState, output: CompressionOutput) -> CompressionRequestKey {
    CompressionRequestKey { state: state_to_key(state), output }
}

fn assert_limit<T>(result: Result<T, ExecutionError>) {
    assert!(matches!(result, Err(ExecutionError::TraceLenExceeded(MAX_TRACE_LEN))));
}

#[test]
fn direct_packed_requests_share_controller_interner_without_controller_rows() {
    let mut hasher = Hasher::default();
    let state = [ZERO; 12];
    let mut other = state;
    other[0] = ONE;

    hasher.compress(state).unwrap();
    hasher.record_packed_compression_request(&state, 2).unwrap();
    hasher.record_packed_compression_request(&other, 4).unwrap();

    assert_eq!(hasher.trace.trace_len(), 1);
    assert_eq!(hasher.compression_request_map.len(), 2);
    assert_eq!(hasher.compression_request_count, 7);
    assert_eq!(hasher.compression_request_map[&key(&state, CompressionOutput::Packed)], 3);
    assert_eq!(hasher.compression_request_map[&key(&other, CompressionOutput::Packed)], 4);
    assert_eq!(hasher.eidos_compression_trace_len(), 2 * EIDOS_COMPRESSION_CYCLE_LEN);
}

#[test]
fn packed_and_aead_output_shapes_keep_separate_multiplicities() {
    let mut hasher = Hasher::default();
    let state = [ZERO; 12];
    let clk = RowIndex::from(3);
    let output = CompressionOutput::AeadXof { clk: clk.into() };

    hasher.record_packed_compression_request(&state, 2).unwrap();
    hasher.compress_aead_xof(ContextId::root(), clk, state).unwrap();
    let requests = hasher.compression_request_map.clone();
    assert!(matches!(
        hasher.compress_aead_xof(ContextId::root(), clk, state),
        Err(ExecutionError::Internal("duplicate or nonunit AEAD compression request")),
    ));
    assert_eq!(hasher.compression_request_map, requests);
    assert_eq!(hasher.compression_request_count, 3);
    assert!(matches!(
        hasher.record_compression_request(&state, CompressionOutput::AeadXof { clk: ONE }, 2),
        Err(ExecutionError::Internal("duplicate or nonunit AEAD compression request")),
    ));
    assert_eq!(hasher.compression_request_map, requests);
    assert_eq!(hasher.compression_request_count, 3);
    hasher.compress_aead_xof(ContextId::root(), RowIndex::from(4), state).unwrap();

    assert_eq!(hasher.trace.trace_len(), 0);
    assert_eq!(hasher.compression_request_map.len(), 3);
    assert_eq!(hasher.compression_request_count, 4);
    assert_eq!(hasher.compression_request_map[&key(&state, CompressionOutput::Packed)], 2);
    assert_eq!(hasher.compression_request_map[&key(&state, output)], 1);
    assert_eq!(hasher.eidos_compression_trace_len(), 3 * EIDOS_COMPRESSION_CYCLE_LEN);
}

#[test]
fn summed_request_ceiling_rejects_duplicate_and_new_state_without_mutation() {
    let mut hasher = Hasher::default();
    let state = [ZERO; 12];
    let mut other = state;
    other[0] = ONE;
    hasher.record_packed_compression_request(&state, MAX_TRACE_LEN as u64).unwrap();
    let requests = hasher.compression_request_map.clone();

    assert_limit(hasher.record_packed_compression_request(&state, 1));
    assert_limit(hasher.record_packed_compression_request(&other, 1));
    assert_limit(hasher.record_packed_compression_request(&other, u64::MAX));
    assert_limit(hasher.compress(state));
    assert_limit(hasher.compress_aead_xof(ContextId::root(), RowIndex::from(0), state));
    assert_eq!(hasher.trace.trace_len(), 0);
    assert_eq!(hasher.compression_request_map, requests);
    assert_eq!(hasher.compression_request_count, MAX_TRACE_LEN as u64);
}

#[test]
fn entry_overflow_rejects_without_mutating_synthetic_boundary_state() {
    let mut hasher = Hasher::default();
    let state = [ZERO; 12];
    // An admitted entry cannot reach u64::MAX. Seed it directly to exercise checked addition.
    hasher
        .compression_request_map
        .insert(key(&state, CompressionOutput::Packed), u64::MAX);

    assert_limit(hasher.record_packed_compression_request(&state, 1));
    assert_eq!(hasher.compression_request_map.len(), 1);
    assert_eq!(
        hasher.compression_request_map[&key(&state, CompressionOutput::Packed)],
        u64::MAX
    );
    assert_eq!(hasher.compression_request_count, 0);
}

#[test]
fn unique_cycle_admission_checks_ceiling_and_native_overflow_without_allocation() {
    let max_unique = MAX_TRACE_LEN / EIDOS_COMPRESSION_CYCLE_LEN;
    assert_eq!(checked_compression_request_counts(None, 0, max_unique - 1, 1).unwrap(), (1, 1),);
    assert_eq!(checked_compression_request_counts(Some(1), 1, max_unique, 1).unwrap(), (2, 2),);
    assert_limit(checked_compression_request_counts(None, 0, max_unique, 1));
    assert_limit(checked_compression_request_counts(None, 0, usize::MAX, 1));
    assert_limit(checked_compression_request_counts(Some(1), 1, usize::MAX, 1));
    assert_limit(checked_compression_request_counts(None, u64::MAX, 0, 1));
}

#[test]
fn zero_multiplicity_is_noop_but_finalized_recording_always_rejects() {
    let mut hasher = Hasher::default();
    let state = [ZERO; 12];
    hasher.record_packed_compression_request(&state, 0).unwrap();
    assert!(hasher.compression_request_map.is_empty());
    assert_eq!(hasher.compression_request_count, 0);

    hasher.record_packed_compression_request(&state, 1).unwrap();
    hasher.finalize_trace();
    let requests = hasher.compression_request_map.clone();
    for multiplicity in [0, 1] {
        assert!(matches!(
            hasher.record_packed_compression_request(&state, multiplicity),
            Err(ExecutionError::Internal("compression request after hasher finalization")),
        ));
    }
    assert!(matches!(hasher.compress(state), Err(ExecutionError::Internal(_))));
    assert!(matches!(
        hasher.compress_aead_xof(ContextId::root(), RowIndex::from(0), state),
        Err(ExecutionError::Internal(_)),
    ));
    assert_eq!(hasher.trace.trace_len(), 0);
    assert_eq!(hasher.compression_request_map, requests);
    assert_eq!(hasher.compression_request_count, 1);
}
