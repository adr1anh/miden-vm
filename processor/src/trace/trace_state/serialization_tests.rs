use alloc::vec::Vec;

use miden_core::serde::{BudgetedReader, SliceReader};

use super::*;
use crate::{mast::MastForestId, trace::parallel::MAX_TRACE_LEN};

fn logical_address(encoded: u32) -> LogicalControllerAddress {
    LogicalControllerAddress::from_felt(Felt::from_u32(encoded)).unwrap()
}

#[test]
fn memory_reads_replay_rejects_oversized_queue_lengths_before_allocation() {
    let mut bytes = Vec::new();
    usize::MAX.write_into(&mut bytes);

    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    let err = MemoryReadsReplay::read_from(&mut reader).unwrap_err();
    assert!(err.to_string().contains("reader can provide at most"));

    let mut bytes = Vec::new();
    0usize.write_into(&mut bytes);
    usize::MAX.write_into(&mut bytes);

    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    let err = MemoryReadsReplay::read_from(&mut reader).unwrap_err();
    assert!(err.to_string().contains("reader can provide at most"));
}

#[test]
fn stack_state_read_rejects_depth_below_minimum() {
    let mut bytes = Vec::new();
    [ZERO; MIN_STACK_DEPTH].write_into(&mut bytes);
    (MIN_STACK_DEPTH - 1).write_into(&mut bytes);
    ZERO.write_into(&mut bytes);

    let err = StackState::read_from_bytes(&bytes).unwrap_err();
    assert!(err.to_string().contains("below minimum"));
}

#[test]
fn execution_replay_round_trip_preserves_replay_order() {
    let mut replay = ExecutionReplay::default();
    replay.block_stack.record_node_start_parent_addr(logical_address(7));
    replay
        .block_stack
        .record_node_end(logical_address(9), logical_address(8), logical_address(7));
    replay.execution_context.record_execution_context(ExecutionContextSystemInfo {
        parent_ctx: ContextId::from(3),
        parent_fn_hash: Word::from([ONE, ZERO, ZERO, ZERO]),
    });
    replay
        .stack_overflow
        .record_pop_overflow(Felt::from_u32(11), Felt::from_u32(10));
    replay
        .stack_overflow
        .record_restore_context_overflow_addr(17, Felt::from_u32(16));
    replay.memory_reads.record_read_element(
        Felt::from_u32(21),
        Felt::from_u32(20),
        ContextId::from(4),
        RowIndex::from(5_u32),
    );
    replay.memory_reads.record_read_word(
        Word::from([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)]),
        Felt::from_u32(24),
        ContextId::from(4),
        RowIndex::from(6_u32),
    );
    replay.advice.record_pop_stack(Felt::from_u32(31));
    replay
        .advice
        .record_pop_stack_word(Word::from([Felt::from_u32(5), ZERO, ZERO, ZERO]));
    replay.advice.record_pop_stack_dword([
        Word::from([Felt::from_u32(6), ZERO, ZERO, ZERO]),
        Word::default(),
    ]);
    replay.hasher.record_compression(logical_address(40), [Felt::from_u32(41); 12]);
    replay.block_address.record_block_address(logical_address(50));
    replay
        .mast_forest_resolution
        .record_resolution(MastNodeId::from(2), MastForestId::from(1));

    let bytes = replay.to_bytes();
    let mut restored = ExecutionReplay::read_from_bytes(&bytes).unwrap();

    assert_eq!(
        restored.block_stack.replay_node_start_parent_addr().unwrap(),
        logical_address(7)
    );
    let node_end = restored.block_stack.replay_node_end().unwrap();
    assert_eq!(node_end.ended_node_addr, logical_address(9));
    assert_eq!(node_end.prev_addr, logical_address(8));
    assert_eq!(node_end.prev_parent_addr, logical_address(7));
    let ctx = restored.execution_context.replay_execution_context().unwrap();
    assert_eq!(ctx.parent_ctx, ContextId::from(3));
    assert_eq!(ctx.parent_fn_hash, Word::from([ONE, ZERO, ZERO, ZERO]));
    assert_eq!(
        restored.stack_overflow.replay_pop_overflow().unwrap(),
        (Felt::from_u32(11), Felt::from_u32(10))
    );
    assert_eq!(
        restored.stack_overflow.replay_restore_context_overflow_addr().unwrap(),
        (17, Felt::from_u32(16))
    );
    assert_eq!(
        restored.memory_reads.replay_read_element(Felt::from_u32(20)).unwrap(),
        Felt::from_u32(21)
    );
    assert_eq!(
        restored.memory_reads.replay_read_word(Felt::from_u32(24)).unwrap(),
        Word::from([Felt::from_u32(1), Felt::from_u32(2), Felt::from_u32(3), Felt::from_u32(4)])
    );
    assert_eq!(restored.advice.replay_pop_stack().unwrap(), Felt::from_u32(31));
    assert_eq!(
        restored.advice.replay_pop_stack_word().unwrap(),
        Word::from([Felt::from_u32(5), ZERO, ZERO, ZERO])
    );
    assert_eq!(
        restored.advice.replay_pop_stack_dword().unwrap(),
        [Word::from([Felt::from_u32(6), ZERO, ZERO, ZERO]), Word::default()]
    );
    assert_eq!(
        restored.hasher.replay_compression().unwrap(),
        (logical_address(40), [Felt::from_u32(41); 12])
    );
    assert_eq!(restored.block_address.replay_block_address().unwrap(), logical_address(50));
    assert_eq!(
        restored.mast_forest_resolution.replay_resolution().unwrap(),
        (MastNodeId::from(2), MastForestId::from(1))
    );
}

#[test]
fn decoder_state_uses_existing_logical_felt_wire_encoding() {
    let absent = LogicalControllerAddress::ABSENT;
    let row_zero = logical_address(1);
    let end_cursor = logical_address(MAX_TRACE_LEN as u32 + 1);

    for (current_addr, parent_addr) in
        [(absent, row_zero), (row_zero, absent), (end_cursor, row_zero)]
    {
        let state = DecoderState { current_addr, parent_addr };
        let mut legacy_bytes = Vec::new();
        current_addr.to_felt().write_into(&mut legacy_bytes);
        parent_addr.to_felt().write_into(&mut legacy_bytes);

        assert_eq!(state.to_bytes(), legacy_bytes);
        assert_eq!(DecoderState::read_from_bytes(&legacy_bytes).unwrap(), state);
    }
    assert_ne!(absent, row_zero);
}

#[test]
fn saved_fragment_replays_logical_addresses_after_round_trip() {
    let absent = LogicalControllerAddress::ABSENT;
    let row_zero = logical_address(1);
    let end_cursor = logical_address(MAX_TRACE_LEN as u32 + 1);
    let mut replay = ExecutionReplay::default();
    replay.block_address.record_block_address(row_zero);
    replay.block_stack.record_node_start_parent_addr(absent);
    replay.block_stack.record_node_end(row_zero, end_cursor, absent);
    replay.hasher.record_compression(row_zero, [ONE; 12]);
    replay.hasher.record_build_merkle_root(end_cursor, Word::default());
    replay
        .hasher
        .record_update_merkle_root(absent, Word::default(), Word::from([ONE; 4]));

    let fragment = CoreTraceFragmentContext {
        state: CoreTraceState {
            system: SystemState {
                clk: RowIndex::from(29u32),
                ctx: ContextId::from(3),
                fn_hash: Word::from([ONE; 4]),
                deferred_root: Word::default(),
            },
            decoder: DecoderState {
                current_addr: end_cursor,
                parent_addr: absent,
            },
            stack: StackState::new([ONE; MIN_STACK_DEPTH], MIN_STACK_DEPTH + 1, Felt::from_u32(17)),
        },
        replay,
        continuation: ContinuationStack::default(),
        initial_mast_forest_id: MastForestId::from(0u32),
    };
    let bytes = fragment.to_bytes();
    let mut restored = CoreTraceFragmentContext::read_from_bytes(&bytes).unwrap();
    assert_eq!(restored, fragment);
    assert_eq!(restored.to_bytes(), bytes);
    restored
        .state
        .decoder
        .replay_node_start(&mut restored.replay.block_address, &mut restored.replay.block_stack)
        .unwrap();
    assert_eq!(restored.state.decoder.current_addr, row_zero);
    assert_eq!(restored.state.decoder.parent_addr, absent);
    assert_eq!(
        restored
            .state
            .decoder
            .replay_node_end(&mut restored.replay.block_stack)
            .unwrap(),
        row_zero
    );
    assert_eq!(restored.state.decoder.current_addr, end_cursor);
    assert_eq!(restored.state.decoder.parent_addr, absent);
    assert_eq!(restored.replay.hasher.replay_compression().unwrap(), (row_zero, [ONE; 12]));
    assert_eq!(
        restored.replay.hasher.replay_build_merkle_root().unwrap(),
        (end_cursor, Word::default())
    );
    assert_eq!(
        restored.replay.hasher.replay_update_merkle_root().unwrap(),
        (absent, Word::default(), Word::from([ONE; 4]))
    );
    assert_eq!(restored.state.system, fragment.state.system);
    assert_eq!(restored.state.stack, fragment.state.stack);

    // After replay is consumed, this is a compact saved fragment with empty queues. Its Vec
    // allocation bound must follow the wire size rather than the larger in-memory address type.
    assert_eq!(restored.replay, ExecutionReplay::default());
    let compact_fragments = vec![restored];
    let bytes = compact_fragments.to_bytes();
    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    assert_eq!(
        Vec::<CoreTraceFragmentContext>::read_from(&mut reader).unwrap(),
        compact_fragments
    );
}

#[test]
fn logical_state_codec_rejects_address_beyond_exact_cap_cursor() {
    let invalid = Felt::from_u32(MAX_TRACE_LEN as u32 + 2);
    let mut bytes = invalid.to_bytes();
    ZERO.write_into(&mut bytes);
    assert!(matches!(
        DecoderState::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(message))
            if message.contains("invalid logical Controller address")
    ));

    // Replayed addresses use the same checked codec as decoder snapshots.
    let mut bytes = Vec::new();
    1usize.write_into(&mut bytes);
    invalid.write_into(&mut bytes);
    assert!(matches!(
        BlockAddressReplay::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue(message))
            if message.contains("invalid logical Controller address")
    ));
}

#[test]
fn compact_node_end_replay_round_trips_with_exact_byte_budget() {
    let mut replay = BlockStackReplay::default();
    replay.record_node_end(
        logical_address(1),
        logical_address(MAX_TRACE_LEN as u32 + 1),
        LogicalControllerAddress::ABSENT,
    );
    let bytes = replay.to_bytes();
    let mut reader = BudgetedReader::new(SliceReader::new(&bytes), bytes.len());
    assert_eq!(BlockStackReplay::read_from(&mut reader).unwrap(), replay);
    assert_eq!(NodeEndData::min_serialized_size(), 3 * Felt::min_serialized_size());
}
