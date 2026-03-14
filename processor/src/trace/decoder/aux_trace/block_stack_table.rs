use miden_air::trace::{
    Challenges, RowIndex,
    bus_interactions::{BLOCK_STACK_TABLE, block_stack_cols::*},
};
use miden_core::{field::ExtensionField, operations::opcodes};

use super::{AuxColumnBuilder, Felt, MainTrace, ONE, ZERO};
use crate::debug::BusDebugger;

// BLOCK STACK TABLE MESSAGE
// ================================================================================================

/// Describes a single message sent on the block stack table bus.
///
/// The `Simple` variant is used for JOIN, SPLIT, SPAN, DYN, LOOP, and RESPAN blocks, which only
/// store `block_id`, `parent_id`, and `is_loop`.
///
/// The `Full` variant is used for CALL, SYSCALL, and DYNCALL blocks, which additionally store the
/// parent execution context (ctx, stack depth, overflow address, and function hash).
pub(crate) enum BlockStackMessage {
    Simple {
        block_id: Felt,
        parent_id: Felt,
        is_loop: Felt,
    },
    Full {
        block_id: Felt,
        parent_id: Felt,
        is_loop: Felt,
        ctx: Felt,
        depth: Felt,
        overflow: Felt,
        fn_hash: [Felt; 4],
    },
}

impl BlockStackMessage {
    pub fn encode<E: ExtensionField<Felt>>(&self, challenges: &Challenges<E>) -> E {
        match self {
            Self::Simple { block_id, parent_id, is_loop } => {
                challenges.encode_sparse(
                    BLOCK_STACK_TABLE,
                    [BLOCK_ID, PARENT_ID, IS_LOOP],
                    [*block_id, *parent_id, *is_loop],
                )
            },
            Self::Full { block_id, parent_id, is_loop, ctx, depth, overflow, fn_hash } => {
                challenges.encode_sparse(
                    BLOCK_STACK_TABLE,
                    [BLOCK_ID, PARENT_ID, IS_LOOP, CTX, DEPTH, OVERFLOW, FN_HASH_0, FN_HASH_1, FN_HASH_2, FN_HASH_3],
                    [*block_id, *parent_id, *is_loop, *ctx, *depth, *overflow, fn_hash[0], fn_hash[1], fn_hash[2], fn_hash[3]],
                )
            },
        }
    }
}

// BLOCK STACK TABLE COLUMN BUILDER
// ================================================================================================

/// Builds the execution trace of the decoder's `p1` column which describes the state of the block
/// stack table via multiset checks.
#[derive(Default)]
pub struct BlockStackColumnBuilder {}

impl<E: ExtensionField<Felt>> AuxColumnBuilder<E> for BlockStackColumnBuilder {
    /// Removes a row from the block stack table.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_canonical_u64() as u8;

        match op_code {
            opcodes::RESPAN => get_block_stack_table_respan_multiplicand(main_trace, i, challenges),
            opcodes::END => get_block_stack_table_end_multiplicand(main_trace, i, challenges),
            _ => E::ONE,
        }
    }

    /// Adds a row to the block stack table.
    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let op_code_felt = main_trace.get_op_code(i);
        let op_code = op_code_felt.as_canonical_u64() as u8;

        match op_code {
            opcodes::JOIN
            | opcodes::SPLIT
            | opcodes::SPAN
            | opcodes::DYN
            | opcodes::DYNCALL
            | opcodes::LOOP
            | opcodes::RESPAN
            | opcodes::CALL
            | opcodes::SYSCALL => {
                get_block_stack_table_inclusion_multiplicand(main_trace, i, challenges, op_code)
            },
            _ => E::ONE,
        }
    }

    #[cfg(any(test, feature = "bus-debugger"))]
    fn enforce_bus_balance(&self) -> bool {
        true
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the multiplicand representing the removal of a row from the block stack table when
/// encountering a RESPAN operation.
fn get_block_stack_table_respan_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
) -> E {
    let block_id = main_trace.addr(i);
    let parent_id = main_trace.decoder_hasher_state_element(1, i + 1);

    BlockStackMessage::Simple { block_id, parent_id, is_loop: ZERO }.encode(challenges)
}

/// Computes the multiplicand representing the removal of a row from the block stack table when
/// encountering an END operation.
fn get_block_stack_table_end_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
) -> E {
    let block_id = main_trace.addr(i);
    let parent_id = main_trace.addr(i + 1);
    let is_loop = main_trace.is_loop_flag(i);

    if main_trace.is_call_flag(i) == ONE || main_trace.is_syscall_flag(i) == ONE {
        let parent_ctx = main_trace.ctx(i + 1);
        let parent_stack_depth = main_trace.stack_depth(i + 1);
        let parent_next_overflow_addr = main_trace.parent_overflow_address(i + 1);
        let parent_fn_hash = main_trace.fn_hash(i + 1);

        BlockStackMessage::Full {
            block_id,
            parent_id,
            is_loop,
            ctx: parent_ctx,
            depth: parent_stack_depth,
            overflow: parent_next_overflow_addr,
            fn_hash: parent_fn_hash,
        }
        .encode(challenges)
    } else {
        BlockStackMessage::Simple { block_id, parent_id, is_loop }.encode(challenges)
    }
}

/// Computes the multiplicand representing the inclusion of a new row to the block stack table.
fn get_block_stack_table_inclusion_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
    op_code: u8,
) -> E {
    let block_id = main_trace.addr(i + 1);
    let parent_id = if op_code == opcodes::RESPAN {
        main_trace.decoder_hasher_state_element(1, i + 1)
    } else {
        main_trace.addr(i)
    };
    let is_loop = if op_code == opcodes::LOOP {
        main_trace.stack_element(0, i)
    } else {
        ZERO
    };

    if op_code == opcodes::CALL || op_code == opcodes::SYSCALL {
        let parent_ctx = main_trace.ctx(i);
        let parent_stack_depth = main_trace.stack_depth(i);
        let parent_next_overflow_addr = main_trace.parent_overflow_address(i);
        let parent_fn_hash = main_trace.fn_hash(i);

        BlockStackMessage::Full {
            block_id,
            parent_id,
            is_loop,
            ctx: parent_ctx,
            depth: parent_stack_depth,
            overflow: parent_next_overflow_addr,
            fn_hash: parent_fn_hash,
        }
        .encode(challenges)
    } else if op_code == opcodes::DYNCALL {
        let parent_ctx = main_trace.ctx(i);
        let parent_stack_depth = main_trace.decoder_hasher_state_element(4, i);
        let parent_next_overflow_addr = main_trace.decoder_hasher_state_element(5, i);
        let parent_fn_hash = main_trace.fn_hash(i);

        BlockStackMessage::Full {
            block_id,
            parent_id,
            is_loop,
            ctx: parent_ctx,
            depth: parent_stack_depth,
            overflow: parent_next_overflow_addr,
            fn_hash: parent_fn_hash,
        }
        .encode(challenges)
    } else {
        BlockStackMessage::Simple { block_id, parent_id, is_loop }.encode(challenges)
    }
}
