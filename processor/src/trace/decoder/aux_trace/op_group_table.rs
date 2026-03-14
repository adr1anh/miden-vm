use miden_air::trace::{
    Challenges, RowIndex,
    bus_interactions::OP_GROUP_TABLE,
    decoder::{OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS},
};
use miden_core::{field::ExtensionField, operations::opcodes};

use super::{AuxColumnBuilder, Felt, MainTrace, ONE};
use crate::debug::BusDebugger;

// OP GROUP TABLE MESSAGE
// ================================================================================================

/// Describes a single message sent on the op group table bus. Each message is a tuple
/// `(block_id, group_pos, group_value)` representing a single operation group within a span block.
pub(crate) struct OpGroupMessage {
    pub block_id: Felt,
    pub group_pos: Felt,
    pub group_value: Felt,
}

impl OpGroupMessage {
    pub fn encode<E: ExtensionField<Felt>>(&self, challenges: &Challenges<E>) -> E {
        challenges.encode(OP_GROUP_TABLE, [self.block_id, self.group_pos, self.group_value])
    }
}

// OP GROUP TABLE COLUMN
// ================================================================================================

/// Builds the execution trace of the decoder's `p3` column which describes the state of the op
/// group table via multiset checks.
#[derive(Default)]
pub struct OpGroupTableColumnBuilder {}

impl<E: ExtensionField<Felt>> AuxColumnBuilder<E> for OpGroupTableColumnBuilder {
    /// Removes a row from the block hash table.
    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        i: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let delete_group_flag = main_trace.delta_group_count(i) * main_trace.is_in_span(i);

        if delete_group_flag == ONE {
            get_op_group_table_removal_multiplicand(main_trace, i, challenges)
        } else {
            E::ONE
        }
    }

    /// Adds a row to the block hash table.
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
            opcodes::SPAN | opcodes::RESPAN => {
                get_op_group_table_inclusion_multiplicand(main_trace, i, challenges)
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

/// Computes the multiplicand representing the inclusion of a new row to the op group table.
fn get_op_group_table_inclusion_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
) -> E {
    let block_id = main_trace.addr(i + 1);
    let group_count = main_trace.group_count(i);
    let op_batch_flag = main_trace.op_batch_flag(i);

    if op_batch_flag == OP_BATCH_8_GROUPS {
        let h = main_trace.decoder_hasher_state(i);
        (1..8_u8).fold(E::ONE, |acc, k| {
            acc * OpGroupMessage { block_id, group_pos: group_count - Felt::from_u8(k), group_value: h[k as usize] }.encode(challenges)
        })
    } else if op_batch_flag == OP_BATCH_4_GROUPS {
        let h = main_trace.decoder_hasher_state_first_half(i);
        (1..4_u8).fold(E::ONE, |acc, k| {
            acc * OpGroupMessage { block_id, group_pos: group_count - Felt::from_u8(k), group_value: h[k as usize] }.encode(challenges)
        })
    } else if op_batch_flag == OP_BATCH_2_GROUPS {
        let h = main_trace.decoder_hasher_state_first_half(i);
        OpGroupMessage { block_id, group_pos: group_count - ONE, group_value: h[1] }.encode(challenges)
    } else {
        E::ONE
    }
}

/// Computes the multiplicand representing the removal of a row from the op group table.
fn get_op_group_table_removal_multiplicand<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    i: RowIndex,
    challenges: &Challenges<E>,
) -> E {
    let group_count = main_trace.group_count(i);
    let block_id = main_trace.addr(i);
    let group_value = {
        let op_code = main_trace.get_op_code(i);

        if op_code == Felt::from_u8(opcodes::PUSH) {
            main_trace.stack_element(0, i + 1)
        } else {
            let h0 = main_trace.decoder_hasher_state_first_half(i + 1)[0];

            let op_prime = main_trace.get_op_code(i + 1);
            h0 * Felt::from_u16(1 << 7) + op_prime
        }
    };

    OpGroupMessage { block_id, group_pos: group_count, group_value }.encode(challenges)
}
