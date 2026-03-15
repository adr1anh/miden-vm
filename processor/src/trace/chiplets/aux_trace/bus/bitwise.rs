use miden_air::trace::{
    Challenges, MainTrace, RowIndex,
    bus_messages::{BitwiseMessage, BitwiseSource},
    chiplets::bitwise::OP_CYCLE_LEN as BITWISE_OP_CYCLE_LEN,
};
use miden_core::{Felt, ONE, ZERO, field::ExtensionField};

use super::get_op_label;
use crate::debug::{BusDebugger, BusMessage};

// REQUESTS
// ==============================================================================================

/// Builds requests made to the bitwise chiplet. This can be either a request for the computation
/// of a `XOR` or an `AND` operation.
pub(super) fn build_bitwise_request<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    is_xor: Felt,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let msg = BitwiseMessage {
        op_label: get_op_label(ONE, ZERO, is_xor, ZERO),
        a: main_trace.stack_element(0, row),
        b: main_trace.stack_element(1, row),
        z: main_trace.stack_element(0, row + 1),
        source: if is_xor == ONE { BitwiseSource::U32Xor } else { BitwiseSource::U32And },
    };

    let value = msg.encode(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(msg), challenges);

    value
}

// RESPONSES
// ==============================================================================================

/// Builds the response from the bitwise chiplet at `row`.
pub(super) fn build_bitwise_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    challenges: &Challenges<E>,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let is_xor = main_trace.chiplet_selector_2(row);
    if row.as_usize() % BITWISE_OP_CYCLE_LEN == BITWISE_OP_CYCLE_LEN - 1 {
        let msg = BitwiseMessage {
            op_label: get_op_label(ONE, ZERO, is_xor, ZERO),
            a: main_trace.chiplet_bitwise_a(row),
            b: main_trace.chiplet_bitwise_b(row),
            z: main_trace.chiplet_bitwise_z(row),
            source: BitwiseSource::Chiplet,
        };

        let value = msg.encode(challenges);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(msg), challenges);

        value
    } else {
        E::ONE
    }
}

// BUS MESSAGE IMPL
// ===============================================================================================

impl<E> BusMessage<E> for BitwiseMessage<Felt>
where
    E: ExtensionField<Felt>,
{
    fn value(&self, challenges: &Challenges<E>) -> E {
        self.encode(challenges)
    }

    fn source(&self) -> &str {
        match self.source {
            BitwiseSource::U32And => "u32and",
            BitwiseSource::U32Xor => "u32xor",
            BitwiseSource::Chiplet => "bitwise chiplet",
        }
    }
}
