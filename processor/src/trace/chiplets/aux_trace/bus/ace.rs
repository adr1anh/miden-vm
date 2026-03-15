use miden_air::trace::{
    Challenges, MainTrace, RowIndex,
    bus_messages::{AceMessage, AceSource},
    chiplets::ace::ACE_INIT_LABEL,
};
use miden_core::{Felt, ONE, field::ExtensionField};

use crate::debug::{BusDebugger, BusMessage};

// REQUESTS
// ==============================================================================================

/// Builds requests made to the arithmetic circuit evaluation chiplet.
pub fn build_ace_chiplet_requests<E: ExtensionField<Felt>>(
    main_trace: &MainTrace,
    challenges: &Challenges<E>,
    row: RowIndex,
    _debugger: &mut BusDebugger<E>,
) -> E {
    let msg = AceMessage {
        op_label: ACE_INIT_LABEL,
        clk: main_trace.clk(row),
        ctx: main_trace.ctx(row),
        ptr: main_trace.stack_element(0, row),
        num_read_rows: main_trace.stack_element(1, row),
        num_eval_rows: main_trace.stack_element(2, row),
        source: AceSource::Request,
    };

    let value = msg.encode(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_request(alloc::boxed::Box::new(msg), challenges);

    value
}

// RESPONSES
// ==============================================================================================

/// Builds the response from the ace chiplet at `row`.
pub fn build_ace_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    challenges: &Challenges<E>,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let start_selector = main_trace.chiplet_ace_start_selector(row);
    if start_selector == ONE {
        let num_eval_rows = main_trace.chiplet_ace_num_eval_rows(row) + ONE;
        let id_0 = main_trace.chiplet_ace_id_0(row);

        let msg = AceMessage {
            op_label: ACE_INIT_LABEL,
            clk: main_trace.chiplet_ace_clk(row),
            ctx: main_trace.chiplet_ace_ctx(row),
            ptr: main_trace.chiplet_ace_ptr(row),
            num_read_rows: id_0 + ONE - num_eval_rows,
            num_eval_rows,
            source: AceSource::Chiplet,
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

impl<E> BusMessage<E> for AceMessage<Felt>
where
    E: ExtensionField<Felt>,
{
    fn value(&self, challenges: &Challenges<E>) -> E {
        self.encode(challenges)
    }

    fn source(&self) -> &str {
        match self.source {
            AceSource::Request => "ace request",
            AceSource::Chiplet => "ace response",
        }
    }
}
