use miden_air::trace::{
    Challenges, MainTrace, RowIndex,
    bus_messages::{KernelRomMessage, KernelRomSource},
    chiplets::kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
};
use miden_core::{Felt, field::ExtensionField};

use crate::debug::{BusDebugger, BusMessage};

// RESPONSES
// ================================================================================================

/// Builds the response from the kernel chiplet at `row`.
///
/// # Details
/// Each kernel procedure digest appears `n+1` times in the trace when requested `n` times by
/// the decoder (via SYSCALL). The first row for each unique digest produces a
/// `KernelRomInitMessage` response; the remaining `n` rows produce `KernelRomMessage` responses
/// matching decoder requests.
pub(super) fn build_kernel_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    challenges: &Challenges<E>,
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let digest = [
        main_trace.chiplet_kernel_root_0(row),
        main_trace.chiplet_kernel_root_1(row),
        main_trace.chiplet_kernel_root_2(row),
        main_trace.chiplet_kernel_root_3(row),
    ];

    // The caller ensures this row is a kernel ROM row, so we just need to check if this is
    // the first row for a unique procedure digest.
    let (label, source) = if main_trace.chiplet_kernel_is_first_hash_row(row) {
        (KERNEL_PROC_INIT_LABEL, KernelRomSource::Init)
    } else {
        (KERNEL_PROC_CALL_LABEL, KernelRomSource::Call)
    };

    let message = KernelRomMessage {
        op_label: label,
        kernel_proc_digest: digest,
        source,
    };

    let value = message.encode(challenges);

    #[cfg(any(test, feature = "bus-debugger"))]
    _debugger.add_response(alloc::boxed::Box::new(message), challenges);

    value
}

// BUS MESSAGE IMPL
// ===============================================================================================

impl<E> BusMessage<E> for KernelRomMessage<Felt>
where
    E: ExtensionField<Felt>,
{
    fn value(&self, challenges: &Challenges<E>) -> E {
        self.encode(challenges)
    }

    fn source(&self) -> &str {
        match self.source {
            KernelRomSource::Call => "kernel rom",
            KernelRomSource::Init => "kernel rom init",
        }
    }
}
