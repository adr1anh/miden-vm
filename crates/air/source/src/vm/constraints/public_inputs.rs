//! Public input boundary constraints.
//!
//! Enforces the stack boundaries and the authenticated entry key:
//! - First row: stack[0..16] == stack_inputs[0..16]
//! - Last row:  stack[0..16] == stack_outputs[0..16]
//! - First and last row: fn_hash == 0
//! - Last row: the HALT entry key equals K_entry

use miden_core::WORD_SIZE;
use miden_stark::air::AirBuilder;

use crate::vm::{CoreCols, MidenAirBuilder};

// CONSTANTS
// ================================================================================================

const STACK_DEPTH: usize = 16;

/// Exact Core public layout: stack inputs, stack outputs, then the entry key.
const PUBLIC_LEN: usize = STACK_DEPTH + STACK_DEPTH + WORD_SIZE;

// ENTRY POINTS
// ================================================================================================

/// Enforces public boundaries for the stack and entry key.
///
/// - First row: `stack[i] == stack_inputs[i]` for i in 0..16
/// - Last row:  `stack[i] == stack_outputs[i]` for i in 0..16
/// - First and last row: `fn_hash == 0`
/// - Last row: the HALT entry key equals `K_entry`
pub fn enforce_main<AB>(builder: &mut AB, local: &CoreCols<AB::Var>)
where
    AB: MidenAirBuilder,
{
    // Copy public values into local arrays to release the immutable borrow on builder.
    let pv = builder.public_values();
    let n = pv.len();
    assert_eq!(n, PUBLIC_LEN, "Core requires exactly {PUBLIC_LEN} public values");
    let si: [AB::PublicVar; STACK_DEPTH] = core::array::from_fn(|i| pv[i]);
    let so: [AB::PublicVar; STACK_DEPTH] = core::array::from_fn(|i| pv[STACK_DEPTH + i]);
    let entry: [AB::PublicVar; WORD_SIZE] = core::array::from_fn(|i| pv[2 * STACK_DEPTH + i]);

    builder.when_first_row().assert_zeros(local.system.fn_hash);
    builder.when_last_row().assert_zeros(local.system.fn_hash);
    builder.when_last_row().assert_eq_arrays(local.decoder.halt_entry_key(), entry);

    // First row: stack[i] == stack_inputs[i]
    {
        let builder = &mut builder.when_first_row();
        #[expect(
            clippy::needless_range_loop,
            reason = "index-based loop keeps the stack input slot mapping explicit"
        )]
        for i in 0..STACK_DEPTH {
            builder.assert_eq(local.stack.get(i), si[i]);
        }
    }

    // Last row: stack[i] == stack_outputs[i]
    {
        let builder = &mut builder.when_last_row();
        #[expect(
            clippy::needless_range_loop,
            reason = "index-based loop keeps the stack output slot mapping explicit"
        )]
        for i in 0..STACK_DEPTH {
            builder.assert_eq(local.stack.get(i), so[i]);
        }
    }
}
