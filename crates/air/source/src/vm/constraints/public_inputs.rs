//! Public input boundary constraints.
//!
//! Enforces that the stack and principal match the claimed public inputs:
//! - First row: stack[0..16] == stack_inputs[0..16]
//! - Last row:  stack[0..16] == stack_outputs[0..16]
//! - First and last row: fn_hash == K_entry

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

/// Enforces public boundaries for the stack and entry-established principal.
///
/// - First row: `stack[i] == stack_inputs[i]` for i in 0..16
/// - Last row:  `stack[i] == stack_outputs[i]` for i in 0..16
/// - First and last row: `fn_hash == K_entry`
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

    // Both ends of the trace carry K_entry. Principal preservation through HALT then binds the
    // root END's next principal to the same public key, including root caller-frame returns.
    builder.when_first_row().assert_eq_arrays(local.system.fn_hash, entry);
    builder.when_last_row().assert_eq_arrays(local.system.fn_hash, entry);

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
