//! Four-Felt hasher-return bus interactions.
//!
//! A single-row controller operation can emit an operation-init response and a four-Felt return on
//! the same row. Init responses stay in the shared chiplet-responses column; this column carries
//! completed hash digests and raw-compression CV updates. Its exclusive Memory branch carries
//! the fifth address range check, and its normal Bitwise branch carries byte checks 2/3.

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::lookup::{Deg, LookupBatch, LookupColumn, LookupGroup};

use super::super::operations::merkle;
use crate::vm::constraints::{
    chiplets::hasher_control::flags::ControllerFlags,
    lookup::{
        chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
        messages::{BytePairLookupMsg, HasherMsg, RangeMsg},
    },
};

/// Upper bound on fractions this emitter pushes into its column per row.
pub(in crate::vm::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 2;

/// Emit four-Felt hasher responses.
pub(in crate::vm::constraints::lookup) fn emit_hasher_returns<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;
    let ctrl = local.controller();

    let controller_flag = ctx.chiplet_active.controller.clone();
    let rows = ControllerFlags::<LB::Expr>::new(ctrl);
    let op_final: LB::Expr = local.controller_op_final().into();
    let hash_return = controller_flag * rows.is_hash * op_final;

    let addr: LB::Expr = local.chip_clk.into();
    let hash_result = ctrl.hash_cv();
    let bitwise = local.bitwise();
    let memory_word_addr_hi = local.memory_word_addr_hi();

    builder.next_column(
        |col| {
            col.group(
                "hasher_returns",
                |g| {
                    g.add(
                        "hash_return",
                        hash_return,
                        || HasherMsg::return_hash(addr.clone(), hash_result.map(LB::Expr::from)),
                        Deg { v: 5, u: 6 },
                    );
                    merkle::emit_return::<LB, _>(g, ctx);

                    // Exactly the remaining two AND8 tuples from the original four-byte batch.
                    g.batch(
                        "bitwise_and8_lookups_high",
                        ctx.chiplet_active.bitwise.clone(),
                        |b| {
                            for idx in 2..4 {
                                b.remove(
                                    "bitwise_and8_byte",
                                    BytePairLookupMsg::from_and(
                                        bitwise.a_bytes[idx].into(),
                                        bitwise.b_bytes[idx].into(),
                                        bitwise.and_bytes[idx].into(),
                                    ),
                                    Deg { v: 6, u: 7 },
                                );
                            }
                        },
                        Deg { v: 7, u: 8 }, // Two linear denominators, Bitwise gate degree six.
                    );

                    // Preserve the original 4*w1 check while limiting the range batch in the
                    // hash-kernel column to its four-fraction capacity.
                    g.remove(
                        "mem_w1_mul4",
                        ctx.chiplet_active.memory.clone(),
                        || RangeMsg {
                            value: Into::<LB::Expr>::into(memory_word_addr_hi)
                                * LB::Expr::from_u16(4),
                        },
                        Deg { v: 4, u: 5 },
                    );
                },
                Deg { v: 7, u: 8 },
            );
        },
        Deg { v: 7, u: 8 },
    );
}
