//! Packs block-stack, resolution, range-check, and transcript buses onto one lookup column:
//!
//! - Block-stack table and Library Resolve demands: control-flow nesting and authenticated calls.
//! - u32 and Merkle-depth range-check removes: gated by u32 or Merkle opcodes.
//! - Log-deferred transcript-state: gated by the log deferred opcode.
//!
//! Soundness of the merge relies on the bus families using distinct `bus_prefix[bus]` bases
//! (so their rationals remain linearly independent in the extension field) and on all
//! top-level branches being mutually exclusive by opcode. Simultaneous frame and Resolve
//! interactions are batched inside their shared branch.
//!
//! # Structure
//!
//! One [`miden_stark::lookup::LookupBuilder::next_column`] call with one opcode-gated group:
//!
//! - Block-stack table: JOIN/SPLIT/SPAN/EXEC/DYN, LOOP, DYNCALL, CALL/SYSCALL, two END cases,
//!   RESPAN batch (branches mutually exclusive via decoder opcode flags).
//! - u32 range-check batch: 4 removes gated by `u32_rc_op`.
//! - Merkle range-check batches: depth bounds plus part of the canonical-index witness, gated by
//!   MPVERIFY / MRUPDATE.
//! - Log-deferred transcript-state batch: 1 remove + 1 add gated by `log_deferred`.
//!
//! # Mutual exclusivity
//!
//! The main group is sound under simple-group accumulation because all its gates are
//! mutually exclusive decoder-opcode flags. The branch families live in disjoint
//! opcode sets:
//!
//! - Block-stack: {JOIN, SPLIT, SPAN, EXEC, DYN, LOOP, DYNCALL, CALL, SYSCALL, END, RESPAN}
//! - u32: {U32SPLIT, U32ASSERT2, U32ADD, U32SUB, U32MUL, U32DIV, U32MOD, U32AND, U32XOR, U32ADD3,
//!   U32MADD, …} — prefix_100 in the opcode encoding.
//! - Merkle: {MPVERIFY, MRUPDATE}.
//! - LOGDEFERRED: {LOGDEFERRED} — a single opcode.
//!
//! No row can fire two of these simultaneously. The continuation / caller-frame END split
//! inside block-stack is mutually exclusive because the caller-frame restoration selector is
//! asserted boolean on END rows (decoder/mod.rs) — the group's single-reciprocal accumulation is
//! only well-formed under that, and nothing else establishes it. The two END branches also use
//! an explicit entry-kind field in the same relation, so neither can be substituted for the
//! other.
//!
//! # Degree budget
//!
//! Main group contribution table:
//!
//! |Interaction                                  |Gate deg|Payload              |U degree|V degree|
//! |---------------------------------------------|--------|---------------------|--------|--------|
//! |JOIN/SPLIT/SPAN continuation add              |5       |Continuation, denom 1|6       |5       |
//! |EXEC/DYN continuation + Resolve batch         |5       |2 linear denoms      |7       |6       |
//! |LOOP continuation add                        |5       |Continuation, denom 1|6       |5       |
//! |DYNCALL caller-frame + Resolve batch         |5       |denoms 2 + 1         |8       |7       |
//! |CALL/SYSCALL frame + Resolve batches          |4       |2 linear denoms      |6       |5       |
//! |END continuation + optional root Resolve     |5       |2 linear denoms      |7       |7       |
//! |END caller-frame + optional root Resolve     |5       |2 linear denoms      |7       |7       |
//! |RESPAN batch (k=2, f=respan deg 4)           |—       |Continuation         |6       |5       |
//! |u32rc batch (k=4, f=u32_rc_op deg 3)         |—       |Range, denom 1       |**7**   |**6**   |
//! |MPVERIFY Merkle batch (k=3, f=mpverify deg 5)|—       |Range, denom 1       |**8**   |**7**   |
//! |MRUPDATE Merkle batch (k=4, f=mrupdate deg 4)|—       |Range, denom 1       |**8**   |**7**   |
//! |logpre batch (k=2, f=log_deferred deg 5)     |—       |LogDeferred, denom 1 |**7**   |**6**   |
//!
//! Column max: `U = 8, V = 7`; transition degree is `max(1 + 8, 7) = 9`.

use core::array;

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::lookup::{Deg, LookupBatch, LookupColumn, LookupGroup};

use super::{super::operations::merkle, resolution};
use crate::vm::{
    constraints::{
        lookup::{
            main_air::{MainBusContext, MainLookupBuilder},
            messages::{BlockStackMsg, LogDeferredMsg, RangeMsg},
        },
        utils::BoolNot,
    },
    trace::log_deferred::{HELPER_STATE_PREV_RANGE, STACK_STATE_NEW_RANGE},
};

/// Upper bound on fractions this emitter pushes into its column per row.
///
/// `max(1 (structural), 2 (invocation/END), 2 (RESPAN), 4 (u32rc), 3 (MPVERIFY), 4 (MRUPDATE),
/// 2 (logpre)) = 4`.
pub(in crate::vm::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 4;

/// Emit the merged block-stack + Resolve + u32/Merkle-depth range-check + logpre column.
pub(in crate::vm::constraints::lookup) fn emit_block_stack_and_range_logcap<LB>(
    builder: &mut LB,
    ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
{
    let local = ctx.local;
    let next = ctx.next;
    let op_flags = &ctx.op_flags;

    let dec = &local.decoder;
    let dec_next = &next.decoder;
    let stk = &local.stack;
    let stk_next = &next.stack;

    // ---- Block-stack captures (from block_stack.rs) ----
    //
    // On invocations h[4..8] holds the resolved implementation. DYNCALL derives the saved
    // post-pop depth and stages its saved overflow address in the group-count overlay. END
    // reads h[4..8] through the disjoint semantic EndBlockFlags overlay.
    let addr = dec.addr;
    let addr_next = dec_next.addr;
    let h1_next = dec_next.hasher_state[1];
    let end_flags = dec.end_block_flags();

    let b0 = stk.b0;
    let b1 = stk.b1;
    let b0_next = stk_next.b0;
    let b1_next = stk_next.b1;

    let sys_ctx = local.system.ctx;
    let sys_ctx_next = next.system.ctx;

    // `fn_hash` is used by caller-frame additions (DYNCALL, CALL, SYSCALL), and `fn_hash_next`
    // is used by caller-frame END removals.
    let fn_hash = local.system.fn_hash;
    let fn_hash_next = next.system.fn_hash;

    // ---- u32 and Merkle-depth range-check + logpre captures (from range_logcap.rs) ----

    let user_helpers = dec.user_op_helpers();
    let f_u32rc = op_flags.u32_rc_op();
    let f_log_deferred = op_flags.log_deferred();

    // u32rc helpers: first 4 of the 6 user_op_helpers.
    let u32rc_helpers: [LB::Var; 4] = array::from_fn(|i| user_helpers[i]);

    // LOGDEFERRED transcript-state add/remove payloads.
    let state_prev: [LB::Var; 4] =
        array::from_fn(|i| user_helpers[HELPER_STATE_PREV_RANGE.start + i]);
    let state_new: [LB::Var; 4] = array::from_fn(|i| stk_next.get(STACK_STATE_NEW_RANGE.start + i));

    builder.next_column(
        |col| {
            // ──────────── Main group: all opcode-gated interactions ────────────
            col.group(
                "main_interactions",
                |g| {
                    // ---- Block-stack relation (Continuation / CallerFrame tagged entries) ----

                    // Structural nodes only push their continuation. Invocations below also
                    // demand one authenticated binding, in the same simultaneous batch.
                    let f = op_flags.join() + op_flags.split() + op_flags.span();
                    g.add(
                        "join_split_span",
                        f,
                        || BlockStackMsg::Continuation {
                            block_id: addr_next.into(),
                            parent_id: addr.into(),
                            is_loop: LB::Expr::ZERO,
                        },
                        Deg { v: 5, u: 6 },
                    );
                    g.batch(
                        "exec_dyn",
                        op_flags.exec() + op_flags.dyn_op(),
                        |b| {
                            b.add(
                                "invocation_continuation",
                                BlockStackMsg::Continuation {
                                    block_id: addr_next.into(),
                                    parent_id: addr.into(),
                                    is_loop: LB::Expr::ZERO,
                                },
                                Deg { v: 5, u: 6 },
                            );
                            b.remove(
                                "ordinary_invocation",
                                resolution::invocation_message(dec, LB::Expr::ZERO),
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 },
                    );

                    // LOOP unconditionally enters the body and records its continuation kind.
                    g.add(
                        "loop",
                        op_flags.loop_op(),
                        || BlockStackMsg::Continuation {
                            block_id: addr_next.into(),
                            parent_id: addr.into(),
                            is_loop: LB::Expr::ONE,
                        },
                        Deg { v: 5, u: 6 },
                    );

                    // The derived post-pop depth is quadratic, so this batch's two
                    // denominators have degrees two and one: (V,U)=(2+5,3+5).
                    g.batch(
                        "dyncall",
                        op_flags.dyncall(),
                        |b| {
                            b.add(
                                "dyncall_caller_frame",
                                BlockStackMsg::CallerFrame {
                                    block_id: addr_next.into(),
                                    parent_id: addr.into(),
                                    caller_ctx: sys_ctx.into(),
                                    caller_stack_depth: LB::Expr::from(b0) - op_flags.overflow(),
                                    caller_overflow_addr: dec.dyncall_overflow_addr().into(),
                                    caller_fn_hash: fn_hash.map(LB::Expr::from),
                                },
                                Deg { v: 5, u: 7 },
                            );
                            b.remove(
                                "ordinary_invocation",
                                resolution::invocation_message(dec, LB::Expr::ZERO),
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 7, u: 8 },
                    );

                    // Separate branches keep the syscall tag literal in each linear message.
                    for (name, flag, syscall) in [
                        ("call", op_flags.call(), LB::Expr::ZERO),
                        ("syscall", op_flags.syscall(), LB::Expr::ONE),
                    ] {
                        g.batch(
                            name,
                            flag,
                            |b| {
                                b.add(
                                    "invocation_caller_frame",
                                    BlockStackMsg::CallerFrame {
                                        block_id: addr_next.into(),
                                        parent_id: addr.into(),
                                        caller_ctx: sys_ctx.into(),
                                        caller_stack_depth: b0.into(),
                                        caller_overflow_addr: b1.into(),
                                        caller_fn_hash: fn_hash.map(LB::Expr::from),
                                    },
                                    Deg { v: 4, u: 5 },
                                );
                                b.remove(
                                    "invocation_resolution",
                                    resolution::invocation_message(dec, syscall),
                                    Deg { v: 4, u: 5 },
                                );
                            },
                            Deg { v: 5, u: 6 },
                        );
                    }

                    // The two END subtypes remain exclusive. Both pop a frame and, only when
                    // the Boolean root flag is one, authenticate the completed root binding.
                    // -f/B - f*r/R = -f*(R + r*B)/(B*R), giving (V,U)=(7,7).
                    let restores_caller_frame: LB::Expr = end_flags.restores_caller_frame.into();
                    let f = op_flags.end() * restores_caller_frame.not();
                    g.batch(
                        "end_continuation",
                        f,
                        |b| {
                            b.remove(
                                "end_continuation_frame",
                                BlockStackMsg::Continuation {
                                    block_id: addr.into(),
                                    parent_id: addr_next.into(),
                                    is_loop: end_flags.is_loop.into(),
                                },
                                Deg { v: 5, u: 6 },
                            );
                            b.insert(
                                "root_completion",
                                -LB::Expr::from(end_flags.is_root_end),
                                resolution::root_completion_message(dec, fn_hash_next),
                                Deg { v: 6, u: 6 },
                            );
                        },
                        Deg { v: 7, u: 7 },
                    );
                    let restores_caller_frame: LB::Expr = end_flags.restores_caller_frame.into();
                    let f = op_flags.end() * restores_caller_frame;
                    g.batch(
                        "end_caller_frame",
                        f,
                        |b| {
                            b.remove(
                                "end_caller_frame_pop",
                                BlockStackMsg::CallerFrame {
                                    block_id: addr.into(),
                                    parent_id: addr_next.into(),
                                    caller_ctx: sys_ctx_next.into(),
                                    caller_stack_depth: b0_next.into(),
                                    caller_overflow_addr: b1_next.into(),
                                    caller_fn_hash: fn_hash_next.map(LB::Expr::from),
                                },
                                Deg { v: 5, u: 6 },
                            );
                            b.insert(
                                "root_completion",
                                -LB::Expr::from(end_flags.is_root_end),
                                resolution::root_completion_message(dec, fn_hash_next),
                                Deg { v: 6, u: 6 },
                            );
                        },
                        Deg { v: 7, u: 7 },
                    );

                    // RESPAN: simultaneous push + pop — one batch under the RESPAN flag.
                    g.batch(
                        "respan",
                        op_flags.respan(),
                        |b| {
                            let block_id_add = addr_next.into();
                            let parent_id_add = h1_next.into();
                            let is_loop_add = LB::Expr::ZERO;
                            b.add(
                                "respan_add",
                                BlockStackMsg::Continuation {
                                    block_id: block_id_add,
                                    parent_id: parent_id_add,
                                    is_loop: is_loop_add,
                                },
                                Deg { v: 4, u: 5 },
                            );
                            let block_id_rem = addr.into();
                            let parent_id_rem = h1_next.into();
                            let is_loop_rem = LB::Expr::ZERO;
                            b.remove(
                                "respan_remove",
                                BlockStackMsg::Continuation {
                                    block_id: block_id_rem,
                                    parent_id: parent_id_rem,
                                    is_loop: is_loop_rem,
                                },
                                Deg { v: 4, u: 5 },
                            );
                        },
                        Deg { v: 5, u: 6 }, // (V, U) = (1 + 4, 2 + 4)
                    );

                    // ---- u32 range-check removes (BusId::RangeCheck) ----
                    // Four simultaneous range-check removals under the u32rc flag. Mutually
                    // exclusive with all block-stack branches (u32 ops are disjoint from
                    // control-flow ops) and with logpre (disjoint from LOGDEFERRED).
                    g.batch(
                        "u32_range_check",
                        f_u32rc,
                        move |b| {
                            for helper in u32rc_helpers {
                                let value = helper.into();
                                b.remove("u32rc_remove", RangeMsg { value }, Deg { v: 3, u: 4 });
                            }
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (3 + 3, 4 + 3)
                    );

                    merkle::emit_core_range_checks::<LB, _>(g, ctx);

                    // ---- Log-deferred root update (BusId::LogDeferredRoot) ----
                    // Remove the previous deferred root, add the next. Mutually exclusive with all
                    // block-stack branches and with the u32 and Merkle-depth range checks.
                    g.batch(
                        "log_deferred_state",
                        f_log_deferred,
                        move |b| {
                            let state_prev_expr = state_prev.map(LB::Expr::from);
                            b.remove(
                                "logpre_state_remove",
                                LogDeferredMsg { state: state_prev_expr },
                                Deg { v: 5, u: 6 },
                            );
                            let state_new_expr = state_new.map(LB::Expr::from);
                            b.add(
                                "logpre_state_add",
                                LogDeferredMsg { state: state_new_expr },
                                Deg { v: 5, u: 6 },
                            );
                        },
                        Deg { v: 6, u: 7 }, // (V, U) = (1 + 5, 2 + 5)
                    );
                },
                Deg { v: 7, u: 8 },
            );
        },
        Deg { v: 7, u: 8 },
    );
}
