//! Unit Core demands for authenticated callable bindings.
//!
//! One exclusive group keeps the three opcode-disjoint branches in a single reciprocal.
//! Literal tags keep syscall selection out of the denominator. The largest gate has degree
//! five and each payload is linear, giving `(V, U) = (5, 6)` and recurrence degree seven.

use core::array;

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::lookup::{Deg, LookupColumn, LookupGroup};

use crate::vm::constraints::lookup::{
    main_air::{MainBusContext, MainLookupBuilder},
    messages::LibraryResolveMsg,
};

pub(in crate::vm::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 1;

pub(in crate::vm::constraints::lookup) fn emit_resolution<LB>(
    builder: &mut LB,
    ctx: &MainBusContext<LB>,
) where
    LB: MainLookupBuilder,
{
    let dec = &ctx.local.decoder;
    let flags = &ctx.op_flags;
    let ordinary = flags.exec() + flags.call() + flags.dyn_op() + flags.dyncall();
    let root: LB::Expr = dec.end_block_flags().is_root_end.into();

    builder.next_column(
        |col| {
            col.group(
                "core_resolution",
                |group| {
                    // There is no cache selector: every invocation contributes one demand.
                    group.remove(
                        "ordinary_invocation",
                        ordinary,
                        || LibraryResolveMsg {
                            requires_syscall: LB::Expr::ZERO,
                            key: array::from_fn(|i| dec.hasher_state[i].into()),
                            implementation: dec.resolved_digest.map(Into::into),
                        },
                        Deg { v: 5, u: 6 },
                    );
                    group.remove(
                        "syscall_invocation",
                        flags.syscall(),
                        || LibraryResolveMsg {
                            requires_syscall: LB::Expr::ONE,
                            key: array::from_fn(|i| dec.hasher_state[i].into()),
                            implementation: dec.resolved_digest.map(Into::into),
                        },
                        Deg { v: 4, u: 5 },
                    );
                    // A root CALL restores entry's next principal before this completion.
                    group.remove(
                        "root_completion",
                        flags.end() * root,
                        || LibraryResolveMsg {
                            requires_syscall: LB::Expr::ZERO,
                            key: ctx.next.system.fn_hash.map(Into::into),
                            implementation: array::from_fn(|i| dec.hasher_state[i].into()),
                        },
                        Deg { v: 5, u: 6 },
                    );
                },
                Deg { v: 5, u: 6 },
            );
        },
        Deg { v: 5, u: 6 },
    );
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{
        Felt,
        field::{Field, QuadFelt},
        operations::opcodes,
        utils::RowMajorMatrix,
    };
    use miden_stark::lookup::{Challenges, LookupFractions, LookupMessage, build_lookup_fractions};

    use super::*;
    use crate::vm::constraints::{
        columns::{CoreCols, NUM_CORE_COLS},
        lookup::{
            main_air::{MAIN_COLUMN_SHAPE, MainLookupAir},
            messages::{
                BlockHashMsg, BlockStackMsg, BusId, HasherMsg, MIDEN_MAX_MESSAGE_WIDTH, MemoryMsg,
            },
        },
        op_flags::generate_test_row,
    };

    type Fraction = (Felt, QuadFelt);

    fn challenges() -> Challenges<QuadFelt> {
        Challenges::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        )
    }

    fn word(start: u32) -> [Felt; 4] {
        array::from_fn(|i| Felt::from_u32(start + i as u32))
    }

    fn row(opcode: u8) -> CoreCols<Felt> {
        generate_test_row(opcode.into())
    }

    fn invocation(opcode: u8) -> CoreCols<Felt> {
        let mut local = row(opcode);
        local.decoder.hasher_state[..4].copy_from_slice(&word(101));
        local.decoder.resolved_digest = word(201);
        local
    }

    fn fractions(rows: &[CoreCols<Felt>]) -> LookupFractions<Felt, QuadFelt> {
        let values = rows.iter().flat_map(|row| row.as_slice().iter().copied()).collect();
        let trace = RowMajorMatrix::new(values, NUM_CORE_COLS);
        let result = build_lookup_fractions(&MainLookupAir, &trace, None, &[], &challenges());
        assert_eq!(result.shape(), &[4, 7, 4, 3, 1]);
        for counts in result.counts().as_chunks::<{ MAIN_COLUMN_SHAPE.len() }>().0 {
            assert!(counts.iter().zip(MAIN_COLUMN_SHAPE).all(|(actual, max)| *actual <= max));
        }
        result
    }

    fn at(fractions: &LookupFractions<Felt, QuadFelt>, row: usize, column: usize) -> &[Fraction] {
        let index = row * MAIN_COLUMN_SHAPE.len() + column;
        let offset = fractions.counts()[..index].iter().sum::<usize>();
        &fractions.fractions()[offset..offset + fractions.counts()[index]]
    }

    fn encode<M: LookupMessage<Felt, QuadFelt>>(message: M) -> QuadFelt {
        message.encode(&challenges())
    }

    fn resolve(tag: Felt, key: [Felt; 4], implementation: [Felt; 4]) -> QuadFelt {
        encode(LibraryResolveMsg {
            requires_syscall: tag,
            key,
            implementation,
        })
    }

    fn sum(fractions: &[Fraction]) -> QuadFelt {
        fractions
            .iter()
            .map(|(multiplicity, denominator)| denominator.inverse() * *multiplicity)
            .sum()
    }

    #[test]
    fn each_invocation_demands_its_key_resolved_digest_and_literal_mode() {
        for opcode in
            [opcodes::EXEC, opcodes::CALL, opcodes::SYSCALL, opcodes::DYN, opcodes::DYNCALL]
        {
            let tag = if opcode == opcodes::SYSCALL {
                Felt::ONE
            } else {
                Felt::ZERO
            };
            let rows = [invocation(opcode), row(opcodes::HALT)];
            let actual = fractions(&rows);
            let denominator = resolve(tag, word(101), word(201));
            assert_eq!(at(&actual, 0, 4), &[(-Felt::ONE, denominator)], "opcode {opcode}");
            assert!(at(&actual, 1, 4).is_empty());
            let supply = denominator.inverse();
            assert_eq!(supply + sum(at(&actual, 0, 4)), QuadFelt::ZERO);

            // Keep the authenticated response fixed while mutating the requesting row.
            for lane in 0..4 {
                let mut wrong_key = rows.clone();
                wrong_key[0].decoder.hasher_state[lane] += Felt::ONE;
                assert_ne!(supply + sum(at(&fractions(&wrong_key), 0, 4)), QuadFelt::ZERO);
                let mut wrong_digest = rows.clone();
                wrong_digest[0].decoder.resolved_digest[lane] += Felt::ONE;
                assert_ne!(supply + sum(at(&fractions(&wrong_digest), 0, 4)), QuadFelt::ZERO);
            }
            let wrong_mode_supply = resolve(Felt::ONE - tag, word(101), word(201)).inverse();
            assert_ne!(wrong_mode_supply + sum(at(&actual, 0, 4)), QuadFelt::ZERO);
        }
    }

    #[test]
    fn repeated_cached_binding_still_demands_one_unit_per_invocation() {
        // The second invocation models a binding-cache hit: its trace obligation is identical.
        let rows = [invocation(opcodes::EXEC), invocation(opcodes::EXEC), row(opcodes::HALT)];
        let actual = fractions(&rows);
        let denominator = resolve(Felt::ZERO, word(101), word(201));
        let demand = [at(&actual, 0, 4), at(&actual, 1, 4)].concat();
        assert_eq!(demand, vec![(-Felt::ONE, denominator); 2]);
        let authenticated_supply = denominator.inverse() * Felt::from_u8(2);
        assert_eq!(authenticated_supply + sum(&demand), QuadFelt::ZERO);
        assert_ne!(authenticated_supply + sum(&demand[..1]), QuadFelt::ZERO, "omitted cache hit");
        let doubled = [demand.as_slice(), &demand[..1]].concat();
        assert_ne!(authenticated_supply + sum(&doubled), QuadFelt::ZERO, "doubled demand");
    }

    #[test]
    fn root_completion_uses_restored_next_principal_and_actual_completed_digest() {
        let mut end = row(opcodes::END);
        end.system.fn_hash = word(301);
        end.decoder.hasher_state[..4].copy_from_slice(&word(401));
        end.decoder.hasher_state[6] = Felt::ONE; // The root itself can be a CALL.
        end.decoder.hasher_state[7] = Felt::ONE;
        end.decoder.resolved_digest = word(501); // Never root-completion authority.
        let mut halt = row(opcodes::HALT);
        halt.system.fn_hash = word(601);
        let rows = [end, halt];
        let actual = fractions(&rows);
        let expected = resolve(Felt::ZERO, word(601), word(401));
        assert_eq!(at(&actual, 0, 4), &[(-Felt::ONE, expected)]);
        assert!(at(&actual, 0, 1).is_empty(), "root has no BlockHash removal or seed");
        assert_eq!(at(&actual, 0, 0).len(), 1, "root still pops its caller frame");
        assert_eq!(at(&actual, 0, 2).len(), 1, "root still authenticates its hasher return");
        assert_ne!(expected, resolve(Felt::ZERO, word(301), word(401)));
        assert_ne!(expected, resolve(Felt::ZERO, word(601), word(501)));

        for lane in 0..4 {
            let mut wrong = rows.clone();
            wrong[1].system.fn_hash[lane] += Felt::ONE;
            assert_ne!(expected.inverse() + sum(at(&fractions(&wrong), 0, 4)), QuadFelt::ZERO);
            let mut wrong = rows.clone();
            wrong[0].decoder.hasher_state[lane] += Felt::ONE;
            assert_ne!(expected.inverse() + sum(at(&fractions(&wrong), 0, 4)), QuadFelt::ZERO);
        }
    }

    #[test]
    fn root_completion_requires_exactly_one_demand_against_fixed_unit_library_supply() {
        let mut end = row(opcodes::END);
        end.system.fn_hash = word(601);
        end.decoder.hasher_state[..4].copy_from_slice(&word(401));
        end.decoder.hasher_state[7] = Felt::ONE;
        let mut halt = row(opcodes::HALT);
        halt.system.fn_hash = word(601);

        // Fix the independently authenticated Library response before building Core fractions.
        // Its frequency is one; neither the demand count nor its payload derives this supply.
        let supply = [(Felt::ONE, resolve(Felt::ZERO, word(601), word(401)))];
        let correct = fractions(&[end.clone(), halt.clone()]);
        assert_eq!(sum(&supply) + sum(at(&correct, 0, 4)), QuadFelt::ZERO);

        let mut omitted_end = end.clone();
        omitted_end.decoder.hasher_state[7] = Felt::ZERO;
        let omitted = fractions(&[omitted_end, halt.clone()]);
        assert!(at(&omitted, 0, 4).is_empty());
        assert_ne!(sum(&supply) + sum(at(&omitted, 0, 4)), QuadFelt::ZERO);

        // Exercise two actual root-branch emissions, each with the same fixed K and D.
        // Decoder root-bit/next-HALT constraints independently reject the extra root marker.
        let doubled = fractions(&[end.clone(), end, halt]);
        let demands = [at(&doubled, 0, 4), at(&doubled, 1, 4)].concat();
        assert_eq!(demands.len(), 2);
        assert_ne!(sum(&supply) + sum(&demands), QuadFelt::ZERO);
    }

    #[test]
    fn invocations_register_selected_digest_as_the_executed_child() {
        for opcode in
            [opcodes::EXEC, opcodes::CALL, opcodes::SYSCALL, opcodes::DYN, opcodes::DYNCALL]
        {
            let mut next = row(opcodes::SPAN);
            next.decoder.addr = Felt::from_u8(17);
            let actual = fractions(&[invocation(opcode), next]);
            let expected = encode(BlockHashMsg::Child {
                parent: Felt::from_u8(17),
                child_hash: word(201),
            });
            assert_eq!(at(&actual, 0, 1), &[(Felt::ONE, expected)], "opcode {opcode}");
            assert_ne!(
                expected,
                encode(BlockHashMsg::Child {
                    parent: Felt::from_u8(17),
                    child_hash: word(101)
                })
            );
        }
    }

    #[test]
    fn callee_end_closes_resolved_child_while_root_authenticates_the_invocation_wrapper() {
        let mut invoke = invocation(opcodes::EXEC);
        invoke.decoder.addr = Felt::from_u8(11);
        let mut span = row(opcodes::SPAN);
        span.decoder.addr = Felt::from_u8(17);
        let mut child_end = row(opcodes::END);
        child_end.decoder.addr = Felt::from_u8(31);
        child_end.decoder.hasher_state[..4].copy_from_slice(&word(201));
        let mut root_end = row(opcodes::END);
        root_end.decoder.addr = Felt::from_u8(17);
        root_end.decoder.hasher_state[..4].copy_from_slice(&word(301));
        root_end.decoder.hasher_state[7] = Felt::ONE;
        let mut halt = row(opcodes::HALT);
        halt.system.fn_hash = word(401);
        let rows = [invoke, span, child_end, root_end, halt];
        let actual = fractions(&rows);
        let block_hash_events = [at(&actual, 0, 1), at(&actual, 2, 1), at(&actual, 3, 1)].concat();
        assert_eq!(block_hash_events.len(), 2, "the root wrapper has no BlockHash removal");
        assert_eq!(sum(&block_hash_events), QuadFelt::ZERO);
        assert_eq!(at(&actual, 3, 4), &[(-Felt::ONE, resolve(Felt::ZERO, word(401), word(301)))]);

        let mut wrong_child = rows;
        wrong_child[2].decoder.hasher_state[..4].copy_from_slice(&word(101));
        let wrong = fractions(&wrong_child);
        let events = [at(&wrong, 0, 1), at(&wrong, 2, 1)].concat();
        assert_ne!(sum(&events), QuadFelt::ZERO, "K cannot replace the completed implementation D");
    }

    #[test]
    fn immediate_hashes_commit_key_and_zero_second_word() {
        for opcode in [opcodes::EXEC, opcodes::CALL, opcodes::SYSCALL] {
            let mut local = invocation(opcode);
            // Even malformed helper cells cannot turn the preimage into a D commitment.
            local.decoder.hasher_state[4..].copy_from_slice(&word(701));
            let mut next = row(opcodes::SPAN);
            next.decoder.addr = Felt::from_u8(17);
            let actual = fractions(&[local, next]);
            let input = array::from_fn(|i| if i < 4 { word(101)[i] } else { Felt::ZERO });
            let expected = encode(HasherMsg::control_block(Felt::from_u8(17), &input, opcode));
            assert!(at(&actual, 0, 2).contains(&(-Felt::ONE, expected)), "opcode {opcode}");
        }
    }

    #[test]
    fn dynamic_hashes_are_zero_and_memory_key_uses_pre_invocation_context_and_clock() {
        for opcode in [opcodes::DYN, opcodes::DYNCALL] {
            let mut local = invocation(opcode);
            local.system.ctx = Felt::from_u8(31);
            local.system.clk = Felt::from_u8(37);
            local.stack.top[0] = Felt::from_u8(41);
            let mut next = row(opcodes::SPAN);
            next.decoder.addr = Felt::from_u8(17);
            next.system.ctx = Felt::from_u8(43);
            next.system.clk = Felt::from_u8(47);
            let actual = fractions(&[local, next]);
            let control =
                encode(HasherMsg::control_block(Felt::from_u8(17), &[Felt::ZERO; 8], opcode));
            let memory = encode(MemoryMsg::read_word(
                Felt::from_u8(31),
                Felt::from_u8(41),
                Felt::from_u8(37),
                word(101),
            ));
            assert!(at(&actual, 0, 2).contains(&(-Felt::ONE, control)));
            assert!(at(&actual, 0, 2).contains(&(-Felt::ONE, memory)));
            assert_eq!(at(&actual, 0, 2).len(), if opcode == opcodes::DYNCALL { 3 } else { 2 });
        }
    }

    #[test]
    fn exec_continuation_and_caller_frame_returns_use_distinct_entries() {
        let mut exec = invocation(opcodes::EXEC);
        exec.decoder.addr = Felt::from_u8(11);
        let mut next = row(opcodes::SPAN);
        next.decoder.addr = Felt::from_u8(17);
        let actual = fractions(&[exec, next]);
        let continuation = encode(BlockStackMsg::Continuation {
            block_id: Felt::from_u8(17),
            parent_id: Felt::from_u8(11),
            is_loop: Felt::ZERO,
        });
        assert_eq!(at(&actual, 0, 0), &[(Felt::ONE, continuation)]);

        let mut end = row(opcodes::END);
        end.decoder.addr = Felt::from_u8(17);
        let mut next = row(opcodes::END);
        next.decoder.addr = Felt::from_u8(11);
        let actual = fractions(&[end.clone(), next.clone()]);
        assert_eq!(at(&actual, 0, 0), &[(-Felt::ONE, continuation)]);
        end.decoder.hasher_state[6] = Felt::ONE;
        next.system.fn_hash = word(801);
        let restored = fractions(&[end.clone(), next.clone()]);
        assert_ne!(at(&restored, 0, 0), &[(-Felt::ONE, continuation)]);
        let frame = encode(BlockStackMsg::CallerFrame {
            block_id: Felt::from_u8(17),
            parent_id: Felt::from_u8(11),
            caller_ctx: next.system.ctx,
            caller_stack_depth: next.stack.b0,
            caller_overflow_addr: next.stack.b1,
            caller_fn_hash: word(801),
        });
        assert_eq!(at(&restored, 0, 0), &[(-Felt::ONE, frame)]);
        next.system.fn_hash[0] += Felt::ONE;
        assert_ne!(at(&fractions(&[end, next]), 0, 0), &[(-Felt::ONE, frame)]);
    }
}
