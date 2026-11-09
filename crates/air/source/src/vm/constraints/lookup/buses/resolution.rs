//! Core messages for authenticated callable bindings.
//!
//! Resolve demands share the opcode-exclusive block-stack column. Each invocation batches its
//! demand with its frame push; each END batches a root-weighted demand with its frame pop.

use core::array;

use miden_core::field::PrimeCharacteristicRing;

use crate::vm::constraints::{decoder::columns::DecoderCols, lookup::messages::LibraryResolveMsg};

/// Invocation messages use a literal syscall tag to keep their denominators linear.
pub(super) fn invocation_message<E, V>(
    decoder: &DecoderCols<V>,
    requires_syscall: E,
) -> LibraryResolveMsg<E>
where
    V: Copy + Into<E>,
{
    LibraryResolveMsg {
        requires_syscall,
        key: array::from_fn(|i| decoder.hasher_state[i].into()),
        implementation: decoder.resolved_digest().map(Into::into),
    }
}

/// Authenticates the completed digest against the public entry key carried by the next HALT.
pub(super) fn root_completion_message<E, V>(
    decoder: &DecoderCols<V>,
    next_decoder: &DecoderCols<V>,
) -> LibraryResolveMsg<E>
where
    E: PrimeCharacteristicRing,
    V: Copy + Into<E>,
{
    LibraryResolveMsg {
        requires_syscall: E::ZERO,
        key: next_decoder.halt_entry_key().map(Into::into),
        implementation: array::from_fn(|i| decoder.hasher_state[i].into()),
    }
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
        local.decoder.hasher_state[4..8].copy_from_slice(&word(201));
        local
    }

    fn fractions(rows: &[CoreCols<Felt>]) -> LookupFractions<Felt, QuadFelt> {
        let values = rows.iter().flat_map(|row| row.as_slice().iter().copied()).collect();
        let trace = RowMajorMatrix::new(values, NUM_CORE_COLS);
        let result = build_lookup_fractions(&MainLookupAir, &trace, None, &[], &challenges());
        assert_eq!(result.shape(), &[4, 7, 4, 3]);
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

    // These fixtures contain invocation, END, and HALT rows. Their shared first column emits
    // the frame interaction first and the optional Resolve demand second.
    fn resolution_at(fractions: &LookupFractions<Felt, QuadFelt>, row: usize) -> &[Fraction] {
        at(fractions, row, 0).get(1..).unwrap_or(&[])
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
            assert_eq!(resolution_at(&actual, 0), &[(-Felt::ONE, denominator)], "opcode {opcode}");
            assert!(resolution_at(&actual, 1).is_empty());
            let supply = denominator.inverse();
            assert_eq!(supply + sum(resolution_at(&actual, 0)), QuadFelt::ZERO);

            // Keep the authenticated response fixed while mutating the requesting row.
            for lane in 0..4 {
                let mut wrong_key = rows.clone();
                wrong_key[0].decoder.hasher_state[lane] += Felt::ONE;
                assert_ne!(supply + sum(resolution_at(&fractions(&wrong_key), 0)), QuadFelt::ZERO);
                let mut wrong_digest = rows.clone();
                wrong_digest[0].decoder.hasher_state[4 + lane] += Felt::ONE;
                assert_ne!(
                    supply + sum(resolution_at(&fractions(&wrong_digest), 0)),
                    QuadFelt::ZERO
                );
            }
            let wrong_mode_supply = resolve(Felt::ONE - tag, word(101), word(201)).inverse();
            assert_ne!(wrong_mode_supply + sum(resolution_at(&actual, 0)), QuadFelt::ZERO);
        }
    }

    #[test]
    fn repeated_cached_binding_still_demands_one_unit_per_invocation() {
        // The second invocation models a binding-cache hit: its trace obligation is identical.
        let rows = [invocation(opcodes::EXEC), invocation(opcodes::EXEC), row(opcodes::HALT)];
        let actual = fractions(&rows);
        let denominator = resolve(Felt::ZERO, word(101), word(201));
        let demand = [resolution_at(&actual, 0), resolution_at(&actual, 1)].concat();
        assert_eq!(demand, vec![(-Felt::ONE, denominator); 2]);
        let authenticated_supply = denominator.inverse() * Felt::from_u8(2);
        assert_eq!(authenticated_supply + sum(&demand), QuadFelt::ZERO);
        assert_ne!(authenticated_supply + sum(&demand[..1]), QuadFelt::ZERO, "omitted cache hit");
        let doubled = [demand.as_slice(), &demand[..1]].concat();
        assert_ne!(authenticated_supply + sum(&doubled), QuadFelt::ZERO, "doubled demand");
    }

    #[test]
    fn digest_invocations_commit_mode_and_execute_without_environment_resolution() {
        for opcode in [opcodes::CALL, opcodes::DYN, opcodes::DYNCALL] {
            let mut local = invocation(opcode);
            local.decoder.op_index = Felt::ONE;
            local.decoder.hasher_state[..4].copy_from_slice(&word(201));
            let mut next = row(opcodes::SPAN);
            next.decoder.addr = Felt::from_u8(17);
            let mut input = [Felt::ZERO; 8];
            if opcode == opcodes::CALL {
                input[..4].copy_from_slice(&word(201));
            }
            input[4] = Felt::ONE;
            let actual = fractions(&[local.clone(), next.clone()]);
            assert_eq!(at(&actual, 0, 0).len(), 1, "caller frame or continuation remains");
            assert!(resolution_at(&actual, 0).is_empty());
            let control = encode(HasherMsg::control_block(next.decoder.addr, &input, opcode));
            assert!(at(&actual, 0, 2).contains(&(-Felt::ONE, control)));
            let child = encode(BlockHashMsg::Child {
                parent: next.decoder.addr,
                child_hash: word(201),
            });
            assert_eq!(at(&actual, 0, 1), &[(Felt::ONE, child)]);

            local.decoder.op_index = Felt::ZERO;
            let keyed = fractions(&[local, next]);
            assert!(!at(&keyed, 0, 2).contains(&(-Felt::ONE, control)));
            assert_eq!(
                resolution_at(&keyed, 0),
                &[(-Felt::ONE, resolve(Felt::ZERO, word(201), word(201)))]
            );
        }
    }

    #[test]
    fn dyncall_batches_resolution_with_the_derived_post_pop_caller_frame() {
        for depth in [16_u32, 17, 20] {
            let mut invoke = invocation(opcodes::DYNCALL);
            invoke.decoder.addr = Felt::from_u32(11);
            invoke.decoder.group_count = if depth > 17 { Felt::from_u32(71) } else { Felt::ZERO };
            invoke.system.ctx = Felt::from_u32(31);
            invoke.system.fn_hash = word(301);
            invoke.stack.b0 = Felt::from_u32(depth);
            invoke.stack.h0 = if depth == 16 {
                Felt::ZERO
            } else {
                Felt::from_u32(depth - 16).inverse()
            };
            let mut next = row(opcodes::SPAN);
            next.decoder.addr = Felt::from_u32(17);
            let frame = encode(BlockStackMsg::CallerFrame {
                block_id: next.decoder.addr,
                parent_id: invoke.decoder.addr,
                caller_ctx: invoke.system.ctx,
                caller_stack_depth: Felt::from_u32(depth - u32::from(depth > 16)),
                caller_overflow_addr: invoke.decoder.group_count,
                caller_fn_hash: invoke.system.fn_hash,
            });
            let binding = resolve(Felt::ZERO, word(101), word(201));
            let rows = [invoke, next];
            let actual = fractions(&rows);
            assert_eq!(at(&actual, 0, 0), &[(Felt::ONE, frame), (-Felt::ONE, binding)]);
            assert_eq!(sum(at(&actual, 0, 0)), frame.inverse() - binding.inverse());

            // The saved pointer and derived depth both belong to the caller frame, while
            // changing either must leave the independently authenticated binding unchanged.
            let mut wrong = rows.clone();
            wrong[0].decoder.group_count += Felt::ONE;
            let changed = fractions(&wrong);
            assert_ne!(at(&changed, 0, 0)[0].1, frame);
            assert_eq!(resolution_at(&changed, 0), &[(-Felt::ONE, binding)]);
            if depth > 16 {
                let mut wrong = rows;
                wrong[0].stack.b0 += Felt::ONE;
                wrong[0].stack.h0 = Felt::from_u32(depth + 1 - 16).inverse();
                assert_ne!(at(&fractions(&wrong), 0, 0)[0].1, frame);
                assert_eq!(resolution_at(&fractions(&wrong), 0), &[(-Felt::ONE, binding)]);
            }
        }
    }

    #[test]
    fn both_end_subtypes_batch_exactly_the_root_weighted_resolution_demand() {
        for caller_frame in [false, true] {
            for root in [false, true] {
                let mut end = row(opcodes::END);
                end.decoder.addr = Felt::from_u32(17);
                end.decoder.hasher_state[..4].copy_from_slice(&word(401));
                end.decoder.hasher_state[6] = Felt::from_bool(caller_frame);
                end.decoder.hasher_state[7] = Felt::from_bool(root);
                let mut next = row(if root { opcodes::HALT } else { opcodes::JOIN });
                next.decoder.addr = Felt::from_u32(11);
                next.system.fn_hash = word(501);
                next.decoder.hasher_state[4..8].copy_from_slice(&word(601));
                let frame = if caller_frame {
                    encode(BlockStackMsg::CallerFrame {
                        block_id: end.decoder.addr,
                        parent_id: next.decoder.addr,
                        caller_ctx: next.system.ctx,
                        caller_stack_depth: next.stack.b0,
                        caller_overflow_addr: next.stack.b1,
                        caller_fn_hash: next.system.fn_hash,
                    })
                } else {
                    encode(BlockStackMsg::Continuation {
                        block_id: end.decoder.addr,
                        parent_id: next.decoder.addr,
                        is_loop: Felt::ZERO,
                    })
                };
                let binding = resolve(Felt::ZERO, word(601), word(401));
                let actual = fractions(&[end, next]);
                let mut expected = vec![(-Felt::ONE, frame)];
                if root {
                    expected.push((-Felt::ONE, binding));
                }
                assert_eq!(at(&actual, 0, 0), expected);
                assert_eq!(
                    sum(at(&actual, 0, 0)),
                    -frame.inverse() - binding.inverse() * Felt::from_bool(root),
                );
            }
        }
    }

    #[test]
    fn root_completion_uses_entry_key_and_actual_completed_digest() {
        let mut end = row(opcodes::END);
        end.system.fn_hash = word(301);
        end.decoder.hasher_state[..4].copy_from_slice(&word(401));
        end.decoder.hasher_state[6] = Felt::ONE; // The root itself can be a CALL.
        end.decoder.hasher_state[7] = Felt::ONE;
        let mut halt = row(opcodes::HALT);
        halt.decoder.hasher_state[4..8].copy_from_slice(&word(601));
        let rows = [end, halt];
        let actual = fractions(&rows);
        let expected = resolve(Felt::ZERO, word(601), word(401));
        assert_eq!(resolution_at(&actual, 0), &[(-Felt::ONE, expected)]);
        assert!(at(&actual, 0, 1).is_empty(), "root has no BlockHash removal or seed");
        assert_eq!(at(&actual, 0, 0).len(), 2, "root pops its frame and resolves completion");
        assert_eq!(at(&actual, 0, 2).len(), 1, "root still authenticates its hasher return");
        assert_ne!(expected, resolve(Felt::ZERO, word(301), word(401)));
        assert_ne!(expected, resolve(Felt::ZERO, word(601), word(501)));

        for lane in 0..4 {
            let mut wrong = rows.clone();
            wrong[1].system.fn_hash[lane] += Felt::ONE;
            assert_eq!(resolution_at(&fractions(&wrong), 0), &[(-Felt::ONE, expected)]);
            wrong[1].decoder.hasher_state[4 + lane] += Felt::ONE;
            assert_ne!(
                expected.inverse() + sum(resolution_at(&fractions(&wrong), 0)),
                QuadFelt::ZERO
            );
            let mut wrong = rows.clone();
            wrong[0].decoder.hasher_state[lane] += Felt::ONE;
            assert_ne!(
                expected.inverse() + sum(resolution_at(&fractions(&wrong), 0)),
                QuadFelt::ZERO
            );
        }
    }

    #[test]
    fn root_completion_requires_exactly_one_demand_against_fixed_unit_library_supply() {
        let mut end = row(opcodes::END);
        end.decoder.hasher_state[..4].copy_from_slice(&word(401));
        end.decoder.hasher_state[7] = Felt::ONE;
        let mut halt = row(opcodes::HALT);
        halt.decoder.hasher_state[4..8].copy_from_slice(&word(601));

        // Fix the independently authenticated Library response before building Core fractions.
        // Its frequency is one; neither the demand count nor its payload derives this supply.
        let supply = [(Felt::ONE, resolve(Felt::ZERO, word(601), word(401)))];
        let correct = fractions(&[end.clone(), halt.clone()]);
        assert_eq!(sum(&supply) + sum(resolution_at(&correct, 0)), QuadFelt::ZERO);

        let mut omitted_end = end.clone();
        omitted_end.decoder.hasher_state[7] = Felt::ZERO;
        let omitted = fractions(&[omitted_end, halt.clone()]);
        assert!(resolution_at(&omitted, 0).is_empty());
        assert_ne!(sum(&supply) + sum(resolution_at(&omitted, 0)), QuadFelt::ZERO);

        // Exercise two actual root-branch emissions, each with the same fixed K and D.
        // Decoder root-bit/next-HALT constraints independently reject the extra root marker.
        let doubled = fractions(&[end.clone(), halt.clone(), end, halt]);
        let demands = [resolution_at(&doubled, 0), resolution_at(&doubled, 2)].concat();
        assert_eq!(demands, vec![(-Felt::ONE, supply[0].1); 2]);
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
        halt.decoder.hasher_state[4..8].copy_from_slice(&word(401));
        let rows = [invoke, span, child_end, root_end, halt];
        let actual = fractions(&rows);
        let block_hash_events = [at(&actual, 0, 1), at(&actual, 2, 1), at(&actual, 3, 1)].concat();
        assert_eq!(block_hash_events.len(), 2, "the root wrapper has no BlockHash removal");
        assert_eq!(sum(&block_hash_events), QuadFelt::ZERO);
        assert_eq!(
            resolution_at(&actual, 3),
            &[(-Felt::ONE, resolve(Felt::ZERO, word(401), word(301)))]
        );

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
            // The overlaid implementation word must not enter the invocation-node hash preimage.
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
        assert_eq!(&at(&actual, 0, 0)[..1], &[(Felt::ONE, continuation)]);

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
