//! Untrusted witness preparation for native binary environment collections.

use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    crypto::{hash::Eidos, merkle::InnerNodeInfo},
    events::EventName,
    program::EnvNode,
};
use miden_processor::{
    ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
};

/// Event emitted after MASM has computed the procedure-leaf commitments in memory.
pub const ENVIRONMENT_BUILD_TREE_EVENT_NAME: EventName =
    EventName::new("miden::core::sys::environment::library::build_tree");

/// Maximum leaf count accepted by the default tree-building handler.
///
/// The cap is checked before allocating or reading the input. It bounds host witness-preparation
/// work; the calling MASM procedure independently enforces the same cap and authenticates the root.
pub const MAX_ENVIRONMENT_TREE_LEAVES: usize = 1 << 16;

/// Prepares the native pair-and-promote tree over the supplied opaque leaf commitments.
///
/// Operand input: `[event_id, leaf_ptr, count, ...]`; the operand stack is unchanged.
/// Advice output: `[CANDIDATE_ROOT, ...]`, consumed as one word by `adv_pushw`.
///
/// Every adjacent pair is merged with [`Eidos::merge`]. An unpaired last node is promoted without
/// padding. The empty collection is the typed empty List root; a singleton is its leaf unchanged.
/// The returned mutations register every native parent in the Merkle store and its exact two-word
/// preimage in the advice map. Leaf preimages are supplied separately by the calling constructors.
///
/// This event is untrusted witness preparation. It does not authenticate memory, leaf labels,
/// callable keys, the candidate root, or tree completeness. MASM must verify every expected leaf
/// at its canonical depth and index, with direct checks for the empty and singleton cases.
///
/// All pointer/count/range checks precede allocation and memory reads. Unwritten memory elements
/// read as zero, matching the VM. Failed preparation returns no partial mutations.
pub fn handle_environment_build_tree(
    process: &ProcessorState,
) -> Result<Vec<AdviceMutation>, EventError> {
    let start_value = process.get_stack_item(1).as_canonical_u64();
    let count_value = process.get_stack_item(2).as_canonical_u64();
    let start = u32::try_from(start_value).map_err(|_| EnvironmentTreeError::NotU32 {
        argument: "leaf pointer",
        value: start_value,
    })?;
    let count = u32::try_from(count_value).map_err(|_| EnvironmentTreeError::NotU32 {
        argument: "leaf count",
        value: count_value,
    })?;
    if count as usize > MAX_ENVIRONMENT_TREE_LEAVES {
        return Err(EnvironmentTreeError::TooManyLeaves {
            count,
            max: MAX_ENVIRONMENT_TREE_LEAVES,
        }
        .into());
    }
    if !start.is_multiple_of(4) {
        return Err(EnvironmentTreeError::UnalignedPointer { start }.into());
    }
    let length = count
        .checked_mul(4)
        .ok_or(EnvironmentTreeError::RangeOverflow { start, count })?;
    start
        .checked_add(length)
        .ok_or(EnvironmentTreeError::RangeOverflow { start, count })?;

    let count = count as usize;
    let mut level = Vec::new();
    level
        .try_reserve_exact(count)
        .map_err(|_| EnvironmentTreeError::AllocationFailed)?;
    for offset in 0..count {
        // The checked total range makes each addition safe, including partially unwritten words.
        let address = start + (offset as u32) * 4;
        level.push(Word::new(core::array::from_fn(|i| {
            process.get_mem_value(process.ctx(), address + i as u32).unwrap_or(Felt::ZERO)
        })));
    }

    let mut parents = Vec::new();
    parents
        .try_reserve_exact(count.saturating_sub(1))
        .map_err(|_| EnvironmentTreeError::AllocationFailed)?;
    let mut map = AdviceMap::default();
    let root = if count == 0 {
        let root = EnvNode::List(Vec::new()).commitment()?.into_word();
        map.insert(root, Vec::<Felt>::new());
        root
    } else {
        // All input leaves are retained in level. Each reduction writes behind unread pairs;
        // only the newly computed prefix survives to the next round.
        while level.len() > 1 {
            let old_len = level.len();
            let pairs = old_len / 2;
            for index in 0..pairs {
                let children = [level[2 * index], level[2 * index + 1]];
                let value = Eidos::merge(&children);
                let payload = Word::words_as_elements(&children);
                match map.get(&value) {
                    Some(existing) if existing.as_ref() != payload => {
                        return Err(
                            EnvironmentTreeError::CommitmentCollision { root: value }.into()
                        );
                    },
                    Some(_) => {},
                    None => {
                        map.insert(value, Arc::<[Felt]>::from(payload));
                    },
                }
                parents.push(InnerNodeInfo {
                    value,
                    left: children[0],
                    right: children[1],
                });
                level[index] = value;
            }
            if old_len % 2 != 0 {
                level[pairs] = level[old_len - 1];
            }
            level.truncate(old_len.div_ceil(2));
        }
        level[0]
    };

    let mut stack = AdviceStack::new();
    stack.append_word(root);
    Ok(vec![
        AdviceMutation::extend_merkle_store(parents),
        AdviceMutation::extend_map(map),
        AdviceMutation::extend_advice_stack(stack),
    ])
}

/// Host-side failures while preparing a bounded environment tree witness.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentTreeError {
    #[error("environment {argument} {value} must fit in u32")]
    NotU32 { argument: &'static str, value: u64 },
    #[error("environment leaf pointer {start} must be word-aligned")]
    UnalignedPointer { start: u32 },
    #[error("environment leaf count {count} exceeds maximum {max}")]
    TooManyLeaves { count: u32, max: usize },
    #[error("environment leaf range starting at {start} with {count} words exceeds u32")]
    RangeOverflow { start: u32, count: u32 },
    #[error("environment tree witness allocation failed")]
    AllocationFailed,
    #[error("different environment parent preimages have the same commitment {root:?}")]
    CommitmentCollision { root: Word },
}
