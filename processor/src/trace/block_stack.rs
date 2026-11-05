use alloc::vec::Vec;

use miden_core::{Felt, Word};

use super::chiplets::layout::LogicalControllerAddress;
use crate::{ContextId, ExecutionError};

// BLOCK STACK
// ================================================================================================

/// Tracks per-block data needed for trace generation that the [`ContinuationStack`] does not
/// carry. Specifically, it stores the hasher chiplet addresses (`addr`, `parent_addr`) assigned
/// during execution, and for CALL/SYSCALL/DYNCALL blocks, the caller's execution context so it
/// can be restored on END.
///
/// [`ContinuationStack`]: crate::continuation_stack::ContinuationStack
#[derive(Debug, Default, Clone)]
pub struct BlockStack {
    blocks: Vec<BlockInfo>,
}

impl BlockStack {
    // STATE ACCESSORS AND MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Reserves a start frame before any transition state is published.
    pub(crate) fn prepare_push(&mut self) -> Result<(), ExecutionError> {
        self.blocks
            .try_reserve(1)
            .map_err(|_| ExecutionError::Internal("block-stack allocation failed"))
    }

    /// Checks an END frame without consuming it.
    pub(crate) fn prepare_pop(&self) -> Result<&BlockInfo, ExecutionError> {
        self.blocks.last().ok_or(ExecutionError::Internal("block stack is empty"))
    }

    /// Pushes a new code block onto the block stack and returns the address of the block's parent.
    ///
    /// The block is identified by its address. For CALL, SYSCALL and DYNCALL blocks, execution
    /// context info must be provided so that the caller's context can be restored on END.
    ///
    /// When the block is later popped (on END), the flags for the trace row are fully reconstructed
    /// from the continuation stack, and hence do not need to be stored in this data structure.
    pub fn push(
        &mut self,
        addr: LogicalControllerAddress,
        ctx_info: Option<ExecutionContextInfo>,
    ) -> LogicalControllerAddress {
        let parent_addr = match self.blocks.last() {
            Some(parent) => parent.addr,
            None => LogicalControllerAddress::ABSENT,
        };

        self.blocks.push(BlockInfo { addr, parent_addr, ctx_info });
        parent_addr
    }

    pub fn pop(&mut self) -> BlockInfo {
        self.blocks.pop().expect("block stack is empty")
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn peek(&self) -> &BlockInfo {
        self.blocks.last().expect("block stack is empty")
    }

    pub fn peek_mut(&mut self) -> &mut BlockInfo {
        self.blocks.last_mut().expect("block stack is empty")
    }
}

// BLOCK INFO
// ================================================================================================

#[derive(Debug, Clone)]
pub struct BlockInfo {
    /// Logical addresses are retained across snapshots and fragment replay.
    pub addr: LogicalControllerAddress,
    pub parent_addr: LogicalControllerAddress,
    pub ctx_info: Option<ExecutionContextInfo>,
}

// EXECUTION CONTEXT INFO
// ================================================================================================

/// Saved caller state carried by CALL, DYNCALL, and SYSCALL block-stack entries.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExecutionContextInfo {
    /// Context ID of the block's parent.
    pub parent_ctx: ContextId,
    /// Hash of the function which initiated execution of the block's parent. If the parent is a
    /// root context, this will be set to [ZERO; 4].
    pub parent_fn_hash: Word,
    /// Address of the caller's top overflow row after consuming DYNCALL's address operand,
    /// or at the current stack position for CALL and SYSCALL.
    pub parent_next_overflow_addr: Felt,
}

impl ExecutionContextInfo {
    pub fn new(
        parent_ctx: ContextId,
        parent_fn_hash: Word,
        parent_next_overflow_addr: Felt,
    ) -> Self {
        Self {
            parent_fn_hash,
            parent_ctx,
            parent_next_overflow_addr,
        }
    }
}
