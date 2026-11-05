use alloc::{boxed::Box, vec::Vec};

use miden_air_definitions::vm::trace::{RowIndex, chiplets::hasher::HasherState};
use miden_core::{
    Felt, WORD_SIZE, Word, ZERO,
    chiplets::{eidos_compression, hasher::compress_state},
    crypto::merkle::MerklePath,
    deferred::Digest,
    program::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    AdviceProvider, ContextId, ExecutionError, MapExecErr,
    errors::OperationError,
    fast::{FastProcessor, INITIAL_STACK_TOP_IDX, SystemCallState, memory::Memory},
    processor::{HasherInterface, Processor, StackInterface, SystemInterface},
};

/// Only the caller overflow affected by a prepared context switch.
pub(crate) struct PreparedStackContext {
    overflow: Vec<Felt>,
}

/// A return owns any replacement buffer until both saved frames have been checked.
pub(crate) struct PreparedStackRestore {
    overflow_len: usize,
    replacement: Option<Box<[Felt]>>,
}

/// A complete saved system frame, retained until both return components are prepared.
pub(crate) struct PreparedSystemRestore {
    ctx: ContextId,
    caller_hash: Word,
}

impl Processor for FastProcessor {
    type System = Self;
    type Stack = Self;
    type AdviceProvider = AdviceProvider;
    type Memory = Memory;
    type Hasher = Self;

    #[inline(always)]
    fn stack(&self) -> &Self::Stack {
        self
    }

    #[inline(always)]
    fn stack_mut(&mut self) -> &mut Self::Stack {
        self
    }

    #[inline(always)]
    fn advice_provider(&self) -> &Self::AdviceProvider {
        &self.advice
    }

    #[inline(always)]
    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider {
        &mut self.advice
    }

    #[inline(always)]
    fn memory_mut(&mut self) -> &mut Self::Memory {
        &mut self.memory
    }

    #[inline(always)]
    fn hasher(&mut self) -> &mut Self::Hasher {
        self
    }

    #[inline(always)]
    fn system(&self) -> &Self::System {
        self
    }

    #[inline(always)]
    fn system_mut(&mut self) -> &mut Self::System {
        self
    }
}

impl HasherInterface for FastProcessor {
    #[inline(always)]
    fn compress(
        &mut self,
        mut input_state: HasherState,
    ) -> Result<(Felt, HasherState), OperationError> {
        compress_state(&mut input_state);

        // Return a default value for the address, as it is not needed in trace generation.
        Ok((ZERO, input_state))
    }

    #[inline(always)]
    fn compress_aead_xof(
        &mut self,
        _ctx: ContextId,
        _clk: RowIndex,
        state: HasherState,
    ) -> Result<[Felt; 16], OperationError> {
        Ok(eidos_compression::compress_raw_xof_lanes(&state).map(Felt::from_u32))
    }

    #[inline(always)]
    fn verify_merkle_root(
        &mut self,
        claimed_root: Word,
        value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<Felt, OperationError> {
        let path = path.expect("fast processor expects a valid Merkle path");
        match path.verify(index.as_canonical_u64(), value, &claimed_root) {
            // Return a default value for the address, as it is not needed in trace generation.
            Ok(_) => Ok(ZERO),
            Err(_) => Err(on_err()),
        }
    }

    #[inline(always)]
    fn update_merkle_root(
        &mut self,
        claimed_old_root: Word,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<(Felt, Word), OperationError> {
        let path = path.expect("fast processor expects a valid Merkle path");

        // Verify the old value against the claimed old root.
        if path.verify(index.as_canonical_u64(), old_value, &claimed_old_root).is_err() {
            return Err(on_err());
        };

        // Compute the new root.
        let new_root =
            path.compute_root(index.as_canonical_u64(), new_value).map_err(|_| on_err())?;

        Ok((ZERO, new_root))
    }
}

impl SystemInterface for FastProcessor {
    type CallRestore = PreparedSystemRestore;

    #[inline(always)]
    fn caller_hash(&self) -> Word {
        self.caller_hash
    }

    #[inline(always)]
    fn clock(&self) -> RowIndex {
        self.clk
    }

    #[inline(always)]
    fn ctx(&self) -> ContextId {
        self.ctx
    }

    #[inline(always)]
    fn deferred_root(&self) -> Word {
        self.deferred_state.root()
    }

    #[inline(always)]
    fn increment_clock(&mut self) {
        self.clk += 1_u32;
    }

    #[inline(always)]
    fn log_deferred_statement(
        &mut self,
        statement_digest: Digest,
        expected_new_root: Word,
    ) -> Result<(), OperationError> {
        self.deferred_state
            .log_verified_statement(statement_digest, expected_new_root)
            .map(|_| ())
            .map_err(OperationError::from)
    }

    #[inline(always)]
    fn set_caller_hash(&mut self, caller_hash: Word) {
        self.caller_hash = caller_hash;
    }

    #[inline(always)]
    fn set_ctx(&mut self, ctx: ContextId) {
        self.ctx = ctx;
    }

    #[inline(always)]
    fn prepare_save_call_state(&mut self) -> Result<(), ExecutionError> {
        self.system_call_state_stack
            .try_reserve(1)
            .map_err(|_| ExecutionError::Internal("saved system frame allocation failed"))
    }

    fn prepare_restore_call_state(&self) -> Result<Self::CallRestore, OperationError> {
        self.system_call_state_stack
            .last()
            .map(|saved| PreparedSystemRestore {
                ctx: saved.ctx,
                caller_hash: saved.caller_hash,
            })
            .ok_or(OperationError::Internal(
                "system call state stack should never be empty when restoring context",
            ))
    }

    fn restored_caller_hash(prepared: &Self::CallRestore) -> Word {
        prepared.caller_hash
    }

    #[inline(always)]
    fn save_call_state(&mut self) {
        self.system_call_state_stack.push(SystemCallState {
            ctx: self.ctx,
            caller_hash: self.caller_hash,
        });
    }

    #[inline(always)]
    fn commit_restore_call_state(&mut self, prepared: Self::CallRestore) {
        let saved = self
            .system_call_state_stack
            .pop()
            .expect("prepared return retains its saved system frame");
        debug_assert_eq!(saved.ctx, prepared.ctx);
        debug_assert_eq!(saved.caller_hash, prepared.caller_hash);
        self.ctx = prepared.ctx;
        self.caller_hash = prepared.caller_hash;
    }
}

impl StackInterface for FastProcessor {
    type ContextStart = PreparedStackContext;
    type ContextRestore = PreparedStackRestore;
    type StackPop = ();

    #[inline(always)]
    fn top(&self) -> &[Felt] {
        self.stack_top()
    }

    #[inline(always)]
    fn get(&self, idx: usize) -> Felt {
        self.stack_get(idx)
    }

    #[inline(always)]
    fn get_mut(&mut self, idx: usize) -> &mut Felt {
        self.stack_get_mut(idx)
    }

    #[inline(always)]
    fn get_word(&self, start_idx: usize) -> Word {
        self.stack_get_word(start_idx)
    }

    #[inline(always)]
    fn depth(&self) -> u32 {
        self.stack_depth()
    }

    #[inline(always)]
    fn set(&mut self, idx: usize, element: Felt) {
        self.stack_write(idx, element)
    }

    #[inline(always)]
    fn set_word(&mut self, start_idx: usize, word: &Word) {
        self.stack_write_word(start_idx, word);
    }

    #[inline(always)]
    fn swap(&mut self, idx1: usize, idx2: usize) {
        self.stack_swap(idx1, idx2)
    }

    #[inline(always)]
    fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) = self.stack.split_at_mut(self.stack_top_idx - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    #[inline(always)]
    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_top_element = self.stack[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.stack[rotation_bot_index + i] = self.stack[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.stack_write(0, new_stack_top_element);
    }

    #[inline(always)]
    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_bot_element = self.stack[self.stack_top_idx - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.stack[self.stack_top_idx - i] = self.stack[self.stack_top_idx - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.stack[rotation_bot_index] = new_stack_bot_element;
    }

    #[inline(always)]
    fn increment_size(&mut self) -> Result<(), ExecutionError> {
        self.ensure_stack_capacity_for_push()?;
        self.increment_stack_size();
        Ok(())
    }

    #[inline(always)]
    fn decrement_size(&mut self) -> Result<(), OperationError> {
        self.decrement_stack_size();
        Ok(())
    }

    fn preflight_decrement_size(&self) -> Result<(), OperationError> {
        Ok(())
    }

    fn prepare_decrement_size(&self) -> Result<Self::StackPop, OperationError> {
        Ok(())
    }

    fn commit_decrement_size(&mut self, _prepared: Self::StackPop) {
        self.decrement_stack_size();
    }

    fn prepare_start_context(
        &mut self,
        drop_top: bool,
    ) -> Result<Self::ContextStart, ExecutionError> {
        let overflow_len =
            self.stack_size().saturating_sub(MIN_STACK_DEPTH + usize::from(drop_top));
        let depth = self
            .saved_overflow_len
            .checked_add(overflow_len)
            .and_then(|saved| saved.checked_add(MIN_STACK_DEPTH))
            .ok_or(ExecutionError::Internal("aggregate operand stack depth overflow"))?;
        if depth > self.options.max_stack_depth() {
            return Err(ExecutionError::StackDepthLimitExceeded {
                depth,
                max: self.options.max_stack_depth(),
            });
        }
        self.stack_overflow_save_stack
            .try_reserve(1)
            .map_err(|_| ExecutionError::Internal("saved overflow frame allocation failed"))?;
        let mut overflow = Vec::new();
        overflow
            .try_reserve_exact(overflow_len)
            .map_err(|_| ExecutionError::Internal("caller overflow allocation failed"))?;
        overflow.extend_from_slice(&self.stack[range(self.stack_bot_idx, overflow_len)]);
        Ok(PreparedStackContext { overflow })
    }

    fn commit_start_context(&mut self, prepared: Self::ContextStart) {
        let new_bottom = self.stack_top_idx - MIN_STACK_DEPTH;
        debug_assert_eq!(new_bottom - self.stack_bot_idx, prepared.overflow.len());
        self.stack[self.stack_bot_idx..new_bottom].fill(ZERO);
        self.stack_bot_idx = new_bottom;
        self.saved_overflow_len += prepared.overflow.len();
        self.stack_overflow_save_stack.push(prepared.overflow);
    }

    fn prepare_restore_context(&self) -> Result<Self::ContextRestore, ExecutionError> {
        if self.stack_size() != MIN_STACK_DEPTH {
            return Err(OperationError::InvalidStackDepthOnReturn { depth: self.stack_size() })
                .map_exec_err();
        }
        let overflow_len = self
            .stack_overflow_save_stack
            .last()
            .ok_or(ExecutionError::Internal("saved caller overflow frame is missing"))?
            .len();
        let aggregate_depth = self
            .saved_overflow_len
            .checked_add(MIN_STACK_DEPTH)
            .ok_or(ExecutionError::Internal("aggregate operand stack depth overflow"))?;
        if self.saved_overflow_len < overflow_len
            || aggregate_depth > self.options.max_stack_depth()
        {
            return Err(ExecutionError::Internal("saved caller overflow accounting is invalid"));
        }
        let replacement = if overflow_len > self.stack_bot_idx {
            let len = INITIAL_STACK_TOP_IDX
                .checked_add(overflow_len)
                .and_then(|top| top.checked_add(1))
                .ok_or(ExecutionError::Internal("caller stack restoration size overflow"))?;
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(len).map_err(|_| {
                ExecutionError::Internal("caller stack restoration allocation failed")
            })?;
            buffer.resize(len, ZERO);
            Some(buffer.into_boxed_slice())
        } else {
            None
        };
        Ok(PreparedStackRestore { overflow_len, replacement })
    }

    fn commit_restore_context(&mut self, prepared: Self::ContextRestore) {
        debug_assert_eq!(self.stack_size(), MIN_STACK_DEPTH);
        let overflow = self
            .stack_overflow_save_stack
            .pop()
            .expect("prepared return retains its overflow frame");
        debug_assert_eq!(overflow.len(), prepared.overflow_len);
        if let Some(mut buffer) = prepared.replacement {
            let top = INITIAL_STACK_TOP_IDX + prepared.overflow_len;
            let bottom = top - MIN_STACK_DEPTH;
            buffer[bottom..top]
                .copy_from_slice(&self.stack[self.stack_bot_idx..self.stack_top_idx]);
            self.stack = buffer;
            self.stack_bot_idx = bottom;
            self.stack_top_idx = top;
        }
        self.saved_overflow_len -= prepared.overflow_len;
        let bottom = self.stack_bot_idx - prepared.overflow_len;
        self.stack[bottom..self.stack_bot_idx].copy_from_slice(&overflow);
        self.stack_bot_idx = bottom;
    }

    fn restored_context_depth(prepared: &Self::ContextRestore) -> usize {
        MIN_STACK_DEPTH + prepared.overflow_len
    }
}
