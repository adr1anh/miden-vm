use crate::vm::trace::decoder::{
    NUM_HASHER_COLUMNS, NUM_OP_BITS, NUM_OP_BITS_EXTRA_COLS, NUM_USER_OP_HELPERS,
};

/// Decoder columns in the main execution trace (23 columns).
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct DecoderCols<T> {
    /// Block address (hasher table row pointer).
    pub addr: T,
    /// Opcode bits b0-b6.
    pub op_bits: [T; NUM_OP_BITS],
    /// Hasher state h0-h7 (shared between decoding and MAST node hashing).
    pub hasher_state: [T; NUM_HASHER_COLUMNS],
    /// In-span flag (1 inside a basic block).
    pub in_span: T,
    /// Remaining operation group count, or DYNCALL's saved post-pop overflow pointer.
    pub group_count: T,
    /// Position within operation group (0-8), or the digest mode on an invocation row.
    pub op_index: T,
    /// Boolean flag selecting a full 8-group operation batch.
    pub full_batch: T,
    /// Short-batch code: 1 for 4 groups, -1 for 2 groups, and 0 for 1 group.
    pub batch_size_code: T,
    /// Degree-reduction extra columns e0, e1.
    pub extra: [T; NUM_OP_BITS_EXTRA_COLS],
}

impl<T: Copy> DecoderCols<T> {
    /// Returns whether an invocation uses a digest operand instead of a procedure key.
    pub fn digest_mode(&self) -> T {
        self.op_index
    }

    /// Returns the authenticated implementation overlay on an invocation row.
    /// Other opcodes assign their own meanings to these hasher lanes.
    pub fn resolved_digest(&self) -> [T; 4] {
        [
            self.hasher_state[4],
            self.hasher_state[5],
            self.hasher_state[6],
            self.hasher_state[7],
        ]
    }

    /// Returns the entry key carried by a HALT row.
    pub fn halt_entry_key(&self) -> [T; 4] {
        core::array::from_fn(|i| self.hasher_state[4 + i])
    }

    /// Returns DYNCALL's saved caller overflow pointer after consuming its address operand.
    pub fn dyncall_overflow_addr(&self) -> T {
        self.group_count
    }

    /// Returns the 6 user-op helper registers (hasher_state[2..8]).
    pub fn user_op_helpers(&self) -> [T; NUM_USER_OP_HELPERS] {
        [
            self.hasher_state[2],
            self.hasher_state[3],
            self.hasher_state[4],
            self.hasher_state[5],
            self.hasher_state[6],
            self.hasher_state[7],
        ]
    }

    /// Returns the END flags stored in hasher state columns 4 through 7.
    pub fn end_block_flags(&self) -> EndBlockFlags<T> {
        EndBlockFlags {
            is_loop_body: self.hasher_state[4],
            is_loop: self.hasher_state[5],
            restores_caller_frame: self.hasher_state[6],
            is_root_end: self.hasher_state[7],
        }
    }
}

/// Named overlay for the semantic END flags in `hasher_state[4..8]`.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct EndBlockFlags<T> {
    /// Whether the node that ended is the body of a LOOP node.
    pub is_loop_body: T,
    /// Whether this END closes a LOOP continuation.
    pub is_loop: T,
    /// Whether this END restores state from an authenticated caller-frame entry.
    pub restores_caller_frame: T,
    /// Whether this END enters the terminal HALT suffix.
    pub is_root_end: T,
}
