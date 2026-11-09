use miden_core::WORD_SIZE;

/// System columns in the main execution trace (6 columns).
///
/// These columns track global execution state: clock cycle, execution context, and
/// the implementation digest established by the active ordinary call frame.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SystemCols<T> {
    /// Clock cycle counter.
    pub clk: T,
    /// Context identifier.
    pub ctx: T,
    /// Caller digest. EXEC, DYN and SYSCALL preserve it. CALL and DYNCALL load the selected
    /// digest.
    pub fn_hash: [T; WORD_SIZE],
}
