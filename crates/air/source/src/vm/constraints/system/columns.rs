use miden_core::WORD_SIZE;

/// System columns in the main execution trace (6 columns).
///
/// These columns track global execution state: clock cycle, execution context, and
/// the principal key established by entry or the active ordinary call frame.
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct SystemCols<T> {
    /// Clock cycle counter.
    pub clk: T,
    /// Context identifier.
    pub ctx: T,
    /// Principal key, retaining the legacy `fn_hash` column name during migration.
    /// EXEC, DYN and SYSCALL preserve it; CALL and DYNCALL load their requested key.
    pub fn_hash: [T; WORD_SIZE],
}
