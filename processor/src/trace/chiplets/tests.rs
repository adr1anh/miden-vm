use alloc::vec::Vec;

use miden_air_definitions::vm::trace::{
    CHIPLETS_CLK_COL, CHIPLETS_WIDTH, TRACE_WIDTH,
    chiplets::{
        NUM_BITWISE_SELECTORS, NUM_MEMORY_SELECTORS,
        bitwise::{self, BITWISE_XOR, OP_CYCLE_LEN},
        hasher::{CONTROLLER_ROWS_PER_HASHER_OP, CONTROLLER_TRACE_ALIGNMENT, LINEAR_HASH},
        memory,
    },
};
use miden_core::{
    Felt, ONE, Word, ZERO,
    mast::{BasicBlockNodeBuilder, CallNodeBuilder, MastForest},
    program::{Program, StackInputs},
};

use crate::{
    AdviceInputs, DefaultHost, ExecutionOptions, FastProcessor, KernelDescriptor,
    operation::Operation,
};

type ChipletsTrace = [Vec<Felt>; CHIPLETS_WIDTH];

// HASHER TRACE LENGTH HELPERS
// ================================================================================================

/// Computes the chiplets-side hasher trace length from the number of controller rows.
fn hasher_trace_len(controller_rows: usize) -> usize {
    controller_rows.next_multiple_of(CONTROLLER_TRACE_ALIGNMENT)
}

// TESTS
// ================================================================================================

#[test]
fn hasher_chiplet_trace() {
    // --- single hasher compression with no stack manipulation ---
    // The program is a single basic block containing Compress.
    // This produces:
    //   - 1 span hash controller row
    //   - 1 COMPRESS controller row
    // Total: 2 controller rows padded to the chiplet alignment boundary.
    let stack = [2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
    let operations = vec![Operation::Compress];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, KernelDescriptor::default());

    let controller_rows = 2 * CONTROLLER_ROWS_PER_HASHER_OP; // span hash + Compress
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

    validate_hasher_trace(&chiplets_trace, hasher_len, controller_rows);
}

#[test]
fn bitwise_chiplet_trace() {
    // --- single bitwise operation with no stack manipulation ---
    // This produces: 1 span hash controller row, then 1 bitwise row.
    let stack = [4, 8];
    let operations = vec![Operation::U32xor];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, KernelDescriptor::default());

    let controller_rows = CONTROLLER_ROWS_PER_HASHER_OP; // span hash only
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

    let bitwise_start = library_prefix_len(&chiplets_trace) + hasher_len;
    let bitwise_end = bitwise_start + OP_CYCLE_LEN;
    validate_bitwise_trace(&chiplets_trace, bitwise_start, bitwise_end);
}

#[test]
fn memory_chiplet_trace() {
    // --- single memory operation with no stack manipulation ---
    // This produces: 1 span hash, then 1 memory row.
    let addr = Felt::from_u32(4);
    let stack = [1, 2, 3, 4];
    let operations = vec![Operation::Push(addr), Operation::MStoreW];
    let (chiplets_trace, _trace_len) = build_trace(&stack, operations, KernelDescriptor::default());

    let controller_rows = CONTROLLER_ROWS_PER_HASHER_OP;
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

    let memory_start = library_prefix_len(&chiplets_trace) + hasher_len;
    validate_memory_trace(&chiplets_trace, memory_start, memory_start + 1);
}

#[test]
fn stacked_chiplet_trace() {
    // --- operations in hasher, bitwise, and memory processors ---
    // Operations: U32xor, Push(0), MStoreW, Compress
    // This produces:
    //   - 1 span hash controller row for the basic block
    //   - 1 COMPRESS controller row
    // Total hasher: 2 controller rows padded to the chiplet alignment boundary.
    // Then: 1 bitwise row (U32xor), then 1 memory row (MStoreW)
    let stack = [8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1];
    let ops = vec![
        Operation::U32xor,
        Operation::Push(ZERO),
        Operation::MStoreW,
        Operation::Compress,
    ];
    let kernel = build_kernel();
    let (chiplets_trace, _trace_len) = build_trace(&stack, ops, kernel);

    let controller_rows = 2 * CONTROLLER_ROWS_PER_HASHER_OP; // span hash + Compress
    let hasher_len = hasher_trace_len(controller_rows);
    assert_eq!(hasher_len, CONTROLLER_TRACE_ALIGNMENT);

    // Validate hasher region
    validate_hasher_trace(&chiplets_trace, hasher_len, controller_rows);

    // Memory precedes normal Bitwise in the packed physical layout.
    let memory_start = library_prefix_len(&chiplets_trace) + hasher_len;
    validate_memory_trace(&chiplets_trace, memory_start, memory_start + 1);
    let bitwise_start = memory_start + 1;
    let bitwise_end = bitwise_start + OP_CYCLE_LEN;
    validate_bitwise_trace(&chiplets_trace, bitwise_start, bitwise_end);

    // Kernel descriptors carry no physical authority band. Global padding follows Bitwise.
    let padding_start = bitwise_end;
    let trace_rows = chiplets_trace[0].len();
    validate_padding(&chiplets_trace, padding_start, trace_rows);
}

#[test]
fn regression_trace_build_does_not_panic_when_first_memory_access_clk_is_zero() {
    let processor = FastProcessor::new(StackInputs::default());
    let mut host = DefaultHost::default();

    // A CALL entrypoint records the callee frame pointer write before the processor clock is
    // incremented, so the first memory access is captured at clk = 0.
    let program = {
        let mut forest = MastForest::new();

        let callee = BasicBlockNodeBuilder::new(vec![Operation::Noop])
            .add_to_forest(&mut forest)
            .unwrap();
        forest.make_root(callee);

        let entry = CallNodeBuilder::new(callee).add_to_forest(&mut forest).unwrap();
        forest.make_root(entry);

        Program::with_kernel(forest.into(), entry, KernelDescriptor::default())
    };

    let execution_witness = processor.execute_for_proving_sync(&program, &mut host).unwrap();
    let (vm_witness, _) = execution_witness.into_parts();

    let _trace =
        crate::trace::build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();
}

// HELPER FUNCTIONS
// ================================================================================================

fn build_kernel() -> KernelDescriptor {
    let proc_hash1 = Word::from([1_u32, 0, 1, 0]);
    let proc_hash2 = Word::from([1_u32, 1, 1, 1]);
    KernelDescriptor::new(&[proc_hash1, proc_hash2]).unwrap()
}

fn build_trace(
    stack_inputs: &[u64],
    operations: Vec<Operation>,
    kernel: KernelDescriptor,
) -> (ChipletsTrace, usize) {
    let stack_inputs: Vec<Felt> = stack_inputs.iter().map(|v| Felt::new_unchecked(*v)).collect();
    let processor = FastProcessor::new_with_options(
        StackInputs::new(&stack_inputs).unwrap(),
        AdviceInputs::default(),
        ExecutionOptions::default().with_core_trace_fragment_size(1 << 10).unwrap(),
    )
    .expect("processor advice inputs should fit advice map limits");

    let mut host = DefaultHost::default();
    let program = {
        let mut mast_forest = MastForest::new();
        let basic_block_id =
            BasicBlockNodeBuilder::new(operations).add_to_forest(&mut mast_forest).unwrap();
        mast_forest.make_root(basic_block_id);
        Program::with_kernel(mast_forest.into(), basic_block_id, kernel)
    };

    let execution_witness = processor.execute_for_proving_sync(&program, &mut host).unwrap();
    let (vm_witness, _) = execution_witness.into_parts();
    let trace =
        crate::trace::build_trace(vm_witness, &miden_vm_stark::memory::default_budget()).unwrap();

    let trace_len = trace.get_trace_len();
    (
        trace
            .get_column_range((TRACE_WIDTH - CHIPLETS_WIDTH)..TRACE_WIDTH)
            .try_into()
            .expect("failed to convert vector to array"),
        trace_len,
    )
}

// VALIDATION FUNCTIONS
// ================================================================================================

/// Counts the actual materialized Library prefix, including its mandatory complete PAD pairs.
fn library_prefix_len(trace: &ChipletsTrace) -> usize {
    let prefix = trace[0].iter().take_while(|&&selector| selector == ONE).count();
    assert!(prefix >= 8 && prefix.is_multiple_of(8));
    prefix
}

/// Validates the Controller band after the actual Library prefix.
fn validate_hasher_trace(trace: &ChipletsTrace, expected_len: usize, controller_rows: usize) {
    let prefix = library_prefix_len(trace);
    let s0_col = 2;
    let s1_col = 3;
    let s2_col = 4;
    let controller_padded = hasher_trace_len(controller_rows);
    assert_eq!(expected_len, controller_padded);
    for row in prefix..prefix + controller_padded {
        assert_eq!(trace[0][row], ZERO);
        assert_eq!(trace[1][row], ONE);
    }
    for row in prefix..prefix + controller_rows {
        assert_eq!(trace[s0_col][row], LINEAR_HASH[0]);
    }
    for row in prefix + controller_rows..prefix + controller_padded {
        assert_eq!(trace[s0_col][row], ZERO);
        assert_eq!(trace[s1_col][row], ONE);
        assert_eq!(trace[s2_col][row], ZERO);
        for col in 5..CHIPLETS_WIDTH - 1 {
            assert_eq!(trace[col][row], ZERO, "padding row {row}, col {col} should be zero");
        }
    }
}

/// Validates the bitwise region of the chiplets trace.
///
/// Checks:
/// - Packed section selectors: [0, 0, 0, 1, 1, 0]
/// - Bitwise operation selector = XOR
/// - Columns beyond bitwise trace width + selectors are zero
fn validate_bitwise_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Six selectors precede the thirteen normal Bitwise payload cells.
    let bitwise_used_cols = NUM_BITWISE_SELECTORS + bitwise::TRACE_WIDTH;

    for row in start..end {
        for col in 0..3 {
            assert_eq!(trace[col][row], ZERO);
        }
        assert_eq!(trace[3][row], ONE);
        assert_eq!(trace[4][row], ONE);
        assert_eq!(trace[5][row], ZERO);

        // Internal bitwise operation selector (XOR)
        assert_eq!(BITWISE_XOR, trace[NUM_BITWISE_SELECTORS][row], "bitwise op at row {row}");

        // Columns beyond bitwise trace should be zero (chip_clk excluded; see chip_clk.rs).
        for col in bitwise_used_cols..CHIPLETS_WIDTH - 1 {
            assert_eq!(
                trace[col][row], ZERO,
                "bitwise padding col {col} at row {row} should be zero"
            );
        }
    }
}

/// Validates the memory region of the chiplets trace.
///
/// Checks:
/// - Packed section selectors: [0, 0, 0, 0]
/// - Column beyond memory trace width + selectors is zero
fn validate_memory_trace(trace: &ChipletsTrace, start: usize, end: usize) {
    // Four selectors precede the seventeen compact Memory payload/address-limb cells.
    let memory_used_cols = NUM_MEMORY_SELECTORS + memory::TRACE_WIDTH;

    for row in start..end {
        for col in 0..NUM_MEMORY_SELECTORS {
            assert_eq!(trace[col][row], ZERO);
        }

        // Columns beyond memory trace should be zero (chip_clk excluded; see chip_clk.rs).
        for col in memory_used_cols..CHIPLETS_WIDTH - 1 {
            assert_eq!(
                trace[col][row], ZERO,
                "memory padding col {col} at row {row} should be zero"
            );
        }
    }
}

/// Validates the padding region at the end of the chiplets trace.
///
/// Checks:
/// - Packed global PAD selectors: [0, 0, 0, 1, 1, 1]
/// - payload columns are zero
fn validate_padding(trace: &ChipletsTrace, start: usize, end: usize) {
    for row in start..end {
        for col in 0..3 {
            assert_eq!(ZERO, trace[col][row]);
        }
        for col in 3..6 {
            assert_eq!(ONE, trace[col][row], "padding s{col} at row {row}");
        }
        // chip_clk at CHIPLETS_WIDTH - 1 is non-zero by design.
        for col in 6..CHIPLETS_WIDTH - 1 {
            assert_eq!(ZERO, trace[col][row], "padding data col {col} at row {row} should be zero");
        }
        assert_ne!(ZERO, trace[CHIPLETS_CLK_COL][row], "padding chip_clk at row {row}");
    }
}
