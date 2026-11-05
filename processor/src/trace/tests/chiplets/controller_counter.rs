//! Native Controller placement and address regressions using completed authenticated executions.

use miden_air_definitions::vm::trace::{MIN_TRACE_LEN, chiplets::library::PAD};
use miden_core::{
    Felt, ONE, ZERO,
    mast::{BasicBlockNodeBuilder, MastForest, MastNodeExt},
    operations::Operation,
    program::ImplementationRoot,
};
use rstest::rstest;

use super::super::{build_trace_from_fixture, trace_binding, trace_named_program};
use crate::{RowIndex, test_utils::fixture_code};

/// Balanced Merkle collection paths increase the real Library prefix without adding Controller
/// work. Every case retains the same one-row SPAN operation, its seven Controller padding rows
/// and global PAD. The 64-binding collection has six Merkle openings plus Env and Mast pairs,
/// so its 16 active rows and mandatory PAD pair require a 24-row aligned Library prefix.
#[rstest]
#[case(0, 8, 17)]
#[case(4, 16, 25)]
#[case(63, 24, 33)]
fn controller_counter_is_independent_of_authenticated_library_prefix(
    #[case] additional_bindings: usize,
    #[case] expected_prefix: usize,
    #[case] expected_raw_rows: usize,
) {
    let mut forest = MastForest::new();
    let root = BasicBlockNodeBuilder::new(vec![Operation::Noop])
        .add_to_forest(&mut forest)
        .unwrap();
    forest.make_root(root);
    let implementation = ImplementationRoot::new(forest[root].digest());
    let targets = (0..additional_bindings)
        .map(|index| (trace_binding(&alloc::format!("unused-{index}")), implementation));
    let fixture = trace_named_program(fixture_code(forest.into(), root), targets);
    let trace = build_trace_from_fixture(&fixture, &[]);
    let main = trace.main_trace();

    let prefix = (0..main.chiplets_height())
        .take_while(|&row| main.is_library_row(RowIndex::from(row)))
        .count();
    assert_eq!(prefix, expected_prefix);
    assert!(prefix.is_multiple_of(8));
    assert_eq!(main.chiplet_cols(RowIndex::from(prefix - 1)).library().k, PAD);
    assert_eq!(main.addr(RowIndex::from(0)), ZERO, "absent parent stays absent");
    assert_eq!(main.addr(RowIndex::from(1)), ONE, "Controller row zero encodes as one");

    let controller_end = prefix + 8;
    assert_eq!(controller_end + 1, expected_raw_rows);
    assert_eq!(trace.trace_len_summary().chiplets_rows(), expected_raw_rows);
    assert_eq!(main.chiplets_height(), expected_raw_rows.next_power_of_two().max(MIN_TRACE_LEN));
    assert_eq!(trace.trace_len_summary().padded_heights()[1], MIN_TRACE_LEN);
    for row in 0..main.chiplets_height() {
        let idx = RowIndex::from(row);
        if (prefix..controller_end).contains(&row) {
            assert!(main.is_hash_row(idx));
            assert_eq!(main.chiplet_clk(idx), Felt::from_u32((row - prefix + 1) as u32));
            if row > prefix {
                let ctrl = main.chiplet_cols(idx).controller();
                assert_eq!([ctrl.s0, ctrl.s1, ctrl.s2], [ZERO, ONE, ZERO]);
            }
        } else {
            assert!(!main.is_hash_row(idx), "Controller must not reenter after its band");
            assert_eq!(main.chiplet_clk(idx), ZERO, "non-Controller row {row}");
        }
        if row >= controller_end {
            assert_eq!(
                main.chiplet_cols(idx).chiplet_selectors(),
                [ZERO, ZERO, ZERO, ONE, ONE, ONE]
            );
        }
    }
    for row in 0..main.core_height() {
        assert_eq!(main.clk(RowIndex::from(row)), Felt::from_u32(row as u32));
    }
}
