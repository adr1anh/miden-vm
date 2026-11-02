use core::{
    borrow::{Borrow, BorrowMut},
    mem::{align_of, size_of},
};

use super::columns::LibraryCols;
use crate::vm::{
    constraints::columns::{ChipletCols, NUM_CHIPLETS_COLS},
    trace::{CHIPLETS_CLK_COL, CHIPLETS_WIDTH, chiplets::library::*},
};

#[test]
fn library_layout_matches_shared_chiplet_cells() {
    assert_eq!(TRACE_WIDTH, 22);
    assert_eq!(NUM_CHIPLETS_COLS, 24);
    assert_eq!(CHIPLETS_WIDTH, 24);
    assert_eq!(CHIPLETS_CLK_COL, 23);
    assert_eq!(LIBRARY_COL_RANGE, 1..23);
    assert_eq!(size_of::<LibraryCols<usize>>(), TRACE_WIDTH * size_of::<usize>());
    assert_eq!(size_of::<LibraryCols<Felt>>(), TRACE_WIDTH * size_of::<Felt>());
    assert_eq!(align_of::<LibraryCols<Felt>>(), align_of::<Felt>());

    let row: [usize; CHIPLETS_WIDTH] = core::array::from_fn(|i| i);
    let chiplets: &ChipletCols<usize> = row.as_slice().borrow();
    let cols = chiplets.library();
    assert_eq!(cols.x, [1, 2, 3, 4]);
    assert_eq!(cols.y, [5, 6, 7, 8]);
    assert_eq!(cols.z, [9, 10, 11, 12]);
    assert_eq!(cols.w, [13, 14, 15, 16]);
    assert_eq!(cols.d, 17);
    assert_eq!(cols.a, 18);
    assert_eq!(cols.b, 19);
    assert_eq!(cols.k, [20, 21, 22]);
    assert_eq!(chiplets.chip_clk, 23);

    let direct: &LibraryCols<usize> = row[LIBRARY_COL_RANGE].borrow();
    assert!(core::ptr::eq(cols, direct));
}

#[test]
fn library_mutable_borrow_preserves_selector_and_clock() {
    let mut row = [0_usize; CHIPLETS_WIDTH];
    row[0] = 999;
    row[CHIPLETS_CLK_COL] = 888;
    {
        let cols: &mut LibraryCols<usize> = row[LIBRARY_COL_RANGE].borrow_mut();
        cols.x = [101, 102, 103, 104];
        cols.y = [105, 106, 107, 108];
        cols.z = [109, 110, 111, 112];
        cols.w = [113, 114, 115, 116];
        cols.d = 117;
        cols.a = 118;
        cols.b = 119;
        cols.k = [120, 121, 122];
    }

    let expected: [usize; TRACE_WIDTH] = core::array::from_fn(|i| 101 + i);
    assert_eq!(&row[LIBRARY_COL_RANGE], expected.as_slice());
    assert_eq!(row[0], 999);
    assert_eq!(row[CHIPLETS_CLK_COL], 888);
    let chiplets: &ChipletCols<usize> = row.as_slice().borrow();
    assert_eq!(chiplets.library().k, [120, 121, 122]);
    assert_eq!(chiplets.chip_clk, 888);
}
