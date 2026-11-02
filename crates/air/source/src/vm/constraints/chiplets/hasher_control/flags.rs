//! Semantic row-kind flags for the single-row hasher controller.
//!
//! [`ControllerFlags`] is a pure naming layer over compositions of the hasher-internal
//! sub-selectors `(s0, s1, s2)`. It carries no chiplet-level scope; callers combine these flags
//! with [`ChipletFlags`](super::super::selectors::ChipletFlags).
//!
//! ## Selector encoding
//!
//! | s0   | s1   | s2   | Row type                                              |
//! |------|------|------|-------------------------------------------------------|
//! | 1    | 0    | 0    | Hash start: full Eidos compression input state        |
//! | 0    | 0    | 0    | Hash continuation: full Eidos compression input state |
//! | 1    | 0    | 1    | MP row                                                |
//! | 1    | 1    | 0    | MV row                                                |
//! | 1    | 1    | 1    | MU row                                                |
//! | 0    | 1    | 0    | Padding                                               |
//!
//! The two remaining patterns are invalid.

use miden_core::field::PrimeCharacteristicRing;

use crate::vm::constraints::{chiplets::columns::ControllerCols, utils::BoolNot};

// CONTROLLER FLAGS
// ================================================================================================

/// Named compositions of the controller sub-selectors `(s0, s1, s2)` on the current row.
#[derive(Clone)]
pub struct ControllerFlags<E> {
    pub is_hash: E,
    pub is_invalid: E,
}

impl<E: PrimeCharacteristicRing + Clone> ControllerFlags<E> {
    /// Build all row-kind flags from the current row's sub-selector columns.
    pub fn new<V: Copy + Into<E>>(cols: &ControllerCols<V>) -> Self {
        let s0: E = cols.s0.into();
        let s1: E = cols.s1.into();
        let s2: E = cols.s2.into();
        let is_hash = s1.not() * s2.not();
        let is_invalid = s0.not() * s2;

        Self { is_hash, is_invalid }
    }
}

#[cfg(test)]
mod tests {
    use miden_core::Felt;

    use super::*;

    #[test]
    fn derived_mode_and_row_kinds_cover_all_boolean_patterns() {
        for code in 0_u8..8 {
            let cols = ControllerCols {
                s0: Felt::from_u8(code & 1),
                s1: Felt::from_u8((code >> 1) & 1),
                s2: Felt::from_u8((code >> 2) & 1),
                state: [Felt::ZERO; 12],
                row_data: [Felt::ZERO; 4],
            };
            let flags = ControllerFlags::<Felt>::new(&cols);
            let mode = cols.merkle_or_padding::<Felt>();
            let is_hash = matches!(code, 0 | 1);
            let is_merkle = matches!(code, 3 | 5 | 7);
            let is_padding = code == 2;
            let is_invalid = matches!(code, 4 | 6);
            assert_eq!(flags.is_hash, Felt::from_bool(is_hash), "hash kind {code}");
            assert_eq!(flags.is_invalid, Felt::from_bool(is_invalid), "invalid kind {code}");
            assert_eq!(mode, Felt::from_bool(!is_hash), "derived mode {code}");
            assert_eq!(mode + flags.is_hash, Felt::ONE, "mode/hash complement {code}");
            if !is_invalid {
                assert_eq!(mode, Felt::from_bool(is_merkle || is_padding), "valid row kind {code}");
            }
        }
    }
}
