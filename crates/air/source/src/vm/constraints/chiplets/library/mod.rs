//! Scoped Library expressions for the packed Chiplets prefix.
//!
//! The Chiplets MAIN dispatcher supplies the section selector and fixed periodics. Root Mast
//! suppliers use the fixed initial namespace; the paired lookup relation authenticates its root.

pub mod columns;
pub(crate) mod constraints;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing},
};

use self::columns::LibraryCols;
use crate::vm::constraints::utils::BoolNot;

/// Explicit scope and fixed periodic inputs for the packed Library relation.
///
/// `phase` is the fixed period-two column `[0, 1]`; `exit_aligned` is the fixed AEAD
/// phase-seven column. They must come from the caller's periodic columns, never witness cells.
#[derive(Clone)]
pub struct LibraryRowContext<E> {
    pub is_active: E,
    pub next_is_active: E,
    pub phase: E,
    pub exit_aligned: E,
}

/// Cubic indicators for the little-endian kind bits `(k0, k1, k2)`.
///
/// These expressions have no Library or phase scope. They identify codes 0 through 7 as PAD,
/// Merkle, Env, non-root Mast, List start, List continue, empty List, and root Mast, respectively.
/// The scoped entry point enforces Boolean kind bits.
#[derive(Clone)]
pub struct LibraryKindFlags<E> {
    pub is_pad: E,
    pub is_merkle: E,
    pub is_env: E,
    pub is_mast: E,
    pub is_list_start: E,
    pub is_list_continue: E,
    pub is_empty_list: E,
    pub is_root_mast: E,
}

impl<E: PrimeCharacteristicRing> LibraryKindFlags<E> {
    /// Builds unscoped kind indicators from the shared row schema.
    pub fn new<V: Copy + Into<E>>(cols: &LibraryCols<V>) -> Self {
        let [k0, k1, k2]: [E; 3] = cols.k.map(Into::into);
        let not_k0 = k0.not();
        let not_k1 = k1.not();
        let not_k2 = k2.not();

        Self {
            is_pad: not_k0.clone() * not_k1.clone() * not_k2.clone(),
            is_merkle: k0.clone() * not_k1.clone() * not_k2.clone(),
            is_env: not_k0.clone() * k1.clone() * not_k2.clone(),
            is_mast: k0.clone() * k1.clone() * not_k2,
            is_list_start: not_k0.clone() * not_k1.clone() * k2.clone(),
            is_list_continue: k0.clone() * not_k1 * k2.clone(),
            is_empty_list: not_k0 * k1.clone() * k2.clone(),
            is_root_mast: k0 * k1 * k2,
        }
    }
}

/// Library-scoped A/B gates, separate from the cubic kind indicators.
#[derive(Clone)]
pub struct LibraryPhaseFlags<E> {
    /// `S_lib * (1 - library_phase)`.
    pub phase_a: E,
    /// `S_lib * library_phase`.
    pub phase_b: E,
}

impl<E: PrimeCharacteristicRing> LibraryPhaseFlags<E> {
    /// Builds scope from an explicit Library selector and the fixed period-two phase.
    pub fn new(s_lib: E, library_phase: E) -> Self {
        Self {
            phase_a: s_lib.clone() * library_phase.not(),
            phase_b: s_lib * library_phase,
        }
    }

    /// Returns `S_lib * (1 - library_phase) * kind` (degree five for a cubic kind).
    pub fn kind_a(&self, kind: E) -> E {
        self.phase_a.clone() * kind
    }

    /// Returns `S_lib * library_phase * kind` (degree five for a cubic kind).
    pub fn kind_b(&self, kind: E) -> E {
        self.phase_b.clone() * kind
    }
}

// Fixed inverses in the Felt base field, rather than division of symbolic expressions.
const INV_THREE: Felt = Felt::new_unchecked(12_297_829_379_609_722_881);
const INV_SIX: Felt = Felt::new_unchecked(15_372_286_724_512_153_601);

/// Low unit-selection weight: `sigma * (sigma - 2) * (2*sigma - 5) / 3`.
///
/// On valid sigma values, this is the low Boolean weight. Validity is a separate constraint.
pub fn sigma_lo<E: Algebra<Felt>>(sigma: E) -> E {
    sigma.clone() * (sigma.clone() - E::from_u8(2)) * (sigma.double() - E::from_u8(5)) * INV_THREE
}

/// High unit-selection weight: `sigma * (sigma - 1) * (7 - 2*sigma) / 6`.
///
/// On valid sigma values, this is the high Boolean weight. Validity is a separate constraint.
pub fn sigma_hi<E: Algebra<Felt>>(sigma: E) -> E {
    sigma.clone() * (sigma.clone() - E::ONE) * (E::from_u8(7) - sigma.double()) * INV_SIX
}

/// Quartic validity polynomial, zero exactly at selection values 0, 1, 2, and 3 in Felt.
///
/// The scoped Library entry point constrains this under the appropriate kind and phase;
/// evaluating it alone imposes no constraint.
pub fn sigma_validity<E: PrimeCharacteristicRing>(sigma: E) -> E {
    sigma.clone()
        * (sigma.clone() - E::ONE)
        * (sigma.clone() - E::from_u8(2))
        * (sigma - E::from_u8(3))
}

#[cfg(test)]
mod main_tests;
#[cfg(test)]
mod tests;
