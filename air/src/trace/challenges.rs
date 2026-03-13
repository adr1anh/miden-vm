//! Unified bus challenge encoding.
//!
//! Provides [`Challenges`], a single struct for encoding multiset/LogUp bus messages
//! with per-bus domain separation. Each message is encoded as:
//! `bus_prefix[BUS] + <alphas, message>`
//!
//! Where:
//! - `bus_prefix[BUS] = beta + BUS` provides unique domain separation per bus interaction type
//! - `alphas[i] = alpha^(i+1)` are the reduction coefficients (skipping 1)
//!
//! This type is used by:
//! - **AIR constraints** (symbolic expressions): `Challenges<AB::ExprEF>`
//! - **Processor aux trace builders** (concrete field elements): `Challenges<E>`
//! - **Verifier** (`reduced_aux_values`): `Challenges<EF>`
//!
//! See [`super::bus_message`] for the standard coefficient index layout.
//! See [`super::bus_interactions`] for the bus interaction type constants.

use core::ops::{AddAssign, Mul};

use miden_core::field::PrimeCharacteristicRing;

use super::{MAX_MESSAGE_WIDTH, bus_interactions::NUM_BUS_INTERACTIONS};

/// Encodes multiset/LogUp contributions as **bus_prefix\[BUS\] + \<alphas, message\>**.
///
/// - `alphas`: precomputed powers `[alpha^1, alpha^2, ..., alpha^MAX_MESSAGE_WIDTH]`
/// - `bus_prefix`: precomputed per-bus domain separation values `[beta+0, beta+1, ..., beta+B]`
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
///
/// Precomputed once and passed by reference to all bus components.
pub struct Challenges<EF: PrimeCharacteristicRing> {
    alphas: [EF; MAX_MESSAGE_WIDTH],
    bus_prefix: [EF; NUM_BUS_INTERACTIONS],
}

impl<EF: PrimeCharacteristicRing> Challenges<EF> {
    /// Builds precomputed `alpha` powers and `bus_prefix` values.
    ///
    /// - `alphas[i] = alpha^(i+1)` for i in 0..MAX_MESSAGE_WIDTH
    /// - `bus_prefix[i] = beta + i` for i in 0..NUM_BUS_INTERACTIONS
    pub fn new(alpha: EF, beta: EF) -> Self {
        let alphas = {
            let mut arr: [EF; MAX_MESSAGE_WIDTH] = core::array::from_fn(|_| EF::ONE);
            arr[0] = alpha.clone();
            for i in 1..MAX_MESSAGE_WIDTH {
                arr[i] = arr[i - 1].clone() * alpha.clone();
            }
            arr
        };
        let bus_prefix = core::array::from_fn(|i| beta.clone() + EF::from_u32(i as u32));
        Self { alphas, bus_prefix }
    }

    /// Encodes as **bus_prefix\[BUS\] + sum(alphas\[i\] * elem\[i\])** with K consecutive elements.
    ///
    /// The `BUS` const generic selects the bus interaction type for domain separation.
    #[inline(always)]
    pub fn encode<const BUS: usize, BF, const K: usize>(&self, elems: [BF; K]) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        const { assert!(K <= MAX_MESSAGE_WIDTH, "Message length exceeds alphas capacity") };
        const { assert!(BUS < NUM_BUS_INTERACTIONS, "Bus index exceeds bus_prefix capacity") };
        let mut acc = self.bus_prefix[BUS].clone();
        for (i, elem) in elems.iter().enumerate() {
            acc += self.alphas[i].clone() * elem.clone();
        }
        acc
    }

    /// Encodes as **bus_prefix\[BUS\] + sum(alphas\[layout\[i\]\] * values\[i\])** using sparse
    /// positions.
    ///
    /// The `BUS` const generic selects the bus interaction type for domain separation.
    #[inline(always)]
    pub fn encode_sparse<const BUS: usize, BF, const K: usize>(
        &self,
        layout: [usize; K],
        values: [BF; K],
    ) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        const { assert!(BUS < NUM_BUS_INTERACTIONS, "Bus index exceeds bus_prefix capacity") };
        let mut acc = self.bus_prefix[BUS].clone();
        for i in 0..K {
            let idx = layout[i];
            debug_assert!(
                idx < self.alphas.len(),
                "encode_sparse index {} exceeds alphas length ({})",
                idx,
                self.alphas.len()
            );
            acc += self.alphas[idx].clone() * values[i].clone();
        }
        acc
    }

    /// Creates a partial message by precomputing the bus prefix plus a subset of alpha-reduced
    /// values.
    ///
    /// Returns a [`PartialMessage`] that can be extended with additional elements via
    /// [`extend`](Self::extend).
    ///
    /// # Example
    /// ```ignore
    /// let partial = challenges.partial::<_, BUS, 2>([0, 1], [label, addr]);
    /// let full = challenges.extend(&partial, [2, 3], [val0, val1]);
    /// ```
    #[inline(always)]
    pub fn partial<const BUS: usize, BF, const M: usize>(
        &self,
        indices: [usize; M],
        values: [BF; M],
    ) -> PartialMessage<EF, M>
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        const { assert!(BUS < NUM_BUS_INTERACTIONS, "Bus index exceeds bus_prefix capacity") };
        let mut acc = self.bus_prefix[BUS].clone();
        for i in 0..M {
            debug_assert!(
                indices[i] < self.alphas.len(),
                "partial index {} exceeds alphas length ({})",
                indices[i],
                self.alphas.len()
            );
            acc += self.alphas[indices[i]].clone() * values[i].clone();
        }
        PartialMessage {
            value: acc,
            used_indices: indices,
        }
    }

    /// Extends a partial message with additional alpha-reduced elements.
    ///
    /// In debug mode, asserts that none of the new indices overlap with previously used indices.
    #[inline(always)]
    pub fn extend<BF, const M: usize, const N: usize>(
        &self,
        partial: &PartialMessage<EF, M>,
        indices: [usize; N],
        values: [BF; N],
    ) -> EF
    where
        EF: Mul<BF, Output = EF> + AddAssign,
        BF: Clone,
    {
        #[cfg(debug_assertions)]
        for new_idx in &indices {
            debug_assert!(
                !partial.used_indices.contains(new_idx),
                "extend index {} overlaps with partial message indices {:?}",
                new_idx,
                partial.used_indices
            );
        }
        let mut acc = partial.value.clone();
        for i in 0..N {
            debug_assert!(
                indices[i] < self.alphas.len(),
                "extend index {} exceeds alphas length ({})",
                indices[i],
                self.alphas.len()
            );
            acc += self.alphas[indices[i]].clone() * values[i].clone();
        }
        acc
    }
}

/// A partially-encoded bus message.
///
/// Stores the accumulated value (bus prefix + partial alpha reduction) and the indices
/// already used, enabling `debug_assert` checks against overlapping indices in
/// [`Challenges::extend`].
pub struct PartialMessage<EF: PrimeCharacteristicRing, const M: usize> {
    value: EF,
    used_indices: [usize; M],
}
