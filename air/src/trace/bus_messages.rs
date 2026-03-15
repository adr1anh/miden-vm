//! Shared bus message structs for encoding multiset/LogUp contributions.
//!
//! These types are generic over the field element type, enabling reuse across:
//! - **AIR constraints** (symbolic expressions): e.g. `BitwiseMessage<AB::Expr>`
//! - **Processor aux trace builders** (concrete field elements): e.g. `BitwiseMessage<Felt>`
//!
//! Each struct captures the data fields of a bus message and provides an `encode` method
//! that delegates to [`Challenges::encode`](super::Challenges::encode).

use core::ops::{AddAssign, Mul};

use miden_core::field::PrimeCharacteristicRing;

use super::{Challenges, bus_interactions::{ACE_WIRING_BUS, CHIPLETS_BUS}};

// BITWISE CHIPLET MESSAGE
// ================================================================================================

/// A bitwise chiplet bus message (U32AND / U32XOR).
///
/// Encodes: `bus_prefix[CHIPLETS_BUS] + alpha^1 * label + alpha^2 * a + alpha^3 * b + alpha^4 * z`
pub struct BitwiseMessage<F> {
    pub op_label: F,
    pub a: F,
    pub b: F,
    pub z: F,
}

impl<F: Clone> BitwiseMessage<F> {
    /// Encodes this message against the given challenge set.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(
            CHIPLETS_BUS,
            [self.op_label.clone(), self.a.clone(), self.b.clone(), self.z.clone()],
        )
    }
}

// ACE WIRING BUS MESSAGE
// ================================================================================================

/// An ACE wiring bus message (wire value for the LogUp wiring relation).
///
/// Each wire carries an identifier and a two-element extension field value.
/// The clock cycle (`clk`) and context (`ctx`) are passed to [`encode`](Self::encode)
/// separately since they are constant across all wires within a single circuit evaluation.
///
/// Encodes: `bus_prefix[ACE_WIRING_BUS] + alpha^1 * clk + alpha^2 * ctx
///            + alpha^3 * id + alpha^4 * v0 + alpha^5 * v1`
pub struct AceWireMessage<F> {
    pub id: F,
    pub v0: F,
    pub v1: F,
}

impl<F> AceWireMessage<F> {
    /// Creates an `AceWireMessage` from a `[F; 3]` array of `[id, v0, v1]`.
    pub fn from_array(wire: [F; 3]) -> Self {
        let [id, v0, v1] = wire;
        Self { id, v0, v1 }
    }
}

impl<F: Clone> AceWireMessage<F> {
    /// Encodes this wire message with the given clock and context metadata.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>, clk: F, ctx: F) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(
            ACE_WIRING_BUS,
            [clk, ctx, self.id.clone(), self.v0.clone(), self.v1.clone()],
        )
    }
}
