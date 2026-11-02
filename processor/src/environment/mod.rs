//! Bounded native authentication of individual environment openings.
//!
//! An opening authenticates membership under a caller-selected environment root. Root authority,
//! global executable-key uniqueness, code availability and invocation authorization are separate
//! obligations. This module selects no witness serialization, execution session or proof ledger.

mod witness;

pub use witness::{
    OpeningError, OpeningLimits, OpeningResource, OpeningStep, ResolutionWitness, ResolvedBinding,
    VerifiedOpening,
};

#[cfg(test)]
mod tests;
