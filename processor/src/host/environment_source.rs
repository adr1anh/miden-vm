use alloc::boxed::Box;
use core::error::Error;

use miden_core::program::{EnvironmentRoot, ProcedureKey};

use crate::{OpeningLimits, ResolutionWitness};

/// A request for untrusted evidence resolving one key under a fixed environment root.
///
/// Sources should apply these limits while constructing the candidate. The consumer must
/// independently authenticate it with [`ResolutionWitness::verify`] using the same root, key and
/// limits. Acceptance checks do not bound allocations already made by the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentWitnessRequest {
    pub root: EnvironmentRoot,
    pub key: ProcedureKey,
    pub limits: OpeningLimits,
}

/// A provider failure while retrieving untrusted environment evidence.
pub type EnvironmentSourceError = Box<dyn Error + Send + Sync + 'static>;

/// Supplies bounded native environment witnesses without granting execution authority.
///
/// Code availability, debug metadata and a successful retrieval do not authenticate a binding.
/// Every returned candidate must be independently verified against the requested root and key.
pub trait EnvironmentWitnessSource: Send + Sync {
    /// Retrieves a candidate opening under the request's explicit construction limits.
    ///
    /// `Ok(None)` means evidence is unavailable. It is not authenticated nonmembership and must
    /// never authorize execution by implementation digest or another fallback.
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError>;
}

#[cfg(test)]
mod tests;
