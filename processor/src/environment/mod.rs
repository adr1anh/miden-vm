//! Bounded native authentication, occurrence accounting and descriptor-scoped resolution.
//!
//! An opening authenticates membership under a caller-selected environment root. Root authority,
//! global executable-key uniqueness, code availability and invocation authorization are separate
//! obligations. The native session stages binding/use publication without changing VM state or
//! selecting witness serialization. Its occurrence ledger retains authenticated topology for later
//! proof construction.

mod ledger;
mod session;
mod witness;

pub use ledger::{
    LedgerCounters, LedgerError, LedgerLimits, LedgerResource, OpeningId, OpeningLedger,
    OpeningOccurrence, OpeningParent, PreparedOpening,
};
pub use session::{
    InvocationTag, InvocationUse, OpeningUseCounts, PreparedEntry, PreparedInvocation,
    PreparedRootEnd, ResolutionSession, SessionBinding, SessionCounters, SessionError,
    SessionLimits, SessionPhase, SessionResource,
};
pub use witness::{
    OpeningError, OpeningLimits, OpeningResource, OpeningStep, ResolutionWitness, ResolvedBinding,
    VerifiedOpening,
};

#[cfg(test)]
mod tests;
