//! Bounded storage and complete occurrence validation for an optional environment builder.

use alloc::vec::Vec;
use core::alloc::Layout;

use super::{EnvNode, EnvNodeError, EnvironmentRoot, ProcedureKey};
use crate::{Felt, WORD_SIZE};

mod validation;
pub use validation::{EnvironmentBinding, ValidatedEnvironment};

/// Explicit resource limits for collecting and validating a complete environment.
///
/// No implicit limits are supplied. Visits, depth and bindings apply when finishing the builder.
/// Limits on submitted nodes and encoded bytes count
/// successful submissions, including identical duplicates, rather than just retained records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentBuildLimits {
    /// Maximum number of successfully submitted nodes, including duplicates.
    pub max_submitted_nodes: usize,
    /// Maximum number of physical node occurrences visited during complete traversal.
    pub max_visits: usize,
    /// Maximum physical path depth during complete traversal, with the selected root at zero.
    pub max_depth: usize,
    /// Maximum immediate child count of any submitted List.
    pub max_list_children: usize,
    /// Maximum sum of encoded preimage lengths of successful submissions.
    pub max_encoded_bytes: usize,
    /// Maximum number of executable bindings emitted during complete traversal.
    pub max_bindings: usize,
    /// Maximum requested/logical heap storage, including temporary input and traversal storage.
    ///
    /// This counts retained List capacities, exact internal Vec requests, List hash scratch,
    /// active flags, retained frame/binding requests and conservative old/new Vec growth requests.
    /// Frame requests remain charged after frames are popped. Allocator-provided excess capacity,
    /// allocator metadata, fixed stack storage and process RSS are outside this bound.
    pub max_storage_bytes: usize,
}

/// A caller-selected resource axis of an environment builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvironmentBuildResource {
    SubmittedNodes,
    Visits,
    Depth,
    ListChildren,
    EncodedBytes,
    Bindings,
    StorageBytes,
}

/// An environment cannot be stored or completely validated within the caller's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnvironmentBuildError {
    #[error("environment builder {resource:?} limit {limit} is below requested {requested}")]
    LimitExceeded {
        resource: EnvironmentBuildResource,
        limit: usize,
        requested: usize,
    },
    #[error("environment builder size exceeds arithmetic or allocation-layout bounds")]
    LengthOverflow,
    #[error("environment builder allocation failed")]
    AllocationFailed,
    #[error(transparent)]
    Node(#[from] EnvNodeError),
    #[error("different environment preimages have the same commitment")]
    CommitmentCollision,
    #[error("environment preimage is missing for {0:?}")]
    MissingPreimage(EnvironmentRoot),
    #[error("environment root is already active on the traversal path: {0:?}")]
    Cycle(EnvironmentRoot),
    #[error("environment contains a duplicate procedure key: {0:?}")]
    DuplicateProcedureKey(ProcedureKey),
}

/// Owned, bounded preimages indexed by internally computed environment commitments.
///
/// Insertion alone does not establish completeness or executable-path uniqueness. Finishing
/// validates these properties locally for the selected root's complete reachable preimages.
/// This grants no root authority, code availability or protocol admission, and is not a required
/// enumeration step for mounting externally admitted fragments at runtime.
///
/// Identical submissions reuse the existing record but consume submission and encoded-byte
/// budgets. Rejected insertions leave records and logical accounting unchanged. Storage limits
/// bound requested/logical heap bytes, not allocator overhead or process memory.
#[derive(Debug)]
pub struct EnvironmentBuilder {
    limits: EnvironmentBuildLimits,
    records: Vec<NodeRecord>,
    submitted_nodes: usize,
    encoded_bytes: usize,
    list_storage_bytes: usize,
    peak_storage_bytes: usize,
}

#[derive(Debug)]
struct NodeRecord {
    root: EnvironmentRoot,
    node: EnvNode,
}

impl EnvironmentBuilder {
    /// Creates an empty builder without allocating or selecting an authoritative root.
    pub const fn new(limits: EnvironmentBuildLimits) -> Self {
        Self {
            limits,
            records: Vec::new(),
            submitted_nodes: 0,
            encoded_bytes: 0,
            list_storage_bytes: 0,
            peak_storage_bytes: 0,
        }
    }

    /// Computes and retains a node's commitment within the explicit caller limits.
    ///
    /// Size, arithmetic, layout and resource checks precede hashing and reservation. List input
    /// capacity is charged even when its length is smaller or its preimage is already retained.
    /// Hash scratch is released before record growth; old and new record requests are both
    /// charged for growth. A bounded equality scan recognizes duplicates before this preflight
    /// so they do not require an unused record-growth allowance.
    /// The equality scan and sorted insertion take linear work in the retained record count;
    /// List comparisons also examine children, bounded by the submitted encoded-byte budget.
    pub fn insert(&mut self, node: EnvNode) -> Result<EnvironmentRoot, EnvironmentBuildError> {
        let encoded_len = node.encoded_len()?;
        let submitted_nodes = checked_add(self.submitted_nodes, 1)?;
        check_limit(
            EnvironmentBuildResource::SubmittedNodes,
            submitted_nodes,
            self.limits.max_submitted_nodes,
        )?;
        let encoded_bytes = checked_add(self.encoded_bytes, encoded_len)?;
        check_limit(
            EnvironmentBuildResource::EncodedBytes,
            encoded_bytes,
            self.limits.max_encoded_bytes,
        )?;

        let (input_storage_bytes, hash_scratch_bytes) = match &node {
            EnvNode::List(children) => {
                check_limit(
                    EnvironmentBuildResource::ListChildren,
                    children.len(),
                    self.limits.max_list_children,
                )?;
                let input_bytes = array_bytes::<EnvironmentRoot>(children.capacity())?;
                (input_bytes, list_hash_scratch_bytes(children.len())?)
            },
            _ => (0, 0),
        };
        let record_bytes = array_bytes::<NodeRecord>(self.records.len())?;
        let retained_and_input =
            checked_add(checked_add(record_bytes, self.list_storage_bytes)?, input_storage_bytes)?;
        let hash_peak = checked_add(retained_and_input, hash_scratch_bytes)?;
        check_limit(
            EnvironmentBuildResource::StorageBytes,
            hash_peak,
            self.limits.max_storage_bytes,
        )?;

        // Equality has bounded work: both record count and immediate List lengths were limited
        // on submission. It allocates nothing and does not accept a caller-provided commitment.
        let duplicate = self.records.iter().any(|record| record.node == node);
        let (list_storage_bytes, storage_peak) = if duplicate {
            (self.list_storage_bytes, hash_peak)
        } else {
            let next_record_count = checked_add(self.records.len(), 1)?;
            let next_record_bytes = array_bytes::<NodeRecord>(next_record_count)?;
            let growth_peak = checked_add(retained_and_input, next_record_bytes)?;
            check_limit(
                EnvironmentBuildResource::StorageBytes,
                growth_peak,
                self.limits.max_storage_bytes,
            )?;
            (
                checked_add(self.list_storage_bytes, input_storage_bytes)?,
                hash_peak.max(growth_peak),
            )
        };

        let root = node.commitment()?;
        match self.records.binary_search_by_key(&root, |record| record.root) {
            Ok(index) => {
                let existing =
                    self.records.get(index).ok_or(EnvironmentBuildError::LengthOverflow)?;
                if existing.node != node {
                    return Err(EnvironmentBuildError::CommitmentCollision);
                }
            },
            Err(index) => {
                // A duplicate preimage necessarily computes the same commitment. No fallible
                // operation follows this reservation, and binary_search supplies a valid index.
                self.records
                    .try_reserve_exact(1)
                    .map_err(|_| EnvironmentBuildError::AllocationFailed)?;
                self.records.insert(index, NodeRecord { root, node });
            },
        }
        self.submitted_nodes = submitted_nodes;
        self.encoded_bytes = encoded_bytes;
        self.list_storage_bytes = list_storage_bytes;
        self.peak_storage_bytes = self.peak_storage_bytes.max(storage_peak);
        Ok(root)
    }

    /// Validates every physical occurrence reachable from the selected root and derives bindings.
    ///
    /// Every reachable environment preimage must have been inserted. Shared subtrees are visited
    /// separately under each inherited namespace; duplicate procedure keys reject even if their
    /// implementation roots agree. DATA values and MAST implementation roots are opaque values,
    /// not environment edges. Validation consumes the builder and returns no partial result.
    ///
    /// This establishes local complete-preimage structure and executable-key uniqueness under the
    /// environment's hash assumptions. It does not authorize the root, provide executable code,
    /// or validate manifests, account ownership or protocol admission.
    pub fn finish(
        self,
        root: EnvironmentRoot,
    ) -> Result<ValidatedEnvironment, EnvironmentBuildError> {
        validation::finish(self, root)
    }

    /// Returns the caller's explicit limits, including the limits for later traversal.
    pub const fn limits(&self) -> &EnvironmentBuildLimits {
        &self.limits
    }

    /// Returns a preimage by its internally computed commitment.
    pub fn get(&self, root: EnvironmentRoot) -> Option<&EnvNode> {
        self.records
            .binary_search_by_key(&root, |record| record.root)
            .ok()
            .and_then(|index| self.records.get(index))
            .map(|record| &record.node)
    }

    /// Returns the number of distinct retained preimages.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no preimages have been retained.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns the number of successful submissions, including duplicates.
    pub const fn submitted_nodes(&self) -> usize {
        self.submitted_nodes
    }

    /// Returns the cumulative encoded bytes of successful submissions, including duplicates.
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    /// Returns retained logical record requests plus retained List capacities.
    ///
    /// Each exact record request targets the next record count. Any excess capacity supplied
    /// by the allocator is excluded, even if a later insertion can reuse that excess.
    pub fn storage_bytes(&self) -> usize {
        // Successful insertion checked both terms and their sum before allocation.
        self.records.len() * size_of::<NodeRecord>() + self.list_storage_bytes
    }

    /// Returns the largest preflighted storage peak of a successful insertion.
    pub const fn peak_storage_bytes(&self) -> usize {
        self.peak_storage_bytes
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, EnvironmentBuildError> {
    left.checked_add(right).ok_or(EnvironmentBuildError::LengthOverflow)
}

fn array_bytes<T>(count: usize) -> Result<usize, EnvironmentBuildError> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| EnvironmentBuildError::LengthOverflow)
}

fn list_hash_scratch_bytes(child_count: usize) -> Result<usize, EnvironmentBuildError> {
    let hash_elements = child_count
        .checked_mul(WORD_SIZE)
        .ok_or(EnvironmentBuildError::LengthOverflow)?;
    array_bytes::<Felt>(hash_elements)
}

fn check_limit(
    resource: EnvironmentBuildResource,
    requested: usize,
    limit: usize,
) -> Result<(), EnvironmentBuildError> {
    if requested > limit {
        Err(EnvironmentBuildError::LimitExceeded { resource, limit, requested })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
