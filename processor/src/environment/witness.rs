use alloc::vec::Vec;
use core::alloc::Layout;

use miden_core::{
    Felt, WORD_SIZE,
    program::{
        EnvNode, EnvNodeError, EnvironmentRoot, ImplementationRoot, Namespace, ProcedureKey,
    },
};

/// Explicit caller limits for authenticating one native environment path.
///
/// These are resource policies, rather than proof-validity or environment-admission rules. No
/// deployment defaults are provided. All limits are checked over the entire candidate before
/// hashing starts or the candidate can become a verified opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpeningLimits {
    /// Maximum number of node preimages in the path, including its root and final Mast.
    pub max_nodes: usize,
    /// Maximum path depth, with the root at depth zero.
    pub max_depth: usize,
    /// Maximum immediate child count of any List on the path.
    pub max_list_children: usize,
    /// Maximum sum of all immediate List child counts on the path, including unselected slots.
    pub max_total_list_children: usize,
    /// Maximum sum of the canonical encoded lengths of all path preimages.
    ///
    /// The native candidate is not a serialized witness; lengths use the existing core node codec.
    pub max_encoded_bytes: usize,
    /// Maximum accounted native heap storage during verification and retention.
    ///
    /// Accounts the candidate path Vec's capacity, every List Vec's capacity, and the largest
    /// sequential List-hashing scratch request. All capacities use their native element layouts.
    /// The caller has already allocated the candidate: this check limits acceptance and subsequent
    /// hashing/retention, not the host's prior allocations. Allocator excess in hash scratch,
    /// allocator metadata, fixed stack storage and process RSS are outside this bound. The reused
    /// core hash APIs determine allocation behavior; this is not a general fallible-allocation
    /// guarantee for upstream hash implementations.
    pub max_storage_bytes: usize,
}

/// A caller-selected resource axis for a native opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpeningResource {
    Nodes,
    Depth,
    ListChildren,
    TotalListChildren,
    EncodedBytes,
    StorageBytes,
}

/// An untrusted native node preimage and the exact slot selected for the next path node.
///
/// Env selects slot zero; Merkle selects zero for left or one for right; List selects an immediate
/// child index. Mast terminates the path and selects no child. Data is never an executable opening
/// or an environment edge. Equal child commitments do not make their selected slots
/// interchangeable.
#[derive(Debug, PartialEq, Eq)]
pub struct OpeningStep {
    pub node: EnvNode,
    pub selected_child: Option<usize>,
}

/// An untrusted native candidate containing exactly one root-to-Mast structural path.
///
/// Each collection supplies all immediate child commitments, while only the selected child's
/// preimage follows in the path. This type defines no serialized witness or host-provider ABI.
#[derive(Debug, PartialEq, Eq)]
pub struct ResolutionWitness {
    pub path: Vec<OpeningStep>,
}

/// A single authenticated path, retaining every exact node preimage and selected child slot.
///
/// Construction is private and the retained preimages are immutable. This authenticates selective
/// membership only; it neither authorizes the root nor establishes global executable-key
/// uniqueness. Future occurrence accounting must preserve structural slots rather than deduplicate
/// by digest.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedOpening {
    environment_root: EnvironmentRoot,
    procedure_key: ProcedureKey,
    path: Vec<OpeningStep>,
}

impl VerifiedOpening {
    /// Returns the exact root against which the path was authenticated.
    pub const fn environment_root(&self) -> EnvironmentRoot {
        self.environment_root
    }

    /// Returns the requested key derived by the final Mast under its inherited namespace.
    pub const fn procedure_key(&self) -> ProcedureKey {
        self.procedure_key
    }

    /// Returns the authenticated preimages in path order, including complete immediate Lists.
    pub fn path(&self) -> &[OpeningStep] {
        &self.path
    }
}

/// An authenticated key's immediate parent namespace and selected implementation commitment.
///
/// No invocation mode is classified here. An actual syscall must separately compare the returned
/// full accumulated namespace with its execution descriptor's authorized kernel namespace. Code
/// availability and proof-system authentication are later obligations.
#[derive(Debug, PartialEq, Eq)]
pub struct ResolvedBinding {
    namespace: Namespace,
    implementation_root: ImplementationRoot,
    opening: VerifiedOpening,
}

impl ResolvedBinding {
    /// Returns the authenticated environment root.
    pub const fn environment_root(&self) -> EnvironmentRoot {
        self.opening.environment_root()
    }

    /// Returns the authenticated callable key.
    pub const fn procedure_key(&self) -> ProcedureKey {
        self.opening.procedure_key()
    }

    /// Returns the full accumulated namespace immediately containing the final Mast.
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Returns the implementation commitment bound by the authenticated Mast.
    pub const fn implementation_root(&self) -> ImplementationRoot {
        self.implementation_root
    }

    /// Returns the immutable path authenticating this binding.
    pub const fn opening(&self) -> &VerifiedOpening {
        &self.opening
    }

    /// Moves the immutable authenticated path into occurrence accounting without cloning it.
    pub(super) fn into_path(self) -> Vec<OpeningStep> {
        self.opening.path
    }
}

/// A native candidate cannot authenticate the requested key within the caller's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpeningError {
    #[error("environment opening {resource:?} limit {limit} is below requested {requested}")]
    LimitExceeded {
        resource: OpeningResource,
        limit: usize,
        requested: usize,
    },
    #[error("environment opening exceeds arithmetic or allocation-layout bounds")]
    LengthOverflow,
    #[error(transparent)]
    Node(#[from] EnvNodeError),
    #[error("environment opening path is empty")]
    EmptyPath,
    #[error("environment opening at depth {depth} does not select a child")]
    MissingChildSelection { depth: usize },
    #[error("environment opening at depth {depth} selects invalid child slot {selected_child}")]
    InvalidChildSelection { depth: usize, selected_child: usize },
    #[error("environment opening at depth {depth} is missing the selected child's preimage")]
    MissingChild { depth: usize },
    #[error("environment Mast at depth {depth} selects a child")]
    UnexpectedChildSelection { depth: usize },
    #[error("environment opening has trailing preimages after the Mast at depth {depth}")]
    TrailingPath { depth: usize },
    #[error("environment Data at depth {depth} cannot resolve an executable key")]
    DataNode { depth: usize },
    #[error(
        "environment opening commitment mismatch at depth {depth}: expected {expected:?}, got {actual:?}"
    )]
    CommitmentMismatch {
        depth: usize,
        expected: EnvironmentRoot,
        actual: EnvironmentRoot,
    },
    #[error("environment opening resolves key {actual:?}, rather than requested key {expected:?}")]
    KeyMismatch {
        expected: ProcedureKey,
        actual: ProcedureKey,
    },
}

impl ResolutionWitness {
    /// Consumes and authenticates one structural path from the initial namespace under `root`.
    ///
    /// Preflight bounds all candidate preimages, List work and retained native capacities before
    /// hashing. Every node commitment is recomputed with the core node implementation. Env extends
    /// the full namespace; collections preserve it. A List's complete immediate commitment vector
    /// is hashed before its selected descendant is considered. The final Mast must derive exactly
    /// `key`, have no selected child and terminate the candidate. No partial binding is returned.
    pub fn verify(
        self,
        root: EnvironmentRoot,
        key: ProcedureKey,
        limits: OpeningLimits,
    ) -> Result<ResolvedBinding, OpeningError> {
        self.preflight(limits)?;

        let mut expected = root;
        let mut namespace = Namespace::initial();
        for (depth, step) in self.path.iter().enumerate() {
            let actual = step.node.commitment()?;
            if actual != expected {
                return Err(OpeningError::CommitmentMismatch { depth, expected, actual });
            }

            let child = match &step.node {
                EnvNode::Env { label, child } => {
                    require_child_slot(step.selected_child, depth, 1)?;
                    namespace = namespace.child(*label);
                    *child
                },
                EnvNode::Merkle { left, right } => {
                    match require_child_slot(step.selected_child, depth, 2)? {
                        0 => *left,
                        _ => *right,
                    }
                },
                EnvNode::List(children) => {
                    children[require_child_slot(step.selected_child, depth, children.len())?]
                },
                EnvNode::Mast { label, implementation } => {
                    if step.selected_child.is_some() {
                        return Err(OpeningError::UnexpectedChildSelection { depth });
                    }
                    if depth + 1 != self.path.len() {
                        return Err(OpeningError::TrailingPath { depth });
                    }
                    let actual_key = namespace.procedure_key(*label);
                    if actual_key != key {
                        return Err(OpeningError::KeyMismatch {
                            expected: key,
                            actual: actual_key,
                        });
                    }
                    return Ok(ResolvedBinding {
                        namespace,
                        implementation_root: *implementation,
                        opening: VerifiedOpening {
                            environment_root: root,
                            procedure_key: key,
                            path: self.path,
                        },
                    });
                },
                EnvNode::Data { .. } => return Err(OpeningError::DataNode { depth }),
            };

            if depth + 1 == self.path.len() {
                return Err(OpeningError::MissingChild { depth });
            }
            expected = child;
        }

        // Preflight rejects an empty path; each nonterminal requires a following preimage.
        unreachable!("a nonempty opening must terminate or reject a missing child")
    }

    fn preflight(&self, limits: OpeningLimits) -> Result<(), OpeningError> {
        let node_count = self.path.len();
        let depth = node_count.checked_sub(1).ok_or(OpeningError::EmptyPath)?;
        check_limit(OpeningResource::Nodes, node_count, limits.max_nodes)?;
        check_limit(OpeningResource::Depth, depth, limits.max_depth)?;

        let mut retained_bytes = array_bytes::<OpeningStep>(self.path.capacity())?;
        check_limit(OpeningResource::StorageBytes, retained_bytes, limits.max_storage_bytes)?;
        let mut encoded_bytes = 0;
        let mut total_list_children = 0;
        let mut max_hash_scratch_bytes = 0;
        for step in &self.path {
            encoded_bytes = checked_add(encoded_bytes, step.node.encoded_len()?)?;
            check_limit(OpeningResource::EncodedBytes, encoded_bytes, limits.max_encoded_bytes)?;
            if let EnvNode::List(children) = &step.node {
                check_limit(
                    OpeningResource::ListChildren,
                    children.len(),
                    limits.max_list_children,
                )?;
                total_list_children = checked_add(total_list_children, children.len())?;
                check_limit(
                    OpeningResource::TotalListChildren,
                    total_list_children,
                    limits.max_total_list_children,
                )?;
                retained_bytes = checked_add(
                    retained_bytes,
                    array_bytes::<EnvironmentRoot>(children.capacity())?,
                )?;
                let hash_elements =
                    children.len().checked_mul(WORD_SIZE).ok_or(OpeningError::LengthOverflow)?;
                max_hash_scratch_bytes =
                    max_hash_scratch_bytes.max(array_bytes::<Felt>(hash_elements)?);
            }
            check_limit(
                OpeningResource::StorageBytes,
                checked_add(retained_bytes, max_hash_scratch_bytes)?,
                limits.max_storage_bytes,
            )?;
        }
        Ok(())
    }
}

fn require_child_slot(
    selected_child: Option<usize>,
    depth: usize,
    child_count: usize,
) -> Result<usize, OpeningError> {
    let selected_child = selected_child.ok_or(OpeningError::MissingChildSelection { depth })?;
    if selected_child >= child_count {
        return Err(OpeningError::InvalidChildSelection { depth, selected_child });
    }
    Ok(selected_child)
}

fn array_bytes<T>(count: usize) -> Result<usize, OpeningError> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| OpeningError::LengthOverflow)
}

fn checked_add(left: usize, right: usize) -> Result<usize, OpeningError> {
    left.checked_add(right).ok_or(OpeningError::LengthOverflow)
}

fn check_limit(
    resource: OpeningResource,
    requested: usize,
    limit: usize,
) -> Result<(), OpeningError> {
    if requested > limit {
        Err(OpeningError::LimitExceeded { resource, limit, requested })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_storage_layouts_reject_unrepresentable_requests_without_allocating() {
        assert_eq!(array_bytes::<OpeningStep>(0), Ok(0));
        assert_eq!(array_bytes::<OpeningStep>(1), Ok(size_of::<OpeningStep>()));
        let max_roots = isize::MAX as usize / size_of::<EnvironmentRoot>();
        assert_eq!(
            array_bytes::<EnvironmentRoot>(max_roots),
            Ok(max_roots * size_of::<EnvironmentRoot>()),
        );
        assert_eq!(
            array_bytes::<EnvironmentRoot>(max_roots + 1),
            Err(OpeningError::LengthOverflow),
        );
        assert_eq!(array_bytes::<Felt>(usize::MAX), Err(OpeningError::LengthOverflow));
        assert_eq!(array_bytes::<OpeningStep>(usize::MAX), Err(OpeningError::LengthOverflow));
    }

    #[test]
    fn checked_aggregate_sizes_reject_overflow() {
        assert_eq!(checked_add(usize::MAX - 1, 1), Ok(usize::MAX));
        assert_eq!(checked_add(usize::MAX, 1), Err(OpeningError::LengthOverflow));
    }
}
