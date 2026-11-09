//! Occurrence-based accumulation of authenticated environment paths.
//!
//! This is native witness bookkeeping. It does not authorize an environment root, establish
//! global binding uniqueness, classify invocations, or complete the Library proof relation.

use alloc::vec::Vec;
use core::alloc::Layout;

use miden_core::program::{EnvNode, EnvNodeError, EnvironmentRoot, Namespace};

use super::{OpeningStep, ResolvedBinding};
use crate::trace::limits::MAX_TRACE_LEN;

/// Explicit finite resource policies for one occurrence ledger. No deployment defaults exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerLimits {
    pub max_occurrences: usize,
    /// Sum of complete immediate List payload lengths, including unselected child commitments.
    pub max_total_list_children: usize,
    /// Sum of canonical node encoding lengths, counted once per retained occurrence.
    pub max_encoded_bytes: usize,
    /// Logical Library rows before prefix padding, controller interning or combined-trace layout.
    pub max_library_rows: usize,
    /// Compression requests before any later sharing of identical controller work.
    pub max_compression_requests: usize,
    /// Native retained Vec capacities, using the layouts of their element types.
    pub max_retained_bytes: usize,
    /// Peak requested native storage while preparing a merge.
    ///
    /// Includes the old ledger, the consumed input path and complete List capacities, staged
    /// occurrences and slot arrays, and the old/new top-level buffer overlap on growth. Requests
    /// are checked before reservation; returned capacities are checked again before publication.
    /// Allocator metadata, allocation excess beyond a request, fixed stack storage and process
    /// RSS are excluded. This does not bound allocations made by the caller before preparation.
    pub max_peak_bytes: usize,
}

/// A caller-limited resource of an occurrence ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerResource {
    Occurrences,
    TotalListChildren,
    EncodedBytes,
    LibraryRows,
    CompressionRequests,
    RetainedBytes,
    PeakBytes,
}

/// Checked totals for the published ledger, with no invocation-use frequencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerCounters {
    pub occurrences: usize,
    pub total_list_children: usize,
    pub encoded_bytes: usize,
    /// Pre-padding rows: two per Env/Merkle/Mast, and twice max(1, ceil(n/2)) per List.
    pub library_rows: usize,
    /// Requests: two per Env or child Mast, one per Merkle or root Mast, and max(1, ceil(n/2))
    /// per List.
    ///
    /// This is not a count of distinct controller records or actual controller cycles.
    pub compression_requests: usize,
    /// Sum of published occurrence, complete List and selected-slot Vec capacities.
    pub retained_bytes: usize,
}

impl LedgerCounters {
    /// Exactly one public root seed is needed once the root occurrence is materialized.
    pub const fn root_seed_count(self) -> usize {
        if self.occurrences == 0 { 0 } else { 1 }
    }

    /// Every nonroot occurrence has one unit incoming Open from its parent slot.
    pub const fn selected_edge_count(self) -> usize {
        self.occurrences.saturating_sub(1)
    }
}

/// An opaque identity local to one ledger's occurrence tree.
///
/// Identity is the root, or a parent occurrence and its structural child slot. Equal commitments,
/// namespaces and depths never merge distinct slots. This handle grants no authority and is not
/// a transferable preparation token; inspecting it against another ledger has no defined identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpeningId(usize);

impl OpeningId {
    pub const fn index(self) -> usize {
        self.0
    }
}

/// The unique incoming unit edge of a nonroot occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpeningParent {
    opening: OpeningId,
    child_slot: usize,
}

impl OpeningParent {
    pub const fn opening(self) -> OpeningId {
        self.opening
    }

    pub const fn child_slot(self) -> usize {
        self.child_slot
    }
}

/// A retained canonical preimage at one exact position in the opening tree.
#[derive(Debug, PartialEq, Eq)]
pub struct OpeningOccurrence {
    parent: Option<OpeningParent>,
    depth: usize,
    commitment: EnvironmentRoot,
    namespace: Namespace,
    node: EnvNode,
    selected_children: Vec<Option<OpeningId>>,
}

impl OpeningOccurrence {
    pub const fn parent(&self) -> Option<OpeningParent> {
        self.parent
    }

    /// Actual structural path length from the unique root at depth zero.
    pub const fn depth(&self) -> usize {
        self.depth
    }

    pub const fn commitment(&self) -> EnvironmentRoot {
        self.commitment
    }

    /// Full inherited namespace before this node's own Env extension, if any.
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Complete canonical preimage, including every immediate List commitment.
    pub const fn node(&self) -> &EnvNode {
        &self.node
    }

    /// Structural slots in order; Some denotes one selected unit edge, never a use frequency.
    pub fn selected_children(&self) -> &[Option<OpeningId>] {
        &self.selected_children
    }
}

/// An authenticated path cannot be merged within this ledger's provenance and resource bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    #[error("opening ledger expects root {expected:?}, rather than {actual:?}")]
    WrongRoot {
        expected: EnvironmentRoot,
        actual: EnvironmentRoot,
    },
    #[error("opening ledger has inconsistent preimages or provenance at depth {depth}")]
    InconsistentOccurrence { depth: usize },
    #[error("opening ledger exceeds arithmetic or allocation-layout bounds")]
    LengthOverflow,
    #[error("opening ledger native allocation failed")]
    AllocationFailed,
    #[error(transparent)]
    Node(#[from] EnvNodeError),
    #[error("opening ledger {resource:?} limit {limit} is below requested {requested}")]
    LimitExceeded {
        resource: LedgerResource,
        limit: usize,
        requested: usize,
    },
    #[error("logical Library rows {requested} exceed the necessary trace-row ceiling")]
    TraceRowLimitExceeded { requested: usize },
}

/// One caller-selected root and its accumulated occurrence tree.
#[derive(Debug)]
pub struct OpeningLedger {
    expected_root: EnvironmentRoot,
    limits: LedgerLimits,
    counters: LedgerCounters,
    occurrences: Vec<OpeningOccurrence>,
}

impl OpeningLedger {
    pub const fn new(expected_root: EnvironmentRoot, limits: LedgerLimits) -> Self {
        Self {
            expected_root,
            limits,
            counters: LedgerCounters {
                occurrences: 0,
                total_list_children: 0,
                encoded_bytes: 0,
                library_rows: 0,
                compression_requests: 0,
                retained_bytes: 0,
            },
            occurrences: Vec::new(),
        }
    }

    pub const fn expected_root(&self) -> EnvironmentRoot {
        self.expected_root
    }

    pub const fn limits(&self) -> LedgerLimits {
        self.limits
    }

    pub const fn counters(&self) -> LedgerCounters {
        self.counters
    }

    pub fn root(&self) -> Option<OpeningId> {
        if self.occurrences.is_empty() {
            None
        } else {
            Some(OpeningId(0))
        }
    }

    pub fn occurrences(&self) -> &[OpeningOccurrence] {
        &self.occurrences
    }

    pub fn occurrence(&self, opening: OpeningId) -> Option<&OpeningOccurrence> {
        self.occurrences.get(opening.0)
    }

    /// Stages an authenticated path without changing any published occurrence or counter.
    ///
    /// Exact shared prefixes are reused; the first unselected slot starts a fresh suffix. The
    /// binding is consumed so its complete List buffers can move without hidden cloning. All
    /// fallible checks and native reservations finish before a guard is returned. Dropping a
    /// guard discards its staging. Its exclusive borrow prevents use against another or stale
    /// ledger; it does not prescribe a runtime session, host-loading or transition lifecycle.
    ///
    /// The intrinsic logical-row ceiling is necessary but insufficient for proof admission:
    /// packed prefix padding, combined Chiplets height and final no-wrap/degree gates remain
    /// obligations of the later trace implementation.
    pub fn prepare(
        &mut self,
        binding: ResolvedBinding,
    ) -> Result<PreparedOpening<'_>, LedgerError> {
        self.prepare_with_peak_limit(binding, self.limits.max_peak_bytes)
    }

    /// Composes a parent's simultaneous-storage budget without changing this ledger's policy.
    pub(super) fn prepare_with_peak_limit(
        &mut self,
        binding: ResolvedBinding,
        max_peak_bytes: usize,
    ) -> Result<PreparedOpening<'_>, LedgerError> {
        if binding.environment_root() != self.expected_root {
            return Err(LedgerError::WrongRoot {
                expected: self.expected_root,
                actual: binding.environment_root(),
            });
        }
        let terminal_namespace = binding.namespace();
        let path = binding.into_path();
        let prefix = self.shared_prefix(&path)?;
        let plan = self.plan(&path, path.capacity(), &prefix, terminal_namespace)?;
        self.check_preparation_storage(
            &plan,
            plan.new_occurrences,
            plan.replacement_capacity,
            plan.slot_bytes,
            max_peak_bytes,
        )?;

        // These are independent staging buffers: reserving them never changes the ledger.
        let mut staged = reserve_vec::<OpeningOccurrence>(plan.new_occurrences)?;
        self.check_preparation_storage(
            &plan,
            staged.capacity(),
            plan.replacement_capacity,
            plan.slot_bytes,
            max_peak_bytes,
        )?;
        let replacement = match plan.replacement_capacity {
            Some(capacity) => Some(reserve_vec::<OpeningOccurrence>(capacity)?),
            None => None,
        };
        let replacement_capacity = replacement.as_ref().map(Vec::capacity);
        self.check_preparation_storage(
            &plan,
            staged.capacity(),
            replacement_capacity,
            plan.slot_bytes,
            max_peak_bytes,
        )?;

        let first_new = self.occurrences.len();
        let mut parent = prefix.parent;
        let mut namespace = prefix.namespace;
        let mut commitment = prefix.commitment;
        let mut actual_slot_bytes = 0;
        let mut remaining_slot_bytes = plan.slot_bytes;
        for (depth, step) in path.into_iter().enumerate().skip(prefix.shared) {
            let slot_count = child_count(&step.node);
            let requested_slots = array_bytes::<Option<OpeningId>>(slot_count)?;
            let mut selected_children = reserve_vec::<Option<OpeningId>>(slot_count)?;
            actual_slot_bytes = checked_add(
                actual_slot_bytes,
                array_bytes::<Option<OpeningId>>(selected_children.capacity())?,
            )?;
            remaining_slot_bytes = remaining_slot_bytes
                .checked_sub(requested_slots)
                .ok_or(LedgerError::LengthOverflow)?;
            self.check_preparation_storage(
                &plan,
                staged.capacity(),
                replacement_capacity,
                checked_add(actual_slot_bytes, remaining_slot_bytes)?,
                max_peak_bytes,
            )?;
            selected_children.resize(slot_count, None);

            let id = OpeningId(checked_add(first_new, staged.len())?);
            let next = match step.selected_child {
                Some(slot) => {
                    let next_commitment = child_commitment(&step.node, slot, depth)?;
                    let next_namespace = child_namespace(namespace, &step.node);
                    selected_children[slot] = Some(OpeningId(checked_add(id.0, 1)?));
                    Some((slot, next_commitment, next_namespace))
                },
                None => {
                    if !matches!(step.node, EnvNode::Mast { .. }) || namespace != terminal_namespace
                    {
                        return Err(LedgerError::InconsistentOccurrence { depth });
                    }
                    None
                },
            };
            staged.push(OpeningOccurrence {
                parent,
                depth,
                commitment,
                namespace,
                node: step.node,
                selected_children,
            });
            if let Some((slot, next_commitment, next_namespace)) = next {
                parent = Some(OpeningParent { opening: id, child_slot: slot });
                commitment = next_commitment;
                namespace = next_namespace;
            }
        }

        let (retained_bytes, requested_peak_bytes) = self.check_preparation_storage(
            &plan,
            staged.capacity(),
            replacement_capacity,
            actual_slot_bytes,
            max_peak_bytes,
        )?;
        let mut counters = plan.counters;
        counters.retained_bytes = retained_bytes;
        let opening_id = if staged.is_empty() {
            prefix.terminal.ok_or(LedgerError::InconsistentOccurrence { depth: 0 })?
        } else {
            OpeningId(counters.occurrences - 1)
        };
        let selected_edge = if staged.is_empty() {
            None
        } else {
            prefix.parent.map(|parent| (parent, OpeningId(first_new)))
        };
        Ok(PreparedOpening {
            ledger: self,
            staged,
            replacement,
            selected_edge,
            counters,
            opening_id,
            requested_peak_bytes,
        })
    }

    fn shared_prefix(&self, path: &[OpeningStep]) -> Result<SharedPrefix, LedgerError> {
        if path.is_empty() {
            return Err(LedgerError::InconsistentOccurrence { depth: 0 });
        }
        let mut prefix = SharedPrefix {
            shared: 0,
            parent: None,
            namespace: Namespace::initial(),
            commitment: self.expected_root,
            terminal: None,
        };
        let mut existing = self.root();
        for (depth, step) in path.iter().enumerate() {
            let Some(id) = existing else { break };
            let occurrence =
                self.occurrence(id).ok_or(LedgerError::InconsistentOccurrence { depth })?;
            if occurrence.parent != prefix.parent
                || occurrence.depth != depth
                || occurrence.namespace != prefix.namespace
                || occurrence.commitment != prefix.commitment
                || occurrence.node != step.node
                || occurrence.selected_children.len() != child_count(&step.node)
            {
                return Err(LedgerError::InconsistentOccurrence { depth });
            }
            prefix.shared += 1;
            if depth + 1 == path.len() {
                if step.selected_child.is_some() || !matches!(step.node, EnvNode::Mast { .. }) {
                    return Err(LedgerError::InconsistentOccurrence { depth });
                }
                prefix.terminal = Some(id);
                break;
            }
            let slot = step.selected_child.ok_or(LedgerError::InconsistentOccurrence { depth })?;
            prefix.commitment = child_commitment(&step.node, slot, depth)?;
            prefix.namespace = child_namespace(prefix.namespace, &step.node);
            prefix.parent = Some(OpeningParent { opening: id, child_slot: slot });
            existing = occurrence.selected_children[slot];
        }
        Ok(prefix)
    }

    fn plan(
        &self,
        path: &[OpeningStep],
        path_capacity: usize,
        prefix: &SharedPrefix,
        terminal_namespace: Namespace,
    ) -> Result<MergePlan, LedgerError> {
        let new_occurrences = path.len() - prefix.shared;
        let mut counters = self.counters;
        counters.occurrences = checked_add(counters.occurrences, new_occurrences)?;
        check_limit(
            LedgerResource::Occurrences,
            counters.occurrences,
            self.limits.max_occurrences,
        )?;
        let mut input_bytes = array_bytes::<OpeningStep>(path_capacity)?;
        for step in path {
            input_bytes = checked_add(input_bytes, list_storage_bytes(&step.node)?)?;
        }
        let mut new_list_bytes = 0;
        let mut slot_bytes = 0;
        for (depth, step) in path.iter().enumerate().skip(prefix.shared) {
            let (rows, requests) = logical_cost(&step.node, depth, terminal_namespace)?;
            counters.encoded_bytes = checked_add(counters.encoded_bytes, step.node.encoded_len()?)?;
            counters.library_rows = checked_add(counters.library_rows, rows)?;
            counters.compression_requests = checked_add(counters.compression_requests, requests)?;
            if let EnvNode::List(children) = &step.node {
                counters.total_list_children =
                    checked_add(counters.total_list_children, children.len())?;
            }
            new_list_bytes = checked_add(new_list_bytes, list_storage_bytes(&step.node)?)?;
            slot_bytes = checked_add(
                slot_bytes,
                array_bytes::<Option<OpeningId>>(child_count(&step.node))?,
            )?;
        }
        check_trace_rows(counters.library_rows)?;
        for (resource, requested, limit) in [
            (
                LedgerResource::TotalListChildren,
                counters.total_list_children,
                self.limits.max_total_list_children,
            ),
            (
                LedgerResource::EncodedBytes,
                counters.encoded_bytes,
                self.limits.max_encoded_bytes,
            ),
            (LedgerResource::LibraryRows, counters.library_rows, self.limits.max_library_rows),
            (
                LedgerResource::CompressionRequests,
                counters.compression_requests,
                self.limits.max_compression_requests,
            ),
        ] {
            check_limit(resource, requested, limit)?;
        }
        let replacement_capacity = if counters.occurrences > self.occurrences.capacity() {
            Some(counters.occurrences)
        } else {
            None
        };
        let plan = MergePlan {
            new_occurrences,
            counters,
            input_bytes,
            new_list_bytes,
            slot_bytes,
            replacement_capacity,
        };
        self.check_storage(&plan, new_occurrences, replacement_capacity, slot_bytes)?;
        Ok(plan)
    }

    fn check_storage(
        &self,
        plan: &MergePlan,
        staged_capacity: usize,
        replacement_capacity: Option<usize>,
        slot_bytes: usize,
    ) -> Result<(usize, usize), LedgerError> {
        let old_buffer = array_bytes::<OpeningOccurrence>(self.occurrences.capacity())?;
        let retained_buffer = array_bytes::<OpeningOccurrence>(
            replacement_capacity.unwrap_or(self.occurrences.capacity()),
        )?;
        let retained_base = self
            .counters
            .retained_bytes
            .checked_sub(old_buffer)
            .ok_or(LedgerError::LengthOverflow)?;
        let retained_bytes = checked_add(
            checked_add(checked_add(retained_base, retained_buffer)?, plan.new_list_bytes)?,
            slot_bytes,
        )?;
        let replacement_bytes = match replacement_capacity {
            Some(capacity) => array_bytes::<OpeningOccurrence>(capacity)?,
            None => 0,
        };
        let peak_bytes = checked_add(
            checked_add(
                checked_add(
                    checked_add(self.counters.retained_bytes, plan.input_bytes)?,
                    array_bytes::<OpeningOccurrence>(staged_capacity)?,
                )?,
                replacement_bytes,
            )?,
            slot_bytes,
        )?;
        check_limit(LedgerResource::RetainedBytes, retained_bytes, self.limits.max_retained_bytes)?;
        check_limit(LedgerResource::PeakBytes, peak_bytes, self.limits.max_peak_bytes)?;
        Ok((retained_bytes, peak_bytes))
    }

    fn check_preparation_storage(
        &self,
        plan: &MergePlan,
        staged_capacity: usize,
        replacement_capacity: Option<usize>,
        slot_bytes: usize,
        max_peak_bytes: usize,
    ) -> Result<(usize, usize), LedgerError> {
        let storage =
            self.check_storage(plan, staged_capacity, replacement_capacity, slot_bytes)?;
        check_limit(
            LedgerResource::PeakBytes,
            storage.1,
            self.limits.max_peak_bytes.min(max_peak_bytes),
        )?;
        Ok(storage)
    }
}

/// A short-lived, non-Clone merge guard tied exclusively to its original ledger.
///
/// Drop leaves that ledger unchanged. Commit publishes only already-validated, reserved state.
#[derive(Debug)]
pub struct PreparedOpening<'a> {
    ledger: &'a mut OpeningLedger,
    staged: Vec<OpeningOccurrence>,
    replacement: Option<Vec<OpeningOccurrence>>,
    selected_edge: Option<(OpeningParent, OpeningId)>,
    counters: LedgerCounters,
    opening_id: OpeningId,
    requested_peak_bytes: usize,
}

impl PreparedOpening<'_> {
    /// Prospective terminal identity, materialized by this guard only if it is committed.
    ///
    /// Discarding preparation does not reserve an identity for later use.
    pub const fn opening_id(&self) -> OpeningId {
        self.opening_id
    }

    pub const fn counters(&self) -> LedgerCounters {
        self.counters
    }

    pub const fn requested_peak_bytes(&self) -> usize {
        self.requested_peak_bytes
    }

    /// Publishes this merge exactly once, without allocation or any fallible operation.
    pub fn commit(mut self) -> OpeningId {
        if let Some(mut replacement) = self.replacement.take() {
            replacement.append(&mut self.ledger.occurrences);
            replacement.append(&mut self.staged);
            self.ledger.occurrences = replacement;
        } else {
            self.ledger.occurrences.append(&mut self.staged);
        }
        if let Some((parent, child)) = self.selected_edge {
            self.ledger.occurrences[parent.opening.0].selected_children[parent.child_slot] =
                Some(child);
        }
        self.ledger.counters = self.counters;
        self.opening_id
    }
}

struct SharedPrefix {
    shared: usize,
    parent: Option<OpeningParent>,
    namespace: Namespace,
    commitment: EnvironmentRoot,
    terminal: Option<OpeningId>,
}

struct MergePlan {
    new_occurrences: usize,
    counters: LedgerCounters,
    input_bytes: usize,
    new_list_bytes: usize,
    slot_bytes: usize,
    replacement_capacity: Option<usize>,
}

fn child_count(node: &EnvNode) -> usize {
    match node {
        EnvNode::Env { .. } => 1,
        EnvNode::Merkle { .. } => 2,
        EnvNode::List(children) => children.len(),
        EnvNode::Mast { .. } | EnvNode::Data { .. } => 0,
    }
}

fn child_commitment(
    node: &EnvNode,
    slot: usize,
    depth: usize,
) -> Result<EnvironmentRoot, LedgerError> {
    match node {
        EnvNode::Env { child, .. } if slot == 0 => Ok(*child),
        EnvNode::Merkle { left, .. } if slot == 0 => Ok(*left),
        EnvNode::Merkle { right, .. } if slot == 1 => Ok(*right),
        EnvNode::List(children) => {
            children.get(slot).copied().ok_or(LedgerError::InconsistentOccurrence { depth })
        },
        _ => Err(LedgerError::InconsistentOccurrence { depth }),
    }
}

fn child_namespace(namespace: Namespace, node: &EnvNode) -> Namespace {
    match node {
        EnvNode::Env { label, .. } => namespace.child(*label),
        _ => namespace,
    }
}

fn logical_cost(
    node: &EnvNode,
    depth: usize,
    terminal_namespace: Namespace,
) -> Result<(usize, usize), LedgerError> {
    match node {
        EnvNode::Env { .. } => Ok((2, 2)),
        // Every Mast hashes its object. Only a non-root Mast also hashes its key.
        EnvNode::Mast { .. } => {
            Ok((2, 1 + usize::from(terminal_namespace != Namespace::initial())))
        },
        EnvNode::Merkle { .. } => Ok((2, 1)),
        EnvNode::List(children) => {
            let pairs = checked_add(children.len() / 2, children.len() % 2)?.max(1);
            Ok((pairs.checked_mul(2).ok_or(LedgerError::LengthOverflow)?, pairs))
        },
        EnvNode::Data { .. } => Err(LedgerError::InconsistentOccurrence { depth }),
    }
}

fn list_storage_bytes(node: &EnvNode) -> Result<usize, LedgerError> {
    match node {
        EnvNode::List(children) => array_bytes::<EnvironmentRoot>(children.capacity()),
        _ => Ok(0),
    }
}

fn array_bytes<T>(count: usize) -> Result<usize, LedgerError> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| LedgerError::LengthOverflow)
}

fn reserve_vec<T>(count: usize) -> Result<Vec<T>, LedgerError> {
    array_bytes::<T>(count)?;
    let mut items = Vec::new();
    items.try_reserve_exact(count).map_err(|_| LedgerError::AllocationFailed)?;
    Ok(items)
}

fn checked_add(left: usize, right: usize) -> Result<usize, LedgerError> {
    left.checked_add(right).ok_or(LedgerError::LengthOverflow)
}

fn check_trace_rows(requested: usize) -> Result<(), LedgerError> {
    if requested > MAX_TRACE_LEN {
        Err(LedgerError::TraceRowLimitExceeded { requested })
    } else {
        Ok(())
    }
}

fn check_limit(
    resource: LedgerResource,
    requested: usize,
    limit: usize,
) -> Result<(), LedgerError> {
    if requested > limit {
        Err(LedgerError::LimitExceeded { resource, limit, requested })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
