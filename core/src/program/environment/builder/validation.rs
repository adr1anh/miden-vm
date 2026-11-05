//! Complete, bounded traversal of internally committed environment preimages.

use alloc::vec::Vec;

use super::{
    EnvironmentBuildError, EnvironmentBuildResource, EnvironmentBuilder, array_bytes, check_limit,
    checked_add,
};
use crate::program::{
    EnvNode, EnvironmentRoot, ImplementationRoot, LabelCommitment, Namespace, ProcedureKey,
};

/// A procedure binding derived from an environment occurrence's inherited namespace and label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvironmentBinding {
    key: ProcedureKey,
    namespace: Namespace,
    label: LabelCommitment,
    implementation: ImplementationRoot,
}

impl EnvironmentBinding {
    /// Returns the internally derived procedure key.
    pub const fn key(&self) -> ProcedureKey {
        self.key
    }

    /// Returns the immediate accumulated parent namespace.
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Returns the MAST leaf's local export label commitment.
    pub const fn label(&self) -> LabelCommitment {
        self.label
    }

    /// Returns the bound implementation root, without providing its executable preimage.
    pub const fn implementation(&self) -> ImplementationRoot {
        self.implementation
    }
}

/// An immutable, locally complete environment with unique internally derived procedure keys.
///
/// Only the selected root's reachable environment structure is validated. Other retained nodes
/// may be unrelated or incomplete. This result grants no root authority, executable-code
/// availability, manifest validity, account ownership or protocol admission. It is an optional
/// local construction utility, not a required enumeration step for externally admitted fragments.
#[derive(Debug)]
pub struct ValidatedEnvironment {
    root: EnvironmentRoot,
    store: EnvironmentBuilder,
    bindings: Vec<EnvironmentBinding>,
    visits: usize,
    max_depth: usize,
    storage_bytes: usize,
    peak_storage_bytes: usize,
}

impl ValidatedEnvironment {
    /// Returns the root whose complete reachable structure was validated.
    pub const fn root(&self) -> EnvironmentRoot {
        self.root
    }

    /// Returns the derived bindings, sorted by procedure key using the identity's word ordering.
    ///
    /// This lookup ordering does not define canonical environment collection shape or encoding.
    pub fn bindings(&self) -> &[EnvironmentBinding] {
        &self.bindings
    }

    /// Looks up a binding derived during complete traversal of the selected root.
    pub fn binding(&self, key: ProcedureKey) -> Option<&EnvironmentBinding> {
        self.bindings
            .binary_search_by_key(&key, EnvironmentBinding::key)
            .ok()
            .and_then(|index| self.bindings.get(index))
    }

    /// Returns an immutable retained preimage, including any unrelated submitted preimages.
    ///
    /// Only preimages reachable from [`Self::root`] are covered by this result's validation.
    pub fn get(&self, root: EnvironmentRoot) -> Option<&EnvNode> {
        self.store.get(root)
    }

    /// Returns the number of physical node occurrences visited, including the selected root.
    pub const fn visits(&self) -> usize {
        self.visits
    }

    /// Returns the greatest visited physical depth, with the selected root at zero.
    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Returns retained logical node/List storage and the requested binding-buffer storage.
    ///
    /// Allocator-provided excess capacity, allocator metadata and process RSS are excluded.
    pub const fn storage_bytes(&self) -> usize {
        self.storage_bytes
    }

    /// Returns the greatest preflighted requested/logical storage peak during insertion or finish.
    ///
    /// This includes active flags, retained frame requests and conservative old/new Vec overlap,
    /// with the same allocator and RSS exclusions as [`Self::storage_bytes`].
    pub const fn peak_storage_bytes(&self) -> usize {
        self.peak_storage_bytes
    }
}

pub(super) fn finish(
    store: EnvironmentBuilder,
    root: EnvironmentRoot,
) -> Result<ValidatedEnvironment, EnvironmentBuildError> {
    let output = Traversal::new(&store, root)?.walk(root)?;
    Ok(ValidatedEnvironment {
        root,
        store,
        bindings: output.bindings,
        visits: output.visits,
        max_depth: output.max_depth,
        storage_bytes: output.storage_bytes,
        peak_storage_bytes: output.peak_storage_bytes,
    })
}

#[derive(Debug)]
struct Frame {
    index: usize,
    /// Namespace inherited by this node's children; only Env changes its incoming namespace.
    namespace: Namespace,
    next_child: usize,
}

struct Traversal<'a> {
    store: &'a EnvironmentBuilder,
    active: Vec<u8>,
    frames: Vec<Frame>,
    bindings: Vec<EnvironmentBinding>,
    // Vec::pop does not release its buffer. These track requested capacities, not current lengths
    // or allocator-provided excess; every growth preflight retains the complete old request.
    frame_request: usize,
    binding_request: usize,
    fixed_storage_bytes: usize,
    visits: usize,
    max_depth: usize,
    peak_storage_bytes: usize,
}

struct TraversalOutput {
    bindings: Vec<EnvironmentBinding>,
    visits: usize,
    max_depth: usize,
    storage_bytes: usize,
    peak_storage_bytes: usize,
}

impl<'a> Traversal<'a> {
    fn new(
        store: &'a EnvironmentBuilder,
        root: EnvironmentRoot,
    ) -> Result<Self, EnvironmentBuildError> {
        // Reject absent roots and exhausted root-occurrence budgets before allocating scratch.
        check_limit(EnvironmentBuildResource::Visits, 1, store.limits.max_visits)?;
        store
            .records
            .binary_search_by_key(&root, |record| record.root)
            .map_err(|_| EnvironmentBuildError::MissingPreimage(root))?;
        let fixed_storage_bytes =
            checked_add(store.storage_bytes(), array_bytes::<u8>(store.records.len())?)?;
        check_limit(
            EnvironmentBuildResource::StorageBytes,
            fixed_storage_bytes,
            store.limits.max_storage_bytes,
        )?;
        let mut active = Vec::new();
        active
            .try_reserve_exact(store.records.len())
            .map_err(|_| EnvironmentBuildError::AllocationFailed)?;
        active.resize(store.records.len(), 0);
        Ok(Self {
            store,
            active,
            frames: Vec::new(),
            bindings: Vec::new(),
            frame_request: 0,
            binding_request: 0,
            fixed_storage_bytes,
            visits: 0,
            max_depth: 0,
            peak_storage_bytes: store.peak_storage_bytes.max(fixed_storage_bytes),
        })
    }

    fn walk(mut self, root: EnvironmentRoot) -> Result<TraversalOutput, EnvironmentBuildError> {
        self.enter(root, Namespace::initial())?;
        while let Some(frame) = self.frames.last_mut() {
            // Cursor DFS holds at most one frame per physical depth, and visits children in their
            // stored order. An inactive shared root is entered again under the inherited N.
            let child = match &self.store.records[frame.index].node {
                EnvNode::Env { child, .. } => (frame.next_child == 0).then_some(*child),
                EnvNode::Merkle { left, right } => match frame.next_child {
                    0 => Some(*left),
                    1 => Some(*right),
                    _ => None,
                },
                EnvNode::List(children) => children.get(frame.next_child).copied(),
                EnvNode::Mast { .. } | EnvNode::Data { .. } => None,
            };
            if let Some(child) = child {
                frame.next_child = checked_add(frame.next_child, 1)?;
                let namespace = frame.namespace;
                self.enter(child, namespace)?;
            } else {
                self.active[frame.index] = 0;
                self.frames.pop();
            }
        }

        // In-place sorting allocates no scratch. Equal K is forbidden even when D also agrees.
        self.bindings.sort_unstable_by_key(EnvironmentBinding::key);
        for pair in self.bindings.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(EnvironmentBuildError::DuplicateProcedureKey(pair[0].key));
            }
        }
        let storage_bytes = checked_add(
            self.store.storage_bytes(),
            array_bytes::<EnvironmentBinding>(self.binding_request)?,
        )?;
        Ok(TraversalOutput {
            bindings: self.bindings,
            visits: self.visits,
            max_depth: self.max_depth,
            storage_bytes,
            peak_storage_bytes: self.peak_storage_bytes,
        })
    }

    fn enter(
        &mut self,
        root: EnvironmentRoot,
        namespace: Namespace,
    ) -> Result<(), EnvironmentBuildError> {
        let visits = checked_add(self.visits, 1)?;
        check_limit(EnvironmentBuildResource::Visits, visits, self.store.limits.max_visits)?;
        let depth = self.frames.len();
        check_limit(EnvironmentBuildResource::Depth, depth, self.store.limits.max_depth)?;
        let index = self
            .store
            .records
            .binary_search_by_key(&root, |record| record.root)
            .map_err(|_| EnvironmentBuildError::MissingPreimage(root))?;
        if self.active[index] != 0 {
            return Err(EnvironmentBuildError::Cycle(root));
        }

        let node = &self.store.records[index].node;
        let binding_count = if matches!(node, EnvNode::Mast { .. }) {
            let count = checked_add(self.bindings.len(), 1)?;
            check_limit(EnvironmentBuildResource::Bindings, count, self.store.limits.max_bindings)?;
            Some(count)
        } else {
            None
        };
        let frame_count = checked_add(depth, 1)?;
        let binding_bytes = array_bytes::<EnvironmentBinding>(self.binding_request)?;
        let other_storage = checked_add(self.fixed_storage_bytes, binding_bytes)?;
        reserve_request(
            &mut self.frames,
            &mut self.frame_request,
            frame_count,
            other_storage,
            self.store.limits.max_storage_bytes,
            &mut self.peak_storage_bytes,
        )?;
        if let EnvNode::Mast { label, implementation } = node {
            let binding_count = binding_count.ok_or(EnvironmentBuildError::LengthOverflow)?;
            let frame_bytes = array_bytes::<Frame>(self.frame_request)?;
            let other_storage = checked_add(self.fixed_storage_bytes, frame_bytes)?;
            reserve_request(
                &mut self.bindings,
                &mut self.binding_request,
                binding_count,
                other_storage,
                self.store.limits.max_storage_bytes,
                &mut self.peak_storage_bytes,
            )?;
            self.bindings.push(EnvironmentBinding {
                key: namespace.procedure_key(*label),
                namespace,
                label: *label,
                implementation: *implementation,
            });
        }
        let namespace = match node {
            EnvNode::Env { label, .. } => namespace.child(*label),
            _ => namespace,
        };
        self.active[index] = 1;
        self.frames.push(Frame { index, namespace, next_child: 0 });
        self.visits = visits;
        self.max_depth = self.max_depth.max(depth);
        Ok(())
    }
}

/// Grows a Vec's tracked request only at a new high-water length, charging old/new overlap.
fn reserve_request<T>(
    buffer: &mut Vec<T>,
    request: &mut usize,
    next_count: usize,
    other_storage: usize,
    storage_limit: usize,
    peak_storage_bytes: &mut usize,
) -> Result<(), EnvironmentBuildError> {
    if next_count <= *request {
        return Ok(());
    }
    let overlap_bytes = checked_add(array_bytes::<T>(*request)?, array_bytes::<T>(next_count)?)?;
    let peak = checked_add(other_storage, overlap_bytes)?;
    check_limit(EnvironmentBuildResource::StorageBytes, peak, storage_limit)?;
    let additional = next_count
        .checked_sub(buffer.len())
        .ok_or(EnvironmentBuildError::LengthOverflow)?;
    buffer
        .try_reserve_exact(additional)
        .map_err(|_| EnvironmentBuildError::AllocationFailed)?;
    *request = next_count;
    *peak_storage_bytes = (*peak_storage_bytes).max(peak);
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod storage_tests {
    use alloc::vec;

    use super::*;
    use crate::{Felt, WORD_SIZE, Word, program::EnvironmentBuildLimits};

    #[test]
    fn traversal_storage_peak_has_exact_and_one_short_limits() {
        let (builder, root) = fixture(usize::MAX, 0);
        let insertion_peak = builder.peak_storage_bytes();
        let environment = builder.finish(root).unwrap();
        let required = environment.peak_storage_bytes();
        assert!(required > insertion_peak);

        let (builder, root) = fixture(required, 0);
        assert_eq!(builder.finish(root).unwrap().peak_storage_bytes(), required);

        let (builder, root) = fixture(required - 1, 0);
        assert_eq!(
            builder.finish(root).unwrap_err(),
            EnvironmentBuildError::LimitExceeded {
                resource: EnvironmentBuildResource::StorageBytes,
                limit: required - 1,
                requested: required,
            },
        );
    }

    #[test]
    fn binding_growth_charges_frame_high_water_after_the_deep_branch_is_popped() {
        const DEEP_LISTS: usize = 5;
        let (builder, root) = fixture(usize::MAX, DEEP_LISTS);
        let retained = builder.storage_bytes();
        let active_bytes = builder.len() * size_of::<u8>();
        let insertion_peak = builder.peak_storage_bytes();
        // Root + the nested List branch + its Data leaf. All those frames remain requested
        // while the later shallow MAST siblings grow the binding buffer.
        let frame_bytes = (DEEP_LISTS + 2) * size_of::<Frame>();
        let binding_bytes = EXPORTS * size_of::<EnvironmentBinding>();
        let growth_overlap = (2 * EXPORTS - 1) * size_of::<EnvironmentBinding>();
        let expected_peak = retained + active_bytes + frame_bytes + growth_overlap;
        assert!(expected_peak > insertion_peak);
        let environment = builder.finish(root).unwrap();
        assert_eq!(environment.storage_bytes(), retained + binding_bytes);
        assert_eq!(environment.peak_storage_bytes(), expected_peak);

        let (builder, root) = fixture(expected_peak, DEEP_LISTS);
        assert_eq!(builder.finish(root).unwrap().peak_storage_bytes(), expected_peak);
        let (builder, root) = fixture(expected_peak - 1, DEEP_LISTS);
        assert_eq!(
            builder.finish(root).unwrap_err(),
            EnvironmentBuildError::LimitExceeded {
                resource: EnvironmentBuildResource::StorageBytes,
                limit: expected_peak - 1,
                requested: expected_peak,
            },
        );
    }

    #[test]
    fn active_flags_and_first_frame_are_charged_for_a_data_root() {
        let mut limits = limits(usize::MAX);
        let mut builder = EnvironmentBuilder::new(limits);
        let root = builder.insert(data()).unwrap();
        let required = builder.storage_bytes() + size_of::<u8>() + size_of::<Frame>();
        let environment = builder.finish(root).unwrap();
        assert_eq!(environment.peak_storage_bytes(), required);

        limits.max_storage_bytes = required;
        let mut builder = EnvironmentBuilder::new(limits);
        let root = builder.insert(data()).unwrap();
        assert!(builder.finish(root).is_ok());
        limits.max_storage_bytes = required - 1;
        let mut builder = EnvironmentBuilder::new(limits);
        let root = builder.insert(data()).unwrap();
        assert_eq!(
            builder.finish(root).unwrap_err(),
            EnvironmentBuildError::LimitExceeded {
                resource: EnvironmentBuildResource::StorageBytes,
                limit: required - 1,
                requested: required,
            },
        );
    }

    const EXPORTS: usize = 16;

    fn fixture(storage_limit: usize, deep_lists: usize) -> (EnvironmentBuilder, EnvironmentRoot) {
        let mut builder = EnvironmentBuilder::new(limits(storage_limit));
        let mut deep = builder.insert(data()).unwrap();
        for _ in 0..deep_lists {
            deep = builder.insert(EnvNode::List(vec![deep])).unwrap();
        }
        let mut children = vec![deep];
        for export in 0..EXPORTS {
            let node = EnvNode::Mast {
                label: LabelCommitment::new(word(u32::try_from(export).unwrap())),
                implementation: ImplementationRoot::new(word(100)),
            };
            children.push(builder.insert(node).unwrap());
        }
        let root = builder.insert(EnvNode::List(children)).unwrap();
        (builder, root)
    }

    fn limits(storage_limit: usize) -> EnvironmentBuildLimits {
        EnvironmentBuildLimits {
            max_submitted_nodes: usize::MAX,
            max_visits: usize::MAX,
            max_depth: usize::MAX,
            max_list_children: usize::MAX,
            max_encoded_bytes: usize::MAX,
            max_bindings: usize::MAX,
            max_storage_bytes: storage_limit,
        }
    }

    fn data() -> EnvNode {
        EnvNode::Data {
            kind: 0,
            label: LabelCommitment::new(word(0)),
            value: word(0),
        }
    }

    fn word(value: u32) -> Word {
        Word::new([Felt::from_u32(value); WORD_SIZE])
    }
}
