//! Exact embedded recursive-verifier dependencies and caller-authorized native supply checks.

use alloc::{sync::Arc, vec, vec::Vec};
use core::cmp::Ordering;

use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    program::{
        CanonicalLabel, EnvNode, EnvironmentBinding, EnvironmentBuildError, EnvironmentBuildLimits,
        EnvironmentBuilder, EnvironmentRoot, LabelError, Namespace, ProcedureKey,
        ValidatedEnvironment, VerifierConfiguration, VerifierConfigurationError, VerifierIdentity,
        VerifierMount,
    },
};
use miden_mast_package::{CallableProcedurePath, PackageSymbols};

use crate::{CoreLibrary, embedded_naming};

// These finite construction limits apply only to the exact compiler-owned embedded inventory.
// They are not a default policy for admitting arbitrary packages or outer environments.
const FRAGMENT_LIMITS: EnvironmentBuildLimits = EnvironmentBuildLimits {
    max_submitted_nodes: 262_144,
    max_visits: 262_144,
    max_depth: 256,
    max_list_children: 16_384,
    max_encoded_bytes: 32 * 1024 * 1024,
    max_bindings: 16_384,
    max_storage_bytes: 128 * 1024 * 1024,
};

/// The exact entry, full core fragment, and static advice required by an embedded verifier.
///
/// The fragment contains every owned selected K-to-D binding, including private callbacks. Its
/// root is an ordered List of full binding chains sorted by forward canonical key coordinates.
/// The configuration mounts that complete fragment at [`Namespace::initial()`]. Resource inventory
/// is the existing [`AdviceMap::commitment`] of package static advice plus this relation's
/// canonical ACE stream. Proof-dependent and private advice are outside that required subset.
///
/// Construction derives an identity without authorizing it. Expected identity and outer R_E must
/// come from the caller's owner. The derived identity is never embedded in its own fragment.
#[derive(Debug)]
pub struct CoreVerifierProfile {
    identity: VerifierIdentity,
    entry_key: ProcedureKey,
    relation_id: Word,
    configuration: VerifierConfiguration,
    fragment: Arc<ValidatedEnvironment>,
    required_resource_keys: Vec<Word>,
    required_resource_lengths: Vec<usize>,
}

impl CoreVerifierProfile {
    pub(super) fn new(
        library: &CoreLibrary,
        is_pvm: bool,
    ) -> Result<Self, CoreVerifierProfileError> {
        let (name, metadata) = if is_pvm {
            ("pvm", embedded_naming::pvm_verifier_metadata())
        } else {
            ("vm", embedded_naming::vm_verifier_metadata())
        };
        let path = CallableProcedurePath::from_semantic_components(
            ["miden", "core", "sys", name, "verify_proof"]
                .into_iter()
                .map(Into::into)
                .collect(),
        )
        .expect("the embedded verifier's semantic path is valid");
        Self::from_owned(library.naming(), &path, metadata)
    }

    fn from_owned(
        naming: &PackageSymbols,
        path: &CallableProcedurePath,
        (relation_id, resource_inventory, resources): (Word, Word, &[([u8; 32], usize)]),
    ) -> Result<Self, CoreVerifierProfileError> {
        let callables = naming.callables();
        let entry_key = callables
            .key_for_visible_path(path)
            .ok_or(CoreVerifierProfileError::MissingOwnedEntry)?;
        let implementation = callables
            .selected_implementation(entry_key)
            .ok_or(CoreVerifierProfileError::MissingOwnedEntry)?;
        let fragment = build_fragment(naming)?;
        if fragment.binding(entry_key).map(EnvironmentBinding::implementation)
            != Some(implementation)
        {
            return Err(CoreVerifierProfileError::MissingOwnedEntry);
        }
        let configuration = VerifierConfiguration::new(
            implementation,
            vec![VerifierMount::new(Namespace::initial(), fragment.root())],
            resource_inventory,
        )?;
        let identity =
            VerifierIdentity::derive(relation_id, entry_key, configuration.commitment()?);
        let mut required_resource_keys = Vec::new();
        let mut required_resource_lengths = Vec::new();
        required_resource_keys
            .try_reserve_exact(resources.len())
            .map_err(|_| CoreVerifierProfileError::AllocationFailed)?;
        required_resource_lengths
            .try_reserve_exact(resources.len())
            .map_err(|_| CoreVerifierProfileError::AllocationFailed)?;
        for (key, length) in resources {
            let key = Word::try_from(key.as_slice())
                .map_err(|_| CoreVerifierProfileError::InvalidResourceMetadata)?;
            if required_resource_keys.last().is_some_and(|previous| previous >= &key) {
                return Err(CoreVerifierProfileError::InvalidResourceMetadata);
            }
            required_resource_keys.push(key);
            required_resource_lengths.push(*length);
        }
        Ok(Self {
            identity,
            entry_key,
            relation_id,
            configuration,
            fragment: Arc::new(fragment),
            required_resource_keys,
            required_resource_lengths,
        })
    }

    /// Returns the derived identity without establishing the caller's expected identity.
    pub const fn identity(&self) -> VerifierIdentity {
        self.identity
    }

    /// Returns the owned callable key of the recursive verifier entry.
    pub const fn entry_key(&self) -> ProcedureKey {
        self.entry_key
    }

    /// Returns the pinned proof relation committed by this profile.
    pub const fn relation_id(&self) -> Word {
        self.relation_id
    }

    /// Returns the exact entry implementation, full core mount, and static-resource inventory.
    pub const fn configuration(&self) -> &VerifierConfiguration {
        &self.configuration
    }

    /// Returns the complete fragment that callers must preserve as an actual mounted subtree.
    ///
    /// Equivalent individual bindings or an unrelated retained copy do not satisfy this mount.
    pub fn fragment(&self) -> &ValidatedEnvironment {
        &self.fragment
    }

    /// Shares the exact immutable fragment without copying its retained preimages.
    pub fn shared_fragment(&self) -> Arc<ValidatedEnvironment> {
        Arc::clone(&self.fragment)
    }

    /// Returns required static-resource keys, excluding proof-dependent and private advice.
    pub fn required_resource_keys(&self) -> &[Word] {
        &self.required_resource_keys
    }

    /// Checks this profile against an independently caller-authorized environment and advice.
    ///
    /// `env` supplies complete reachable preimages and globally unique executable keys, while
    /// `authorized_root` supplies the caller's root choice. Every reachable occurrence is visited
    /// with its inherited namespace, within `max_visits`; unrelated retained nodes cannot satisfy
    /// the mount. Required resource lengths and their exact subset commitment must agree. All
    /// additional private, transaction, proof, and query advice is permitted.
    ///
    /// `effective_advice` must describe the selected package and request advice available to this
    /// execution after conflict checks. Success does not supply executable code, compare an
    /// externally expected verifier identity, or authorize a root on the caller's behalf.
    pub fn authorize(
        &self,
        authorized_root: EnvironmentRoot,
        env: &ValidatedEnvironment,
        effective_advice: &AdviceMap,
        max_visits: usize,
    ) -> Result<(), CoreVerifierProfileError> {
        if env.root() != authorized_root {
            return Err(CoreVerifierProfileError::EnvironmentRootMismatch {
                authorized: authorized_root,
                actual: env.root(),
            });
        }
        if env.binding(self.entry_key).map(EnvironmentBinding::implementation)
            != Some(self.configuration.entry_implementation())
        {
            return Err(CoreVerifierProfileError::EntryImplementationMismatch);
        }
        if !contains_mount(env, self.fragment.root(), max_visits)? {
            return Err(CoreVerifierProfileError::MissingCoreMount);
        }
        let mut resources = AdviceMap::default();
        for (key, expected_length) in
            self.required_resource_keys.iter().zip(&self.required_resource_lengths)
        {
            let values = effective_advice
                .get(key)
                .ok_or(CoreVerifierProfileError::MissingResource { key: *key })?;
            if values.len() != *expected_length {
                return Err(CoreVerifierProfileError::ResourceLengthMismatch {
                    key: *key,
                    expected: *expected_length,
                    actual: values.len(),
                });
            }
            resources.insert(*key, values.clone());
        }
        if resources.commitment() != self.configuration.resource_inventory() {
            return Err(CoreVerifierProfileError::ResourceInventoryMismatch);
        }
        Ok(())
    }
}

/// Embedded profile construction or caller-supplied environment/resources failed validation.
#[derive(Debug, thiserror::Error)]
pub enum CoreVerifierProfileError {
    #[error(transparent)]
    Environment(#[from] EnvironmentBuildError),
    #[error(transparent)]
    Configuration(#[from] VerifierConfigurationError),
    #[error(transparent)]
    Label(#[from] LabelError),
    #[error("the owned core inventory does not select the required verifier entry")]
    MissingOwnedEntry,
    #[error("the owned core callable path exceeds the bounded fragment depth")]
    CallableDepthLimit,
    #[error("the owned verifier resource metadata is invalid")]
    InvalidResourceMetadata,
    #[error("the verifier profile allocation failed")]
    AllocationFailed,
    #[error("verifier profile traversal length overflow")]
    LengthOverflow,
    #[error("environment root {actual:?} differs from caller-authorized root {authorized:?}")]
    EnvironmentRootMismatch {
        authorized: EnvironmentRoot,
        actual: EnvironmentRoot,
    },
    #[error("the authorized environment does not bind the expected verifier entry implementation")]
    EntryImplementationMismatch,
    #[error("the full core fragment is not reachable at the initial namespace")]
    MissingCoreMount,
    #[error("verifier mount traversal needs {required} visits, exceeding limit {limit}")]
    VisitLimitExceeded { required: usize, limit: usize },
    #[error("required verifier advice is missing at {key:?}")]
    MissingResource { key: Word },
    #[error("required verifier advice at {key:?} has {actual} elements, expected {expected}")]
    ResourceLengthMismatch {
        key: Word,
        expected: usize,
        actual: usize,
    },
    #[error("required verifier advice differs from the owned resource inventory")]
    ResourceInventoryMismatch,
}

fn compare_words(left: &Word, right: &Word) -> Ordering {
    left.iter()
        .map(Felt::as_canonical_u64)
        .cmp(right.iter().map(Felt::as_canonical_u64))
}

fn build_fragment(
    naming: &PackageSymbols,
) -> Result<ValidatedEnvironment, CoreVerifierProfileError> {
    let callables = naming.callables();
    let selections = callables.selected_implementations();
    if selections.len() > FRAGMENT_LIMITS.max_bindings {
        return Err(EnvironmentBuildError::LimitExceeded {
            resource: miden_core::program::EnvironmentBuildResource::Bindings,
            limit: FRAGMENT_LIMITS.max_bindings,
            requested: selections.len(),
        }
        .into());
    }
    let mut ordered = Vec::new();
    ordered
        .try_reserve_exact(selections.len())
        .map_err(|_| CoreVerifierProfileError::AllocationFailed)?;
    ordered.extend(selections);
    ordered
        .sort_unstable_by(|(left, _), (right, _)| compare_words(left.as_word(), right.as_word()));
    let mut children = Vec::new();
    children
        .try_reserve_exact(ordered.len())
        .map_err(|_| CoreVerifierProfileError::AllocationFailed)?;
    let mut builder = EnvironmentBuilder::new(FRAGMENT_LIMITS);
    for (&key, &implementation) in ordered {
        let binding = callables.binding(key).ok_or(CoreVerifierProfileError::MissingOwnedEntry)?;
        let components = binding.path().components();
        if binding
            .namespace_plan()
            .home()
            .len()
            .checked_add(components.len())
            .is_none_or(|depth| depth > FRAGMENT_LIMITS.max_depth)
        {
            return Err(CoreVerifierProfileError::CallableDepthLimit);
        }
        let (leaf, parents) =
            components.split_last().ok_or(CoreVerifierProfileError::MissingOwnedEntry)?;
        let mut child = builder.insert(EnvNode::Mast {
            label: CanonicalLabel::text(leaf)?.commitment(),
            implementation,
        })?;
        for parent in parents.iter().rev() {
            child = builder.insert(EnvNode::Env {
                label: CanonicalLabel::text(parent)?.commitment(),
                child,
            })?;
        }
        for label in binding.namespace_plan().home().iter().rev() {
            child = builder.insert(EnvNode::Env { label: label.commitment(), child })?;
        }
        children.push(child);
    }
    let root = builder.insert(EnvNode::List(children))?;
    Ok(builder.finish(root)?)
}

struct Frame {
    root: EnvironmentRoot,
    namespace: Namespace,
    next_child: usize,
}

fn contains_mount(
    environment: &ValidatedEnvironment,
    fragment: EnvironmentRoot,
    max_visits: usize,
) -> Result<bool, CoreVerifierProfileError> {
    if environment.visits() > max_visits {
        return Err(CoreVerifierProfileError::VisitLimitExceeded {
            required: environment.visits(),
            limit: max_visits,
        });
    }
    let frame_count = environment
        .max_depth()
        .checked_add(1)
        .ok_or(CoreVerifierProfileError::LengthOverflow)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(frame_count)
        .map_err(|_| CoreVerifierProfileError::AllocationFailed)?;
    frames.push(Frame {
        root: environment.root(),
        namespace: Namespace::initial(),
        next_child: 0,
    });
    let mut mounted = false;
    let mut visits = 0usize;
    while let Some(frame) = frames.last_mut() {
        if frame.next_child == 0 {
            visits = visits.checked_add(1).ok_or(CoreVerifierProfileError::LengthOverflow)?;
            if visits > max_visits {
                return Err(CoreVerifierProfileError::VisitLimitExceeded {
                    required: visits,
                    limit: max_visits,
                });
            }
            mounted |= frame.root == fragment && frame.namespace == Namespace::initial();
        }
        let node = environment
            .get(frame.root)
            .ok_or(EnvironmentBuildError::MissingPreimage(frame.root))?;
        let child = match node {
            EnvNode::Env { label, child } => {
                (frame.next_child == 0).then(|| (*child, frame.namespace.child(*label)))
            },
            EnvNode::Merkle { left, right } => match frame.next_child {
                0 => Some((*left, frame.namespace)),
                1 => Some((*right, frame.namespace)),
                _ => None,
            },
            EnvNode::List(children) => {
                children.get(frame.next_child).map(|child| (*child, frame.namespace))
            },
            EnvNode::Mast { .. } | EnvNode::Data { .. } => None,
        };
        if let Some((root, namespace)) = child {
            frame.next_child += 1;
            frames.push(Frame { root, namespace, next_child: 0 });
        } else {
            frames.pop();
        }
    }
    Ok(mounted)
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use miden_core::{ZERO, chiplets::hasher, program::ImplementationRoot};
    use miden_mast_package::{NamespacePath, PackageCallables, ProcedureName};

    use super::*;

    fn word(value: u32) -> Word {
        Word::from([value, 0, 0, 0])
    }

    fn path(components: &[&str]) -> CallableProcedurePath {
        CallableProcedurePath::from_semantic_components(
            components.iter().map(|component| (*component).to_string()).collect(),
        )
        .unwrap()
    }

    fn fixture() -> (CoreVerifierProfile, AdviceMap) {
        let entry_path = path(&["owned", "verify"]);
        let private_path = path(&["owned", "private_callback"]);
        let home = NamespacePath::new(vec![]);
        let entry = ProcedureName::new(home.clone(), entry_path.clone()).unwrap();
        let private = ProcedureName::new(home.clone(), private_path).unwrap();
        let callables = PackageCallables::new(
            [entry.clone(), private.clone()],
            [(entry_path.clone(), entry.key())],
            [
                (entry.key(), ImplementationRoot::new(word(10))),
                (private.key(), ImplementationRoot::new(word(11))),
            ],
        )
        .unwrap();
        let naming = PackageSymbols::new(home, callables, None).unwrap();
        let resources = AdviceMap::from_iter([(word(20), vec![Felt::ONE, Felt::from_u32(2)])]);
        let metadata: Vec<_> =
            resources.iter().map(|(key, values)| (key.as_bytes(), values.len())).collect();
        let profile = CoreVerifierProfile::from_owned(
            &naming,
            &entry_path,
            (word(30), resources.commitment(), &metadata),
        )
        .unwrap();
        (profile, resources)
    }

    fn copy_fragment(profile: &CoreVerifierProfile, builder: &mut EnvironmentBuilder) {
        let mut pending = vec![profile.fragment().root()];
        while let Some(root) = pending.pop() {
            let node = profile.fragment().get(root).unwrap();
            match node {
                EnvNode::Env { child, .. } => pending.push(*child),
                EnvNode::Merkle { left, right } => pending.extend([*left, *right]),
                EnvNode::List(children) => pending.extend(children.iter().copied()),
                EnvNode::Mast { .. } | EnvNode::Data { .. } => {},
            }
            assert_eq!(builder.insert(node.clone()).unwrap(), root);
        }
    }

    #[test]
    fn profile_retains_private_bindings_and_authorizes_extra_advice_and_root_fragments() {
        let (profile, mut advice) = fixture();
        assert_eq!(profile.fragment().bindings().len(), 2);
        assert_eq!(profile.required_resource_keys(), &[word(20)]);
        advice.insert(word(99), vec![ZERO]);
        let mut builder = EnvironmentBuilder::new(FRAGMENT_LIMITS);
        copy_fragment(&profile, &mut builder);
        let extra = builder
            .insert(EnvNode::Mast {
                label: CanonicalLabel::text("transaction_entry").unwrap().commitment(),
                implementation: ImplementationRoot::new(word(40)),
            })
            .unwrap();
        let root = builder.insert(EnvNode::List(vec![extra, profile.fragment().root()])).unwrap();
        let environment = builder.finish(root).unwrap();
        profile.authorize(root, &environment, &advice, environment.visits()).unwrap();
        assert_eq!(
            profile.identity(),
            VerifierIdentity::derive(
                profile.relation_id(),
                profile.entry_key(),
                profile.configuration().commitment().unwrap(),
            )
        );
    }

    #[test]
    fn authorization_requires_the_selected_root_and_full_visit_budget() {
        let (profile, advice) = fixture();
        let environment = profile.fragment();
        assert!(matches!(
            profile.authorize(EnvironmentRoot::new(word(90)), environment, &advice, usize::MAX),
            Err(CoreVerifierProfileError::EnvironmentRootMismatch { .. }),
        ));
        assert!(matches!(
            profile.authorize(environment.root(), environment, &advice, environment.visits() - 1),
            Err(CoreVerifierProfileError::VisitLimitExceeded { .. }),
        ));
    }

    #[test]
    fn unrelated_retained_fragment_and_equivalent_flattened_bindings_do_not_authorize_mount() {
        let (profile, advice) = fixture();
        let mut builder = EnvironmentBuilder::new(FRAGMENT_LIMITS);
        copy_fragment(&profile, &mut builder);
        let EnvNode::List(children) = profile.fragment().get(profile.fragment().root()).unwrap()
        else {
            panic!("profile fragment must be a List");
        };
        let root = builder
            .insert(EnvNode::Merkle { left: children[0], right: children[1] })
            .unwrap();
        let environment = builder.finish(root).unwrap();
        assert!(environment.get(profile.fragment().root()).is_some());
        assert!(matches!(
            profile.authorize(root, &environment, &advice, environment.visits()),
            Err(CoreVerifierProfileError::MissingCoreMount),
        ));
    }

    #[test]
    fn mount_search_carries_namespaces_instead_of_accepting_the_fragment_under_a_child() {
        let (profile, _) = fixture();
        let mut builder = EnvironmentBuilder::new(FRAGMENT_LIMITS);
        copy_fragment(&profile, &mut builder);
        let root = builder
            .insert(EnvNode::Env {
                label: CanonicalLabel::text("rebound").unwrap().commitment(),
                child: profile.fragment().root(),
            })
            .unwrap();
        let environment = builder.finish(root).unwrap();
        assert!(
            !contains_mount(&environment, profile.fragment().root(), environment.visits()).unwrap()
        );
    }

    #[test]
    fn authorization_rejects_missing_resized_and_conflicting_required_resources() {
        let (profile, advice) = fixture();
        let environment = profile.fragment();
        let authorize = |advice: &AdviceMap| {
            profile.authorize(environment.root(), environment, advice, environment.visits())
        };
        assert!(matches!(
            authorize(&AdviceMap::default()),
            Err(CoreVerifierProfileError::MissingResource { .. }),
        ));
        let mut resized = advice.clone();
        resized.insert(word(20), vec![ZERO]);
        assert!(matches!(
            authorize(&resized),
            Err(CoreVerifierProfileError::ResourceLengthMismatch { .. }),
        ));
        let mut changed = advice;
        changed.insert(word(20), vec![ZERO, ZERO]);
        assert!(matches!(
            authorize(&changed),
            Err(CoreVerifierProfileError::ResourceInventoryMismatch),
        ));
    }

    #[test]
    fn rebound_entry_and_helper_implementations_cannot_authorize_the_profile() {
        let (profile, advice) = fixture();
        for rebound_entry in [true, false] {
            let mut builder = EnvironmentBuilder::new(FRAGMENT_LIMITS);
            let mut children = Vec::new();
            for (name, implementation) in [
                ("verify", if rebound_entry { 100 } else { 10 }),
                ("private_callback", if rebound_entry { 11 } else { 100 }),
            ] {
                let leaf = builder
                    .insert(EnvNode::Mast {
                        label: CanonicalLabel::text(name).unwrap().commitment(),
                        implementation: ImplementationRoot::new(word(implementation)),
                    })
                    .unwrap();
                children.push(
                    builder
                        .insert(EnvNode::Env {
                            label: CanonicalLabel::text("owned").unwrap().commitment(),
                            child: leaf,
                        })
                        .unwrap(),
                );
            }
            let root = builder.insert(EnvNode::List(children)).unwrap();
            let environment = builder.finish(root).unwrap();
            let result = profile.authorize(root, &environment, &advice, environment.visits());
            if rebound_entry {
                assert!(matches!(
                    result,
                    Err(CoreVerifierProfileError::EntryImplementationMismatch)
                ));
            } else {
                assert!(matches!(result, Err(CoreVerifierProfileError::MissingCoreMount)));
            }
        }
    }

    #[test]
    fn embedded_profiles_bind_owned_entries_relations_and_per_request_ace_resources() {
        let library = CoreLibrary::default();
        let vm = library.vm_recursive_verifier_profile().unwrap();
        let pvm = library.pvm_recursive_verifier_profile().unwrap();
        assert_eq!(vm.fragment().root(), pvm.fragment().root());
        assert_eq!(
            vm.fragment().bindings().len(),
            library.naming().callables().selected_implementations().len()
        );
        assert_ne!(vm.identity(), pvm.identity());
        assert_ne!(vm.entry_key(), pvm.entry_key());
        assert_eq!(vm.relation_id(), Word::new(miden_air::vm::config::RELATION_DIGEST));
        assert_eq!(
            pvm.relation_id(),
            Word::new(miden_air::precompiles::PVM_RELATION_DIGEST.map(Felt::new_unchecked))
        );
        let vm_instructions: Vec<_> = miden_air::vm::ace::ACE_INSTRUCTIONS
            .iter()
            .copied()
            .map(Felt::new_unchecked)
            .collect();
        let pvm_circuit = miden_air::precompiles::protocol::recursive_circuit();
        for (profile, key, instructions) in [
            (&vm, hasher::hash_elements(&vm_instructions), vm_instructions),
            (&pvm, pvm_circuit.commitment, pvm_circuit.instructions),
        ] {
            assert!(profile.required_resource_keys().contains(&key));
            let mut advice = library.mast_forest().advice_map().clone();
            if !advice.contains_key(&key) {
                assert!(matches!(
                    profile.authorize(
                        profile.fragment().root(),
                        profile.fragment(),
                        &advice,
                        profile.fragment().visits(),
                    ),
                    Err(CoreVerifierProfileError::MissingResource { .. }),
                ));
            }
            advice.insert(key, instructions);
            profile
                .authorize(
                    profile.fragment().root(),
                    profile.fragment(),
                    &advice,
                    profile.fragment().visits(),
                )
                .unwrap();
        }
    }
}
