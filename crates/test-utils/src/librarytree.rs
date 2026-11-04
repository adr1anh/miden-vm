//! Explicit, bounded execution environments for the shared source fixture convention.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use miden_core::program::{
    CanonicalLabel, EnvNode, EnvironmentBuildLimits, EnvironmentBuilder, EnvironmentRoot,
    ExecutionTarget, ImplementationRoot, Namespace, ProcedureKey, ValidatedEnvironment,
};
use miden_mast_package::{PackageSymbols, ProcedureName};
use miden_processor::{
    EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, ExecutionEnvironment, LedgerLimits, OpeningError, OpeningLimits,
    OpeningResource, OpeningStep, ResolutionWitness, SessionLimits,
};

use super::Report;

// These are policies of this test helper, independent of any production admission profile.
const MAX_REQUESTS: usize = 1 << 20;
const MAX_BINDINGS: usize = 16_384;
const MAX_NAMING_RECORDS: usize = 262_144;
const MAX_NODES: usize = 262_144;
const MAX_DEPTH: usize = 256;
const MAX_ENCODED_BYTES: usize = 32 * 1024 * 1024;
const FIXTURE_OPENING_LIMITS: OpeningLimits = OpeningLimits {
    max_nodes: 257,
    max_depth: 256,
    max_list_children: MAX_BINDINGS,
    max_total_list_children: MAX_BINDINGS,
    max_encoded_bytes: 2 * 1024 * 1024,
    max_storage_bytes: 4 * 1024 * 1024,
};
type FixturePath = Vec<(EnvironmentRoot, Option<usize>)>;

/// A fixture owner's exact code, canonical inventory and locally authorized finite environment.
#[derive(Clone)]
pub struct NamedProgram {
    pub program: miden_core::program::Program,
    pub environment: FixtureEnvironment,
    pub package: Arc<miden_mast_package::Package>,
    pub naming: Arc<PackageSymbols>,
}

/// Selects the source-test naming convention for local definitions in the same parsing context.
/// Imported inventories remain exactly as supplied by their compiler/admission owner. This helper
/// chooses fixture authority only; it supplies no production home or publication admission.
#[cfg(feature = "std")]
pub fn assemble_fixture_program(
    assembler: miden_assembly::Assembler,
    name: &str,
    source: impl miden_assembly::Parse,
    imports: &[&PackageSymbols],
) -> NamedProgram {
    let root = source
        .parse(assembler.warnings_as_errors(), assembler.source_manager())
        .expect("fixture source must parse");
    let mut fixture = miden_assembly::testing::FixtureNamespace::assembly_tests();
    fixture
        .add_module(&root)
        .expect("fixture source must have canonical local definitions");
    let assembler = fixture
        .configure(assembler, [root.as_ref()])
        .expect("fixture source must have explicit local naming");
    let product = assembler
        .assemble_executable_modules(name.into(), root, [])
        .expect("fixture source must compile");
    fixture_from_product(product, imports)
}

/// Retains exact compiler metadata during code extraction and finite environment construction.
/// Imports are canonical owner inputs, never raw artifact metadata or a fallback admission policy.
pub fn fixture_from_product(
    product: miden_assembly::AssemblyProduct,
    imports: &[&PackageSymbols],
) -> NamedProgram {
    try_fixture_from_product(product, imports)
        .expect("fixture product and selections must form a valid named execution environment")
}

/// Fallible conversion for fixture consumers which report assembly or resource-policy errors.
pub fn try_fixture_from_product(
    product: miden_assembly::AssemblyProduct,
    imports: &[&PackageSymbols],
) -> Result<NamedProgram, Report> {
    let naming = Arc::new(product.naming().clone());
    let entry = naming
        .entry_key()
        .ok_or_else(|| Report::msg("fixture program must have an explicit entry"))?;
    let environment = FixtureEnvironment::new(
        entry,
        core::iter::once(naming.as_ref()).chain(imports.iter().copied()),
    )?;
    let package: Arc<miden_mast_package::Package> = product.into_artifact(true)?.into();
    let program = package.try_into_program(&naming)?;
    Ok(NamedProgram { program, environment, package, naming })
}

/// A test owner's selected canonical naming/code bindings and their complete local environment.
///
/// Naming must come from exact local compilation or explicit selected-profile admission. This
/// helper constructs fixture authority from that owner input; it does not admit raw package names,
/// publishers, foreign homes, or a production profile.
#[derive(Clone)]
pub struct FixtureEnvironment {
    environment: Arc<ValidatedEnvironment>,
    paths: Arc<BTreeMap<ProcedureKey, FixturePath>>,
    execution: ExecutionEnvironment,
}

impl FixtureEnvironment {
    /// Builds and validates finite, unique bindings without deriving identity from code roots.
    pub fn new<'a>(
        entry: ProcedureKey,
        naming: impl IntoIterator<Item = &'a PackageSymbols>,
    ) -> Result<Self, Report> {
        Self::new_with_fragments(entry, naming, &[])
    }

    /// Mounts each explicitly selected complete fragment as an ordered root-level List child.
    /// Only preimages reachable from a fragment's validated root are imported. Exact selections
    /// already covered by fragments are retained there rather than duplicated as flat paths.
    pub fn new_with_fragments<'a>(
        entry: ProcedureKey,
        naming: impl IntoIterator<Item = &'a PackageSymbols>,
        fragments: &[Arc<ValidatedEnvironment>],
    ) -> Result<Self, Report> {
        if fragments.len() > MAX_BINDINGS {
            return Err(Report::msg("fixture fragment input limit exceeded"));
        }
        let mut selections = BTreeMap::<ProcedureKey, (ProcedureName, ImplementationRoot)>::new();
        let mut naming_records = 0usize;
        for naming in naming {
            naming_records = naming_records
                .checked_add(1)
                .filter(|count| *count <= MAX_NAMING_RECORDS)
                .ok_or_else(|| Report::msg("fixture naming input limit exceeded"))?;
            for (&key, &implementation) in naming.callables().selected_implementations() {
                naming_records = naming_records
                    .checked_add(1)
                    .filter(|count| *count <= MAX_NAMING_RECORDS)
                    .ok_or_else(|| Report::msg("fixture naming input limit exceeded"))?;
                let binding = naming.callables().binding(key).ok_or_else(|| {
                    Report::msg("selected fixture implementation has no canonical binding")
                })?;
                if let Some((previous_binding, previous_implementation)) = selections.get(&key) {
                    if previous_binding != binding || *previous_implementation != implementation {
                        return Err(Report::msg(
                            "conflicting fixture selection for a procedure key",
                        ));
                    }
                } else {
                    if selections.len() >= MAX_BINDINGS {
                        return Err(Report::msg("fixture binding limit exceeded"));
                    }
                    if binding
                        .namespace_plan()
                        .home()
                        .len()
                        .checked_add(binding.path().components().len())
                        .is_none_or(|depth| depth > MAX_DEPTH)
                    {
                        return Err(Report::msg("fixture callable path depth limit exceeded"));
                    }
                    selections.insert(key, (binding.clone(), implementation));
                }
            }
        }
        if !selections.contains_key(&entry) {
            return Err(Report::msg("fixture entry has no selected implementation"));
        }

        let mut builder = EnvironmentBuilder::new(EnvironmentBuildLimits {
            max_submitted_nodes: MAX_NODES,
            max_visits: MAX_NODES,
            max_depth: MAX_DEPTH,
            max_list_children: MAX_BINDINGS,
            max_encoded_bytes: MAX_ENCODED_BYTES,
            max_bindings: MAX_BINDINGS,
            max_storage_bytes: 128 * 1024 * 1024,
        });
        let mut children = Vec::new();
        let mut paths = BTreeMap::new();
        let mut fragment_visits = 1usize; // Include the final parent List.
        for fragment in fragments {
            fragment_visits = fragment_visits
                .checked_add(fragment.visits())
                .filter(|visits| *visits <= MAX_NODES)
                .ok_or_else(|| Report::msg("fixture fragment visit limit exceeded"))?;
            if fragment.max_depth() >= MAX_DEPTH {
                return Err(Report::msg("fixture fragment depth limit exceeded"));
            }
            if paths
                .len()
                .checked_add(fragment.bindings().len())
                .is_none_or(|count| count > MAX_BINDINGS)
            {
                return Err(Report::msg("fixture binding limit exceeded"));
            }
            for covered in fragment.bindings() {
                if let Some((binding, implementation)) = selections.get(&covered.key()) {
                    let leaf = binding.path().components().last().ok_or_else(|| {
                        Report::msg("fixture callable path must have a procedure label")
                    })?;
                    if *implementation != covered.implementation()
                        || binding.parent_namespace() != covered.namespace()
                        || CanonicalLabel::text(leaf).map_err(Report::msg)?.commitment()
                            != covered.label()
                    {
                        return Err(Report::msg("conflicting fixture fragment binding"));
                    }
                    selections.remove(&covered.key());
                }
            }
            let slot = children.len();
            import_fragment(&mut builder, fragment, slot, &mut paths)?;
            children.push(fragment.root());
        }
        if children
            .len()
            .checked_add(selections.len())
            .is_none_or(|count| count > MAX_BINDINGS)
            || paths
                .len()
                .checked_add(selections.len())
                .is_none_or(|count| count > MAX_BINDINGS)
        {
            return Err(Report::msg("fixture binding limit exceeded"));
        }
        for (key, (binding, implementation)) in selections {
            let components = binding.path().components();
            let (leaf, parents) = components
                .split_last()
                .ok_or_else(|| Report::msg("fixture callable path must have a procedure label"))?;
            let leaf = CanonicalLabel::text(leaf).map_err(Report::msg)?;
            let mut child = builder
                .insert(EnvNode::Mast { label: leaf.commitment(), implementation })
                .map_err(Report::msg)?;
            let mut path = alloc::vec![(child, None)];
            let labels = binding
                .namespace_plan()
                .home()
                .iter()
                .cloned()
                .chain(parents.iter().map(|text| {
                    CanonicalLabel::text(text).expect("validated semantic callable component")
                }))
                .collect::<Vec<_>>();
            for label in labels.iter().rev() {
                child = builder
                    .insert(EnvNode::Env { label: label.commitment(), child })
                    .map_err(Report::msg)?;
                path.push((child, Some(0)));
            }
            path.reverse();
            // Keep the actual parent slot with this path. A fragment can contribute many keys,
            // so key-map iteration order cannot recover the top-level List position.
            path.insert(0, (child, Some(children.len())));
            children.push(child);
            paths.insert(key, path);
        }
        let root = builder.insert(EnvNode::List(children)).map_err(Report::msg)?;
        for path in paths.values_mut() {
            path[0].0 = root;
        }
        let environment = Arc::new(builder.finish(root).map_err(Report::msg)?);
        // Every advertised binding must be resolvable under the fixture's own opening policy.
        // In particular, a mounted fragment adds its Lists to the enclosing root List's budget.
        for path in paths.values() {
            preflight_path(&environment, path, FIXTURE_OPENING_LIMITS).map_err(Report::msg)?;
        }
        let execution = ExecutionEnvironment::new(
            ExecutionTarget::new(entry, root),
            FIXTURE_OPENING_LIMITS,
            LedgerLimits {
                max_occurrences: 262_144,
                max_total_list_children: 16 * 1024 * 1024,
                max_encoded_bytes: 512 * 1024 * 1024,
                max_library_rows: 64 * 1024 * 1024,
                max_compression_requests: 64 * 1024 * 1024,
                max_retained_bytes: 512 * 1024 * 1024,
                max_peak_bytes: 1024 * 1024 * 1024,
            },
            SessionLimits {
                max_cached_keys: MAX_BINDINGS,
                max_requests: MAX_REQUESTS,
                max_retained_bytes: 768 * 1024 * 1024,
                max_prepare_peak_bytes: 1536 * 1024 * 1024,
            },
        );
        Ok(Self {
            environment,
            paths: Arc::new(paths),
            execution,
        })
    }

    /// Returns the selected entry/root and this helper's finite resolution policies.
    pub fn execution(&self) -> ExecutionEnvironment {
        self.execution
    }

    /// Returns the complete locally constructed environment, including mounted fragments.
    pub fn validated_environment(&self) -> &ValidatedEnvironment {
        &self.environment
    }

    /// Creates an independent source request budget for one host's execution.
    pub fn source(&self) -> Arc<dyn EnvironmentWitnessSource> {
        Arc::new(FixtureSource {
            fixture: self.clone(),
            requests: AtomicUsize::new(0),
        })
    }
}

/// A cursor frame retains one occurrence per depth, even for a wide shared DAG.
struct FragmentFrame {
    root: EnvironmentRoot,
    namespace: Namespace,
    next_child: usize,
    selected_child: Option<usize>,
    entered: bool,
}

fn import_fragment(
    builder: &mut EnvironmentBuilder,
    fragment: &ValidatedEnvironment,
    outer_slot: usize,
    paths: &mut BTreeMap<ProcedureKey, FixturePath>,
) -> Result<(), Report> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(fragment.max_depth() + 1)
        .map_err(|_| Report::msg("fixture fragment traversal allocation failed"))?;
    frames.push(FragmentFrame {
        root: fragment.root(),
        namespace: Namespace::initial(),
        next_child: 0,
        selected_child: None,
        entered: false,
    });
    let mut visits = 0usize;
    let mut copied_bytes = 0usize;
    while !frames.is_empty() {
        let index = frames.len() - 1;
        let frame = &frames[index];
        let node = fragment
            .get(frame.root)
            .ok_or_else(|| Report::msg("fixture fragment has no reachable preimage"))?;
        if !frame.entered {
            visits = visits
                .checked_add(1)
                .filter(|visits| *visits <= MAX_NODES)
                .ok_or_else(|| Report::msg("fixture fragment visit limit exceeded"))?;
            copied_bytes = copied_bytes
                .checked_add(node.encoded_len().map_err(Report::msg)?)
                .filter(|bytes| *bytes <= MAX_ENCODED_BYTES)
                .ok_or_else(|| Report::msg("fixture fragment encoded byte limit exceeded"))?;
            // Check the source length before cloning; its retained capacity is not authority or
            // a reason to allocate unrelated storage in the fixture.
            let copied = if let EnvNode::List(children) = node {
                if children.len() > MAX_BINDINGS {
                    return Err(Report::msg("fixture fragment List child limit exceeded"));
                }
                let mut copied = Vec::new();
                copied
                    .try_reserve_exact(children.len())
                    .map_err(|_| Report::msg("fixture fragment List allocation failed"))?;
                copied.extend_from_slice(children);
                EnvNode::List(copied)
            } else {
                node.clone()
            };
            builder.insert(copied).map_err(Report::msg)?;
            if let EnvNode::Mast { label, .. } = node {
                let key = frame.namespace.procedure_key(*label);
                if paths.contains_key(&key) {
                    return Err(Report::msg("duplicate fixture fragment binding"));
                }
                let mut path = Vec::new();
                path.try_reserve_exact(frames.len() + 1)
                    .map_err(|_| Report::msg("fixture fragment path allocation failed"))?;
                path.push((fragment.root(), Some(outer_slot)));
                path.extend(frames.iter().map(|frame| (frame.root, frame.selected_child)));
                paths.insert(key, path);
            }
            frames[index].entered = true;
        }
        let frame = &mut frames[index];
        let slot = frame.next_child;
        let child = match node {
            EnvNode::Env { child, .. } => (slot == 0).then_some(*child),
            EnvNode::Merkle { left, right } => match slot {
                0 => Some(*left),
                1 => Some(*right),
                _ => None,
            },
            EnvNode::List(children) => children.get(slot).copied(),
            EnvNode::Mast { .. } | EnvNode::Data { .. } => None,
        };
        if let Some(child) = child {
            let namespace = match node {
                EnvNode::Env { label, .. } => frame.namespace.child(*label),
                _ => frame.namespace,
            };
            frame.next_child += 1;
            frame.selected_child = Some(slot);
            frames.push(FragmentFrame {
                root: child,
                namespace,
                next_child: 0,
                selected_child: None,
                entered: false,
            });
        } else {
            frames.pop();
        }
    }
    Ok(())
}

/// Finite keyed capture/replay policies for executions using this fixture helper.
pub fn trace_limits() -> EnvironmentTraceLimits {
    EnvironmentTraceLimits {
        max_events: MAX_REQUESTS,
        max_retained_bytes: 1024 * 1024 * 1024,
        max_prepare_peak_bytes: 1536 * 1024 * 1024,
        max_validation_work: 1024 * 1024 * 1024,
    }
}

struct FixtureSource {
    fixture: FixtureEnvironment,
    requests: AtomicUsize,
}

/// Checks the exact requested storage of the candidate produced by `FixtureSource`, before any
/// preimage is copied. Candidate paths and cloned Lists reserve their exact iterator lengths;
/// authentication additionally checks their actual native capacities before hashing.
fn preflight_path(
    environment: &ValidatedEnvironment,
    path: &FixturePath,
    limits: OpeningLimits,
) -> Result<(), OpeningError> {
    fn bytes<T>(count: usize) -> Result<usize, OpeningError> {
        core::alloc::Layout::array::<T>(count)
            .map(|layout| layout.size())
            .map_err(|_| OpeningError::LengthOverflow)
    }
    fn add(left: usize, right: usize) -> Result<usize, OpeningError> {
        left.checked_add(right).ok_or(OpeningError::LengthOverflow)
    }
    fn check(
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

    let depth = path.len().checked_sub(1).ok_or(OpeningError::EmptyPath)?;
    check(OpeningResource::Nodes, path.len(), limits.max_nodes)?;
    check(OpeningResource::Depth, depth, limits.max_depth)?;
    let mut storage = bytes::<OpeningStep>(path.len())?;
    check(OpeningResource::StorageBytes, storage, limits.max_storage_bytes)?;
    let mut encoded = 0usize;
    let mut total_list_children = 0usize;
    let mut scratch = 0usize;
    for (root, _) in path {
        let node = environment.get(*root).expect("validated fixture preimage");
        encoded = add(encoded, node.encoded_len()?)?;
        check(OpeningResource::EncodedBytes, encoded, limits.max_encoded_bytes)?;
        if let EnvNode::List(children) = node {
            check(OpeningResource::ListChildren, children.len(), limits.max_list_children)?;
            total_list_children = add(total_list_children, children.len())?;
            check(
                OpeningResource::TotalListChildren,
                total_list_children,
                limits.max_total_list_children,
            )?;
            storage = add(storage, bytes::<EnvironmentRoot>(children.len())?)?;
            let hash_elements = children
                .len()
                .checked_mul(miden_core::WORD_SIZE)
                .ok_or(OpeningError::LengthOverflow)?;
            scratch = scratch.max(bytes::<miden_core::Felt>(hash_elements)?);
        }
        check(OpeningResource::StorageBytes, add(storage, scratch)?, limits.max_storage_bytes)?;
    }
    Ok(())
}

impl EnvironmentWitnessSource for FixtureSource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        let mut count = self.requests.load(Ordering::Relaxed);
        loop {
            let Some(next) = count.checked_add(1).filter(|next| *next <= MAX_REQUESTS) else {
                return Ok(None);
            };
            match self.requests.compare_exchange_weak(
                count,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        if request.root != self.fixture.environment.root() {
            return Ok(None);
        }
        let Some(path) = self.fixture.paths.get(&request.key) else {
            return Ok(None);
        };
        // Bound construction before copying any node/List preimages. The final verification below
        // also checks actual Vec capacities, exact commitments, slots and the requested key.
        let limits = request.limits;
        if preflight_path(&self.fixture.environment, path, limits).is_err() {
            return Ok(None);
        }
        let candidate = || ResolutionWitness {
            path: path
                .iter()
                .map(|(root, selected_child)| OpeningStep {
                    node: self
                        .fixture
                        .environment
                        .get(*root)
                        .expect("validated fixture preimage")
                        .clone(),
                    selected_child: *selected_child,
                })
                .collect(),
        };
        candidate().verify(request.root, request.key, limits)?;
        Ok(Some(candidate()))
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{Felt, Word};
    use miden_mast_package::{CallableProcedurePath, NamespacePath, PackageCallables};

    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn fallible_fixture_conversion_reports_a_valid_products_environment_limit() {
        use miden_assembly::{Assembler, Parse, testing::FixtureNamespace};
        let assembler = Assembler::default();
        let root = Parse::parse("begin nop end", false, assembler.source_manager()).unwrap();
        let deep_home = NamespacePath::new(alloc::vec![CanonicalLabel::text("deep").unwrap(); 257]);
        let mut fixture = FixtureNamespace::new(deep_home);
        fixture.add_module(&root).unwrap();
        let product = fixture
            .configure(assembler, [root.as_ref()])
            .unwrap()
            .assemble_executable_modules("deep_fixture".into(), root, [])
            .unwrap();
        let Err(error) = try_fixture_from_product(product, &[]) else {
            panic!("the finite environment path policy must reject an overly deep valid product");
        };
        assert!(alloc::format!("{error}").contains("fixture callable path depth limit"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn shared_source_fixture_retains_exact_artifact_names_and_executes() {
        let fixture = assemble_fixture_program(
            miden_assembly::Assembler::default(),
            "shared_fixture",
            "proc helper push.5 end begin exec.helper swap drop end",
            &[],
        );
        fixture.package.check_naming(&fixture.naming).unwrap();
        let execution = fixture.environment.execution();
        let entry = fixture.naming.entry_key().unwrap();
        assert_eq!(execution.descriptor().entry_key(), entry);
        assert_ne!(entry.into_word(), fixture.program.hash());
        let implementation = fixture.naming.callables().selected_implementation(entry).unwrap();
        assert_eq!(implementation.into_word(), fixture.program.hash());
        let request = EnvironmentWitnessRequest {
            root: execution.descriptor().environment_root(),
            key: entry,
            limits: execution.opening_limits(),
        };
        let resolved = fixture
            .environment
            .source()
            .get(request)
            .unwrap()
            .unwrap()
            .verify(request.root, entry, request.limits)
            .unwrap();
        assert_eq!(resolved.implementation_root(), implementation);
        let mut host = miden_processor::DefaultHost::default()
            .with_environment_source(fixture.environment.source());
        let output =
            miden_processor::FastProcessor::new(miden_core::program::StackInputs::default())
                .execute_sync(&fixture.program, execution, &mut host)
                .unwrap();
        assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(5)));
    }

    fn naming(name: &str, implementation: u32) -> PackageSymbols {
        let binding = ProcedureName::new(
            NamespacePath::new(alloc::vec![CanonicalLabel::text("selected-test-owner").unwrap()]),
            CallableProcedurePath::from_semantic_components(alloc::vec![name.into()]).unwrap(),
        )
        .unwrap();
        let key = binding.key();
        PackageSymbols::new(
            binding.namespace_plan().clone(),
            PackageCallables::new(
                [binding],
                [],
                [(key, ImplementationRoot::new(Word::new([Felt::from_u32(implementation); 4])))],
            )
            .unwrap(),
            Some(key),
        )
        .unwrap()
    }

    fn branching_fragment(
        first: &PackageSymbols,
        second: &PackageSymbols,
    ) -> (Arc<ValidatedEnvironment>, EnvironmentRoot) {
        let mut builder = EnvironmentBuilder::new(EnvironmentBuildLimits {
            max_submitted_nodes: MAX_NODES,
            max_visits: MAX_NODES,
            max_depth: MAX_DEPTH,
            max_list_children: MAX_BINDINGS,
            max_encoded_bytes: MAX_ENCODED_BYTES,
            max_bindings: MAX_BINDINGS,
            max_storage_bytes: 128 * 1024 * 1024,
        });
        let mut leaf = |naming: &PackageSymbols| {
            let key = naming.entry_key().unwrap();
            let binding = naming.callables().binding(key).unwrap();
            builder
                .insert(EnvNode::Mast {
                    label: CanonicalLabel::text(binding.path().components().last().unwrap())
                        .unwrap()
                        .commitment(),
                    implementation: naming.callables().selected_implementation(key).unwrap(),
                })
                .unwrap()
        };
        let left = leaf(first);
        let right = leaf(second);
        let pair = builder.insert(EnvNode::Merkle { left, right }).unwrap();
        let owner = builder
            .insert(EnvNode::Env {
                label: first.namespace_plan().home()[0].commitment(),
                child: pair,
            })
            .unwrap();
        let root = builder.insert(EnvNode::List(alloc::vec![owner])).unwrap();
        // A validated result may retain incomplete preimages outside its selected root.
        let unrelated = builder
            .insert(EnvNode::Env {
                label: CanonicalLabel::text("unrelated").unwrap().commitment(),
                child: EnvironmentRoot::new(Word::new([Felt::from_u32(99); 4])),
            })
            .unwrap();
        (Arc::new(builder.finish(root).unwrap()), unrelated)
    }

    #[test]
    fn explicit_fragment_remains_reachable_and_all_bindings_have_exact_openings() {
        let first = naming("first", 1);
        let second = naming("second", 2);
        let entry = naming("entry", 3);
        let (fragment, unrelated) = branching_fragment(&first, &second);
        assert!(fragment.get(unrelated).is_some());
        let fixture = FixtureEnvironment::new_with_fragments(
            entry.entry_key().unwrap(),
            // The second binding is available solely through the explicit fragment.
            [&entry, &first],
            core::slice::from_ref(&fragment),
        )
        .unwrap();
        let environment = fixture.validated_environment();
        let EnvNode::List(children) = environment.get(environment.root()).unwrap() else {
            panic!("fixture root must remain a List");
        };
        assert_eq!(children.len(), 2, "covered naming selections must not be duplicated");
        assert_eq!(children[0], fragment.root());
        assert_eq!(environment.bindings().len(), 3);
        assert!(
            environment.get(unrelated).is_none(),
            "unreachable retained nodes are not imported"
        );
        for (selected, branch) in [(&first, Some(0)), (&second, Some(1)), (&entry, None)] {
            let key = selected.entry_key().unwrap();
            let request = EnvironmentWitnessRequest {
                root: environment.root(),
                key,
                limits: fixture.execution().opening_limits(),
            };
            let witness = fixture.source().get(request).unwrap().unwrap();
            if let Some(branch) = branch {
                assert_eq!(witness.path[0].selected_child, Some(0));
                assert_eq!(witness.path[1].node.commitment().unwrap(), fragment.root());
                assert_eq!(witness.path[1].selected_child, Some(0));
                assert_eq!(witness.path[2].selected_child, Some(0));
                assert_eq!(witness.path[3].selected_child, Some(branch));
            } else {
                assert_eq!(witness.path[0].selected_child, Some(1));
            }
            let resolved = witness.verify(request.root, key, request.limits).unwrap();
            assert_eq!(
                resolved.implementation_root(),
                selected.callables().selected_implementation(key).unwrap()
            );
        }
    }

    #[test]
    fn mounted_fragment_opening_budgets_include_the_outer_list() {
        fn wide_fragment(naming: &PackageSymbols, count: usize) -> Arc<ValidatedEnvironment> {
            let mut builder = EnvironmentBuilder::new(EnvironmentBuildLimits {
                max_submitted_nodes: 4,
                max_visits: count + 2,
                max_depth: 2,
                max_list_children: MAX_BINDINGS,
                max_encoded_bytes: MAX_ENCODED_BYTES,
                max_bindings: 1,
                max_storage_bytes: 4 * 1024 * 1024,
            });
            let key = naming.entry_key().unwrap();
            let leaf = builder
                .insert(EnvNode::Mast {
                    label: CanonicalLabel::text("entry").unwrap().commitment(),
                    implementation: naming.callables().selected_implementation(key).unwrap(),
                })
                .unwrap();
            let owner = builder
                .insert(EnvNode::Env {
                    label: naming.namespace_plan().home()[0].commitment(),
                    child: leaf,
                })
                .unwrap();
            let data = builder
                .insert(EnvNode::Data {
                    kind: 0,
                    label: CanonicalLabel::text("padding").unwrap().commitment(),
                    value: Word::new([Felt::from_u32(1); 4]),
                })
                .unwrap();
            let mut children = alloc::vec![data; count];
            children[0] = owner;
            let root = builder.insert(EnvNode::List(children)).unwrap();
            Arc::new(builder.finish(root).unwrap())
        }

        let selected = naming("entry", 1);
        let key = selected.entry_key().unwrap();
        let accepted = wide_fragment(&selected, MAX_BINDINGS - 1);
        let fixture =
            FixtureEnvironment::new_with_fragments(key, [&selected], &[accepted]).unwrap();
        let request = EnvironmentWitnessRequest {
            root: fixture.validated_environment().root(),
            key,
            limits: fixture.execution().opening_limits(),
        };
        let witness = fixture.source().get(request).unwrap().unwrap();
        assert_eq!(
            witness
                .path
                .iter()
                .map(|step| match &step.node {
                    EnvNode::List(children) => children.len(),
                    _ => 0,
                })
                .sum::<usize>(),
            MAX_BINDINGS
        );
        witness.verify(request.root, key, request.limits).unwrap();

        let rejected = wide_fragment(&selected, MAX_BINDINGS);
        let error = FixtureEnvironment::new_with_fragments(key, [&selected], &[rejected])
            .err()
            .expect("the mounted path exceeds the aggregate List child opening budget");
        assert!(alloc::format!("{error}").contains("TotalListChildren"));
    }

    #[test]
    fn conflicting_fragment_selection_and_duplicate_fragment_bindings_reject() {
        let selected = naming("first", 1);
        let conflict = naming("first", 7);
        let second = naming("second", 2);
        let (fragment, _) = branching_fragment(&selected, &second);
        let key = selected.entry_key().unwrap();
        assert!(
            FixtureEnvironment::new_with_fragments(key, [], core::slice::from_ref(&fragment))
                .is_err(),
            "the fixture entry must still have an explicitly selected implementation"
        );
        let error = FixtureEnvironment::new_with_fragments(
            key,
            [&conflict],
            core::slice::from_ref(&fragment),
        )
        .err()
        .expect("the exact covered implementation must agree");
        assert!(alloc::format!("{error}").contains("conflicting fixture fragment binding"));
        assert!(
            FixtureEnvironment::new_with_fragments(key, [&selected], &[fragment.clone(), fragment])
                .is_err()
        );
    }

    #[test]
    fn empty_fragment_constructor_preserves_the_original_root_and_path_shape() {
        let first = naming("first", 1);
        let second = naming("second", 2);
        let key = first.entry_key().unwrap();
        let original = FixtureEnvironment::new(key, [&first, &second]).unwrap();
        let explicit = FixtureEnvironment::new_with_fragments(key, [&first, &second], &[]).unwrap();
        assert_eq!(original.environment.root(), explicit.environment.root());
        assert_eq!(original.paths, explicit.paths);
        let expected_children = original
            .environment
            .bindings()
            .iter()
            .map(|binding| {
                let leaf = EnvNode::Mast {
                    label: binding.label(),
                    implementation: binding.implementation(),
                }
                .commitment()
                .unwrap();
                EnvNode::Env {
                    label: first.namespace_plan().home()[0].commitment(),
                    child: leaf,
                }
                .commitment()
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            original.environment.root(),
            EnvNode::List(expected_children).commitment().unwrap()
        );
        assert!(original.paths.values().all(|path| path.len() == 3));
    }

    #[test]
    fn identical_selections_deduplicate_and_distinct_keys_can_select_equal_code() {
        let first = naming("first", 1);
        let second = naming("second", 1);
        let entry = first.entry_key().unwrap();
        let fixture = FixtureEnvironment::new(entry, [&first, &first, &second]).unwrap();
        assert_eq!(fixture.environment.bindings().len(), 2);
        for key in [entry, second.entry_key().unwrap()] {
            let request = EnvironmentWitnessRequest {
                root: fixture.environment.root(),
                key,
                limits: fixture.execution().opening_limits(),
            };
            fixture
                .source()
                .get(request)
                .unwrap()
                .unwrap()
                .verify(request.root, request.key, request.limits)
                .unwrap();
        }
    }

    #[test]
    fn conflicting_implementations_for_one_key_reject() {
        let first = naming("same", 1);
        let second = naming("same", 2);
        assert!(FixtureEnvironment::new(first.entry_key().unwrap(), [&first, &second]).is_err());
    }

    #[test]
    fn source_respects_requested_root_key_and_construction_limits() {
        let first = naming("first", 1);
        let other = naming("unselected", 1);
        let fixture = FixtureEnvironment::new(first.entry_key().unwrap(), [&first]).unwrap();
        let source = fixture.source();
        let request = EnvironmentWitnessRequest {
            root: fixture.environment.root(),
            key: first.entry_key().unwrap(),
            limits: fixture.execution().opening_limits(),
        };
        assert!(
            source
                .get(EnvironmentWitnessRequest {
                    key: other.entry_key().unwrap(),
                    ..request
                })
                .unwrap()
                .is_none()
        );
        assert!(
            source
                .get(EnvironmentWitnessRequest {
                    root: EnvironmentRoot::new(Word::new([Felt::from_u32(99); 4])),
                    ..request
                })
                .unwrap()
                .is_none()
        );
        assert!(
            source
                .get(EnvironmentWitnessRequest {
                    limits: OpeningLimits { max_nodes: 0, ..request.limits },
                    ..request
                })
                .unwrap()
                .is_none()
        );
        assert!(
            source
                .get(EnvironmentWitnessRequest {
                    limits: OpeningLimits { max_storage_bytes: 0, ..request.limits },
                    ..request
                })
                .unwrap()
                .is_none()
        );
        assert!(source.get(request).unwrap().is_some());
    }
}
