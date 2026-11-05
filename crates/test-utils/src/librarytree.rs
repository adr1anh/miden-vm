//! Explicit, bounded execution environments for the shared source fixture convention.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId},
    program::{
        CanonicalLabel, EnvNode, EnvironmentBuildLimits, EnvironmentBuilder, EnvironmentRoot,
        ExecutionTarget, ImplementationRoot, Namespace, ProcedureKey, ValidatedEnvironment,
    },
};
use miden_mast_package::{
    CallableProcedurePath, CodePackage, NamespacePath, Package, PackageCallables,
    PackageProcedureOccurrence, PackageSymbols, ProcedureName, TargetType, Version,
};
use miden_processor::{
    EnvironmentSource, EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    LedgerLimits, OpeningError, OpeningLimits, OpeningResource, OpeningStep, ResolutionLimits,
    ResolutionWitness, SessionLimits,
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
// A local opening and its ordered collection item, before the collection prefix is attached.
type MountedPaths = BTreeMap<ProcedureKey, (usize, FixturePath)>;

/// Names every retained root under the explicit raw-test convention, independently of its digest.
///
/// The selected root is `raw-fixture/entry`; the other retained roots use `helper_<index>` labels.
/// Exact occurrence rows preserve distinct roots even when they have equal implementation digests.
/// This supplies checked code only. Tests still select their target, finite resolution policies
/// and witness source separately; no kernel or production home authority is implied.
pub fn fixture_code(forest: Arc<MastForest>, root: MastNodeId) -> CodePackage {
    assert!(
        forest.is_procedure_root(root),
        "fixture entry must be a retained procedure root"
    );
    let home = NamespacePath::new(alloc::vec![
        CanonicalLabel::text("raw-fixture").expect("fixed fixture home is valid"),
    ]);
    let mut bindings = Vec::new();
    let mut implementations = Vec::new();
    let mut occurrences = Vec::new();
    let mut entry = None;
    for (index, &node) in forest.procedure_roots().iter().enumerate() {
        let label = if node == root {
            "entry".into()
        } else {
            alloc::format!("helper_{index}")
        };
        let path = CallableProcedurePath::from_semantic_components(alloc::vec![label])
            .expect("fixed fixture procedure label is valid");
        let binding =
            ProcedureName::new(home.clone(), path).expect("fixed fixture procedure name is valid");
        let key = binding.key();
        if node == root {
            entry = Some(key);
        }
        bindings.push(binding);
        implementations.push((key, ImplementationRoot::new(forest[node].digest())));
        occurrences.push(PackageProcedureOccurrence::new(key, node, None));
    }
    let callables = PackageCallables::new(bindings, [], implementations)
        .expect("raw fixture labels must be unique");
    let symbols = Arc::new(
        PackageSymbols::new(home, callables, entry).expect("fixture entry must be declared"),
    );
    let package = Package::create(
        "raw-fixture".into(),
        Version::new(0, 0, 0),
        TargetType::Executable,
        forest,
        [],
        [],
        &symbols,
    )
    .expect("fixture symbols must cover every retained root");
    occurrences.sort_by_key(|row| row.key().as_word().as_bytes());
    let package = package
        .with_procedure_occurrences(occurrences, &symbols)
        .expect("fixture occurrences must identify their exact retained roots");
    CodePackage::new(Arc::new(package), symbols).expect("fixture package must match its symbols")
}

/// Inspects the fixture's exact entry occurrence without selecting the first root with its digest.
pub fn fixture_entry_root(code: &CodePackage) -> MastNodeId {
    let key = code.symbols().entry_key().expect("fixture code must have an explicit entry");
    code.package()
        .procedure_occurrence(key)
        .expect("fixture entry must retain an exact occurrence")
        .exec_node()
}

/// Inspects the implementation digest of the fixture's exact entry occurrence.
pub fn fixture_entry_digest(code: &CodePackage) -> Word {
    code.package().mast_forest()[fixture_entry_root(code)].digest()
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
) -> (CodePackage, FixtureEnvironment) {
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
) -> (CodePackage, FixtureEnvironment) {
    try_fixture_from_product(product, imports)
        .expect("fixture product and selections must form a valid named execution environment")
}

/// Fallible conversion for fixture consumers which report assembly or resource-policy errors.
pub fn try_fixture_from_product(
    product: miden_assembly::AssemblyProduct,
    imports: &[&PackageSymbols],
) -> Result<(CodePackage, FixtureEnvironment), Report> {
    let naming = product.naming();
    let entry = naming
        .entry_key()
        .ok_or_else(|| Report::msg("fixture program must have an explicit entry"))?;
    let environment =
        FixtureEnvironment::new(entry, core::iter::once(naming).chain(imports.iter().copied()))?;
    let code = product.into_code_package(true)?;
    Ok((code, environment))
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
    target: ExecutionTarget,
    resolution_limits: ResolutionLimits,
}

impl FixtureEnvironment {
    /// Builds and validates finite, unique bindings without deriving identity from code roots.
    pub fn new<'a>(
        entry: ProcedureKey,
        naming: impl IntoIterator<Item = &'a PackageSymbols>,
    ) -> Result<Self, Report> {
        Self::new_with_fragments(entry, naming, &[])
    }

    /// Mounts complete fragments first, in input order, then uncovered selections in key order.
    /// The collection splits at the midpoint recursively, without padding or namespace edges.
    /// A singleton is mounted directly; an empty collection is represented by an empty List.
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
                        .checked_add(binding.path().components().len().saturating_sub(1))
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
        let mut fragment_visits = 0usize;
        for fragment in fragments {
            fragment_visits = fragment_visits
                .checked_add(fragment.visits())
                .filter(|visits| *visits <= MAX_NODES)
                .ok_or_else(|| Report::msg("fixture fragment visit limit exceeded"))?;
            if fragment.max_depth() > MAX_DEPTH {
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
            // A fragment can contribute many keys, so retain the actual collection item index.
            paths.insert(key, (children.len(), path));
            children.push(child);
        }
        // Count physical occurrences, including every new collection branch. The builder also
        // enforces the complete traversal budget, including uncovered naming paths.
        fragment_visits
            .checked_add(collection_nodes(children.len()))
            .filter(|visits| *visits <= MAX_NODES)
            .ok_or_else(|| Report::msg("fixture fragment visit limit exceeded"))?;
        let root = collection_root(&mut builder, &children)?;
        let paths = paths
            .into_iter()
            .map(|(key, (slot, path))| {
                collection_path(&builder, root, children.len(), slot, path).map(|path| (key, path))
            })
            .collect::<Result<BTreeMap<_, _>, Report>>()?;
        let environment = Arc::new(builder.finish(root).map_err(Report::msg)?);
        // Every advertised binding must be resolvable under the fixture's own opening policy.
        // Mounted Lists retain their finite per-node and aggregate opening budgets.
        for path in paths.values() {
            preflight_path(&environment, path, FIXTURE_OPENING_LIMITS).map_err(Report::msg)?;
        }
        let resolution_limits = ResolutionLimits::new(
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
            target: ExecutionTarget::new(entry, root),
            resolution_limits,
        })
    }

    /// Returns the fixture owner's independently selected entry and environment root.
    pub fn target(&self) -> ExecutionTarget {
        self.target
    }

    /// Returns this helper's explicit finite resolution policies.
    pub fn resolution_limits(&self) -> ResolutionLimits {
        self.resolution_limits
    }

    /// Returns the complete locally constructed environment, including mounted fragments.
    pub fn validated_environment(&self) -> &ValidatedEnvironment {
        &self.environment
    }

    /// Creates an independent source request budget for one host's execution.
    pub fn source(&self) -> Arc<dyn EnvironmentSource> {
        Arc::new(FixtureSource {
            fixture: self.clone(),
            requests: AtomicUsize::new(0),
        })
    }
}

/// Number of collection occurrences added around the existing items.
fn collection_nodes(count: usize) -> usize {
    if count == 0 { 1 } else { count - 1 }
}

/// Stable midpoint splitting preserves item order and adds no namespace boundaries.
/// Recursion is bounded by ceil(log2(MAX_BINDINGS)), independently of fragment depth.
fn collection_root(
    builder: &mut EnvironmentBuilder,
    children: &[EnvironmentRoot],
) -> Result<EnvironmentRoot, Report> {
    match children {
        [] => builder.insert(EnvNode::List(Vec::new())).map_err(Report::msg),
        [root] => Ok(*root),
        _ => {
            let midpoint = children.len() / 2;
            let left = collection_root(builder, &children[..midpoint])?;
            let right = collection_root(builder, &children[midpoint..])?;
            builder.insert(EnvNode::Merkle { left, right }).map_err(Report::msg)
        },
    }
}

/// Prepends the item's actual collection route to its unchanged local opening.
fn collection_path(
    builder: &EnvironmentBuilder,
    mut root: EnvironmentRoot,
    mut count: usize,
    mut slot: usize,
    local: FixturePath,
) -> Result<FixturePath, Report> {
    let mut prefix = Vec::new();
    while count > 1 {
        let midpoint = count / 2;
        let EnvNode::Merkle { left, right } = builder.get(root).expect("built collection branch")
        else {
            unreachable!("non-singleton collection must be Merkle");
        };
        let branch = usize::from(slot >= midpoint);
        prefix.push((root, Some(branch)));
        if branch == 0 {
            root = *left;
            count = midpoint;
        } else {
            root = *right;
            count -= midpoint;
            slot -= midpoint;
        }
    }
    let nodes = prefix
        .len()
        .checked_add(local.len())
        .filter(|nodes| *nodes <= FIXTURE_OPENING_LIMITS.max_nodes)
        .ok_or_else(|| Report::msg("fixture mounted opening depth limit exceeded"))?;
    prefix
        .try_reserve_exact(nodes - prefix.len())
        .map_err(|_| Report::msg("fixture collection path allocation failed"))?;
    prefix.extend(local);
    Ok(prefix)
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
    paths: &mut MountedPaths,
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
                path.try_reserve_exact(frames.len())
                    .map_err(|_| Report::msg("fixture fragment path allocation failed"))?;
                path.extend(frames.iter().map(|frame| (frame.root, frame.selected_child)));
                paths.insert(key, (outer_slot, path));
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

impl EnvironmentSource for FixtureSource {
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
        let (code, environment) = assemble_fixture_program(
            miden_assembly::Assembler::default(),
            "shared_fixture",
            "proc helper push.5 end begin exec.helper swap drop end",
            &[],
        );
        code.package().check_naming(code.symbols()).unwrap();
        let target = environment.target();
        let entry = code.symbols().entry_key().unwrap();
        assert_eq!(target.entry_key(), entry);
        let implementation = code.symbols().callables().selected_implementation(entry).unwrap();
        assert_ne!(entry.into_word(), implementation.into_word());
        let request = EnvironmentWitnessRequest {
            root: target.environment_root(),
            key: entry,
            limits: environment.resolution_limits().opening_limits(),
        };
        let resolved = environment
            .source()
            .get(request)
            .unwrap()
            .unwrap()
            .verify(request.root, entry, request.limits)
            .unwrap();
        assert_eq!(resolved.implementation_root(), implementation);
        let mut host =
            miden_processor::DefaultHost::default().with_environment_source(environment.source());
        host.load_library(code).unwrap();
        let output = miden_processor::FastProcessor::new_with_options(
            miden_core::program::StackInputs::default(),
            miden_core::advice::AdviceInputs::default(),
            miden_processor::ExecutionOptions::default()
                .with_resolution_limits(environment.resolution_limits()),
        )
        .unwrap()
        .execute_sync(target, &mut host)
        .unwrap();
        assert_eq!(output.stack.get_element(0), Some(Felt::from_u32(5)));
    }

    fn naming(name: &str, implementation: u32) -> PackageSymbols {
        naming_at(
            NamespacePath::new(alloc::vec![CanonicalLabel::text("selected-test-owner").unwrap()]),
            &[name],
            implementation,
        )
    }

    fn naming_at(home: NamespacePath, path: &[&str], implementation: u32) -> PackageSymbols {
        let binding = ProcedureName::new(
            home,
            CallableProcedurePath::from_semantic_components(
                path.iter().map(|component| (*component).into()).collect(),
            )
            .unwrap(),
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

    #[test]
    fn collection_empty_singleton_and_uneven_shapes_are_explicit_and_balanced() {
        fn inspect(
            builder: &EnvironmentBuilder,
            root: EnvironmentRoot,
            leaves: &mut Vec<EnvironmentRoot>,
        ) -> (usize, usize) {
            if let EnvNode::Merkle { left, right } = builder.get(root).unwrap() {
                let (left_count, left_depth) = inspect(builder, *left, leaves);
                let (right_count, right_depth) = inspect(builder, *right, leaves);
                assert!(right_count == left_count || right_count == left_count + 1);
                (left_count + right_count, left_depth.max(right_depth) + 1)
            } else {
                leaves.push(root);
                (1, 0)
            }
        }
        for count in [0usize, 1, 2, 3, 5, 8, 17] {
            let mut builder = EnvironmentBuilder::new(EnvironmentBuildLimits {
                max_submitted_nodes: 34,
                max_visits: 34,
                max_depth: 5,
                max_list_children: 0,
                max_encoded_bytes: 4096,
                max_bindings: 0,
                max_storage_bytes: 64 * 1024,
            });
            let children = (0..count)
                .map(|index| {
                    builder
                        .insert(EnvNode::Data {
                            kind: 0,
                            label: CanonicalLabel::text(&alloc::format!("data_{index}"))
                                .unwrap()
                                .commitment(),
                            value: Word::default(),
                        })
                        .unwrap()
                })
                .collect::<Vec<_>>();
            let root = collection_root(&mut builder, &children).unwrap();
            if count == 0 {
                assert_eq!(builder.get(root), Some(&EnvNode::List(Vec::new())));
            } else {
                let mut actual = Vec::new();
                let (actual_count, depth) = inspect(&builder, root, &mut actual);
                assert_eq!(actual, children);
                assert_eq!(actual_count, count);
                assert_eq!(depth, count.next_power_of_two().ilog2() as usize);
                if count == 1 {
                    assert_eq!(root, children[0]);
                }
            }
            assert_eq!(builder.finish(root).unwrap().visits(), count + collection_nodes(count));
        }
        assert!(FixtureEnvironment::new(naming("entry", 1).entry_key().unwrap(), []).is_err());
    }

    #[test]
    fn deterministic_collections_preserve_every_binding_and_syscall_namespace() {
        let selected = [
            naming("first", 1),
            naming("second", 1),
            naming("third", 3),
            naming_at(NamespacePath::new(Vec::new()), &["kernel_export"], 4),
            naming_at(
                NamespacePath::new(alloc::vec![CanonicalLabel::text("home").unwrap()]),
                &["module", "helper"],
                5,
            ),
        ];
        let entry = selected[0].entry_key().unwrap();
        let fixture = FixtureEnvironment::new(entry, &selected).unwrap();
        let reordered =
            FixtureEnvironment::new(entry, selected.iter().rev().chain(selected.iter())).unwrap();
        assert_eq!(fixture.environment.root(), reordered.environment.root());
        assert_eq!(fixture.paths, reordered.paths);
        assert_eq!(fixture.environment.bindings().len(), selected.len());
        for naming in &selected {
            let key = naming.entry_key().unwrap();
            let canonical = naming.callables().binding(key).unwrap();
            let binding = fixture.environment.binding(key).unwrap();
            assert_eq!(binding.key(), canonical.key());
            assert_eq!(binding.namespace(), canonical.parent_namespace());
            assert_eq!(
                binding.label(),
                CanonicalLabel::text(canonical.path().components().last().unwrap())
                    .unwrap()
                    .commitment(),
            );
            assert_eq!(
                binding.implementation(),
                naming.callables().selected_implementation(key).unwrap()
            );
            let request = EnvironmentWitnessRequest {
                root: fixture.environment.root(),
                key,
                limits: fixture.resolution_limits().opening_limits(),
            };
            let witness = fixture.source().get(request).unwrap().unwrap();
            assert!(witness.path.iter().all(|step| !matches!(step.node, EnvNode::List(_))));
            let resolved = witness.verify(request.root, key, request.limits).unwrap();
            assert_eq!(resolved.namespace(), canonical.parent_namespace());
            assert_eq!(resolved.implementation_root(), binding.implementation());
        }
        assert_eq!(
            fixture
                .environment
                .binding(selected[3].entry_key().unwrap())
                .unwrap()
                .namespace(),
            Namespace::initial()
        );
        assert_ne!(fixture.environment.binding(entry).unwrap().namespace(), Namespace::initial());
    }

    #[test]
    fn openings_reuse_shared_merkle_prefixes_and_reject_changed_slots() {
        let selected = [naming("a", 1), naming("b", 2), naming("c", 3), naming("d", 4)];
        let fixture = FixtureEnvironment::new(selected[0].entry_key().unwrap(), &selected).unwrap();
        let mut ledger = miden_processor::OpeningLedger::new(
            fixture.environment.root(),
            fixture.resolution_limits().ledger_limits(),
        );
        let keys = fixture.paths.keys().copied().collect::<Vec<_>>();
        let request = |key| EnvironmentWitnessRequest {
            root: fixture.environment.root(),
            key,
            limits: fixture.resolution_limits().opening_limits(),
        };
        for (key, expected_occurrences) in [(keys[0], 4), (keys[1], 6), (keys[0], 6)] {
            let witness = fixture.source().get(request(key)).unwrap().unwrap();
            let binding = witness.verify(request(key).root, key, request(key).limits).unwrap();
            ledger.prepare(binding).unwrap().commit();
            assert_eq!(ledger.counters().occurrences, expected_occurrences);
            assert_eq!(ledger.counters().library_rows, 2 * expected_occurrences);
        }
        let mut altered = fixture.source().get(request(keys[0])).unwrap().unwrap();
        altered.path[0].selected_child = Some(1);
        assert!(altered.verify(request(keys[0]).root, keys[0], request(keys[0]).limits).is_err());
    }

    #[test]
    fn merkle_openings_enforce_exact_node_depth_byte_and_storage_boundaries() {
        let selected = [naming("a", 1), naming("b", 2), naming("c", 3)];
        let fixture = FixtureEnvironment::new(selected[0].entry_key().unwrap(), &selected).unwrap();
        let (&key, path) = fixture.paths.iter().max_by_key(|(_, path)| path.len()).unwrap();
        let encoded = path
            .iter()
            .map(|(root, _)| fixture.environment.get(*root).unwrap().encoded_len().unwrap())
            .sum();
        let exact = OpeningLimits {
            max_nodes: path.len(),
            max_depth: path.len() - 1,
            max_list_children: 0,
            max_total_list_children: 0,
            max_encoded_bytes: encoded,
            max_storage_bytes: path.len() * core::mem::size_of::<OpeningStep>(),
        };
        let source = fixture.source();
        let request = EnvironmentWitnessRequest {
            root: fixture.environment.root(),
            key,
            limits: exact,
        };
        let witness = source.get(request).unwrap().unwrap();
        witness.verify(request.root, key, exact).unwrap();
        for limits in [
            OpeningLimits { max_nodes: exact.max_nodes - 1, ..exact },
            OpeningLimits { max_depth: exact.max_depth - 1, ..exact },
            OpeningLimits {
                max_encoded_bytes: exact.max_encoded_bytes - 1,
                ..exact
            },
            OpeningLimits {
                max_storage_bytes: exact.max_storage_bytes - 1,
                ..exact
            },
        ] {
            assert!(source.get(EnvironmentWitnessRequest { limits, ..request }).unwrap().is_none());
        }
    }

    #[test]
    fn singleton_depth_limit_includes_no_wrapper_but_merkle_mounts_add_depth() {
        let selected = naming_at(
            NamespacePath::new(alloc::vec![CanonicalLabel::text("deep").unwrap(); MAX_DEPTH]),
            &["entry"],
            1,
        );
        let key = selected.entry_key().unwrap();
        let singleton = FixtureEnvironment::new(key, [&selected]).unwrap();
        assert_eq!(singleton.environment.max_depth(), MAX_DEPTH);
        assert_eq!(singleton.paths[&key].len(), MAX_DEPTH + 1);
        let fragment = singleton.environment.clone();
        let mounted = FixtureEnvironment::new_with_fragments(
            key,
            [&selected],
            core::slice::from_ref(&fragment),
        )
        .unwrap();
        assert_eq!(mounted.environment.root(), fragment.root());
        let shallow = naming("other", 2);
        assert!(FixtureEnvironment::new(key, [&selected, &shallow]).is_err());
        assert!(
            FixtureEnvironment::new_with_fragments(key, [&selected, &shallow], &[fragment])
                .is_err()
        );
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
        let EnvNode::Merkle { left, .. } = environment.get(environment.root()).unwrap() else {
            panic!("two collection items must form a Merkle pair");
        };
        assert_eq!(*left, fragment.root(), "covered selections stay in the first fragment");
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
                limits: fixture.resolution_limits().opening_limits(),
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
    fn uneven_collection_keeps_fragment_order_and_all_local_paths() {
        let first = naming("first", 1);
        let second = naming("second", 2);
        let third = naming("third", 3);
        let fourth = naming("fourth", 4);
        let entry = naming("entry", 5);
        let (left, _) = branching_fragment(&first, &second);
        let (right, _) = branching_fragment(&third, &fourth);
        let fixture = FixtureEnvironment::new_with_fragments(
            entry.entry_key().unwrap(),
            [&entry, &first, &third],
            &[left.clone(), right.clone()],
        )
        .unwrap();
        let EnvNode::Merkle { left: first_item, right: pair } =
            fixture.environment.get(fixture.environment.root()).unwrap()
        else {
            panic!("three items must split one and two");
        };
        assert_eq!(*first_item, left.root());
        let EnvNode::Merkle { left: second_item, .. } = fixture.environment.get(*pair).unwrap()
        else {
            panic!("the last two items must form a pair");
        };
        assert_eq!(*second_item, right.root());
        assert_eq!(fixture.environment.bindings().len(), 5);
        for (selected, prefix, fragment_root) in [
            (&first, 1, left.root()),
            (&second, 1, left.root()),
            (&third, 2, right.root()),
            (&fourth, 2, right.root()),
        ] {
            let key = selected.entry_key().unwrap();
            let request = EnvironmentWitnessRequest {
                root: fixture.environment.root(),
                key,
                limits: fixture.resolution_limits().opening_limits(),
            };
            let witness = fixture.source().get(request).unwrap().unwrap();
            assert_eq!(witness.path[prefix].node.commitment().unwrap(), fragment_root);
            let binding = witness.verify(request.root, key, request.limits).unwrap();
            assert_eq!(
                binding.namespace(),
                selected.callables().binding(key).unwrap().parent_namespace()
            );
            assert_eq!(
                binding.implementation_root(),
                selected.callables().selected_implementation(key).unwrap()
            );
        }
    }

    #[test]
    fn mounted_fragment_list_budgets_remain_finite_without_an_outer_list() {
        fn wide_fragment(naming: &PackageSymbols, nested: bool) -> Arc<ValidatedEnvironment> {
            let count = MAX_BINDINGS;
            let mut builder = EnvironmentBuilder::new(EnvironmentBuildLimits {
                max_submitted_nodes: 5,
                max_visits: count + 4,
                max_depth: 4,
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
            let mut root = builder.insert(EnvNode::List(children)).unwrap();
            if nested {
                root = builder.insert(EnvNode::List(alloc::vec![root])).unwrap();
            }
            Arc::new(builder.finish(root).unwrap())
        }

        let selected = naming("entry", 1);
        let key = selected.entry_key().unwrap();
        let accepted = wide_fragment(&selected, false);
        let fragment_root = accepted.root();
        let fixture =
            FixtureEnvironment::new_with_fragments(key, [&selected], &[accepted]).unwrap();
        let request = EnvironmentWitnessRequest {
            root: fixture.validated_environment().root(),
            key,
            limits: fixture.resolution_limits().opening_limits(),
        };
        assert_eq!(request.root, fragment_root, "a singleton adds no collection wrapper");
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

        let rejected = wide_fragment(&selected, true);
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
    fn empty_fragment_input_uses_the_same_deterministic_merkle_collection() {
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
            EnvNode::Merkle {
                left: expected_children[0],
                right: expected_children[1]
            }
            .commitment()
            .unwrap()
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
                limits: fixture.resolution_limits().opening_limits(),
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
            limits: fixture.resolution_limits().opening_limits(),
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
