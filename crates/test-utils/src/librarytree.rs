//! Explicit, bounded execution environments for the shared source fixture convention.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use miden_core::program::{
    CanonicalLabel, EnvNode, EnvironmentBuildLimits, EnvironmentBuilder, EnvironmentRoot,
    ExecutionDescriptor, ImplementationRoot, ProcedureKey, ValidatedEnvironment,
};
use miden_mast_package::{CallableBinding, PackageNaming};
use miden_processor::{
    EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, ExecutionEnvironment, LedgerLimits, OpeningLimits, OpeningStep,
    ResolutionWitness, SessionLimits,
};

use super::Report;

// These are policies of this test helper, independent of any production admission profile.
const MAX_REQUESTS: usize = 1 << 20;
const MAX_BINDINGS: usize = 16_384;
const MAX_NAMING_RECORDS: usize = 262_144;
type FixturePath = Vec<(EnvironmentRoot, Option<usize>)>;

/// A fixture owner's exact code, canonical inventory and locally authorized finite environment.
#[derive(Clone)]
pub struct NamedProgram {
    pub program: miden_core::program::Program,
    pub environment: FixtureEnvironment,
    pub package: Arc<miden_mast_package::Package>,
    pub naming: Arc<PackageNaming>,
}

/// Selects the source-test naming convention for local definitions in the same parsing context.
/// Imported inventories remain exactly as supplied by their compiler/admission owner. This helper
/// chooses fixture authority only; it supplies no production home or publication admission.
#[cfg(feature = "std")]
pub fn assemble_fixture_program(
    assembler: miden_assembly::Assembler,
    name: &str,
    source: impl miden_assembly::Parse,
    imports: &[&PackageNaming],
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
    imports: &[&PackageNaming],
) -> NamedProgram {
    try_fixture_from_product(product, imports)
        .expect("fixture product and selections must form a valid named execution environment")
}

/// Fallible conversion for fixture consumers which report assembly or resource-policy errors.
pub fn try_fixture_from_product(
    product: miden_assembly::AssemblyProduct,
    imports: &[&PackageNaming],
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
        naming: impl IntoIterator<Item = &'a PackageNaming>,
    ) -> Result<Self, Report> {
        let mut selections = BTreeMap::<ProcedureKey, (CallableBinding, ImplementationRoot)>::new();
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
                        .is_none_or(|depth| depth > 256)
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
            max_submitted_nodes: 262_144,
            max_visits: 262_144,
            max_depth: 256,
            max_list_children: MAX_BINDINGS,
            max_encoded_bytes: 32 * 1024 * 1024,
            max_bindings: MAX_BINDINGS,
            max_storage_bytes: 128 * 1024 * 1024,
        });
        let mut children = Vec::new();
        let mut paths = BTreeMap::new();
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
            children.push(child);
            paths.insert(key, path);
        }
        let root = builder.insert(EnvNode::List(children)).map_err(Report::msg)?;
        for (slot, path) in paths.values_mut().enumerate() {
            path.insert(0, (root, Some(slot)));
        }
        let environment = Arc::new(builder.finish(root).map_err(Report::msg)?);
        let execution = ExecutionEnvironment::new(
            ExecutionDescriptor::new(entry, root),
            OpeningLimits {
                max_nodes: 257,
                max_depth: 256,
                max_list_children: MAX_BINDINGS,
                max_total_list_children: MAX_BINDINGS,
                max_encoded_bytes: 2 * 1024 * 1024,
                max_storage_bytes: 4 * 1024 * 1024,
            },
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

    /// Creates an independent source request budget for one host's execution.
    pub fn source(&self) -> Arc<dyn EnvironmentWitnessSource> {
        Arc::new(FixtureSource {
            fixture: self.clone(),
            requests: AtomicUsize::new(0),
        })
    }
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
        if path.len() > limits.max_nodes || path.len().saturating_sub(1) > limits.max_depth {
            return Ok(None);
        }
        let mut bytes = 0usize;
        let mut children_total = 0usize;
        let Some(mut storage) = path.len().checked_mul(size_of::<OpeningStep>()) else {
            return Ok(None);
        };
        let mut scratch = 0usize;
        for (root, _) in path {
            let node = self.fixture.environment.get(*root).expect("validated fixture preimage");
            let Ok(encoded_len) = node.encoded_len() else {
                return Ok(None);
            };
            let Some(next_bytes) = bytes.checked_add(encoded_len) else {
                return Ok(None);
            };
            bytes = next_bytes;
            if let EnvNode::List(children) = node {
                let Some(total) = children_total.checked_add(children.len()) else {
                    return Ok(None);
                };
                children_total = total;
                if children.len() > limits.max_list_children
                    || children_total > limits.max_total_list_children
                {
                    return Ok(None);
                }
                let Some(list_bytes) = children.len().checked_mul(size_of::<EnvironmentRoot>())
                else {
                    return Ok(None);
                };
                let Some(next_storage) = storage.checked_add(list_bytes) else {
                    return Ok(None);
                };
                storage = next_storage;
                scratch = scratch.max(list_bytes);
            }
            if bytes > limits.max_encoded_bytes
                || storage.checked_add(scratch).is_none_or(|size| size > limits.max_storage_bytes)
            {
                return Ok(None);
            }
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
    use miden_mast_package::{CallableProcedurePath, NamespacePlan, PackageCallables};

    use super::*;

    #[cfg(feature = "std")]
    #[test]
    fn fallible_fixture_conversion_reports_a_valid_products_environment_limit() {
        use miden_assembly::{Assembler, Parse, testing::FixtureNamespace};
        let assembler = Assembler::default();
        let root = Parse::parse("begin nop end", false, assembler.source_manager()).unwrap();
        let deep_home = NamespacePlan::new(alloc::vec![CanonicalLabel::text("deep").unwrap(); 257]);
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

    fn naming(name: &str, implementation: u32) -> PackageNaming {
        let binding = CallableBinding::new(
            NamespacePlan::new(alloc::vec![CanonicalLabel::text("selected-test-owner").unwrap()]),
            CallableProcedurePath::from_semantic_components(alloc::vec![name.into()]).unwrap(),
        )
        .unwrap();
        let key = binding.key();
        PackageNaming::new(
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
