//! Explicit fixture-owner naming and bounded openings for prover security regressions.

use alloc::sync::Arc;

use miden_assembly::{
    Assembler,
    ast::{Module, ModuleKind},
    package::{
        CallableProcedurePath, NamespacePath, PackageCallables, PackageSymbols, ProcedureName,
    },
    testing::FixtureNamespace,
};
use miden_core::program::{CanonicalLabel, ImplementationRoot, ProcedureKey, Program};
use miden_debug_types::DefaultSourceManager;
use miden_utils_testing::librarytree::FixtureEnvironment;

pub(crate) struct NamedSource {
    pub program: Program,
    pub naming: PackageSymbols,
    pub environment: FixtureEnvironment,
}

impl NamedSource {
    /// Selects the retained canonical name, independently of implementation digest/order.
    pub fn key(&self, procedure: &str) -> ProcedureKey {
        let mut keys = self.naming.callables().bindings().filter_map(|(&key, binding)| {
            (binding.path().components() == [miden_assembly::Path::EXEC_PATH, procedure])
                .then_some(key)
        });
        let key = keys.next().expect("fixture must retain the requested procedure name");
        assert!(keys.next().is_none(), "fixture procedure name must be unambiguous");
        key
    }
}

pub(crate) fn named_source(source: &str) -> NamedSource {
    let manager = Arc::new(DefaultSourceManager::default());
    let root = Module::parser(Some(ModuleKind::Executable))
        .parse_str(Some(miden_assembly::Path::exec_path()), source, manager.clone())
        .expect("fixture source must parse");
    let mut names = FixtureNamespace::assembly_tests();
    names.add_module(&root).expect("fixture names must validate");
    let assembler = names
        .configure(Assembler::new(manager), [root.as_ref()])
        .expect("fixture home must be configured");
    let product = assembler
        .assemble_executable_modules("prover-security-fixture".into(), root, [])
        .expect("fixture source must compile");
    let naming = product.naming().clone();
    let package = product.into_artifact(true).expect("fixture package must retain naming");
    let program = package.try_into_program(&naming).expect("fixture entry must select code");
    let environment = FixtureEnvironment::new(naming.entry_key().unwrap(), [&naming])
        .expect("fixture environment must validate");
    NamedSource { program, naming, environment }
}

/// Selects a standalone synthetic entry under an explicit test-owned home. The caller supplies
/// its name; its body supplies only D. These raw forests contain no runtime invocation targets.
pub(crate) fn raw_environment(program: &Program, entry_name: &str) -> FixtureEnvironment {
    let home = NamespacePath::new(alloc::vec![
        CanonicalLabel::text("miden-prover-security-fixtures").unwrap(),
    ]);
    let entry = ProcedureName::new(
        home.clone(),
        CallableProcedurePath::from_semantic_components(alloc::vec![entry_name.into()]).unwrap(),
    )
    .unwrap();
    let key = entry.key();
    let callables =
        PackageCallables::new([entry], [], [(key, ImplementationRoot::new(program.hash()))])
            .unwrap();
    let naming = PackageSymbols::new(home, callables, Some(key)).unwrap();
    FixtureEnvironment::new(key, [&naming]).expect("synthetic fixture environment must validate")
}
