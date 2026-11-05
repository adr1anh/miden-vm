//! Exact local names and bounded openings for source-owned Wasm handler fixtures.

use std::sync::Arc;

use miden_assembly::{
    Assembler, DefaultSourceManager,
    ast::{Module, ModuleKind},
    testing::FixtureNamespace,
};
use miden_mast_package::{Package, PackageSymbols};
use miden_utils_testing::librarytree::FixtureEnvironment;

pub fn named_package(
    name: &str,
    source: &str,
) -> (Box<Package>, PackageSymbols, FixtureEnvironment) {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let module = Module::parser(Some(ModuleKind::Executable))
        .parse_str(None, source, source_manager.clone())
        .expect("fixture source parses");
    let mut namespace = FixtureNamespace::assembly_tests();
    namespace.add_module(&module).expect("fixture declarations have explicit names");
    let assembler = namespace
        .configure(Assembler::new(source_manager), [module.as_ref()])
        .expect("fixture namespace configures");
    let product = assembler
        .assemble_executable_modules(name.into(), module, [])
        .expect("fixture program assembles");
    let naming = product.naming().clone();
    let environment =
        FixtureEnvironment::new(naming.entry_key().expect("fixture entry is named"), [&naming])
            .expect("fixture environment validates");
    let package = product.into_artifact(true).expect("fixture package builds");
    (package, naming, environment)
}
