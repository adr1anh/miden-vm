//! Explicit local naming and finite execution environments for manually assembled test programs.

use miden_assembly::{Assembler, AssemblyProduct, Parse, testing::FixtureNamespace};
use miden_core::program::Program;
use miden_mast_package::PackageNaming;
use miden_utils_testing::librarytree::FixtureEnvironment;

pub struct NamedProgram {
    pub program: Program,
    pub environment: FixtureEnvironment,
}

/// Uses the shared source-test convention for local definitions only. Imported inventories stay
/// exactly as supplied by their compiler/admission owner; source aliases never reinterpret them.
pub fn assemble(
    assembler: Assembler,
    name: &str,
    source: impl Parse,
    imports: &[&PackageNaming],
) -> NamedProgram {
    let root = source
        .parse(assembler.warnings_as_errors(), assembler.source_manager())
        .expect("manual test source must parse");
    let mut fixture = FixtureNamespace::assembly_tests();
    fixture
        .add_module(&root)
        .expect("manual test source must have canonical local definitions");
    let assembler = fixture
        .configure(assembler, [root.as_ref()])
        .expect("manual test source must have explicit fixture naming");
    let product = assembler
        .assemble_executable_modules(name.into(), root, [])
        .expect("manual test source must compile");
    from_product(product, imports)
}

/// Retains the product's exact metadata through code extraction and environment construction.
/// The fixture chooses this environment; it does not claim production profile admission.
pub fn from_product(product: AssemblyProduct, imports: &[&PackageNaming]) -> NamedProgram {
    let naming = product.naming().clone();
    let entry = naming.entry_key().expect("manual test program must have an explicit entry");
    let environment =
        FixtureEnvironment::new(entry, core::iter::once(&naming).chain(imports.iter().copied()))
            .expect("manual test canonical selections must form a valid finite environment");
    let program = product.into_program(true).expect("manual test code must match retained naming");
    NamedProgram { program, environment }
}
