use miden_assembly::{NamespaceInputs, Report, ast::Module, package::NamespacePath};

/// Selects the defining semantic source paths under an explicitly supplied compilation home.
///
/// Per-module benchmarks use the same defining-path convention as the configured core project.
/// Private procedures are included, and reexports acquire their defining binding during assembly.
pub fn source_namespace_inputs<'a>(
    home: NamespacePath,
    modules: impl IntoIterator<Item = &'a Module>,
) -> Result<NamespaceInputs, Report> {
    NamespaceInputs::new()
        .with_namespace_plan(home)
        .with_default_callable_paths(modules)
}
