use miden_assembly::{
    NamespaceInputs, Report,
    ast::{Module, PathComponent},
    diagnostics::IntoDiagnostic,
    package::{CallableProcedurePath, NamespacePlan},
};

/// Selects the defining semantic source paths under an explicitly supplied compilation home.
///
/// Core uses the empty custom home and preserves its full `miden::core` path, including private
/// and generated procedures. Reexports acquire their defining binding during assembly.
pub fn source_namespace_inputs<'a>(
    home: NamespacePlan,
    modules: impl IntoIterator<Item = &'a Module>,
) -> Result<NamespaceInputs, Report> {
    let mut inputs = NamespaceInputs::new().with_namespace_plan(home);
    for module in modules {
        for procedure in module.procedures() {
            let declaration = module.path().join(procedure.name());
            let mut components = Vec::new();
            for component in declaration.components() {
                let component = component.into_diagnostic()?;
                if component != PathComponent::Root {
                    components.push(component.as_str().to_owned());
                }
            }
            let canonical =
                CallableProcedurePath::from_semantic_components(components).into_diagnostic()?;
            inputs = inputs.with_callable_path(declaration.into(), canonical)?;
        }
    }
    Ok(inputs)
}
