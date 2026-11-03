use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::Arc,
};

use miden_assembly_syntax::diagnostics::{IntoDiagnostic, Report};
use miden_mast_package::{CallableProcedurePath, NamespacePlan};

use super::Assembler;
use crate::{CallableBinding, Path};

/// Raw namespace configuration for one assembly target, independent of code supply.
///
/// Local canonical paths use the caller home supplied here when compilation prebinds declarations.
/// Complete bindings retain their own homes. Defining source paths identify where to attach this
/// metadata; source namespaces and aliases never supply canonical names or authority.
///
/// The default is incomplete configuration, not a default namespace. Compilation still requires an
/// explicit caller home and canonical bindings for every retained callable. These inputs do not
/// perform home/profile or execution-environment admission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceInputs {
    namespace_plan: Option<NamespacePlan>,
    kernel_namespace_plan: Option<NamespacePlan>,
    declarations: BTreeMap<Arc<Path>, CallableInput>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CallableInput {
    LocalPath(CallableProcedurePath),
    Bound(CallableBinding),
}

impl NamespaceInputs {
    /// Creates incomplete inputs, ready for explicit homes and canonical declaration metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Supplies the home used to derive bindings for local canonical paths at compilation time.
    pub fn with_namespace_plan(mut self, plan: NamespacePlan) -> Self {
        self.namespace_plan = Some(plan);
        self
    }

    /// Returns the explicitly supplied caller home, if any.
    pub fn namespace_plan(&self) -> Option<&NamespacePlan> {
        self.namespace_plan.as_ref()
    }

    /// Sets or clears the complete kernel home as a raw input.
    ///
    /// This configures expected names during lowering; authenticated execution-environment
    /// bindings and the authorized complete kernel namespace determine actual syscall authority.
    pub fn with_kernel_namespace_plan(mut self, plan: Option<NamespacePlan>) -> Self {
        self.kernel_namespace_plan = plan;
        self
    }

    /// Returns the supplied kernel home without selecting build/runtime admission policy.
    pub fn kernel_namespace_plan(&self) -> Option<&NamespacePlan> {
        self.kernel_namespace_plan.as_ref()
    }

    /// Names a defining source declaration under the caller home supplied at compilation time.
    pub fn with_callable_path(
        self,
        declaration: Arc<Path>,
        canonical: CallableProcedurePath,
    ) -> Result<Self, Report> {
        self.with_callable_input(declaration, CallableInput::LocalPath(canonical))
    }

    /// Supplies a defining source declaration's complete canonical binding, including its home.
    pub fn with_callable_binding(
        self,
        declaration: Arc<Path>,
        binding: CallableBinding,
    ) -> Result<Self, Report> {
        self.with_callable_input(declaration, CallableInput::Bound(binding))
    }

    fn with_callable_input(
        mut self,
        declaration: Arc<Path>,
        input: CallableInput,
    ) -> Result<Self, Report> {
        match self.declarations.entry(declaration) {
            Entry::Vacant(entry) => {
                entry.insert(input);
            },
            Entry::Occupied(entry) => {
                return Err(Report::msg(format!(
                    "duplicate callable metadata for '{}'",
                    entry.key()
                )));
            },
        }
        Ok(self)
    }

    pub(super) fn into_plans(self) -> (Option<NamespacePlan>, Option<NamespacePlan>) {
        (self.namespace_plan, self.kernel_namespace_plan)
    }
}

impl Assembler {
    /// Attaches explicit canonical metadata to existing concrete declarations before codegen.
    pub(super) fn prebind_callables(&self) -> Result<(), Report> {
        let caller = self
            .namespace_inputs
            .namespace_plan()
            .ok_or_else(|| Report::msg("assembly requires an explicit caller NamespacePlan"))?;
        let mut seen = BTreeSet::new();
        for module in self.linker.modules() {
            for symbol in module.symbols() {
                if !symbol.is_procedure() {
                    continue;
                }
                let declaration: Arc<Path> = module.path().join(symbol.name()).into();
                let Some(input) = self.namespace_inputs.declarations.get(&declaration) else {
                    continue;
                };
                let binding = match input {
                    CallableInput::LocalPath(path) => {
                        CallableBinding::new(caller.clone(), path.clone()).into_diagnostic()?
                    },
                    CallableInput::Bound(binding) => binding.clone(),
                };
                symbol.bind_callable(binding).map_err(|_| {
                    Report::msg(format!("conflicting callable metadata for '{declaration}'"))
                })?;
                seen.insert(declaration);
            }
        }
        for declaration in self.namespace_inputs.declarations.keys() {
            if !seen.contains(declaration) {
                return Err(Report::msg(format!(
                    "callable metadata does not name a concrete declaration: '{declaration}'"
                )));
            }
        }
        self.validate_inline_pins()
    }
}

#[cfg(test)]
mod tests;
