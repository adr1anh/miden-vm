use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    string::ToString,
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    PathComponent,
    ast::{Item, Module},
    diagnostics::{IntoDiagnostic, Report},
};
use miden_core::program::Namespace;
#[cfg(any(feature = "std", test))]
use miden_core::{Word, chiplets::hasher};
use miden_mast_package::{CallableProcedurePath, NamespacePlan};

use super::Assembler;
use crate::{CallableBinding, Path, linker::SymbolResolutionContext};

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

    /// Commits to the exact requested naming configuration for compiler cache matching.
    ///
    /// This private, versioned cache format is not a library identity or an admission proof.
    /// Complete typed homes and semantic path components determine each binding's key without
    /// implementation roots. Defining source paths retain their exact input bytes, even when
    /// malformed, so cache matching cannot silently normalize invalid declaration metadata.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn cache_commitment(&self) -> Result<Word, Report> {
        let caller = self.require_namespace_plan()?;
        let bindings = self.resolved_bindings()?;
        let mut bytes = b"miden.assembly.namespace-inputs.v1".to_vec();
        append_cache_home(&mut bytes, caller)?;
        append_cache_len(&mut bytes, bindings.len())?;
        for (declaration, binding) in bindings {
            append_cache_bytes(&mut bytes, declaration.as_str().as_bytes())?;
            append_cache_home(&mut bytes, binding.namespace_plan())?;
            append_cache_len(&mut bytes, binding.path().components().len())?;
            for component in binding.path().components() {
                append_cache_bytes(&mut bytes, component.as_bytes())?;
            }
        }
        Ok(hasher::hash(&bytes))
    }

    /// Resolves local paths under the final caller home while preserving complete foreign bindings.
    pub(crate) fn resolved_bindings(&self) -> Result<BTreeMap<Arc<Path>, CallableBinding>, Report> {
        let caller = self.require_namespace_plan()?;
        self.declarations
            .iter()
            .map(|(declaration, input)| {
                let binding = match input {
                    CallableInput::LocalPath(path) => {
                        CallableBinding::new(caller.clone(), path.clone()).into_diagnostic()?
                    },
                    CallableInput::Bound(binding) => binding.clone(),
                };
                Ok((declaration.clone(), binding))
            })
            .collect()
    }

    fn require_namespace_plan(&self) -> Result<&NamespacePlan, Report> {
        self.namespace_plan()
            .ok_or_else(|| Report::msg("assembly requires an explicit caller NamespacePlan"))
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

    /// Names concrete source procedures by their semantic defining paths under the caller home.
    ///
    /// This is an explicit opt-in convention requiring an already supplied [`NamespacePlan`].
    /// Private helpers and executable entrypoints receive names; aliases and re-exports retain
    /// their defining procedures' bindings. Only the absolute source-root component is omitted
    /// from canonical paths. Existing local-path overrides and complete bindings are preserved.
    /// Source paths and the caller home make no publication or public-ownership claim.
    ///
    /// Duplicate modules or concrete declarations within the supplied cohort are rejected.
    /// Kernel modules require separate explicit placement of root exports and private helpers;
    /// this ordinary source convention cannot select their syscall-authorized bindings.
    pub fn with_default_callable_paths<'a>(
        mut self,
        modules: impl IntoIterator<Item = &'a Module>,
    ) -> Result<Self, Report> {
        self.require_namespace_plan()?;
        let mut seen_modules = BTreeSet::new();
        let mut seen_declarations = BTreeSet::new();
        for module in modules {
            if module.is_in_kernel() {
                return Err(Report::msg(
                    "kernel source requires explicit root-export and private-helper placement",
                ));
            }
            if !seen_modules.insert(module.path()) {
                return Err(Report::msg(format!(
                    "duplicate source module in callable naming cohort: '{}'",
                    module.path()
                )));
            }
            for item in module.items() {
                if !matches!(item, Item::Procedure(_)) {
                    continue;
                }
                let declaration: Arc<Path> = module.path().join(item.name()).into();
                if !seen_declarations.insert(declaration.clone()) {
                    return Err(Report::msg(format!(
                        "duplicate source callable declaration: '{declaration}'"
                    )));
                }
                if let Entry::Vacant(entry) = self.declarations.entry(declaration) {
                    let canonical = Self::default_callable_path(entry.key())?;
                    entry.insert(CallableInput::LocalPath(canonical));
                }
            }
        }
        Ok(self)
    }

    /// Names a kernel source cohort with public executable exports in the fixed root namespace.
    ///
    /// The first module is the root; public submodule edges and public item re-exports determine
    /// its public surface. Concrete exported definitions default to their defining leaf labels at
    /// root, while private definitions keep their full semantic paths under the explicitly chosen
    /// caller home. That home may itself be empty when the resulting helper parent is a child
    /// namespace. Compatible explicit local paths and complete bindings are preserved.
    ///
    /// Item aliases resolve through `base` and retain the actual defining binding. An imported
    /// callable must already have explicit canonical metadata, and a public imported binding must
    /// already be at root. This convention never relocates an imported callable or gives an alias
    /// a second key. Existing bindings of inherited source definitions, including private helpers,
    /// are retained independently of this cohort's caller home. This convention does not change
    /// runtime syscall authorization or perform home admission.
    ///
    /// Duplicate cohort modules/declarations, incompatible overrides, and canonical collisions
    /// with other definitions or imported bindings are rejected before defaults are returned.
    pub fn with_kernel_root_exports(
        mut self,
        base: &Assembler,
        modules: &[&Module],
    ) -> Result<Self, Report> {
        let caller = self.require_namespace_plan()?.clone();
        let Some(root) = modules.first() else {
            return Err(Report::msg("kernel callable naming requires a root module"));
        };
        let mut cohort = BTreeMap::new();
        let mut concrete = BTreeMap::new();
        for module in modules {
            let path = absolute_callable_path(module.path())?;
            if cohort.insert(path, *module).is_some() {
                return Err(Report::msg(format!(
                    "duplicate source module in callable naming cohort: '{}'",
                    module.path()
                )));
            }
            for procedure in module.procedures() {
                let declaration = absolute_callable_path(&module.path().join(procedure.name()))?;
                if concrete.insert(declaration.clone(), procedure.name()).is_some() {
                    return Err(Report::msg(format!(
                        "duplicate source callable declaration: '{declaration}'"
                    )));
                }
            }
        }

        let mut public_modules = BTreeSet::new();
        let mut pending = vec![absolute_callable_path(root.path())?];
        while let Some(path) = pending.pop() {
            if !public_modules.insert(path.clone()) {
                continue;
            }
            if let Some(module) = cohort.get(&path) {
                for child in
                    module.submodules().iter().filter(|child| child.visibility.is_exported())
                {
                    pending.push(absolute_callable_path(&module.path().join(&child.name))?);
                }
            }
        }
        let mut exports = BTreeSet::new();
        for module in modules {
            if public_modules.contains(&absolute_callable_path(module.path())?) {
                for procedure in module.procedures().filter(|proc| proc.visibility().is_exported())
                {
                    exports.insert(absolute_callable_path(&module.path().join(procedure.name()))?);
                }
            }
        }

        let resolved = self.resolved_bindings()?;
        let base_bindings = if base.namespace_plan().is_some() {
            base.namespace_inputs().resolved_bindings()?
        } else {
            base.namespace_inputs()
                .declarations
                .iter()
                .filter_map(|(declaration, input)| match input {
                    CallableInput::Bound(binding) => Some((declaration.clone(), binding.clone())),
                    CallableInput::LocalPath(_) => None,
                })
                .collect()
        };
        let mut inherited_bindings = BTreeMap::new();
        if modules.iter().any(|module| {
            public_modules.contains(module.path())
                && module.imports().any(|import| import.visibility().is_exported())
        }) {
            // Preserve the linker's visibility, import validity, and alias-cycle diagnostics.
            let mut linker = base.linker.clone();
            linker.link_modules(modules.iter().map(|module| Box::new((**module).clone())))?;
            for module in linker.modules() {
                if !public_modules.contains(module.path()) {
                    continue;
                }
                for import in module.imports().filter(|import| import.visibility().is_exported()) {
                    let context = SymbolResolutionContext {
                        span: import.span(),
                        module: module.id(),
                        kind: None,
                    };
                    let path = module.path().join(import.local_name());
                    if let Some(gid) = linker.resolve_path(&context, &path)?.into_global_id()
                        && linker[gid].is_procedure()
                    {
                        let declaration = absolute_callable_path(
                            &linker[gid.module].path().join(linker[gid].name()),
                        )?;
                        exports.insert(declaration.clone());
                        if concrete.contains_key(&declaration) {
                            continue;
                        }
                        let actual = linker[gid]
                            .callable_binding()
                            .or_else(|| base_bindings.get(&declaration))
                            .ok_or_else(|| Report::msg(format!(
                                "missing canonical callable binding for imported kernel export '{declaration}'"
                            )))?;
                        if resolved.get(&declaration).is_some_and(|binding| binding != actual) {
                            return Err(Report::msg(format!(
                                "conflicting callable metadata for imported kernel export '{declaration}'"
                            )));
                        }
                        validate_kernel_binding(&declaration, actual, true)?;
                        inherited_bindings.insert(declaration, actual.clone());
                    }
                }
            }
        }

        // Required package inventories also reserve bindings which have no source descriptor.
        // Multiple imported aliases may refer to the same key; a new concrete definition may not.
        let mut reserved = BTreeSet::new();
        for module in base.linker.modules() {
            for symbol in module.symbols().filter(|symbol| symbol.is_procedure()) {
                let declaration = absolute_callable_path(&module.path().join(symbol.name()))?;
                if let Some(binding) =
                    symbol.callable_binding().or_else(|| base_bindings.get(&declaration))
                {
                    if resolved.get(&declaration).is_some_and(|requested| requested != binding) {
                        return Err(Report::msg(format!(
                            "conflicting callable metadata for imported kernel declaration '{declaration}'"
                        )));
                    }
                    reserved.insert(binding.key());
                    if !module.is_mast() {
                        inherited_bindings.insert(declaration, binding.clone());
                    }
                }
            }
        }
        for library in base.linker.libraries() {
            reserved.extend(library.naming().callables().bindings().map(|(&key, _)| key));
        }
        if let Some(naming) = base.linker.kernel_naming() {
            reserved.extend(naming.callables().bindings().map(|(&key, _)| key));
        }
        for (declaration, binding) in resolved.iter().chain(inherited_bindings.iter()) {
            if !concrete.contains_key(declaration) {
                reserved.insert(binding.key());
            }
        }

        let mut defaults = Vec::new();
        for (declaration, name) in concrete {
            let exported = exports.contains(&declaration);
            let binding = if let Some(binding) = resolved.get(&declaration) {
                binding.clone()
            } else if exported {
                let canonical =
                    CallableProcedurePath::from_semantic_components(vec![name.to_string()])
                        .into_diagnostic()?;
                CallableBinding::new(NamespacePlan::new(vec![]), canonical).into_diagnostic()?
            } else {
                CallableBinding::new(caller.clone(), Self::default_callable_path(&declaration)?)
                    .into_diagnostic()?
            };
            validate_kernel_binding(&declaration, &binding, exported)?;
            if !reserved.insert(binding.key()) {
                return Err(Report::msg(format!(
                    "kernel callable naming has conflicting canonical bindings for '{declaration}'"
                )));
            }
            let input = if exported {
                CallableInput::Bound(binding)
            } else {
                CallableInput::LocalPath(binding.path().clone())
            };
            defaults.push((declaration, input));
        }
        for (declaration, input) in defaults {
            self.declarations.entry(declaration).or_insert(input);
        }
        // An inherited AST symbol may still be unbound until the final compilation. Retain its
        // exact selected binding, including private helpers, across replacement of base inputs.
        // These are foreign to this cohort: changing its caller home must never rebase them.
        for (declaration, binding) in inherited_bindings {
            self.declarations.insert(declaration, CallableInput::Bound(binding));
        }
        Ok(self)
    }

    /// Shared defining-path lowering for production opt-in and explicit source fixtures.
    pub(crate) fn default_callable_path(
        declaration: &Path,
    ) -> Result<CallableProcedurePath, Report> {
        let mut components = Vec::new();
        for component in declaration.components() {
            let component = component.into_diagnostic()?;
            if !matches!(component, PathComponent::Root) {
                components.push(component.as_str().to_string());
            }
        }
        CallableProcedurePath::from_semantic_components(components).into_diagnostic()
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

    pub(super) fn into_namespace_plan(self) -> Option<NamespacePlan> {
        self.namespace_plan
    }
}

fn absolute_callable_path(path: &Path) -> Result<Arc<Path>, Report> {
    let path = path.to_absolute().into_diagnostic()?;
    Ok(Arc::from(path.as_ref()))
}

fn validate_kernel_binding(
    declaration: &Path,
    binding: &CallableBinding,
    exported: bool,
) -> Result<(), Report> {
    let at_root = binding.parent_namespace() == Namespace::initial();
    if exported && !at_root {
        Err(Report::msg(format!(
            "kernel export '{declaration}' must be in the fixed root syscall namespace"
        )))
    } else if !exported && at_root {
        Err(Report::msg(format!(
            "retained kernel helper '{declaration}' must be beneath a child Env namespace"
        )))
    } else {
        Ok(())
    }
}

#[cfg(any(feature = "std", test))]
fn append_cache_len(bytes: &mut Vec<u8>, len: usize) -> Result<(), Report> {
    let len =
        u64::try_from(len).map_err(|_| Report::msg("namespace cache input length exceeds u64"))?;
    bytes.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

#[cfg(any(feature = "std", test))]
fn append_cache_bytes(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), Report> {
    append_cache_len(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

#[cfg(any(feature = "std", test))]
fn append_cache_home(bytes: &mut Vec<u8>, plan: &NamespacePlan) -> Result<(), Report> {
    append_cache_len(bytes, plan.home().len())?;
    for label in plan.home() {
        append_cache_bytes(bytes, label.as_bytes())?;
    }
    Ok(())
}

impl Assembler {
    /// Exact project-cache inputs once target naming and all package inputs have been selected.
    ///
    /// Inherited source modules and declaration-only inputs currently have no complete persisted
    /// snapshot. They remain compilable, but cannot justify artifact reuse. In particular, AST
    /// equality/printing omits advice and is not a cache identity.
    #[cfg(feature = "std")]
    pub(crate) fn project_cache_commitment(
        &self,
        profile_name: &str,
    ) -> Result<Option<Word>, Report> {
        if self.linker.modules().iter().any(|module| {
            !module.is_mast()
                || module.symbols().any(|symbol| {
                    matches!(symbol.item(), crate::linker::SymbolItem::CallableDeclaration(_))
                })
        }) {
            return Ok(None);
        }
        let mut bytes = b"miden.assembly.project-inputs.v1".to_vec();
        bytes.extend_from_slice(&self.namespace_inputs.cache_commitment()?.as_bytes());
        append_cache_bytes(&mut bytes, profile_name.as_bytes())?;
        bytes.extend_from_slice(&[
            u8::from(self.emit_debug_info),
            u8::from(self.trim_paths),
            u8::from(self.warnings_as_errors),
        ]);
        append_cache_len(&mut bytes, self.inline_pins.len())?;
        for (path, implementation) in &self.inline_pins {
            append_cache_bytes(&mut bytes, path.as_str().as_bytes())?;
            bytes.extend_from_slice(&implementation.as_word().as_bytes());
        }
        let libraries = self.linker.libraries().collect::<Vec<_>>();
        append_cache_len(&mut bytes, libraries.len())?;
        for library in libraries {
            // The full artifact includes debug/other sections as well as exact required naming.
            bytes.extend_from_slice(&library.package.commitment().as_bytes());
            bytes.push(match library.linkage {
                miden_project::Linkage::Static => 0,
                miden_project::Linkage::Dynamic => 1,
            });
        }
        match self.linker.kernel_package() {
            Some(kernel) => {
                bytes.push(1);
                bytes.extend_from_slice(&kernel.commitment().as_bytes());
            },
            None => bytes.push(0),
        }
        Ok(Some(hasher::hash(&bytes)))
    }

    /// Attaches explicit canonical metadata to existing concrete declarations before codegen.
    pub(super) fn prebind_callables(&self) -> Result<(), Report> {
        let bindings = self.namespace_inputs.resolved_bindings()?;
        let mut seen = BTreeSet::new();
        for module in self.linker.modules() {
            for symbol in module.symbols() {
                if !symbol.is_procedure() {
                    continue;
                }
                let declaration: Arc<Path> = module.path().join(symbol.name()).into();
                let Some(binding) = bindings.get(&declaration) else {
                    continue;
                };
                symbol.bind_callable(binding.clone()).map_err(|_| {
                    Report::msg(format!("conflicting callable metadata for '{declaration}'"))
                })?;
                seen.insert(declaration);
            }
        }
        for declaration in bindings.keys() {
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
