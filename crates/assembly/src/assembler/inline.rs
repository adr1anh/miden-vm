use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    ast::{InvocationTarget, InvokeKind, SymbolResolution},
    debuginfo::{SourceSpan, Spanned},
    diagnostics::Report,
};
use miden_core::program::ImplementationRoot;
use miden_mast_package::debug_info::DebugSourceInlineCall;

use super::{Assembler, AssemblerError};
use crate::{
    GlobalItemIndex, ModuleIndex, Path,
    linker::{SymbolItem, SymbolResolutionContext},
    mast_forest_builder::{MastForestBuilder, MastNodeUse},
};

impl Assembler {
    /// Selects the exact implementation permitted for an imported `inline` target.
    ///
    /// `declaration` must name its concrete definition, rather than a source import/re-export
    /// alias. The selected body must have `implementation` as its root when it is expanded.
    /// Code supply and static linkage alone never select an implementation for inlining.
    /// This generic selection does not validate a Protocol release or registration.
    pub fn with_pinned_callable(
        mut self,
        declaration: Arc<Path>,
        implementation: ImplementationRoot,
    ) -> Result<Self, Report> {
        if self.inline_pins.contains_key(&declaration) {
            return Err(Report::msg(format!(
                "duplicate inline implementation pin for '{declaration}'"
            )));
        }
        self.inline_pins.insert(declaration, implementation);
        Ok(self)
    }

    pub(super) fn record_assembly_modules(&mut self, first_module: usize) {
        self.assembly_modules
            .extend((first_module..self.linker.modules().len()).map(ModuleIndex::new));
    }

    pub(super) fn validate_inline_pins(&self) -> Result<(), Report> {
        for declaration in self.inline_pins.keys() {
            let is_definition = self.linker.modules().iter().any(|module| {
                module.symbols().any(|symbol| {
                    symbol.is_procedure()
                        && module.path().join(symbol.name()).as_path() == declaration.as_ref()
                })
            });
            if !is_definition {
                return Err(Report::msg(format!(
                    "inline implementation pin does not name a concrete declaration: '{declaration}'"
                )));
            }
        }
        Ok(())
    }

    fn invalid_inline_target(
        &self,
        span: SourceSpan,
        reason: impl Into<alloc::string::String>,
    ) -> Report {
        AssemblerError::InvalidInlineTarget {
            span,
            source_file: self.source_manager.get(span.source_id()).ok(),
            reason: reason.into(),
        }
        .into()
    }

    /// Reuses a fixed callee's structural body without changing any inner callable keys.
    pub(crate) fn inline(
        &self,
        target: &InvocationTarget,
        caller: GlobalItemIndex,
        call_site: SourceSpan,
        mast_forest_builder: &mut MastForestBuilder,
        mut inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeUse, Report> {
        let context = SymbolResolutionContext {
            span: target.span(),
            module: caller.module,
            kind: Some(InvokeKind::Inline),
        };
        let gid = match self.linker.resolve_invoke_target(&context, target)? {
            SymbolResolution::Exact { gid, .. } => gid,
            SymbolResolution::MastRoot(_) => {
                return Err(self.invalid_inline_target(
                    target.span(),
                    "a procedure key does not select a fixed implementation; use a named local definition or an explicitly pinned import",
                ));
            },
            SymbolResolution::Module { .. }
            | SymbolResolution::External(_)
            | SymbolResolution::Local(_) => {
                unreachable!("invoke resolver returns concrete callable targets")
            },
        };
        let definition = self.linker[gid.module].path().join(self.linker[gid].name());
        let pin = self.inline_pins.get(definition.as_path());
        let is_local = self.assembly_modules.contains(&gid.module)
            && matches!(self.linker[gid].item(), SymbolItem::Procedure(_));
        if !is_local && pin.is_none() {
            return Err(self.invalid_inline_target(
                target.span(),
                format!(
                    "import '{definition}' has no explicit implementation pin; Latest imports cannot be inlined"
                ),
            ));
        }

        let procedure = mast_forest_builder.get_procedure(gid).ok_or_else(|| {
            self.invalid_inline_target(
                target.span(),
                format!("inline target '{definition}' has no selected implementation body"),
            )
        })?;
        if let Some(expected) = pin
            && expected.as_word() != &procedure.mast_root()
        {
            return Err(self.invalid_inline_target(
                target.span(),
                format!(
                    "inline implementation pin for '{definition}' expected {}, selected body has {}",
                    expected.as_word().to_hex(),
                    procedure.mast_root().to_hex(),
                ),
            ));
        }
        let body = procedure.body_node_use();
        if let Some(callee_idx) = mast_forest_builder.procedure_function_index(gid)
            && let Ok(location) = self.source_manager.location(call_site)
        {
            let loc_idx = mast_forest_builder.debug_info_mut().add_location(location);
            // Compiler-provided source frames enclose this explicit inline boundary; any
            // existing callee frames are retained further inside the cloned source tree.
            inline_calls.insert(
                0,
                DebugSourceInlineCall {
                    op_idx: 0,
                    op_end: 0,
                    callee_idx,
                    loc_idx,
                },
            );
        }
        mast_forest_builder.record_inline_calls(body, &inline_calls)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
