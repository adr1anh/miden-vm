use alloc::sync::Arc;

use miden_assembly_syntax::{
    ast::{InvocationTarget, InvokeKind, Path, SymbolResolution},
    debuginfo::{SourceManager, SourceSpan, Span, Spanned},
    module::ItemInfo,
};

use crate::{
    GlobalItemIndex, LinkerError, ModuleIndex,
    linker::{
        Linker, SymbolItem,
        namespaces::{NamespaceGraph, ResolvedImports, ResolvedUse},
    },
};

// HELPER STRUCTS
// ================================================================================================

/// Represents the context in which symbols should be resolved.
///
/// A symbol may be resolved in different ways depending on where it is being referenced from, and
/// how it is being referenced.
#[derive(Debug, Clone)]
pub struct SymbolResolutionContext {
    /// The source span of the caller/referent
    pub span: SourceSpan,
    /// The "where", i.e. index of the caller/referent's module node in the [Linker] module graph.
    pub module: ModuleIndex,
    /// The "how", i.e. how the symbol is being referenced/invoked.
    ///
    /// This is primarily relevant for procedure invocations, particularly syscalls, as "local"
    /// names resolve in the kernel module, _not_ in the caller's module. Non-procedure symbols are
    /// always pure references.
    pub kind: Option<InvokeKind>,
}

impl SymbolResolutionContext {
    #[inline]
    pub fn in_syscall(&self) -> bool {
        matches!(self.kind, Some(InvokeKind::SysCall))
    }
}

// SYMBOL RESOLVER
// ================================================================================================

/// A [SymbolResolver] is used to resolve a procedure invocation target to its concrete definition.
///
/// Because modules can re-export/alias the procedures of modules they import, resolving the name of
/// a procedure can require multiple steps to reach the original concrete definition of the
/// procedure.
///
/// A resolution identifies the concrete definition without changing the invocation's access path.
/// Callers retain that path for subsequent resolution, since replacing a re-export alias with the
/// definition's path could discard the visibility granted by the alias.
///
/// The [SymbolResolver] encapsulates the tricky details of doing this, so that users of the
/// resolver need only provide a reference to the [Linker], a name they wish to resolve, and some
/// information about the caller necessary to determine the context in which the name should be
/// resolved.
pub struct SymbolResolver<'a> {
    /// The graph containing already-compiled and partially-resolved modules.
    graph: &'a Linker,
    /// Namespace graph for direct link-time path resolution.
    namespaces: Option<&'a NamespaceGraph>,
    /// Precomputed import resolutions for the current link pass.
    imports: Option<&'a ResolvedImports>,
}

impl<'a> SymbolResolver<'a> {
    /// Create a new [SymbolResolver] for the provided [Linker].
    pub fn new(graph: &'a Linker) -> Self {
        Self { graph, namespaces: None, imports: None }
    }

    /// Create a new [SymbolResolver] with precomputed namespace and import resolutions.
    pub fn with_namespaces(
        graph: &'a Linker,
        namespaces: &'a NamespaceGraph,
        imports: &'a ResolvedImports,
    ) -> Self {
        Self {
            graph,
            namespaces: Some(namespaces),
            imports: Some(imports),
        }
    }

    pub(crate) fn resolved_import(&self, owner: ModuleIndex, alias: &str) -> Option<ResolvedUse> {
        self.imports.and_then(|imports| imports.get(owner, alias))
    }

    fn to_symbol_resolution(&self, span: SourceSpan, resolved: ResolvedUse) -> SymbolResolution {
        match resolved {
            ResolvedUse::Module(id) => SymbolResolution::Module {
                id,
                path: Span::new(span, Arc::from(self.module_path(id))),
            },
            ResolvedUse::Item { id: gid, .. } => SymbolResolution::Exact {
                gid,
                path: Span::new(span, self.item_path(gid)),
            },
        }
    }

    fn source_file(
        &self,
        span: SourceSpan,
    ) -> Option<Arc<miden_assembly_syntax::debuginfo::SourceFile>> {
        self.source_manager().get(span.source_id()).ok()
    }

    fn is_procedure(&self, gid: GlobalItemIndex) -> bool {
        matches!(
            self.graph[gid].item(),
            SymbolItem::CallableDeclaration(_)
                | SymbolItem::Procedure(_)
                | SymbolItem::Compiled(ItemInfo::Procedure(_))
        )
    }

    fn is_constant(&self, gid: GlobalItemIndex) -> bool {
        matches!(
            self.graph[gid].item(),
            SymbolItem::Constant(_) | SymbolItem::Compiled(ItemInfo::Constant(_))
        )
    }

    fn is_type(&self, gid: GlobalItemIndex) -> bool {
        matches!(
            self.graph[gid].item(),
            SymbolItem::Type(_) | SymbolItem::Compiled(ItemInfo::Type(_))
        )
    }

    fn invalid_constant_ref(&self, span: SourceSpan) -> LinkerError {
        LinkerError::InvalidConstantRef {
            span,
            source_file: self.source_file(span),
        }
    }

    fn invalid_type_ref(&self, span: SourceSpan) -> LinkerError {
        LinkerError::InvalidTypeRef {
            span,
            source_file: self.source_file(span),
        }
    }

    fn ensure_procedure_target(
        &self,
        context: &SymbolResolutionContext,
        resolution: SymbolResolution,
    ) -> Result<SymbolResolution, LinkerError> {
        match resolution {
            resolution @ SymbolResolution::MastRoot(_) => Ok(resolution),
            resolution @ SymbolResolution::Exact { gid, .. } if self.is_procedure(gid) => {
                Ok(resolution)
            },
            SymbolResolution::Exact { path, .. } | SymbolResolution::Module { path, .. } => {
                Err(LinkerError::InvalidInvokeTarget {
                    span: context.span,
                    source_file: self.source_file(context.span),
                    path: path.into_inner(),
                })
            },
            SymbolResolution::Local(_) | SymbolResolution::External(_) => {
                unreachable!("link-time namespace resolution should produce exact ids")
            },
        }
    }

    pub fn resolve_constant_path(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<GlobalItemIndex, LinkerError> {
        match self.resolve_path(context, path)? {
            SymbolResolution::Exact { gid, .. } if self.is_constant(gid) => Ok(gid),
            SymbolResolution::Exact { .. }
            | SymbolResolution::Module { .. }
            | SymbolResolution::MastRoot(_) => Err(self.invalid_constant_ref(path.span())),
            SymbolResolution::Local(_) | SymbolResolution::External(_) => {
                unreachable!("link-time namespace resolution should produce exact ids")
            },
        }
    }

    pub fn resolve_type_path(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<GlobalItemIndex, LinkerError> {
        match self.resolve_path(context, path)? {
            SymbolResolution::Exact { gid, .. } if self.is_type(gid) => Ok(gid),
            SymbolResolution::Exact { .. }
            | SymbolResolution::Module { .. }
            | SymbolResolution::MastRoot(_) => Err(self.invalid_type_ref(path.span())),
            SymbolResolution::Local(_) | SymbolResolution::External(_) => {
                unreachable!("link-time namespace resolution should produce exact ids")
            },
        }
    }

    #[inline(always)]
    pub fn source_manager(&self) -> &dyn SourceManager {
        &self.graph.source_manager
    }

    #[inline(always)]
    pub fn source_manager_arc(&self) -> Arc<dyn SourceManager> {
        self.graph.source_manager.clone()
    }

    #[inline(always)]
    pub(crate) fn linker(&self) -> &Linker {
        self.graph
    }

    /// Resolve `target`, a possibly-resolved symbol reference, to a [SymbolResolution], using
    /// `context` as the context.
    pub fn resolve_invoke_target(
        &self,
        context: &SymbolResolutionContext,
        target: &InvocationTarget,
    ) -> Result<SymbolResolution, LinkerError> {
        let resolution = match target {
            // Existing digest-shaped syntax denotes K directly. Code availability and reverse-D
            // lookup cannot change the identity of a retained invocation.
            InvocationTarget::MastRoot(key) => SymbolResolution::MastRoot(*key),
            InvocationTarget::Symbol(symbol) => {
                let path = Path::from_ident(symbol);
                let mut context = context.clone();
                // Preserve the established unqualified syscall source alias even when a caller
                // has a same-named local symbol. This lookup adapter selects only a definition;
                // its explicit canonical binding and the full kernel plan govern authorization.
                if context.in_syscall()
                    && let Some(kernel) = self.graph.kernel_index
                    && (self.graph[kernel].get(symbol.as_str()).is_some()
                        || self.graph[kernel].get_import(symbol.as_str()).is_some())
                {
                    context.module = kernel;
                }
                self.resolve_path(&context, Span::new(symbol.span(), path.as_ref()))?
            },
            InvocationTarget::Path(path) => self.resolve_path(context, path.as_deref())?,
        };
        self.ensure_procedure_target(context, resolution)
    }

    pub fn resolve_path(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<SymbolResolution, LinkerError> {
        let resolved = self.resolve_reference(context, path)?;
        Ok(self.to_symbol_resolution(path.span(), resolved))
    }

    /// Resolves a reference while preserving visibility granted through re-export aliases.
    pub(crate) fn resolve_reference(
        &self,
        context: &SymbolResolutionContext,
        path: Span<&Path>,
    ) -> Result<ResolvedUse, LinkerError> {
        match (self.namespaces, self.imports) {
            (Some(namespaces), Some(imports)) => {
                namespaces.resolve_code_path(context.module, path, imports, self.graph)
            },
            _ => {
                let namespaces = NamespaceGraph::build(self.graph)?;
                let imports = namespaces.resolve_imports(self.graph)?;
                namespaces.resolve_code_path(context.module, path, &imports, self.graph)
            },
        }
    }

    pub fn resolve_local(
        &self,
        context: &SymbolResolutionContext,
        symbol: &str,
    ) -> Result<SymbolResolution, LinkerError> {
        let mut context = context.clone();
        if context.in_syscall() {
            // Resolve local names relative to the kernel
            match self.graph.kernel_index {
                Some(kernel) => context.module = kernel,
                None => {
                    return Err(LinkerError::InvalidSysCallTarget {
                        span: context.span,
                        source_file: self.source_manager().get(context.span.source_id()).ok(),
                        callee: Arc::from(Path::new(symbol)),
                    });
                },
            }
        }
        let path = Path::new(symbol);
        self.resolve_path(&context, Span::new(context.span, path))
    }

    #[inline]
    pub fn module_path(&self, module: ModuleIndex) -> &Path {
        self.graph[module].path()
    }

    pub fn item_path(&self, item: GlobalItemIndex) -> Arc<Path> {
        let module = &self.graph[item.module];
        let name = module[item.index].name();
        module.path().join(name).into()
    }
}
