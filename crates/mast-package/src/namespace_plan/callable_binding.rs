use miden_core::program::{LabelError, Namespace, ProcedureKey};

use crate::{CallableProcedurePath, NamespacePath};

/// A declaration's explicit canonical name, independent of its implementation and source aliases.
///
/// This derives a callable identity; it does not authenticate an environment binding or authorize
/// the supplied home. The owning profile must validate publisher and home policy separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureName {
    namespace_plan: NamespacePath,
    path: CallableProcedurePath,
    key: ProcedureKey,
    parent_namespace: Namespace,
}

impl ProcedureName {
    pub fn new(
        namespace_plan: NamespacePath,
        path: CallableProcedurePath,
    ) -> Result<Self, LabelError> {
        let key = namespace_plan.callable_procedure_key(&path)?;
        let parent_namespace = namespace_plan.callable_parent_namespace(&path)?;
        Ok(Self {
            namespace_plan,
            path,
            key,
            parent_namespace,
        })
    }

    pub fn namespace_plan(&self) -> &NamespacePath {
        &self.namespace_plan
    }

    pub fn path(&self) -> &CallableProcedurePath {
        &self.path
    }

    pub fn key(&self) -> ProcedureKey {
        self.key
    }

    pub fn parent_namespace(&self) -> Namespace {
        self.parent_namespace
    }
}
