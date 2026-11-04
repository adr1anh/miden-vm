//! Maps primitive constraint emissions while preserving the wrapped builder's inputs.

use miden_stark::air::{
    AirBuilder, AirBuilderWithContext, ExtensionBuilder, PermutationAirBuilder,
};

/// Counts primitive assertions in one shared base/extension emission order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct EmissionCounts {
    pub(super) total: usize,
    pub(super) base: usize,
    pub(super) extension: usize,
}

/// Applies caller-supplied maps to constraints before forwarding them to `inner`.
///
/// Each callback receives the zero-based index in the shared emission order. Read access remains
/// delegated to `inner`, and each primitive assertion is mapped exactly once.
pub(super) struct EmissionAdapter<'a, AB, BaseMap, ExtMap> {
    inner: &'a mut AB,
    base_map: BaseMap,
    ext_map: ExtMap,
    counts: EmissionCounts,
}

impl<'a, AB, BaseMap, ExtMap> EmissionAdapter<'a, AB, BaseMap, ExtMap> {
    pub(super) fn new(inner: &'a mut AB, base_map: BaseMap, ext_map: ExtMap) -> Self {
        Self {
            inner,
            base_map,
            ext_map,
            counts: EmissionCounts::default(),
        }
    }

    pub(super) fn counts(&self) -> EmissionCounts {
        self.counts
    }
}

impl<AB, BaseMap, ExtMap> EmissionAdapter<'_, AB, BaseMap, ExtMap>
where
    AB: AirBuilder,
    BaseMap: FnMut(usize, AB::Expr) -> AB::Expr,
{
    fn map_base<I: Into<AB::Expr>>(&mut self, value: I) -> AB::Expr {
        let value = value.into();
        let index = self.counts.total;
        self.counts.total += 1;
        self.counts.base += 1;
        (self.base_map)(index, value)
    }
}

impl<AB, BaseMap, ExtMap> EmissionAdapter<'_, AB, BaseMap, ExtMap>
where
    AB: ExtensionBuilder,
    ExtMap: FnMut(usize, AB::ExprEF) -> AB::ExprEF,
{
    fn map_extension<I: Into<AB::ExprEF>>(&mut self, value: I) -> AB::ExprEF {
        let value = value.into();
        let index = self.counts.total;
        self.counts.total += 1;
        self.counts.extension += 1;
        (self.ext_map)(index, value)
    }
}

impl<AB, BaseMap, ExtMap> AirBuilder for EmissionAdapter<'_, AB, BaseMap, ExtMap>
where
    AB: AirBuilder,
    BaseMap: FnMut(usize, AB::Expr) -> AB::Expr,
{
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = AB::MainWindow;
    type PublicVar = AB::PublicVar;
    type PeriodicVar = AB::PeriodicVar;

    const WINDOW: usize = AB::WINDOW;

    fn main(&self) -> Self::MainWindow {
        self.inner.main()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        let value = self.map_base(value);
        self.inner.assert_zero(value);
    }

    fn assert_zeros<const N: usize, I: Into<Self::Expr>>(&mut self, values: [I; N]) {
        let values = values.map(|value| self.map_base(value));
        self.inner.assert_zeros(values);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}

impl<AB, BaseMap, ExtMap> ExtensionBuilder for EmissionAdapter<'_, AB, BaseMap, ExtMap>
where
    AB: ExtensionBuilder,
    BaseMap: FnMut(usize, AB::Expr) -> AB::Expr,
    ExtMap: FnMut(usize, AB::ExprEF) -> AB::ExprEF,
{
    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;

    fn assert_zero_ext<I>(&mut self, value: I)
    where
        I: Into<Self::ExprEF>,
    {
        let value = self.map_extension(value);
        self.inner.assert_zero_ext(value);
    }

    fn assert_zeros_ext<const N: usize, I>(&mut self, values: [I; N])
    where
        I: Into<Self::ExprEF>,
    {
        let values = values.map(|value| self.map_extension(value));
        self.inner.assert_zeros_ext(values);
    }
}

impl<AB, BaseMap, ExtMap> PermutationAirBuilder for EmissionAdapter<'_, AB, BaseMap, ExtMap>
where
    AB: PermutationAirBuilder,
    BaseMap: FnMut(usize, AB::Expr) -> AB::Expr,
    ExtMap: FnMut(usize, AB::ExprEF) -> AB::ExprEF,
{
    type MP = AB::MP;
    type RandomVar = AB::RandomVar;
    type PermutationVar = AB::PermutationVar;

    fn permutation(&self) -> Self::MP {
        self.inner.permutation()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.inner.permutation_values()
    }
}

impl<AB, BaseMap, ExtMap> AirBuilderWithContext for EmissionAdapter<'_, AB, BaseMap, ExtMap>
where
    AB: AirBuilderWithContext,
    BaseMap: FnMut(usize, AB::Expr) -> AB::Expr,
{
    type EvalContext = AB::EvalContext;

    fn eval_context(&self) -> &Self::EvalContext {
        self.inner.eval_context()
    }
}

/// Shares one mapped evaluator instantiation across the private four-lane comparison policies.
/// Keeping the policy data outside the mapper also preserves one primitive assertion order.
pub(super) fn eval_with_base_replacements<
    AB: miden_stark::air::LiftedAirBuilder<F = miden_core::Felt>,
>(
    air: miden_air::vm::MidenAir,
    builder: &mut AB,
    replacements: [(usize, AB::Expr); 4],
) {
    use miden_stark::air::LiftedAir;

    let mut replaced = 0;
    let mut adapter = EmissionAdapter::new(
        builder,
        |index: usize, original: AB::Expr| {
            if let Some((_, replacement)) = replacements.iter().find(|(slot, _)| *slot == index) {
                replaced += 1;
                replacement.clone()
            } else {
                original
            }
        },
        |_: usize, original: AB::ExprEF| original,
    );
    <miden_air::vm::MidenAir as LiftedAir<miden_core::Felt, AB::EF>>::eval(&air, &mut adapter);
    let counts = adapter.counts();
    assert!(replacements.iter().all(|(index, _)| *index < counts.total));
    assert_eq!(replaced, replacements.len());
}
