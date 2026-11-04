//! Test-only AIR adapters that vary core evaluation while preserving production metadata.

use alloc::{borrow::Cow, vec::Vec};

use miden_air::vm::{AIRS, MIDEN_AIR_COUNT, MidenAir, MidenMultiAir};
use miden_core::{Felt, field::ExtensionField, utils::RowMajorMatrix};
use miden_stark::{
    air::{
        BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, MultiAir, ReductionError,
        symbolic::AirLayout,
    },
    lookup,
};
use p3_air::BoundaryPublic;
use p3_challenger::CanObserve;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoreMode {
    Standard,
    Alternate,
    CoarseContext,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct ComparisonAir {
    inner: MidenAir,
    mode: CoreMode,
    compare_syscall_namespace: bool,
}

impl ComparisonAir {
    #[cfg(test)]
    pub(super) fn core(mode: CoreMode) -> Self {
        Self {
            inner: MidenAir::CORE,
            mode,
            compare_syscall_namespace: false,
        }
    }
}

impl ComparisonAir {
    fn without_syscall_namespace_check() -> Self {
        Self {
            inner: MidenAir::CHIPLETS,
            mode: CoreMode::Standard,
            compare_syscall_namespace: true,
        }
    }
}

impl BaseAir<Felt> for ComparisonAir {
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.inner.preprocessed_trace()
    }

    fn preprocessed_width(&self) -> usize {
        self.inner.preprocessed_width()
    }

    fn num_periodic_columns(&self) -> usize {
        self.inner.num_periodic_columns()
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        self.inner.periodic_columns()
    }

    fn periodic_values(&self, row_index: usize) -> Vec<Felt> {
        self.inner.periodic_values(row_index)
    }

    fn periodic_columns_matrix(&self) -> Option<RowMajorMatrix<Felt>> {
        self.inner.periodic_columns_matrix()
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        self.inner.main_next_row_columns()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.inner.preprocessed_next_row_columns()
    }

    fn num_constraints(&self) -> Option<usize> {
        self.inner.num_constraints()
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        self.inner.max_constraint_degree()
    }

    fn num_public_values(&self) -> usize {
        self.inner.num_public_values()
    }

    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        self.inner.public_boundary_io()
    }

    fn assumes_boolean_trace(&self) -> bool {
        self.inner.assumes_boolean_trace()
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for ComparisonAir {
    fn max_periodic_length(&self) -> usize {
        <MidenAir as LiftedAir<Felt, EF>>::max_periodic_length(&self.inner)
    }

    fn num_randomness(&self) -> usize {
        <MidenAir as LiftedAir<Felt, EF>>::num_randomness(&self.inner)
    }

    fn aux_width(&self) -> usize {
        <MidenAir as LiftedAir<Felt, EF>>::aux_width(&self.inner)
    }

    fn num_aux_values(&self) -> usize {
        <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&self.inner)
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        <MidenAir as LiftedAir<Felt, EF>>::build_aux_trace(
            &self.inner,
            main,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }

    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        <MidenAir as LiftedAir<Felt, EF>>::build_aux_trace_with_preprocessed(
            &self.inner,
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }

    fn air_layout(&self) -> AirLayout {
        <MidenAir as LiftedAir<Felt, EF>>::air_layout(&self.inner)
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        <MidenAir as LiftedAir<Felt, EF>>::constraint_degree(&self.inner)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        if self.inner == MidenAir::CORE {
            match self.mode {
                CoreMode::CoarseContext => super::comparison_context::eval(builder),
                mode => super::comparison_core::eval(builder, mode),
            }
        } else if self.inner == MidenAir::CHIPLETS && self.compare_syscall_namespace {
            super::comparison_library::eval(builder);
        } else {
            <MidenAir as LiftedAir<Felt, EF>>::eval(&self.inner, builder);
        }
    }
}

impl<LB> lookup::LookupAir<LB> for ComparisonAir
where
    LB: lookup::LookupBuilder<F = Felt>,
    MidenAir: lookup::LookupAir<LB>,
{
    fn num_columns(&self) -> usize {
        <MidenAir as lookup::LookupAir<LB>>::num_columns(&self.inner)
    }

    fn column_shape(&self) -> &[usize] {
        <MidenAir as lookup::LookupAir<LB>>::column_shape(&self.inner)
    }

    fn max_message_width(&self) -> usize {
        <MidenAir as lookup::LookupAir<LB>>::max_message_width(&self.inner)
    }

    fn num_bus_ids(&self) -> usize {
        <MidenAir as lookup::LookupAir<LB>>::num_bus_ids(&self.inner)
    }

    fn eval(&self, builder: &mut LB) {
        <MidenAir as lookup::LookupAir<LB>>::eval(&self.inner, builder)
    }

    fn eval_boundary<B>(&self, builder: &mut B)
    where
        B: lookup::BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        <MidenAir as lookup::LookupAir<LB>>::eval_boundary(&self.inner, builder)
    }
}

#[derive(Copy, Clone, Debug)]
pub(super) struct ComparisonMultiAir {
    airs: [ComparisonAir; MIDEN_AIR_COUNT],
}

impl ComparisonMultiAir {
    pub(super) fn new(mode: CoreMode) -> Self {
        Self {
            airs: AIRS.map(|inner| ComparisonAir {
                inner,
                mode,
                compare_syscall_namespace: false,
            }),
        }
    }
}

impl ComparisonMultiAir {
    pub(super) fn without_syscall_namespace_check() -> Self {
        let mut result = Self::new(CoreMode::Standard);
        result.airs[MidenAir::CHIPLETS.instance_index()] =
            ComparisonAir::without_syscall_namespace_check();
        result
    }
}

#[test]
fn comparison_context_policy_is_isolated() {
    super::comparison_context::assert_context_policy_is_isolated(ComparisonAir::core(
        CoreMode::CoarseContext,
    ));
}

#[test]
fn comparison_namespace_policy_is_isolated() {
    super::comparison_library::assert_namespace_policy_is_isolated(
        ComparisonAir::without_syscall_namespace_check(),
    );
}

impl<EF: ExtensionField<Felt>> MultiAir<Felt, EF> for ComparisonMultiAir {
    type Air = ComparisonAir;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }

    fn max_aux_inputs(&self) -> usize {
        <MidenMultiAir as MultiAir<Felt, EF>>::max_aux_inputs(&MidenMultiAir::new())
    }

    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        log_trace_heights: &[u8],
    ) {
        <MidenMultiAir as MultiAir<Felt, EF>>::observe(
            &MidenMultiAir::new(),
            challenger,
            air_inputs,
            aux_inputs,
            log_trace_heights,
        )
    }

    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        <MidenMultiAir as MultiAir<Felt, EF>>::eval_external(
            &MidenMultiAir::new(),
            challenges,
            air_inputs,
            aux_inputs,
            aux_values,
            log_trace_heights,
        )
    }
}
