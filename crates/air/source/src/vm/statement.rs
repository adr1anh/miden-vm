//! Authored public-input binding and external LogUp closure for the VM relation.
//!
//! Every per-AIR slice follows the canonical instance order in [`super::AIRS`]. The caller
//! initializes the challenger with the accepted relation digest before invoking [`observe`].

use alloc::vec::Vec;

use miden_core::{WORD_SIZE, field::ExtensionField, program::NUM_CLAIM_ELEMENTS};
use miden_stark::{
    air::{BaseAir, LiftedAir, ReductionError},
    lookup::Challenges,
};
use p3_challenger::CanObserve;

use super::{
    AIRS, Felt, MidenAir,
    inputs::{AUX_DEFERRED_ROOT, NUM_AUX_INPUTS, NUM_PUBLIC_VALUES},
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    trace,
};

/// The only statement-owned auxiliary values are the authenticated deferred root.
pub const fn max_aux_inputs() -> usize {
    NUM_AUX_INPUTS
}

/// Absorbs exactly one block: claim_hash[4] || deferred_root[4].
///
/// The canonical claim is K_entry || R_E || I || O under claim domain v2. All four AIR public
/// groups and the exact deferred-only aux4 shape are checked before deriving its commitment.
/// The caller preloads the accepted relation digest into the challenger.
pub fn observe<C: CanObserve<Felt>>(
    challenger: &mut C,
    air_inputs: &[Vec<Felt>],
    aux_inputs: &[Felt],
    _log_trace_heights: &[u8],
) {
    assert_eq!(air_inputs.len(), AIRS.len(), "unexpected AIR public-input count");
    for (air, public) in AIRS.iter().zip(air_inputs) {
        assert_eq!(public.len(), air.num_public_values(), "unexpected AIR public-value count");
    }
    let core_inputs = &air_inputs[0];
    assert_eq!(core_inputs.len(), NUM_PUBLIC_VALUES, "unexpected public-value count");
    assert_eq!(aux_inputs.len(), NUM_AUX_INPUTS, "expected exactly four deferred-root inputs");
    let deferred_root = &aux_inputs[AUX_DEFERRED_ROOT..AUX_DEFERRED_ROOT + WORD_SIZE];

    let mut claim = [Felt::ZERO; NUM_CLAIM_ELEMENTS];
    let io_len = NUM_PUBLIC_VALUES - WORD_SIZE;
    claim[..WORD_SIZE].copy_from_slice(&core_inputs[io_len..]);
    claim[WORD_SIZE..2 * WORD_SIZE].copy_from_slice(&air_inputs[1]);
    claim[2 * WORD_SIZE..].copy_from_slice(&core_inputs[..io_len]);
    let claim_hash = miden_core::program::claim_commitment(&claim);

    for &v in claim_hash.as_elements().iter().chain(deferred_root) {
        challenger.observe(v);
    }
}

/// Cross-AIR LogUp closure: each AIR commits `sigma_prime_i = sigma_i / n_i`, so the
/// trace-length-weighted sum `sum_i(n_i * sigma_prime_i)` plus the per-trace boundary
/// corrections must vanish. Boundary corrections are added once and are not trace-length
/// scaled. `aux_values` and `log_trace_heights` are parallel in instance order. `aux_inputs`
/// carries only the deferred root.
pub fn eval_external<EF: ExtensionField<Felt>>(
    challenges: &[EF],
    air_inputs: &[Vec<Felt>],
    aux_inputs: &[Felt],
    aux_values: &[&[EF]],
    log_trace_heights: &[u8],
) -> Result<Vec<EF>, ReductionError> {
    if air_inputs.len() != AIRS.len() {
        return Err(format!(
            "expected public inputs for {} AIRs, got {}",
            AIRS.len(),
            air_inputs.len()
        )
        .into());
    }
    for (air, public) in AIRS.iter().zip(air_inputs) {
        let expected = air.num_public_values();
        if public.len() != expected {
            return Err(format!(
                "{} expects {expected} public values, got {}",
                air.name(),
                public.len()
            )
            .into());
        }
    }
    if aux_values.len() != AIRS.len() {
        return Err(format!(
            "expected aux values for {} AIRs, got {}",
            AIRS.len(),
            aux_values.len()
        )
        .into());
    }
    if log_trace_heights.len() != AIRS.len() {
        return Err(format!(
            "expected log heights for {} AIRs, got {}",
            AIRS.len(),
            log_trace_heights.len()
        )
        .into());
    }
    if challenges.len() != trace::AUX_TRACE_RAND_CHALLENGES {
        return Err(format!(
            "expected {} aux trace challenges, got {}",
            trace::AUX_TRACE_RAND_CHALLENGES,
            challenges.len()
        )
        .into());
    }
    if air_inputs[0].len() != NUM_PUBLIC_VALUES {
        return Err(format!(
            "expected {NUM_PUBLIC_VALUES} public values, got {}",
            air_inputs[0].len()
        )
        .into());
    }
    if aux_inputs.len() != NUM_AUX_INPUTS {
        return Err(format!(
            "expected exactly {NUM_AUX_INPUTS} deferred-root inputs, got {}",
            aux_inputs.len()
        )
        .into());
    }
    let challenges =
        Challenges::<EF>::new(challenges[0], challenges[1], MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

    let mut weighted_aux_sum = EF::ZERO;
    let mut boundary_correction = EF::ZERO;
    for (((air, public), values), &log_height) in AIRS
        .iter()
        .copied()
        .zip(air_inputs)
        .zip(aux_values.iter())
        .zip(log_trace_heights)
    {
        boundary_correction += air.boundary_correction(&challenges, public, aux_inputs)?;
        let expected = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&air);
        if values.len() != expected {
            return Err(format!(
                "{} expects {expected} aux boundary values, got {}",
                air.name(),
                values.len()
            )
            .into());
        }

        let trace_length = 1_u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
            ReductionError::from(format!(
                "{} log trace height {log_height} does not fit in u64",
                air.name()
            ))
        })?;
        weighted_aux_sum += values.iter().copied().sum::<EF>() * Felt::new_unchecked(trace_length);
    }

    Ok(vec![weighted_aux_sum + boundary_correction])
}
