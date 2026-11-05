use alloc::vec;

use super::{AdviceError, AdviceMap, AdviceProvider};
use crate::{AdviceInputs, ExecutionOptions, Felt, Word};

fn key(seed: u32) -> Word {
    [Felt::from_u32(seed); 4].into()
}

#[test]
fn preparation_reports_first_conflict_before_budget_without_mutation() {
    let mut provider = AdviceProvider::new(
        AdviceInputs::default().with_map([(key(2), vec![Felt::ONE]), (key(3), vec![Felt::ONE])]),
        &ExecutionOptions::default(),
    )
    .unwrap();
    let current = provider.advice_size_bytes;
    provider
        .set_options(&ExecutionOptions::default().with_max_advice_size_bytes(current))
        .unwrap();
    let before = provider.fingerprint();
    let other: AdviceMap = [
        (key(3), vec![Felt::ZERO]),
        (key(1), vec![Felt::ONE]),
        (key(2), vec![Felt::ZERO]),
    ]
    .into_iter()
    .collect();

    let Err(error) = provider.prepare_extend_map(&other) else {
        panic!("conflicting extension must fail");
    };
    assert!(matches!(
        error,
        AdviceError::MapKeyAlreadyPresent { key: actual, prev_values, new_values }
            if actual == key(2) && prev_values == vec![Felt::ONE] && new_values == vec![Felt::ZERO]
    ));
    assert_eq!(provider.fingerprint(), before);
    assert_eq!(provider.advice_size_bytes, current);
    assert_eq!(provider.max_advice_size_bytes, current);
}

#[test]
fn preparation_rejects_combined_budget_without_mutation() {
    let mut provider = AdviceProvider::default();
    provider.push_stack(Felt::ONE).unwrap();
    let current = provider.advice_size_bytes;
    let entry_bytes = AdviceProvider::map_entry_bytes(1).unwrap();
    let max = current + entry_bytes;
    provider
        .set_options(&ExecutionOptions::default().with_max_advice_size_bytes(max))
        .unwrap();
    let before = provider.fingerprint();
    let other: AdviceMap =
        [(key(1), vec![Felt::ONE]), (key(2), vec![Felt::ZERO])].into_iter().collect();

    let Err(error) = provider.prepare_extend_map(&other) else {
        panic!("over-budget extension must fail");
    };
    assert!(matches!(
        error,
        AdviceError::SizeBudgetExceeded { current: actual, added, max: limit }
            if actual == current && added == 2 * entry_bytes && limit == max
    ));
    assert_eq!(provider.fingerprint(), before);
    assert_eq!(provider.advice_size_bytes, current);
    assert_eq!(provider.max_advice_size_bytes, max);
}

#[test]
fn dropping_preparation_leaves_contents_and_capacity_unchanged() {
    let mut provider = AdviceProvider::default();
    let current = provider.advice_size_bytes;
    let entry_bytes = AdviceProvider::map_entry_bytes(1).unwrap();
    let max = current + entry_bytes;
    provider
        .set_options(&ExecutionOptions::default().with_max_advice_size_bytes(max))
        .unwrap();
    let before = provider.fingerprint();
    let other: AdviceMap = [(key(1), vec![Felt::ONE])].into_iter().collect();

    {
        let _prepared = provider.prepare_extend_map(&other).unwrap();
    }
    assert_eq!(provider.fingerprint(), before);
    assert_eq!(provider.advice_size_bytes, current);
    assert_eq!(provider.max_advice_size_bytes, max);

    // Dropped preparation did not consume the capacity needed by the same extension.
    provider.prepare_extend_map(&other).unwrap().commit();
    assert_eq!(provider.get_mapped_values(&key(1)), Some([Felt::ONE].as_slice()));
    assert_eq!(provider.advice_size_bytes, max);
    assert!(matches!(
        provider.push_stack(Felt::ONE),
        Err(AdviceError::SizeBudgetExceeded { .. })
    ));
}

#[test]
fn commit_charges_only_new_entries_and_repeated_extension_is_idempotent() {
    let mut provider = AdviceProvider::new(
        AdviceInputs::default().with_map([(key(1), vec![Felt::ONE]), (key(3), vec![Felt::ZERO])]),
        &ExecutionOptions::default(),
    )
    .unwrap();
    let max = provider.advice_size_bytes + AdviceProvider::map_entry_bytes(2).unwrap();
    provider
        .set_options(&ExecutionOptions::default().with_max_advice_size_bytes(max))
        .unwrap();
    let other: AdviceMap = [(key(1), vec![Felt::ONE]), (key(2), vec![Felt::ONE, Felt::ZERO])]
        .into_iter()
        .collect();

    provider.prepare_extend_map(&other).unwrap().commit();
    assert_eq!(provider.advice_size_bytes, max);
    assert_eq!(provider.advice_size_bytes, provider.compute_advice_size_bytes().unwrap());
    assert_eq!(provider.get_mapped_values(&key(2)), Some([Felt::ONE, Felt::ZERO].as_slice()));
    assert_eq!(provider.get_mapped_values(&key(3)), Some([Felt::ZERO].as_slice()));
    let committed = provider.fingerprint();

    provider.prepare_extend_map(&other).unwrap().commit();
    provider.extend_map(&other).unwrap();
    assert_eq!(provider.fingerprint(), committed);
    assert_eq!(provider.advice_size_bytes, max);
}
