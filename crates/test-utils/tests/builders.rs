extern crate alloc;

use alloc::sync::Arc;

use miden_test_utils::{
    AdviceInputs, DefaultSourceManager, Felt, SourceLanguage, SourceManager, Test,
    advice_stack_from, build_debug_test, build_test, crypto::init_merkle_store,
    stack_inputs_from_ints,
};

fn assert_source_context(test: &Test, source: &str) {
    assert_eq!(test.source.as_str(), source);
    let managed_source = test.source_manager.get(test.source.id()).unwrap();
    assert!(Arc::ptr_eq(&test.source, &managed_source));
}

#[test]
fn external_builder_macros_preserve_source_context_and_inputs() {
    let source = "begin adv_push.1 add end";
    let stack = [13, 17];
    let advice = [19, 23];
    let (leaves, store) = init_merkle_store(&[2, 3]);
    let map = [(leaves[0], vec![Felt::new_unchecked(29)])];
    let expected_advice = AdviceInputs::default().with_stack(advice_stack_from(advice).unwrap());

    // Expand every source/input arity from outside the defining crate. Private Test state must
    // remain initialized by the crate even when downstream callers supply all advice components.
    let cases = [
        (build_test!(source), &[][..], AdviceInputs::default(), false),
        (build_debug_test!(source, &stack), &stack[..], AdviceInputs::default(), true),
        (build_test!(source, &stack, &advice), &stack[..], expected_advice.clone(), false),
        (
            build_debug_test!(source, &stack, &advice, store.clone()),
            &stack[..],
            expected_advice.clone().with_merkle_store(store.clone()),
            true,
        ),
        (
            build_test!(source, &stack, &advice, store.clone(), map.clone()),
            &stack[..],
            expected_advice.with_merkle_store(store).with_map(map),
            false,
        ),
    ];

    for (test, stack, advice, tracing) in cases {
        assert_source_context(&test, source);
        assert_eq!(test.stack_inputs, stack_inputs_from_ints(stack.iter().copied()));
        assert_eq!(test.advice_inputs, advice);
        assert_eq!(test.in_tracing_mode, tracing);
    }
}

#[test]
fn source_parts_constructor_retains_the_callers_loaded_source() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    source_manager.load(SourceLanguage::Masm, "earlier".into(), "begin nop end".into());
    let source = source_manager.load(
        SourceLanguage::Masm,
        "retained://fixture/source.masm".into(),
        "source is retained without parsing".into(),
    );
    let stack_inputs = stack_inputs_from_ints([31, 37]);
    let advice_inputs = AdviceInputs::default().with_stack(advice_stack_from([41, 43]).unwrap());
    let test = Test::from_source_parts(
        source_manager.clone(),
        source.clone(),
        stack_inputs,
        advice_inputs.clone(),
        true,
    );

    assert!(Arc::ptr_eq(&test.source_manager, &source_manager));
    assert!(Arc::ptr_eq(&test.source, &source));
    assert_source_context(&test, source.as_str());
    assert_eq!(test.stack_inputs, stack_inputs);
    assert_eq!(test.advice_inputs, advice_inputs);
    assert!(test.in_tracing_mode);
}
