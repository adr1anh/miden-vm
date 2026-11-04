//! Property-test generation for complete VM public inputs.

use miden_core::{
    Felt, WORD_SIZE, Word,
    program::{
        EnvironmentRoot, ExecutionTarget, MIN_STACK_DEPTH, ProcedureKey, StackInputs, StackOutputs,
    },
};
use proptest::prelude::*;

use super::PublicInputs;

impl Arbitrary for PublicInputs {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        fn felt_strategy() -> impl Strategy<Value = Felt> {
            any::<u32>().prop_map(Felt::from)
        }
        fn word_strategy() -> impl Strategy<Value = Word> {
            any::<[u32; WORD_SIZE]>().prop_map(|values| Word::new(values.map(Felt::from)))
        }
        let descriptor = (word_strategy(), word_strategy()).prop_map(|(entry, root)| {
            ExecutionTarget::new(ProcedureKey::new(entry), EnvironmentRoot::new(root))
        });
        let stack_inputs = proptest::collection::vec(felt_strategy(), 0..=MIN_STACK_DEPTH)
            .prop_map(|values| StackInputs::new(&values).expect("generated stack inputs fit"));
        let stack_outputs = proptest::collection::vec(felt_strategy(), 0..=MIN_STACK_DEPTH)
            .prop_map(|values| StackOutputs::new(&values).expect("generated stack outputs fit"));
        (descriptor, stack_inputs, stack_outputs, word_strategy())
            .prop_map(|(descriptor, inputs, outputs, root)| {
                Self::new(descriptor, inputs, outputs, root)
            })
            .boxed()
    }
}
