use miden_core::{
    Word,
    program::{EnvironmentRoot, ExecutionDescriptor, ImplementationRoot},
};

fn main() {
    let implementation = ImplementationRoot::new(Word::empty());
    let environment = EnvironmentRoot::new(Word::empty());

    let _ = ExecutionDescriptor::new(implementation, environment);
}
