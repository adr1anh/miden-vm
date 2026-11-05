use miden_core::{
    Word,
    program::{EnvironmentRoot, ExecutionTarget, ImplementationRoot},
};

fn main() {
    let implementation = ImplementationRoot::new(Word::empty());
    let environment = EnvironmentRoot::new(Word::empty());

    let _ = ExecutionTarget::new(implementation, environment);
}
