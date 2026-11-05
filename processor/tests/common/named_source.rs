//! Explicit source-fixture names and bounded environment policies, shared by integration tests.

use miden_processor::Program;
use miden_utils_testing::{Test, librarytree::FixtureEnvironment};

pub fn named_source(source: &str) -> (Program, FixtureEnvironment) {
    let test = Test::new("processor-integration", source, false);
    let (program, ..) = test.compile().expect("source fixture should compile");
    let environment = test.fixture_environment().expect("fixture names should validate");
    (program, environment)
}
