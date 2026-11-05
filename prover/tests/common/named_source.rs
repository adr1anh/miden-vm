//! Shared source fixture policy with explicit names and bounded environment openings.

use miden_assembly::CodePackage;
use miden_utils_testing::{Test, librarytree::FixtureEnvironment};

pub fn named_source(source: &str) -> (CodePackage, FixtureEnvironment) {
    let test = Test::new("prover-integration", source, false);
    let (program, ..) = test.compile().expect("fixture source must compile");
    let environment = test.fixture_environment().expect("fixture environment must validate");
    (program, environment)
}
