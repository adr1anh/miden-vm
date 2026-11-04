//! Shared fixture naming and bounded execution inputs for manual core tests.

pub use miden_utils_testing::librarytree::assemble_fixture_program as assemble;

pub type NamedProgram = (
    miden_mast_package::CodePackage,
    miden_utils_testing::librarytree::FixtureEnvironment,
);
