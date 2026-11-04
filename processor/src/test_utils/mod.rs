#[cfg(test)]
mod fixture;
#[cfg(test)]
mod named;
#[cfg(test)]
mod non_tracing_test_host;
mod test_host;

#[cfg(test)]
pub(crate) use fixture::{native_fixture_environment, native_replay_budget, native_trace_limits};
#[cfg(test)]
pub(crate) use miden_utils_testing::librarytree::{
    fixture_code, fixture_entry_digest, fixture_entry_root,
};
#[cfg(test)]
pub(crate) use named::{NamedFixture, named_module, named_package, named_program, named_source};
pub use test_host::{ProcessorStateSnapshot, TestHost};

#[derive(Clone)]
struct TestEnvironmentSource(alloc::sync::Arc<dyn crate::EnvironmentSource>);

impl core::fmt::Debug for TestEnvironmentSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("EnvironmentSource").finish_non_exhaustive()
    }
}
