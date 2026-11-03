#[cfg(test)]
mod fixture;
#[cfg(test)]
mod non_tracing_test_host;
mod test_host;

#[cfg(test)]
pub(crate) use fixture::native_fixture_environment;
pub use test_host::{ProcessorStateSnapshot, TestHost};

#[derive(Clone)]
struct EnvironmentSource(alloc::sync::Arc<dyn crate::EnvironmentWitnessSource>);

impl core::fmt::Debug for EnvironmentSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("EnvironmentWitnessSource").finish_non_exhaustive()
    }
}
