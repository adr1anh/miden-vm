//! Local expressions for the future packed Library region.
//!
//! The shared schema and expressions here do not activate a Library section or enforce its AIR.
//! The current `c[0]` selects Controller rows. Library activation must migrate the section
//! selectors, physical views and writers, Controller gates, and periodic consumers together.

pub mod columns;

#[cfg(test)]
mod tests;
