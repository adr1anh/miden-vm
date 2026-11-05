//! Physical lookup-column emitters for the Miden VM's LogUp argument.
//!
//! The Core and Chiplets LogUp buses are emitted across 9 columns — most host a single bus, but
//! several host two or more linearly-independent buses sharing one running accumulator via
//! distinct `bus_prefix[bus]` additive bases (see per-bus module docs for the merges).
//! Each emitter opens one [`miden_stark::lookup::LookupBuilder::next_column`] closure and fixes
//! group placement, column degree, and per-row fraction capacity. AEAD and Merkle logic lives in
//! [`super::operations`]; these emitters call it inside the appropriate column groups.
//!
//! ## Shared merge rules
//!
//! A [`miden_stark::lookup::LookupColumn::group`] assumes its top-level entries are mutually
//! exclusive, so the column degree is the max over active branches. Simultaneous fractions belong
//! in a [`miden_stark::lookup::LookupGroup::batch`] with an explicit degree. If two interaction
//! families are not mutually exclusive, they must be emitted as sibling groups; sibling groups
//! compose product-wise and increase the column degree accordingly.
//!
//! Some columns merge multiple bus families into one group. This is valid only when their
//! row selectors are mutually exclusive. Each bus still has its own `bus_prefix[bus]`.
//!
//! The emitters are routed per-AIR:
//! - [`super::main_air::MainLookupAir`] for the main-trace columns, driven by
//!   [`crate::vm::CoreAir`]'s `LookupAir` impl.
//! - [`super::chiplet_air::emit_chiplet_lookup_columns`] for the chiplet-trace columns, driven by
//!   [`crate::vm::ChipletsAir`]'s `LookupAir` impl.
//! - [`crate::vm::constraints::eidos_compression::lookup`] for the standalone Eidos compression
//!   columns, driven by [`crate::vm::EidosCompressionAir`]'s `LookupAir` impl.
//! - [`crate::vm::constraints::and8_lookup`] for the fixed byte-table columns, driven by
//!   [`crate::vm::And8LookupAir`]'s `LookupAir` impl.
//!
//! ## Shared precompute contexts
//!
//! The main-trace and chiplet-trace contexts live next to their respective LookupAirs:
//! - [`super::main_air::MainBusContext`]: two-row window plus the shared [`LookupOpFlags`] instance
//!   consumed by the 5 main-trace emitters.
//! - [`super::chiplet_air::ChipletBusContext`]: two-row window plus the shared
//!   [`ChipletActiveFlags`] snapshot consumed by the 4 chiplet-trace emitters.
//!
//! Each context is built once per `eval` through an extension-trait hook
//! ([`super::main_air::MainLookupBuilder::build_op_flags`] /
//! [`super::chiplet_air::ChipletLookupBuilder::build_chiplet_active`]). Prover-side
//! implementations can override those hooks with boolean fast paths without changing
//! emitter code. [`ChipletActiveFlags`] lives in this module because it is the pure
//! helper used by the default chiplet hook and by optimized implementations.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::vm::ChipletCols;

pub(in crate::vm::constraints::lookup) mod block_hash_and_op_group;
pub(in crate::vm::constraints::lookup) mod block_stack_and_range_logcap;
pub(in crate::vm::constraints::lookup) mod chiplet_requests;
pub(in crate::vm::constraints::lookup) mod chiplet_responses;
pub(in crate::vm::constraints::lookup) mod hash_kernel;
pub(in crate::vm::constraints::lookup) mod hasher_returns;
pub(crate) mod library;
pub(in crate::vm::constraints::lookup) mod lookup_op_flags;
pub(in crate::vm::constraints::lookup) mod resolution;
pub(in crate::vm::constraints::lookup) mod stack_overflow;
pub(in crate::vm::constraints::lookup) mod wiring;

pub(in crate::vm::constraints::lookup) use lookup_op_flags::LookupOpFlags;

// CHIPLET ACTIVE FLAGS
// ================================================================================================

/// Per-chiplet `is_active` expressions, mirroring the active-flag block of
/// [`build_chiplet_selectors`](super::super::chiplets::selectors::build_chiplet_selectors).
///
/// These are the only chiplet flags the LogUp buses consume.
/// `is_transition`, `is_last`, and `next_is_first` are used only by the chiplet
/// constraints, so this type does not carry them.
///
/// The constructor is a pure compute function: it builds the same algebra as
/// `build_chiplet_selectors` but does NOT emit any `when` / `assert_*` calls, so it is
/// safe to run in parallel with the constraint-path chiplet selector pass.
pub(crate) struct ChipletActiveFlags<E> {
    /// Direct scope for the Library prefix.
    pub library: E,
    /// `is_active` for the hasher controller sub-chiplet.
    pub controller: E,
    /// `is_active` for normal bitwise rows.
    pub bitwise: E,
    /// `is_active` for the separate AEAD stream section.
    pub aead_stream: E,
    /// `is_active` for the memory chiplet.
    pub memory: E,
    /// `is_active` for the ACE chiplet.
    pub ace: E,
}

impl<E> ChipletActiveFlags<E>
where
    E: PrimeCharacteristicRing + Clone,
{
    /// Build the chiplet active-flag snapshot from a `ChipletCols` borrow.
    ///
    /// Mirrors the active-flag block of
    /// [`build_chiplet_selectors`](super::super::chiplets::selectors::build_chiplet_selectors):
    /// The six shared selector cells are `S_lib, C, A, m, a, b`. Prefix products
    /// scope the later selectors so payload cells in earlier sections cannot activate them.
    pub fn from_chiplet_cols<V>(local: &ChipletCols<V>) -> Self
    where
        V: Copy,
        E: Algebra<V>,
    {
        let library: E = local.chiplets[0].into();
        let controller_selector: E = local.chiplets[1].into();
        let aead_selector: E = local.chiplets[2].into();
        let memory_end: E = local.chiplets[3].into();
        let ace_end: E = local.chiplets[4].into();
        let bitwise_end: E = local.chiplets[5].into();

        let after_library = E::ONE - library.clone();
        let controller = after_library.clone() * controller_selector.clone();
        let after_controller = after_library * (E::ONE - controller_selector);
        let aead_stream = after_controller.clone() * aead_selector.clone();
        let after_aead = after_controller * (E::ONE - aead_selector);
        let after_memory = after_aead.clone() * memory_end;
        let memory = after_aead - after_memory.clone();
        let after_ace = after_memory.clone() * ace_end;
        let ace = after_memory - after_ace.clone();
        let bitwise = after_ace * (E::ONE - bitwise_end);

        Self {
            library,
            controller,
            bitwise,
            aead_stream,
            memory,
            ace,
        }
    }
}
