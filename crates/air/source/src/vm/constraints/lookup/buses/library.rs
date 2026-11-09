//! Lookup primitives for the packed Library relation.
//!
//! The caller supplies the Library scope and fixed A/B phase explicitly. These exclusive row
//! batches share the existing hash-kernel group.
//! Open edges are unit selections, while authenticated Mast bindings have normal/syscall
//! frequencies. Compression requests use the existing positive HasherCompressionLink convention.

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing},
    program::{Namespace, domain},
};
use miden_stark::lookup::{BoundaryBuilder, Deg, LookupBatch, LookupGroup};

use crate::{
    shared::eidos::framing::initial_cv_from_frame,
    vm::constraints::{
        chiplets::library::{
            LibraryKindFlags, LibraryPhaseFlags, LibraryRowContext, columns::LibraryCols, sigma_hi,
            sigma_lo,
        },
        lookup::messages::{HasherCompressionLinkMsg, LibraryOpenMsg, LibraryResolveMsg},
    },
};

/// Emit Library interactions into an existing exclusive lookup group.
///
/// `ctx.is_active` must be the direct Library selector, and `ctx.phase` the fixed period-two
/// value. The live Controller selector must never stand in for Library scope. Constraints from
/// `enforce_library_constraints` authenticate all payloads and enforce kind/phase exclusivity.
///
/// Across these batches the exact group contribution is `Deg { v: 9, u: 7 }`: cubic child
/// selection determines the numerator maximum, and each batch has at most two linear
/// denominators under a degree-five flag. The enclosing auxiliary constraint has degree nine.
pub(crate) fn emit_library<G, V>(
    group: &mut G,
    local: &LibraryCols<V>,
    next: &LibraryCols<V>,
    ctx: &LibraryRowContext<G::Expr>,
) where
    G: LookupGroup,
    G::Expr: Algebra<Felt>,
    V: Copy + Into<G::Expr>,
{
    let kinds = LibraryKindFlags::new(local);
    let phases = LibraryPhaseFlags::new(ctx.is_active.clone(), ctx.phase.clone());

    emit_header(
        group,
        "library_merkle_a",
        phases.kind_a(kinds.is_merkle.clone()),
        local,
        [Felt::ZERO; 4],
    );
    group.batch(
        "library_merkle_b",
        phases.kind_b(kinds.is_merkle),
        |batch| emit_selected_children(batch, local),
        Deg { v: 9, u: 7 },
    );

    emit_header(
        group,
        "library_env_a",
        phases.kind_a(kinds.is_env.clone()),
        local,
        felt_pair_frame(domain::domain_tag(domain::ENV_ENVIRONMENT)),
    );
    group.batch(
        "library_env_b",
        phases.kind_b(kinds.is_env),
        |batch| {
            let depth: G::Expr = local.d.into();
            batch.add(
                "library_namespace_compression",
                fixed_compression(
                    local,
                    felt_pair_frame(domain::domain_tag(domain::ENV_NAMESPACE)),
                ),
                Deg { v: 5, u: 6 },
            );
            batch.add(
                "library_env_child",
                LibraryOpenMsg {
                    depth: depth + G::Expr::ONE,
                    commitment: local.w.map(Into::into),
                    namespace: local.z.map(Into::into),
                },
                Deg { v: 5, u: 6 },
            );
        },
        Deg { v: 6, u: 7 },
    );

    emit_header(
        group,
        "library_mast_a",
        phases.kind_a(kinds.is_mast.clone() + kinds.is_root_mast.clone()),
        local,
        felt_pair_frame(domain::domain_tag(domain::ENV_MAST)),
    );
    group.batch(
        "library_mast_b",
        phases.kind_b(kinds.is_mast),
        |batch| {
            batch.add(
                "library_key_compression",
                fixed_compression(
                    local,
                    felt_pair_frame(domain::domain_tag(domain::ENV_PROCEDURE)),
                ),
                Deg { v: 5, u: 6 },
            );
            batch.insert(
                "library_resolve_normal",
                local.a.into(),
                LibraryResolveMsg {
                    requires_syscall: G::Expr::ZERO,
                    key: local.z.map(Into::into),
                    implementation: local.w.map(Into::into),
                },
                Deg { v: 6, u: 6 },
            );
        },
        Deg { v: 7, u: 7 },
    );
    group.batch(
        "library_root_mast_b",
        phases.kind_b(kinds.is_root_mast),
        |batch| {
            for (name, tag, frequency) in [
                ("library_resolve_normal", G::Expr::ZERO, local.a),
                ("library_resolve_syscall", G::Expr::ONE, local.b),
            ] {
                batch.insert(
                    name,
                    frequency.into(),
                    LibraryResolveMsg {
                        requires_syscall: tag,
                        key: local.y.map(Into::into),
                        implementation: local.w.map(Into::into),
                    },
                    Deg { v: 6, u: 6 },
                );
            }
        },
        Deg { v: 7, u: 7 },
    );

    // Every real List block requests compression. The B row holds the input CV; the A row
    // holds the output CV, including the header's authenticated final commitment.
    for (name, kind) in [
        ("library_list_start_a", kinds.is_list_start.clone()),
        ("library_empty_list_a", kinds.is_empty_list),
    ] {
        group.batch(
            name,
            phases.kind_a(kind),
            |batch| {
                batch.remove("library_list_header", header(local), Deg { v: 5, u: 6 });
                batch.add(
                    "library_list_compression",
                    list_compression(local, next),
                    Deg { v: 5, u: 6 },
                );
            },
            Deg { v: 6, u: 7 },
        );
    }
    group.batch(
        "library_list_continue_a",
        phases.kind_a(kinds.is_list_continue.clone()),
        |batch| {
            batch.add(
                "library_list_compression",
                list_compression(local, next),
                Deg { v: 5, u: 6 },
            );
        },
        Deg { v: 5, u: 6 },
    );
    group.batch(
        "library_list_b",
        phases.kind_b(kinds.is_list_start + kinds.is_list_continue),
        |batch| emit_selected_children(batch, local),
        Deg { v: 9, u: 7 },
    );
}

/// Supply the single external Open token under the canonical initial namespace.
///
/// The caller must pass its validated public environment root. This entrypoint neither reads
/// legacy boundary auxiliaries nor supplies a fallback for absent public inputs.
pub(crate) fn emit_open_seed<B>(boundary: &mut B, environment_root: [B::F; 4])
where
    B: BoundaryBuilder,
    B::F: Algebra<Felt>,
{
    let namespace = Namespace::initial().into_word();
    boundary.add(
        "library_open_seed",
        LibraryOpenMsg {
            depth: B::F::ZERO,
            commitment: environment_root,
            namespace: core::array::from_fn(|i| namespace[i].into()),
        },
    );
}

fn emit_header<G, V>(
    group: &mut G,
    name: &'static str,
    flag: G::Expr,
    local: &LibraryCols<V>,
    frame: [Felt; 4],
) where
    G: LookupGroup,
    G::Expr: Algebra<Felt>,
    V: Copy + Into<G::Expr>,
{
    group.batch(
        name,
        flag,
        |batch| {
            batch.remove("library_header", header(local), Deg { v: 5, u: 6 });
            batch.add(
                "library_object_compression",
                fixed_compression(local, frame),
                Deg { v: 5, u: 6 },
            );
        },
        Deg { v: 6, u: 7 },
    );
}

fn header<E, V>(local: &LibraryCols<V>) -> LibraryOpenMsg<E>
where
    V: Copy + Into<E>,
{
    LibraryOpenMsg {
        depth: local.d.into(),
        commitment: local.z.map(Into::into),
        namespace: local.w.map(Into::into),
    }
}

/// Standard Felt-sequence framing for the fixed two-word environment and key payloads.
/// Native binary Merkle nodes instead use the reserved all-zero frame.
fn felt_pair_frame(domain_tag: Felt) -> [Felt; 4] {
    [domain_tag, Felt::from_u8(8), Felt::ZERO, Felt::ZERO]
}

fn fixed_compression<E, V>(local: &LibraryCols<V>, frame: [Felt; 4]) -> HasherCompressionLinkMsg<E>
where
    E: Algebra<Felt>,
    V: Copy + Into<E>,
{
    HasherCompressionLinkMsg {
        block: core::array::from_fn(|i| {
            if i < 4 {
                local.x[i].into()
            } else {
                local.y[i - 4].into()
            }
        }),
        cv_in: initial_cv_from_frame(frame.map(Into::into)),
        cv_out: local.z.map(Into::into),
    }
}

fn list_compression<E, V>(
    local: &LibraryCols<V>,
    next: &LibraryCols<V>,
) -> HasherCompressionLinkMsg<E>
where
    V: Copy + Into<E>,
{
    HasherCompressionLinkMsg {
        block: core::array::from_fn(|i| {
            if i < 4 {
                local.x[i].into()
            } else {
                local.y[i - 4].into()
            }
        }),
        cv_in: next.z.map(Into::into),
        cv_out: local.z.map(Into::into),
    }
}

fn emit_selected_children<B, V>(batch: &mut B, local: &LibraryCols<V>)
where
    B: LookupBatch,
    B::Expr: Algebra<Felt>,
    V: Copy + Into<B::Expr>,
{
    let sigma: B::Expr = local.b.into();
    let depth: B::Expr = local.d.into();
    for (name, commitment, weight) in [
        ("library_child_low", local.x, sigma_lo(sigma.clone())),
        ("library_child_high", local.y, sigma_hi(sigma)),
    ] {
        batch.insert(
            name,
            weight,
            LibraryOpenMsg {
                depth: depth.clone() + B::Expr::ONE,
                commitment: commitment.map(Into::into),
                namespace: local.w.map(Into::into),
            },
            Deg { v: 8, u: 6 },
        );
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod relation_tests;
