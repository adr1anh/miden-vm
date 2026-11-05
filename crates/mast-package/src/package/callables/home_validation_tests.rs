use alloc::{vec, vec::Vec};
use core::cell::Cell;

use miden_core::{
    Felt, Word,
    program::{CanonicalLabel, ImplementationRoot},
};

use super::PackageCallables;
use crate::{
    CallableProcedurePath, NamespacePath, ProcedureName,
    interface::serialization::{
        Budget, CodecError, CodecLimits, HomeProfile, ProfileOperation, TypedIdProfile,
    },
};

type Error = CodecError<&'static str>;

const CODEC: u32 = 77;
const ID: &[u8] = &[0xa5, 0, 0xff];

struct FixtureProfile {
    typed_calls: Cell<usize>,
    home_calls: Cell<usize>,
}

#[derive(Clone)]
struct Context {
    permitted_homes: Vec<Vec<CanonicalLabel>>,
    permit_home: bool,
    permit_typed: bool,
}

impl TypedIdProfile for FixtureProfile {
    type Context = Context;
    type Error = &'static str;

    fn validate_typed_id(
        &self,
        context: &Context,
        codec: u32,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.typed_calls.set(self.typed_calls.get() + 1);
        if codec != CODEC {
            Err("unrecognized synthetic codec")
        } else if bytes != ID {
            Err("noncanonical synthetic ID")
        } else if !context.permit_typed {
            Err("synthetic codec rejected in this context")
        } else {
            Ok(())
        }
    }
}

impl HomeProfile for FixtureProfile {
    fn validate_home(&self, context: &Context, home: &[CanonicalLabel]) -> Result<(), Self::Error> {
        self.home_calls.set(self.home_calls.get() + 1);
        if !context.permit_home {
            Err("home forbidden in this context")
        } else if !context.permitted_homes.iter().any(|permitted| permitted == home) {
            Err("home association mismatch")
        } else {
            Ok(())
        }
    }
}

fn path(components: &[&str]) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(
        components.iter().map(|component| (*component).into()).collect(),
    )
    .unwrap()
}

fn binding(home: Vec<CanonicalLabel>, components: &[&str]) -> ProcedureName {
    ProcedureName::new(NamespacePath::new(home), path(components)).unwrap()
}

fn context(permitted_homes: Vec<Vec<CanonicalLabel>>) -> Context {
    Context {
        permitted_homes,
        permit_home: true,
        permit_typed: true,
    }
}

fn fixture_profile() -> FixtureProfile {
    FixtureProfile {
        typed_calls: Cell::new(0),
        home_calls: Cell::new(0),
    }
}

fn typed_label(codec: u32) -> CanonicalLabel {
    // Construction supplies only a synthetic seed validator; each operation must revalidate it.
    CanonicalLabel::typed_id(codec, ID, |_, _| Ok(())).unwrap()
}

fn generous_limits() -> CodecLimits {
    CodecLimits::new(4096, 64, 64, 4096)
}

fn complete_fixture() -> (PackageCallables, Context) {
    let home = vec![CanonicalLabel::text("hβ").unwrap(), typed_label(CODEC)];
    let public = binding(home.clone(), &["m", "runβ"]);
    let hidden = binding(home.clone(), &["hidden", "𐐀"]);
    let key = public.key();
    let implementation = ImplementationRoot::new(Word::new([7; 4].map(Felt::from_u32)));
    let inventory = PackageCallables::new(
        [public, hidden],
        [(path(&["alias", "goβ"]), key)],
        [(key, implementation)],
    )
    .unwrap();
    (inventory, context(vec![home]))
}

fn exact_fixture_limits() -> CodecLimits {
    // Two owned homes each contain envelopes of 9 + 13 bytes and payloads of 3 + 7 bytes.
    // Canonical paths contain 6 + 10 UTF-8 bytes; the alias contains 9 UTF-8 bytes.
    // Logical bytes: 2*32 + 2*22 + 16 + 32 + 9 + 32 + 32 = 229.
    // Records: two bindings + one alias + one selection + four owned home labels = eight.
    // Components: four home labels + four canonical path components + two alias components.
    CodecLimits::new(229, 8, 10, 45)
}

fn assert_limit(
    error: Error,
    expected_resource: &str,
    expected_actual: usize,
    expected_limit: usize,
) {
    match error {
        Error::LimitExceeded { resource, actual, limit } => {
            assert_eq!(resource, expected_resource);
            assert_eq!(actual, expected_actual);
            assert_eq!(limit, expected_limit);
        },
        error => panic!("expected a {expected_resource} limit failure, got {error}"),
    }
}

#[test]
fn complete_owned_relations_have_exact_aggregate_limits_before_policy() {
    let (inventory, context) = complete_fixture();
    let unchanged = inventory.clone();
    let profile = fixture_profile();
    inventory.validate_homes(&profile, &context, exact_fixture_limits()).unwrap();
    assert_eq!(profile.typed_calls.get(), 2);
    assert_eq!(profile.home_calls.get(), 2);
    assert_eq!(inventory, unchanged);

    for (limits, resource, actual, limit) in [
        (CodecLimits::new(228, 8, 10, 45), "logical bytes", 229, 228),
        (CodecLimits::new(229, 7, 10, 45), "records", 8, 7),
        (CodecLimits::new(229, 8, 9, 45), "components", 10, 9),
        (CodecLimits::new(229, 8, 10, 44), "blob bytes", 45, 44),
    ] {
        let profile = fixture_profile();
        assert_limit(
            inventory.validate_homes(&profile, &context, limits).unwrap_err(),
            resource,
            actual,
            limit,
        );
        assert_eq!(profile.typed_calls.get(), 0);
        assert_eq!(profile.home_calls.get(), 0);
    }
}

#[test]
fn every_distinct_unaliased_home_requires_its_own_context_association() {
    let first_home = vec![CanonicalLabel::text("first").unwrap()];
    let second_home = vec![CanonicalLabel::text("second").unwrap()];
    let inventory = PackageCallables::new(
        [
            binding(first_home.clone(), &["run"]),
            binding(second_home.clone(), &["helpers", "hidden"]),
        ],
        [],
        [],
    )
    .unwrap();
    let profile = fixture_profile();
    let permitted = context(vec![first_home.clone(), second_home]);
    inventory.validate_homes(&profile, &permitted, generous_limits()).unwrap();
    assert_eq!(profile.home_calls.get(), 2);
    assert_eq!(profile.typed_calls.get(), 0);
    assert_eq!(inventory.visible_paths().len(), 0);
    assert_eq!(inventory.selected_implementations().len(), 0);

    let missing_association = context(vec![first_home]);
    assert!(matches!(
        inventory.validate_homes(&profile, &missing_association, generous_limits()),
        Err(Error::ProfileRejected {
            operation: ProfileOperation::Home,
            error: "home association mismatch"
        })
    ));
}

#[test]
fn explicit_n0_is_bounded_and_revalidated_by_home_policy() {
    let inventory = PackageCallables::new([binding(vec![], &["r"])], [], []).unwrap();
    let profile = fixture_profile();
    let permitted = context(vec![vec![]]);
    let exact = CodecLimits::new(33, 1, 1, 1);
    inventory.validate_homes(&profile, &permitted, exact).unwrap();
    assert_eq!(profile.home_calls.get(), 1);
    assert_eq!(profile.typed_calls.get(), 0);

    let forbidden = Context { permit_home: false, ..permitted };
    assert!(matches!(
        inventory.validate_homes(&profile, &forbidden, exact),
        Err(Error::ProfileRejected {
            operation: ProfileOperation::Home,
            error: "home forbidden in this context"
        })
    ));
    assert_eq!(profile.home_calls.get(), 2);
}

#[test]
fn empty_inventory_fits_zero_limits_without_inventing_a_home() {
    let inventory = PackageCallables::new([], [], []).unwrap();
    let profile = fixture_profile();
    let context = Context {
        permitted_homes: vec![],
        permit_home: false,
        permit_typed: false,
    };
    inventory
        .validate_homes(&profile, &context, CodecLimits::new(0, 0, 0, 0))
        .unwrap();
    assert_eq!(profile.home_calls.get(), 0);
    assert_eq!(profile.typed_calls.get(), 0);
}

#[test]
fn current_profile_rejects_unknown_typed_ids_despite_prior_construction() {
    let home = vec![typed_label(999)];
    let inventory = PackageCallables::new([binding(home.clone(), &["run"])], [], []).unwrap();
    let profile = fixture_profile();
    assert!(matches!(
        inventory.validate_homes(&profile, &context(vec![home]), generous_limits()),
        Err(Error::ProfileRejected {
            operation: ProfileOperation::TypedId,
            error: "unrecognized synthetic codec"
        })
    ));
    assert_eq!(profile.typed_calls.get(), 1);
    assert_eq!(profile.home_calls.get(), 0);
}

#[test]
fn successful_validation_does_not_cache_typed_id_or_home_context_permission() {
    let (inventory, permitted) = complete_fixture();
    let profile = fixture_profile();
    inventory.validate_homes(&profile, &permitted, exact_fixture_limits()).unwrap();
    assert_eq!(profile.typed_calls.get(), 2);
    assert_eq!(profile.home_calls.get(), 2);

    let typed_forbidden = Context { permit_typed: false, ..permitted.clone() };
    assert!(matches!(
        inventory.validate_homes(&profile, &typed_forbidden, exact_fixture_limits()),
        Err(Error::ProfileRejected {
            operation: ProfileOperation::TypedId,
            error: "synthetic codec rejected in this context"
        })
    ));
    assert_eq!(profile.typed_calls.get(), 3);
    assert_eq!(profile.home_calls.get(), 2);

    let unrelated = Context { permitted_homes: vec![], ..permitted };
    assert!(matches!(
        inventory.validate_homes(&profile, &unrelated, exact_fixture_limits()),
        Err(Error::ProfileRejected {
            operation: ProfileOperation::Home,
            error: "home association mismatch"
        })
    ));
    assert_eq!(profile.typed_calls.get(), 4);
    assert_eq!(profile.home_calls.get(), 3);
}

#[test]
fn shared_budget_preflight_includes_preexisting_consumption_for_every_resource() {
    let (inventory, context) = complete_fixture();
    for (resource, actual, limit) in [
        ("logical bytes", 230, 229),
        ("records", 9, 8),
        ("components", 11, 10),
        ("blob bytes", 46, 45),
    ] {
        let mut budget = Budget::new(exact_fixture_limits());
        let charged: Result<(), Error> = match resource {
            "logical bytes" => budget.logical_bytes(1),
            "records" => budget.records(1),
            "components" => budget.components(1),
            "blob bytes" => budget.blob_bytes(1),
            _ => unreachable!(),
        };
        charged.unwrap();
        let profile = fixture_profile();
        assert_limit(
            inventory
                .validate_homes_with_budget(&profile, &context, &mut budget)
                .unwrap_err(),
            resource,
            actual,
            limit,
        );
        assert_eq!(profile.typed_calls.get(), 0);
        assert_eq!(profile.home_calls.get(), 0);
    }
}

#[test]
fn shared_budget_does_not_reset_logical_bytes_between_inventories() {
    let (first, context) = complete_fixture();
    let second = first.clone();
    let combined = CodecLimits::new(457, 16, 20, 90);
    for inventory in [&first, &second] {
        inventory.validate_homes(&fixture_profile(), &context, combined).unwrap();
    }

    let mut budget = Budget::new(combined);
    let profile = fixture_profile();
    first.validate_homes_with_budget(&profile, &context, &mut budget).unwrap();
    assert_eq!(profile.typed_calls.get(), 2);
    assert_eq!(profile.home_calls.get(), 2);
    assert_limit(
        second.validate_homes_with_budget(&profile, &context, &mut budget).unwrap_err(),
        "logical bytes",
        458,
        457,
    );
    assert_eq!(profile.typed_calls.get(), 2);
    assert_eq!(profile.home_calls.get(), 2);
}
