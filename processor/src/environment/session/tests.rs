use alloc::{vec, vec::Vec};
use core::mem::size_of;

use miden_core::{
    Felt, Word,
    program::{CanonicalLabel, EnvNode, LabelCommitment},
};

use super::*;
use crate::environment::{
    LedgerCounters, LedgerResource, OpeningLimits, OpeningParent, OpeningStep, ResolutionWitness,
};

macro_rules! rejected {
    ($session:ident, $operation:expr, $expected:expr) => {{
        let before = snapshot(&$session);
        assert_eq!($operation.unwrap_err(), $expected);
        assert_eq!(snapshot(&$session), before);
    }};
}

#[test]
fn unentered_session_exposes_its_descriptor_but_cannot_issue_or_finalize_requests() {
    let fixture = direct("entry", 40);
    let descriptor = fixture.descriptor(Namespace::initial());
    let limits = session_limits();
    let mut session = ResolutionSession::new(descriptor, ledger_limits(), limits);
    assert_eq!(session.descriptor(), descriptor);
    assert_eq!(session.limits(), limits);
    assert_eq!(session.phase(), SessionPhase::Unentered);
    assert_eq!(session.counters().cached_keys, 0);
    assert_eq!(session.counters().committed_requests, 0);
    assert_eq!(session.counters().reserved_requests, 0);
    assert_eq!(session.counters().retained_bytes, 0);
    assert_eq!(session.ledger().expected_root(), fixture.root);
    assert!(session.bindings().is_empty());
    assert_eq!(session.uses().count(), 0);
    rejected!(
        session,
        session.prepare(fixture.key, fixture.binding(), InvocationTag::Normal, row(5)),
        phase_error(SessionPhase::PendingEntry, SessionPhase::Unentered)
    );
    rejected!(
        session,
        session.prepare_cached(fixture.key, InvocationTag::Normal, row(5)),
        phase_error(SessionPhase::PendingEntry, SessionPhase::Unentered)
    );
    rejected!(
        session,
        session.prepare_root_end(fixture.implementation, row(5)),
        phase_error(SessionPhase::PendingEntry, SessionPhase::Unentered)
    );
    rejected!(
        session,
        session.finalize(),
        phase_error(SessionPhase::Completed, SessionPhase::Unentered)
    );
}

#[test]
fn entry_requires_the_exact_descriptor_root_and_key_and_drop_publishes_nothing() {
    let tree = tree();
    let mut session = new_session(&tree.entry, tree.kernel.namespace);
    let other_root = direct("entry", 40);
    rejected!(
        session,
        session.prepare_entry(other_root.binding()),
        SessionError::WrongRoot {
            expected: tree.entry.root,
            actual: other_root.root,
        }
    );
    rejected!(
        session,
        session.prepare_entry(tree.normal.binding()),
        SessionError::WrongKey {
            expected: tree.entry.key,
            actual: tree.normal.key,
        }
    );
    let before = snapshot(&session);
    let prepared = session.prepare_entry(tree.entry.binding()).unwrap();
    assert_binding(prepared.binding(), &tree.entry);
    assert_eq!(prepared.binding().counts(), OpeningUseCounts { normal: 0, syscall: 0 });
    assert_eq!(prepared.counters().cached_keys, 1);
    assert_eq!(prepared.counters().committed_requests, 0);
    assert_eq!(prepared.counters().reserved_requests, 1);
    assert!(prepared.requested_peak_bytes() >= prepared.counters().retained_bytes);
    drop(prepared);
    assert_eq!(snapshot(&session), before);

    let binding = session.prepare_entry(tree.entry.binding()).unwrap().commit();
    assert_binding(binding, &tree.entry);
    assert_opening(&session, binding, &tree.entry);
    assert_eq!(session.phase(), SessionPhase::PendingEntry);
    assert_eq!(session.bindings(), &[binding]);
    assert_eq!(session.counters().reserved_requests, 1);
    assert_eq!(session.counters().committed_requests, 0);
    assert_eq!(session.uses().count(), 0);
    assert_eq!(session.ledger().counters().root_seed_count(), 1);
    rejected!(
        session,
        session.prepare_entry(tree.entry.binding()),
        phase_error(SessionPhase::Unentered, SessionPhase::PendingEntry)
    );
    rejected!(
        session,
        session.finalize(),
        phase_error(SessionPhase::Completed, SessionPhase::PendingEntry)
    );
}

#[test]
fn each_ordinary_and_cached_invocation_records_its_key_opening_and_row_including_recursion() {
    let tree = tree();
    let mut session = entered(&tree.entry, tree.kernel.namespace);
    let before = snapshot(&session);
    let prepared = session
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(17))
        .unwrap();
    assert_record(
        prepared.use_record(),
        InvocationTag::Normal,
        &tree.normal,
        prepared.binding(),
        17,
    );
    assert_eq!(prepared.binding().counts(), OpeningUseCounts { normal: 1, syscall: 0 });
    drop(prepared);
    assert_eq!(snapshot(&session), before);

    let first = session
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(17))
        .unwrap()
        .commit();
    let ledger_after_first = ledger_snapshot(session.ledger());
    let before = snapshot(&session);
    let prepared = session.prepare_cached(tree.normal.key, InvocationTag::Normal, row(19)).unwrap();
    assert_eq!(prepared.use_record().opening_id(), first.opening_id());
    assert_eq!(prepared.binding().counts(), OpeningUseCounts { normal: 2, syscall: 0 });
    drop(prepared);
    assert_eq!(snapshot(&session), before);
    let second = session
        .prepare_cached(tree.normal.key, InvocationTag::Normal, row(19))
        .unwrap()
        .commit();
    // A caller can recursively request the same K, with or without resupplying its opening.
    let third = session
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(23))
        .unwrap()
        .commit();
    assert_eq!(ledger_snapshot(session.ledger()), ledger_after_first);
    let binding = session.bindings()[1];
    assert_opening(&session, binding, &tree.normal);
    assert_eq!(binding.counts(), OpeningUseCounts { normal: 3, syscall: 0 });
    assert_eq!(session.uses().copied().collect::<Vec<_>>(), vec![first, second, third]);
    for (record, expected_row) in [(first, 17), (second, 19), (third, 23)] {
        assert_record(record, InvocationTag::Normal, &tree.normal, binding, expected_row);
    }
    assert_eq!(session.counters().committed_requests, 3);
    assert_eq!(session.counters().reserved_requests, 1);
    assert_eq!(session.counters().cached_keys, 2);
}

#[test]
fn same_implementation_under_distinct_keys_keeps_distinct_bindings_and_requests() {
    let tree = tree();
    assert_eq!(tree.normal.implementation, tree.alias.implementation);
    assert_ne!(tree.normal.key, tree.alias.key);
    let mut session = entered(&tree.entry, tree.kernel.namespace);
    let first = session
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(2))
        .unwrap()
        .commit();
    let second = session
        .prepare(tree.alias.key, tree.alias.binding(), InvocationTag::Normal, row(3))
        .unwrap()
        .commit();
    assert_ne!(first.procedure_key(), second.procedure_key());
    assert_eq!(first.implementation_root(), second.implementation_root());
    assert_ne!(first.opening_id(), second.opening_id());
    assert_opening(&session, session.bindings()[1], &tree.normal);
    assert_opening(&session, session.bindings()[2], &tree.alias);
    assert_eq!(session.counters().cached_keys, 3);
    assert_eq!(session.bindings()[1].counts().normal, 1);
    assert_eq!(session.bindings()[2].counts().normal, 1);
    rejected!(
        session,
        session.prepare(tree.normal.key, tree.alias.binding(), InvocationTag::Normal, row(4)),
        SessionError::WrongKey {
            expected: tree.normal.key,
            actual: tree.alias.key
        }
    );
    // D-shaped words remain keys; a cached implementation is never a fallback authority.
    let digest_key = ProcedureKey::new(tree.normal.implementation.into_word());
    assert_ne!(digest_key, tree.normal.key);
    rejected!(
        session,
        session.prepare_cached(digest_key, InvocationTag::Normal, row(4)),
        SessionError::MissingCachedBinding { key: digest_key }
    );
}

#[test]
fn syscall_authorization_checks_the_full_immediate_namespace_on_misses_and_hits() {
    let tree = tree();
    let mut session = entered(&tree.entry, tree.kernel.namespace);
    assert_eq!(InvocationTag::Normal as u8, 0);
    assert_eq!(InvocationTag::Syscall as u8, 1);
    assert_ne!(tree.decoy.namespace, tree.kernel.namespace);
    assert_ne!(tree.descendant.namespace, tree.kernel.namespace);
    for fixture in [&tree.normal, &tree.descendant, &tree.decoy] {
        rejected!(
            session,
            session.prepare(fixture.key, fixture.binding(), InvocationTag::Syscall, row(7)),
            SessionError::UnauthorizedSyscall {
                expected: tree.kernel.namespace,
                actual: fixture.namespace,
            }
        );
        session
            .prepare(fixture.key, fixture.binding(), InvocationTag::Normal, row(8))
            .unwrap()
            .commit();
        rejected!(
            session,
            session.prepare_cached(fixture.key, InvocationTag::Syscall, row(9)),
            SessionError::UnauthorizedSyscall {
                expected: tree.kernel.namespace,
                actual: fixture.namespace,
            }
        );
    }
    let first = session
        .prepare(tree.kernel.key, tree.kernel.binding(), InvocationTag::Syscall, row(10))
        .unwrap()
        .commit();
    let second = session
        .prepare_cached(tree.kernel.key, InvocationTag::Syscall, row(11))
        .unwrap()
        .commit();
    // Ordinary invocation of a direct kernel export is equally permitted.
    let third = session
        .prepare_cached(tree.kernel.key, InvocationTag::Normal, row(12))
        .unwrap()
        .commit();
    let binding = *session
        .bindings()
        .iter()
        .find(|binding| binding.procedure_key() == tree.kernel.key)
        .unwrap();
    assert_opening(&session, binding, &tree.kernel);
    assert_eq!(binding.counts(), OpeningUseCounts { normal: 1, syscall: 2 });
    assert_record(first, InvocationTag::Syscall, &tree.kernel, binding, 10);
    assert_record(second, InvocationTag::Syscall, &tree.kernel, binding, 11);
    assert_record(third, InvocationTag::Normal, &tree.kernel, binding, 12);
}

#[test]
fn entry_may_be_a_kernel_export_and_root_end_is_still_one_normal_use() {
    let tree = tree();
    let mut session = entered(&tree.kernel, tree.kernel.namespace);
    assert_eq!(session.bindings()[0].counts(), OpeningUseCounts { normal: 0, syscall: 0 });
    session
        .prepare_cached(tree.kernel.key, InvocationTag::Syscall, row(3))
        .unwrap()
        .commit();
    let end = session.prepare_root_end(tree.kernel.implementation, row(8)).unwrap().commit();
    assert_record(end, InvocationTag::Normal, &tree.kernel, session.bindings()[0], 8);
    assert_eq!(session.bindings()[0].counts(), OpeningUseCounts { normal: 1, syscall: 1 });
}

#[test]
fn bindings_and_cache_are_scoped_to_the_immutable_environment_root() {
    let (first, second) = same_key_different_roots();
    assert_eq!(first.key, second.key);
    assert_ne!(first.root, second.root);
    let mut session = entered(&first, Namespace::initial());
    let descriptor = session.descriptor();
    rejected!(
        session,
        session.prepare(second.key, second.binding(), InvocationTag::Normal, row(6)),
        SessionError::WrongRoot {
            expected: first.root,
            actual: second.root
        }
    );
    assert_eq!(session.descriptor(), descriptor);
    let mut other = new_session(&second, Namespace::initial());
    rejected!(
        other,
        other.prepare_cached(first.key, InvocationTag::Normal, row(6)),
        phase_error(SessionPhase::PendingEntry, SessionPhase::Unentered)
    );
    other.prepare_entry(second.binding()).unwrap().commit();
    assert_eq!(other.bindings()[0].implementation_root(), second.implementation);
    assert_eq!(session.bindings()[0].implementation_root(), first.implementation);
    let unknown = Namespace::initial().procedure_key(label("unknown"));
    rejected!(
        other,
        other.prepare_cached(unknown, InvocationTag::Normal, row(7)),
        SessionError::MissingCachedBinding { key: unknown }
    );
}

#[test]
fn observed_conflicting_metadata_or_structural_opening_provenance_is_rejected_atomically() {
    for same_implementation in [false, true] {
        let (first, second) = duplicate_key_slots(same_implementation);
        assert_eq!(first.root, second.root);
        assert_eq!(first.key, second.key);
        // Both paths prove membership. This deliberately duplicated-key root is not an admission
        // fixture and selective verification makes no global uniqueness claim.
        let mut session = entered(&first, Namespace::initial());
        rejected!(
            session,
            session.prepare(second.key, second.binding(), InvocationTag::Normal, row(4)),
            SessionError::InconsistentBinding { key: first.key }
        );
        session
            .prepare_cached(first.key, InvocationTag::Normal, row(5))
            .unwrap()
            .commit();
        assert_eq!(session.counters().cached_keys, 1);
        assert_eq!(session.bindings()[0].counts().normal, 1);
        assert_eq!(session.ledger().counters().occurrences, 2);
    }
}

#[test]
fn root_end_keeps_its_reservation_on_error_or_drop_and_completes_exactly_once() {
    let tree = tree();
    let mut session = entered(&tree.entry, tree.kernel.namespace);
    let wrong = implementation(900);
    rejected!(
        session,
        session.prepare_root_end(wrong, row(22)),
        SessionError::WrongEntryImplementation {
            expected: tree.entry.implementation,
            actual: wrong
        }
    );
    let before = snapshot(&session);
    let prepared = session.prepare_root_end(tree.entry.implementation, row(22)).unwrap();
    assert_record(
        prepared.use_record(),
        InvocationTag::Normal,
        &tree.entry,
        prepared.native.binding,
        22,
    );
    assert_eq!(prepared.counters().committed_requests, 1);
    assert_eq!(prepared.counters().reserved_requests, 0);
    assert!(prepared.native.buffers.bindings.is_none());
    assert!(prepared.native.buffers.uses.is_none());
    assert!(prepared.native.buffers.root_use.is_none());
    drop(prepared);
    assert_eq!(snapshot(&session), before);
    let end = session.prepare_root_end(tree.entry.implementation, row(22)).unwrap().commit();
    assert_eq!(session.uses().copied().collect::<Vec<_>>(), vec![end]);
    assert_eq!(session.phase(), SessionPhase::Completed);
    assert_eq!(session.counters().committed_requests, 1);
    assert_eq!(session.counters().reserved_requests, 0);
    assert_eq!(session.bindings()[0].counts(), OpeningUseCounts { normal: 1, syscall: 0 });
    rejected!(
        session,
        session.prepare_root_end(tree.entry.implementation, row(23)),
        phase_error(SessionPhase::PendingEntry, SessionPhase::Completed)
    );
    rejected!(
        session,
        session.prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(23)),
        phase_error(SessionPhase::PendingEntry, SessionPhase::Completed)
    );
    rejected!(
        session,
        session.prepare_cached(tree.entry.key, InvocationTag::Normal, row(23)),
        phase_error(SessionPhase::PendingEntry, SessionPhase::Completed)
    );
    rejected!(
        session,
        session.prepare_entry(tree.entry.binding()),
        phase_error(SessionPhase::Unentered, SessionPhase::Completed)
    );
    // Native finalization is read-only; no actual VM transition or proof completion is implied.
    let before = snapshot(&session);
    assert_eq!(session.finalize(), Ok(session.counters()));
    assert_eq!(session.finalize(), Ok(session.counters()));
    assert_eq!(snapshot(&session), before);
}

#[test]
fn ordinary_requests_cannot_consume_the_root_demand_or_its_dedicated_record_buffer() {
    let tree = tree();
    for request_limit in [1, 2] {
        let mut limits = session_limits();
        limits.max_requests = request_limit;
        let mut session = ResolutionSession::new(
            tree.entry.descriptor(tree.kernel.namespace),
            ledger_limits(),
            limits,
        );
        session.prepare_entry(tree.entry.binding()).unwrap().commit();
        let root_allocation = allocation(&session.state.root_use);
        assert!(root_allocation.1 >= 1);
        if request_limit == 2 {
            session
                .prepare_cached(tree.entry.key, InvocationTag::Normal, row(2))
                .unwrap()
                .commit();
            assert_eq!(allocation(&session.state.root_use), root_allocation);
            assert_ne!(session.state.uses.as_ptr(), session.state.root_use.as_ptr());
        }
        rejected!(
            session,
            session.prepare_cached(tree.entry.key, InvocationTag::Normal, row(3)),
            SessionError::LimitExceeded {
                resource: SessionResource::Requests,
                limit: request_limit,
                requested: request_limit + 1,
            }
        );
        session.prepare_root_end(tree.entry.implementation, row(4)).unwrap().commit();
        assert_eq!(allocation(&session.state.root_use), root_allocation);
        assert_eq!(session.counters().committed_requests, request_limit);
        assert_eq!(session.counters().reserved_requests, 0);
        assert_eq!(session.uses().last().unwrap().row(), row(4));
    }
}

#[test]
fn every_session_limit_accepts_exact_and_rejects_one_below_on_an_empty_session() {
    let tree = tree();
    let mut calibration = new_session(&tree.entry, tree.kernel.namespace);
    let requirements = measure_entry(&mut calibration, &tree.entry);
    for resource in resources() {
        let requested = requirements.value(resource);
        assert!(requested > 0);
        let mut exact_limits = session_limits();
        set_limit(&mut exact_limits, resource, requested);
        let mut exact = ResolutionSession::new(
            tree.entry.descriptor(tree.kernel.namespace),
            ledger_limits(),
            exact_limits,
        );
        let prepared = exact.prepare_entry(tree.entry.binding()).unwrap();
        assert_eq!(prepared.counters(), requirements.counters);
        assert_eq!(prepared.requested_peak_bytes(), requirements.peak);
        prepared.commit();
        let mut below_limits = session_limits();
        set_limit(&mut below_limits, resource, requested - 1);
        let mut below = ResolutionSession::new(
            tree.entry.descriptor(tree.kernel.namespace),
            ledger_limits(),
            below_limits,
        );
        rejected!(
            below,
            below.prepare_entry(tree.entry.binding()),
            SessionError::LimitExceeded {
                resource,
                limit: requested - 1,
                requested
            }
        );
    }
}

#[test]
fn every_session_limit_accepts_exact_and_rejects_one_below_on_a_populated_session() {
    let tree = tree();
    let mut calibration = entered(&tree.entry, tree.kernel.namespace);
    let requirements = measure_invocation(&mut calibration, &tree.normal);
    for resource in resources() {
        let requested = requirements.value(resource);
        let mut exact_limits = session_limits();
        set_limit(&mut exact_limits, resource, requested);
        let mut exact = ResolutionSession::new(
            tree.entry.descriptor(tree.kernel.namespace),
            ledger_limits(),
            exact_limits,
        );
        exact.prepare_entry(tree.entry.binding()).unwrap().commit();
        let prepared = exact
            .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(9))
            .unwrap();
        assert_eq!(prepared.counters(), requirements.counters);
        assert_eq!(prepared.requested_peak_bytes(), requirements.peak);
        prepared.commit();
        let mut below_limits = session_limits();
        set_limit(&mut below_limits, resource, requested - 1);
        let mut below = ResolutionSession::new(
            tree.entry.descriptor(tree.kernel.namespace),
            ledger_limits(),
            below_limits,
        );
        below.prepare_entry(tree.entry.binding()).unwrap().commit();
        rejected!(
            below,
            below.prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(9)),
            SessionError::LimitExceeded {
                resource,
                limit: requested - 1,
                requested
            }
        );
    }
}

#[test]
fn native_peak_composes_actual_ledger_peak_old_buffers_and_all_replacement_capacities() {
    let tree = tree();
    let mut session = new_session(&tree.entry, tree.kernel.namespace);
    let before = snapshot(&session);
    let prepared = session.prepare_entry(tree.entry.binding()).unwrap();
    assert_eq!(
        prepared.requested_peak_bytes(),
        prepared.opening.requested_peak_bytes() + replacement_storage(&prepared.native.buffers),
    );
    assert_eq!(
        prepared.counters().retained_bytes,
        prepared.opening.counters().retained_bytes + prospective_storage(&prepared.native),
    );
    drop(prepared);
    assert_eq!(snapshot(&session), before);
    session.prepare_entry(tree.entry.binding()).unwrap().commit();
    let before = snapshot(&session);
    let old_storage = native_storage(&session);
    let prepared = session
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(9))
        .unwrap();
    let opening = prepared.opening.as_ref().unwrap();
    assert_eq!(
        prepared.requested_peak_bytes(),
        old_storage
            + opening.requested_peak_bytes()
            + replacement_storage(&prepared.native.buffers),
    );
    assert_eq!(
        prepared.counters().retained_bytes,
        opening.counters().retained_bytes + prospective_storage(&prepared.native),
    );
    assert!(prepared.native.buffers.bindings.is_some());
    assert!(prepared.native.buffers.uses.is_some());
    assert!(prepared.native.buffers.root_use.is_none());
    drop(prepared);
    assert_eq!(snapshot(&session), before);
    session
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(9))
        .unwrap()
        .commit();
    assert_eq!(
        session.counters().retained_bytes,
        session.ledger().counters().retained_bytes + native_storage(&session)
    );
    let before = snapshot(&session);
    let old_storage = native_storage(&session);
    let prepared = session.prepare_cached(tree.normal.key, InvocationTag::Normal, row(10)).unwrap();
    assert!(prepared.opening.is_none());
    assert_eq!(
        prepared.requested_peak_bytes(),
        prepared.native.state.counters.retained_bytes
            + replacement_storage(&prepared.native.buffers),
    );
    assert!(old_storage > 0);
    drop(prepared);
    assert_eq!(snapshot(&session), before);
}

#[test]
fn a_large_declared_ledger_peak_does_not_preclude_modest_actual_work_under_the_outer_limit() {
    let tree = tree();
    let mut calibration = entered(&tree.entry, tree.kernel.namespace);
    let requirements = measure_invocation(&mut calibration, &tree.normal);
    let mut limits = session_limits();
    limits.max_prepare_peak_bytes = requirements.peak;
    let declared = ledger_limits();
    assert_eq!(declared.max_peak_bytes, usize::MAX);
    let mut session =
        ResolutionSession::new(tree.entry.descriptor(tree.kernel.namespace), declared, limits);
    session.prepare_entry(tree.entry.binding()).unwrap().commit();
    let prepared = session
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(9))
        .unwrap();
    assert_eq!(prepared.requested_peak_bytes(), limits.max_prepare_peak_bytes);
    prepared.commit();
    assert_eq!(session.ledger().limits(), declared);
}

#[test]
fn the_outer_peak_can_tighten_ledger_preparation_without_mutating_the_stored_policy_or_ledger() {
    let tree = tree();
    let mut calibration = new_session(&tree.entry, tree.kernel.namespace);
    let entry_peak = measure_entry(&mut calibration, &tree.entry).peak;
    calibration.prepare_entry(tree.entry.binding()).unwrap().commit();
    let before = snapshot(&calibration);
    let old_storage = native_storage(&calibration);
    let prepared = calibration
        .prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(9))
        .unwrap();
    let ledger_peak = prepared.opening.as_ref().unwrap().requested_peak_bytes();
    let outer_limit = old_storage + ledger_peak - 1;
    drop(prepared);
    assert_eq!(snapshot(&calibration), before);
    assert!(outer_limit >= entry_peak);
    let mut limits = session_limits();
    limits.max_prepare_peak_bytes = outer_limit;
    let declared = ledger_limits();
    let mut session =
        ResolutionSession::new(tree.entry.descriptor(tree.kernel.namespace), declared, limits);
    session.prepare_entry(tree.entry.binding()).unwrap().commit();
    rejected!(
        session,
        session.prepare(tree.normal.key, tree.normal.binding(), InvocationTag::Normal, row(9)),
        SessionError::Ledger(LedgerError::LimitExceeded {
            resource: LedgerResource::PeakBytes,
            limit: ledger_peak - 1,
            requested: ledger_peak,
        })
    );
    assert_eq!(session.ledger().limits(), declared);
}

#[test]
fn capacity_rechecks_reject_allocator_excess_before_publication() {
    let tree = tree();
    let session = entered(&tree.entry, tree.kernel.namespace);
    let before = snapshot(&session);
    let plan = BufferPlan {
        bindings: Some(session.state.bindings.capacity() + 1),
        uses: Some(1),
        root_use: None,
    };
    let ledger_bytes = session.ledger().counters().retained_bytes;
    let planned_native = (session.state.bindings.capacity() + 1) * size_of::<SessionBinding>()
        + size_of::<InvocationUse>()
        + session.state.root_use.capacity() * size_of::<InvocationUse>();
    let planned_replacements = (session.state.bindings.capacity() + 1)
        * size_of::<SessionBinding>()
        + size_of::<InvocationUse>();
    let retained = ledger_bytes + planned_native;
    let peak = ledger_bytes + native_storage(&session) + planned_replacements;
    assert_eq!(
        plan.check(&session.state, session_limits(), ledger_bytes, ledger_bytes),
        Ok((retained, peak))
    );
    for resource in [SessionResource::RetainedBytes, SessionResource::PreparePeakBytes] {
        let mut limits = session_limits();
        let exact = if resource == SessionResource::RetainedBytes {
            retained
        } else {
            peak
        };
        set_limit(&mut limits, resource, exact);
        let excess = BufferPlan {
            bindings: plan.bindings.map(|capacity| capacity + 1),
            uses: plan.uses,
            root_use: plan.root_use,
        };
        assert_eq!(
            excess.check(&session.state, limits, ledger_bytes, ledger_bytes),
            Err(SessionError::LimitExceeded {
                resource,
                limit: exact,
                requested: exact + size_of::<SessionBinding>(),
            }),
        );
        assert_eq!(snapshot(&session), before);
    }
}

#[test]
fn intrinsic_request_ceiling_and_arithmetic_layout_boundaries_need_no_large_allocation() {
    let limits = session_limits();
    assert_eq!(check_requests(MAX_TRACE_LEN - 1, 1, limits), Ok(()));
    assert_eq!(check_requests(MAX_TRACE_LEN, 0, limits), Ok(()));
    assert_eq!(
        check_requests(MAX_TRACE_LEN, 1, limits),
        Err(SessionError::TraceRequestLimitExceeded { requested: MAX_TRACE_LEN + 1 }),
    );
    assert_eq!(check_requests(usize::MAX, 1, limits), Err(SessionError::LengthOverflow));
    assert_eq!(checked_add(usize::MAX - 1, 1), Ok(usize::MAX));
    assert_eq!(checked_add(usize::MAX, 1), Err(SessionError::LengthOverflow));
    assert_eq!(growth(usize::MAX, usize::MAX, true), Err(SessionError::LengthOverflow));
    assert_eq!(array_bytes::<SessionBinding>(0), Ok(0));
    assert_eq!(array_bytes::<SessionBinding>(usize::MAX), Err(SessionError::LengthOverflow));
    let beyond_layout = isize::MAX as usize / size_of::<InvocationUse>() + 1;
    assert_eq!(array_bytes::<InvocationUse>(beyond_layout), Err(SessionError::LengthOverflow));
    assert_eq!(
        reserve_vec::<InvocationUse>(usize::MAX).unwrap_err(),
        SessionError::LengthOverflow
    );
    let counts = OpeningUseCounts { normal: usize::MAX, syscall: 0 };
    assert_eq!(counts.increment(InvocationTag::Normal), Err(SessionError::LengthOverflow));
    let counts = OpeningUseCounts { normal: 0, syscall: usize::MAX };
    assert_eq!(counts.increment(InvocationTag::Syscall), Err(SessionError::LengthOverflow));
}

struct Fixture {
    path: Vec<OpeningStep>,
    root: EnvironmentRoot,
    key: ProcedureKey,
    namespace: Namespace,
    implementation: ImplementationRoot,
}

impl Fixture {
    fn new(path: Vec<OpeningStep>) -> Self {
        let root = path[0].node.commitment().unwrap();
        let mut namespace = Namespace::initial();
        for step in &path {
            if let EnvNode::Env { label, .. } = &step.node {
                namespace = namespace.child(*label);
            }
        }
        let EnvNode::Mast { label, implementation } = &path.last().unwrap().node else {
            panic!("fixture must terminate at a Mast");
        };
        Self {
            root,
            key: namespace.procedure_key(*label),
            namespace,
            implementation: *implementation,
            path,
        }
    }

    fn binding(&self) -> ResolvedBinding {
        let path = self
            .path
            .iter()
            .map(|step| OpeningStep {
                node: step.node.clone(),
                selected_child: step.selected_child,
            })
            .collect();
        ResolutionWitness { path }
            .verify(self.root, self.key, opening_limits())
            .unwrap()
    }

    fn descriptor(&self, kernel: Namespace) -> ExecutionDescriptor {
        ExecutionDescriptor::new(self.key, self.root, kernel)
    }
}

struct Tree {
    entry: Fixture,
    normal: Fixture,
    alias: Fixture,
    kernel: Fixture,
    descendant: Fixture,
    decoy: Fixture,
}

fn tree() -> Tree {
    let entry = mast("entry", 40);
    let normal = mast("normal", 80);
    let alias = mast("alias", 80);
    let service = mast("service", 120);
    let descendant = mast("descendant", 160);
    let child = env("child", &descendant);
    let exports = EnvNode::List(vec![service.commitment().unwrap(), child.commitment().unwrap()]);
    let kernel = env("kernel", &exports);
    let decoy = mast("decoy", 200);
    let other_kernel = env("kernel", &decoy);
    let other = env("other", &other_kernel);
    let list = EnvNode::List(vec![
        entry.commitment().unwrap(),
        normal.commitment().unwrap(),
        alias.commitment().unwrap(),
        kernel.commitment().unwrap(),
        other.commitment().unwrap(),
    ]);
    let runtime = env("runtime", &list);
    let prefix = |slot| vec![step(runtime.clone(), Some(0)), step(list.clone(), Some(slot))];
    let leaf_fixture = |slot, leaf| {
        let mut path = prefix(slot);
        path.push(step(leaf, None));
        Fixture::new(path)
    };
    let mut kernel_path = prefix(3);
    kernel_path.push(step(kernel.clone(), Some(0)));
    kernel_path.push(step(exports.clone(), Some(0)));
    kernel_path.push(step(service, None));
    let mut descendant_path = prefix(3);
    descendant_path.push(step(kernel, Some(0)));
    descendant_path.push(step(exports, Some(1)));
    descendant_path.push(step(child, Some(0)));
    descendant_path.push(step(descendant, None));
    let mut decoy_path = prefix(4);
    decoy_path.push(step(other, Some(0)));
    decoy_path.push(step(other_kernel, Some(0)));
    decoy_path.push(step(decoy, None));
    Tree {
        entry: leaf_fixture(0, entry),
        normal: leaf_fixture(1, normal),
        alias: leaf_fixture(2, alias),
        kernel: Fixture::new(kernel_path),
        descendant: Fixture::new(descendant_path),
        decoy: Fixture::new(decoy_path),
    }
}

fn direct(export: &str, seed: u64) -> Fixture {
    Fixture::new(vec![step(mast(export, seed), None)])
}

fn same_key_different_roots() -> (Fixture, Fixture) {
    (direct("entry", 40), direct("entry", 80))
}

fn duplicate_key_slots(same_implementation: bool) -> (Fixture, Fixture) {
    let first = mast("entry", 40);
    let second = mast("entry", if same_implementation { 40 } else { 80 });
    let list = EnvNode::List(vec![first.commitment().unwrap(), second.commitment().unwrap()]);
    (
        Fixture::new(vec![step(list.clone(), Some(0)), step(first, None)]),
        Fixture::new(vec![step(list, Some(1)), step(second, None)]),
    )
}

fn new_session(fixture: &Fixture, kernel: Namespace) -> ResolutionSession {
    ResolutionSession::new(fixture.descriptor(kernel), ledger_limits(), session_limits())
}

fn entered(fixture: &Fixture, kernel: Namespace) -> ResolutionSession {
    let mut session = new_session(fixture, kernel);
    session.prepare_entry(fixture.binding()).unwrap().commit();
    session
}

fn assert_binding(binding: SessionBinding, fixture: &Fixture) {
    assert_eq!(binding.procedure_key(), fixture.key);
    assert_eq!(binding.namespace(), fixture.namespace);
    assert_eq!(binding.implementation_root(), fixture.implementation);
}

fn assert_opening(session: &ResolutionSession, binding: SessionBinding, fixture: &Fixture) {
    let mut opening = session.ledger().root().unwrap();
    let mut namespace = Namespace::initial();
    for (depth, step) in fixture.path.iter().enumerate() {
        let occurrence = session.ledger().occurrence(opening).unwrap();
        assert_eq!(occurrence.depth(), depth);
        assert_eq!(occurrence.namespace(), namespace);
        assert_eq!(occurrence.node(), &step.node);
        assert_eq!(occurrence.commitment(), step.node.commitment().unwrap());
        if let Some(slot) = step.selected_child {
            let child = occurrence.selected_children()[slot].unwrap();
            let parent = session.ledger().occurrence(child).unwrap().parent().unwrap();
            assert_eq!(parent.opening(), opening);
            assert_eq!(parent.child_slot(), slot);
            opening = child;
            if let EnvNode::Env { label, .. } = &step.node {
                namespace = namespace.child(*label);
            }
        }
    }
    assert_eq!(binding.opening_id(), opening);
}

fn assert_record(
    record: InvocationUse,
    tag: InvocationTag,
    fixture: &Fixture,
    binding: SessionBinding,
    expected_row: usize,
) {
    assert_eq!(record.tag(), tag);
    assert_eq!(record.procedure_key(), fixture.key);
    assert_eq!(record.implementation_root(), fixture.implementation);
    assert_eq!(record.opening_id(), binding.opening_id());
    assert_eq!(record.row(), row(expected_row));
}

fn phase_error(expected: SessionPhase, actual: SessionPhase) -> SessionError {
    SessionError::InvalidPhase { expected, actual }
}

#[derive(Clone, Copy)]
struct Requirements {
    counters: SessionCounters,
    peak: usize,
}

impl Requirements {
    fn value(self, resource: SessionResource) -> usize {
        match resource {
            SessionResource::CachedKeys => self.counters.cached_keys,
            SessionResource::Requests => {
                self.counters.committed_requests + self.counters.reserved_requests
            },
            SessionResource::RetainedBytes => self.counters.retained_bytes,
            SessionResource::PreparePeakBytes => self.peak,
        }
    }
}

fn measure_entry(session: &mut ResolutionSession, fixture: &Fixture) -> Requirements {
    let before = snapshot(session);
    let prepared = session.prepare_entry(fixture.binding()).unwrap();
    let result = Requirements {
        counters: prepared.counters(),
        peak: prepared.requested_peak_bytes(),
    };
    drop(prepared);
    assert_eq!(snapshot(session), before);
    result
}

fn measure_invocation(session: &mut ResolutionSession, fixture: &Fixture) -> Requirements {
    let before = snapshot(session);
    let prepared = session
        .prepare(fixture.key, fixture.binding(), InvocationTag::Normal, row(9))
        .unwrap();
    let result = Requirements {
        counters: prepared.counters(),
        peak: prepared.requested_peak_bytes(),
    };
    drop(prepared);
    assert_eq!(snapshot(session), before);
    result
}

fn native_storage(session: &ResolutionSession) -> usize {
    session.state.bindings.capacity() * size_of::<SessionBinding>()
        + session.state.uses.capacity() * size_of::<InvocationUse>()
        + session.state.root_use.capacity() * size_of::<InvocationUse>()
}

fn replacement_storage(buffers: &PreparedBuffers) -> usize {
    buffers
        .bindings
        .as_ref()
        .map_or(0, |buffer| buffer.capacity() * size_of::<SessionBinding>())
        + buffers
            .uses
            .as_ref()
            .map_or(0, |buffer| buffer.capacity() * size_of::<InvocationUse>())
        + buffers
            .root_use
            .as_ref()
            .map_or(0, |buffer| buffer.capacity() * size_of::<InvocationUse>())
}

fn prospective_storage(native: &PreparedNative<'_>) -> usize {
    native.buffers.bindings.as_ref().unwrap_or(&native.state.bindings).capacity()
        * size_of::<SessionBinding>()
        + native.buffers.uses.as_ref().unwrap_or(&native.state.uses).capacity()
            * size_of::<InvocationUse>()
        + native.buffers.root_use.as_ref().unwrap_or(&native.state.root_use).capacity()
            * size_of::<InvocationUse>()
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    descriptor: ExecutionDescriptor,
    limits: SessionLimits,
    phase: SessionPhase,
    counters: SessionCounters,
    bindings: Vec<SessionBinding>,
    uses: Vec<InvocationUse>,
    native_allocations: [(usize, usize); 3],
    ledger: LedgerSnapshot,
}

#[derive(Debug, PartialEq, Eq)]
struct LedgerSnapshot {
    expected_root: EnvironmentRoot,
    limits: LedgerLimits,
    counters: LedgerCounters,
    root: Option<OpeningId>,
    pointer: usize,
    occurrences: Vec<OccurrenceSnapshot>,
}

#[derive(Debug, PartialEq, Eq)]
struct OccurrenceSnapshot {
    parent: Option<OpeningParent>,
    depth: usize,
    namespace: Namespace,
    commitment: EnvironmentRoot,
    node: EnvNode,
    list_allocation: Option<(usize, usize)>,
    selections: Vec<Option<OpeningId>>,
    selection_pointer: usize,
}

fn snapshot(session: &ResolutionSession) -> Snapshot {
    Snapshot {
        descriptor: session.descriptor(),
        limits: session.limits(),
        phase: session.phase(),
        counters: session.counters(),
        bindings: session.bindings().to_vec(),
        uses: session.uses().copied().collect(),
        native_allocations: [
            allocation(&session.state.bindings),
            allocation(&session.state.uses),
            allocation(&session.state.root_use),
        ],
        ledger: ledger_snapshot(session.ledger()),
    }
}

fn ledger_snapshot(ledger: &OpeningLedger) -> LedgerSnapshot {
    // Ledger's private top-level/selection capacities are covered by its own atomicity suite.
    // Session tests retain all observable topology, pointers and List capacities, plus its retained
    // capacity charge. The session can change ledger storage only through its prepared guard.
    LedgerSnapshot {
        expected_root: ledger.expected_root(),
        limits: ledger.limits(),
        counters: ledger.counters(),
        root: ledger.root(),
        pointer: ledger.occurrences().as_ptr() as usize,
        occurrences: ledger
            .occurrences()
            .iter()
            .map(|occurrence| OccurrenceSnapshot {
                parent: occurrence.parent(),
                depth: occurrence.depth(),
                namespace: occurrence.namespace(),
                commitment: occurrence.commitment(),
                node: occurrence.node().clone(),
                list_allocation: match occurrence.node() {
                    EnvNode::List(children) => Some(allocation(children)),
                    _ => None,
                },
                selections: occurrence.selected_children().to_vec(),
                selection_pointer: occurrence.selected_children().as_ptr() as usize,
            })
            .collect(),
    }
}

fn allocation<T>(buffer: &Vec<T>) -> (usize, usize) {
    (buffer.as_ptr() as usize, buffer.capacity())
}

fn resources() -> [SessionResource; 4] {
    [
        SessionResource::CachedKeys,
        SessionResource::Requests,
        SessionResource::RetainedBytes,
        SessionResource::PreparePeakBytes,
    ]
}

fn set_limit(limits: &mut SessionLimits, resource: SessionResource, value: usize) {
    match resource {
        SessionResource::CachedKeys => limits.max_cached_keys = value,
        SessionResource::Requests => limits.max_requests = value,
        SessionResource::RetainedBytes => limits.max_retained_bytes = value,
        SessionResource::PreparePeakBytes => limits.max_prepare_peak_bytes = value,
    }
}

fn session_limits() -> SessionLimits {
    SessionLimits {
        max_cached_keys: usize::MAX,
        max_requests: usize::MAX,
        max_retained_bytes: usize::MAX,
        max_prepare_peak_bytes: usize::MAX,
    }
}

fn ledger_limits() -> LedgerLimits {
    LedgerLimits {
        max_occurrences: usize::MAX,
        max_total_list_children: usize::MAX,
        max_encoded_bytes: usize::MAX,
        max_library_rows: usize::MAX,
        max_compression_requests: usize::MAX,
        max_retained_bytes: usize::MAX,
        max_peak_bytes: usize::MAX,
    }
}

fn opening_limits() -> OpeningLimits {
    OpeningLimits {
        max_nodes: usize::MAX,
        max_depth: usize::MAX,
        max_list_children: usize::MAX,
        max_total_list_children: usize::MAX,
        max_encoded_bytes: usize::MAX,
        max_storage_bytes: usize::MAX,
    }
}

fn step(node: EnvNode, selected_child: Option<usize>) -> OpeningStep {
    OpeningStep { node, selected_child }
}

fn mast(export: &str, seed: u64) -> EnvNode {
    EnvNode::Mast {
        label: label(export),
        implementation: implementation(seed),
    }
}

fn env(name: &str, child: &EnvNode) -> EnvNode {
    EnvNode::Env {
        label: label(name),
        child: child.commitment().unwrap(),
    }
}

fn label(text: &str) -> LabelCommitment {
    CanonicalLabel::text(text).unwrap().commitment()
}

fn implementation(seed: u64) -> ImplementationRoot {
    ImplementationRoot::new(Word::new(
        [seed, seed + 1, seed + 2, seed + 3].map(Felt::new_unchecked),
    ))
}

fn row(index: usize) -> RowIndex {
    index.into()
}
