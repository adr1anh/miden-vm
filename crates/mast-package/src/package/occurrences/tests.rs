use alloc::{sync::Arc, vec, vec::Vec};
use core::{assert_matches, cell::Cell};

use miden_core::{
    advice::AdviceMap,
    mast::{BasicBlockNodeBuilder, ExternalNodeBuilder, MastNode, MastNodeExt},
    operations::Operation,
    program::{CanonicalLabel, ImplementationRoot},
    serde::{Deserializable, Serializable},
    utils::IndexVec,
};

use super::*;
use crate::{
    CallableProcedurePath, NamespacePath, PackageCallables, PackageId, ProcedureName, Section,
    SectionId, TargetType, Version,
    debug_info::{DebugSourceAsmOp, DebugSourceNode, PackageDebugInfoBuilder},
    interface::serialization::{HomeProfile, TypedIdProfile},
};

const LIMITS: CodecLimits = CodecLimits::new(1 << 20, 1024, 1024, 1024);

struct ExactHome;

impl TypedIdProfile for ExactHome {
    type Context = NamespacePath;
    type Error = &'static str;

    fn validate_typed_id(
        &self,
        _context: &Self::Context,
        _codec: u32,
        _canonical_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        Err("fixture permits no TypedId codec")
    }
}

impl HomeProfile for ExactHome {
    fn validate_home(
        &self,
        context: &Self::Context,
        home: &[CanonicalLabel],
    ) -> Result<(), Self::Error> {
        if context.home() == home {
            Ok(())
        } else {
            Err("unexpected fixture home")
        }
    }
}

struct Fixture {
    package: Package,
    symbols: PackageSymbols,
    rows: Vec<PackageProcedureOccurrence>,
    other_root: MastNodeId,
    non_root: MastNodeId,
}

fn fixture() -> Fixture {
    let home = NamespacePath::new(vec![CanonicalLabel::text("occurrence-fixture").unwrap()]);
    let mut nodes = IndexVec::<MastNodeId, MastNode>::new();
    let mut roots = Vec::new();
    let mut bindings = Vec::new();
    let mut selected = Vec::new();
    let mut rows = Vec::new();
    let mut debug = PackageDebugInfoBuilder::default();
    let mut entry = None;
    for (index, (name, operation)) in
        [("left", Operation::Add), ("right", Operation::Add), ("other", Operation::Mul)]
            .into_iter()
            .enumerate()
    {
        let node = BasicBlockNodeBuilder::new(vec![operation]).build().unwrap();
        let digest = node.digest();
        let node_id = nodes.push(node.into()).unwrap();
        let path = CallableProcedurePath::from_semantic_components(vec![name.into()]).unwrap();
        let binding = ProcedureName::new(home.clone(), path).unwrap();
        let key = binding.key();
        if index == 1 {
            entry = Some(key);
        }
        let source = if index < 2 {
            let context = debug.add_string(name);
            let operation = debug.add_string("add");
            let source = debug
                .add_node(DebugSourceNode {
                    exec_node: node_id,
                    children: Vec::new(),
                    op_start: 0,
                    op_end: 1,
                    asm_ops: vec![DebugSourceAsmOp::new(0, None, context, operation, 1)],
                    debug_vars: Vec::new(),
                    inline_calls: Vec::new(),
                })
                .unwrap();
            debug.add_root(source);
            Some(source)
        } else {
            None
        };
        rows.push(PackageProcedureOccurrence::new(key, node_id, source));
        bindings.push(binding);
        selected.push((key, ImplementationRoot::new(digest)));
        roots.push(node_id);
    }
    let other_root = roots[2];
    let node = BasicBlockNodeBuilder::new(vec![Operation::Drop]).build().unwrap();
    let non_root = nodes.push(node.into()).unwrap();
    let mast = Arc::new(MastForest::from_raw_parts(nodes, roots, AdviceMap::default()).unwrap());
    let symbols =
        PackageSymbols::new(home, PackageCallables::new(bindings, [], selected).unwrap(), entry)
            .unwrap();
    let mut package = Package::create(
        PackageId::from("private-occurrences"),
        Version::new(1, 0, 0),
        TargetType::Executable,
        mast,
        [],
        [],
        &symbols,
    )
    .unwrap();
    package.sections.push(Section::new(
        SectionId::DEBUG_INFO,
        debug.build().to_bytes_with_standard_limits().unwrap(),
    ));
    rows.sort_by_key(|row| row.key.as_word().as_bytes());
    Fixture {
        package,
        symbols,
        rows,
        other_root,
        non_root,
    }
}

fn payload(rows: &[PackageProcedureOccurrence]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_payload(rows, &mut bytes);
    bytes
}

fn replace_payload(package: &Package, payload: &[u8]) -> Vec<u8> {
    let bytes = package.to_bytes();
    let mut prefix = Vec::new();
    package.write_header_into(&mut prefix);
    package.mast.write_into(&mut prefix);
    let offset = prefix.len() + 4 + package.naming.as_bytes().len();
    let previous_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    let mut changed = bytes[..offset].to_vec();
    changed.write_u32(payload.len().try_into().unwrap());
    changed.extend_from_slice(payload);
    changed.extend_from_slice(&bytes[offset + 4 + previous_len..]);
    changed
}

#[test]
fn private_equal_digest_occurrences_roundtrip_without_public_aliases() {
    let Fixture { package, symbols, rows, .. } = fixture();
    assert_eq!(package.manifest.num_exports(), 0);
    assert_eq!(symbols.callables().visible_paths().len(), 0);
    let selected = *rows.iter().find(|row| Some(row.key) == symbols.entry_key()).unwrap();
    let other = rows
        .iter()
        .find(|row| row.key != selected.key && row.exec_node != MastNodeId::new_unchecked(2))
        .unwrap();
    assert_ne!(selected.exec_node, other.exec_node);
    assert_eq!(
        package.mast[selected.exec_node].digest(),
        package.mast[other.exec_node].digest()
    );
    assert_ne!(selected.source_node, other.source_node);

    for emit_debug in [true, false] {
        let mut package =
            package.clone().with_procedure_occurrences(rows.clone(), &symbols).unwrap();
        if !emit_debug {
            package.strip_debug_info().unwrap();
        }
        let bytes = package.to_bytes();
        for decoded in [
            Package::read_from_bytes(&bytes).unwrap(),
            Package::read_from_bytes_trusted(&bytes).unwrap(),
        ] {
            assert_eq!(decoded.procedure_occurrences(), package.procedure_occurrences());
            assert_eq!(
                decoded.validate_symbols(&ExactHome, symbols.namespace_plan(), LIMITS).unwrap(),
                symbols,
            );
            let occurrence = decoded.procedure_occurrence(selected.key).unwrap();
            assert_eq!(occurrence.exec_node(), selected.exec_node);
            if emit_debug {
                assert_eq!(occurrence.source_node(), selected.source_node);
                let debug = decoded.debug_info().unwrap().unwrap();
                let source = occurrence.source_node().unwrap();
                assert_eq!(debug.source_node(source).unwrap().exec_node, selected.exec_node);
                let operation = debug.first_asm_op_for_source_node(source).unwrap();
                assert_eq!(debug[operation.context_name_idx].as_ref(), "right");
            } else {
                assert_eq!(occurrence.source_node(), None);
                assert!(decoded.debug_info().unwrap().is_none());
            }
        }
    }
}

#[test]
fn occurrence_attachment_checks_order_key_and_selected_implementation() {
    let Fixture {
        package,
        symbols,
        rows,
        other_root,
        non_root,
    } = fixture();
    let first = rows[0];
    for invalid in [vec![first, first], rows.iter().copied().rev().collect()] {
        assert_matches!(
            package.clone().with_procedure_occurrences(invalid, &symbols),
            Err(PackageProcedureOccurrencesError::UnsortedOrDuplicateKey { .. }),
        );
    }
    let zero = ProcedureKey::new(Word::default());
    assert!(symbols.callables().binding(zero).is_none());
    assert_matches!(
        package.clone().with_procedure_occurrences(
            [PackageProcedureOccurrence::new(zero, first.exec_node, None)],
            &symbols,
        ),
        Err(PackageProcedureOccurrencesError::UnknownKey { .. }),
    );
    let selected = *rows.iter().find(|row| row.exec_node != other_root).unwrap();
    assert_matches!(
        package.clone().with_procedure_occurrences(
            [PackageProcedureOccurrence::new(selected.key, other_root, None)],
            &symbols,
        ),
        Err(PackageProcedureOccurrencesError::ImplementationMismatch { .. }),
    );
    for invalid_node in [non_root, MastNodeId::new_unchecked(u32::MAX)] {
        assert_matches!(
            package.clone().with_procedure_occurrences(
                [PackageProcedureOccurrence::new(first.key, invalid_node, None)],
                &symbols,
            ),
            Err(PackageProcedureOccurrencesError::InvalidExecutionNode { .. }),
        );
    }
}

#[test]
fn supplied_rows_do_not_require_a_public_entry_or_complete_selection_table() {
    let Fixture { package, symbols, rows, .. } = fixture();
    package.check_procedure_occurrences(&symbols).unwrap();
    assert!(package.procedure_occurrences().is_empty());
    let package = package.with_procedure_occurrences([rows[0]], &symbols).unwrap();
    assert_eq!(package.procedure_occurrences(), &[rows[0]]);
}

#[test]
fn occurrence_limits_charge_each_row_before_retaining_it() {
    let Fixture { package, symbols, rows, .. } = fixture();
    let consumed = Cell::new(0);
    let iterator = rows.iter().copied().inspect(|_| consumed.set(consumed.get() + 1));
    assert_matches!(
        package.clone().with_procedure_occurrences_with_limits(
            iterator,
            &symbols,
            CodecLimits::new(1024, 1, 0, 0),
        ),
        Err(PackageProcedureOccurrencesError::Codec(CodecError::LimitExceeded {
            resource: "records",
            actual: 2,
            limit: 1,
        })),
    );
    assert_eq!(consumed.get(), 2);
    assert_matches!(
        package.with_procedure_occurrences_with_limits(
            [rows[0]],
            &symbols,
            CodecLimits::new(COUNT_BYTES as u32, 1, 0, 0),
        ),
        Err(PackageProcedureOccurrencesError::Codec(CodecError::LimitExceeded {
            resource: "wire bytes",
            ..
        })),
    );
    let bytes = payload(&rows);
    let fixture = fixture();
    assert!(read_payload(&bytes, &fixture.package.mast, CodecLimits::new(1024, 0, 0, 0)).is_err());
    assert!(read_payload(&bytes, &fixture.package.mast, CodecLimits::new(4, 1024, 0, 0)).is_err());
}

#[test]
fn package_admission_shares_naming_and_occurrence_byte_record_limits() {
    let Fixture { package, symbols, rows, .. } = fixture();
    let package = package.with_procedure_occurrences(rows, &symbols).unwrap();
    let table_bytes = payload_len(package.procedure_occurrences()).unwrap() as u32;
    let naming_bytes = package.naming.as_bytes().len() as u32;
    let records = package.procedure_occurrences().len() as u32;
    for limits in [
        CodecLimits::new(table_bytes - 1, 1024, 1024, 1024),
        CodecLimits::new(1 << 20, records - 1, 1024, 1024),
        CodecLimits::new(naming_bytes + table_bytes - 1, 1024, 1024, 1024),
    ] {
        assert!(package.validate_symbols(&ExactHome, symbols.namespace_plan(), limits).is_err());
    }
    assert!(
        package
            .validate_symbols(
                &ExactHome,
                symbols.namespace_plan(),
                CodecLimits::new(naming_bytes + table_bytes, 1024, 1024, 1024),
            )
            .is_ok()
    );
}

#[test]
fn both_package_readers_reject_malformed_occurrence_payloads() {
    let Fixture { package, rows, non_root, .. } = fixture();
    let first = rows[0];
    let valid = payload(&rows);
    let mut bad_tag = valid.clone();
    bad_tag[COUNT_BYTES + 32 + 4] = 2;
    let mut bad_key = valid.clone();
    bad_key[COUNT_BYTES..COUNT_BYTES + 32].fill(0xff);
    let mut trailing = valid;
    trailing.push(0);
    let mut short_row = payload(&[PackageProcedureOccurrence::new(
        first.key,
        first.exec_node,
        Some(DebugSourceNodeId::from(0)),
    )]);
    short_row.pop();
    for malformed in [
        Vec::new(),
        u32::MAX.to_le_bytes().to_vec(),
        payload(&[first, first]),
        payload(&rows.iter().copied().rev().collect::<Vec<_>>()),
        payload(&[PackageProcedureOccurrence::new(first.key, non_root, None)]),
        payload(&[PackageProcedureOccurrence::new(
            first.key,
            MastNodeId::new_unchecked(u32::MAX),
            None,
        )]),
        bad_tag,
        bad_key,
        trailing,
        short_row,
    ] {
        let bytes = replace_payload(&package, &malformed);
        for result in [Package::read_from_bytes(&bytes), Package::read_from_bytes_trusted(&bytes)] {
            assert!(result.is_err(), "reader accepted malformed occurrence payload");
        }
    }
}

#[test]
fn source_references_are_exact_and_trusted_readers_defer_debug_checks() {
    let Fixture { package, rows, .. } = fixture();
    let row = *rows.iter().find(|row| row.source_node.is_some()).unwrap();
    let other = rows
        .iter()
        .find(|other| other.source_node.is_some() && other.key != row.key)
        .unwrap();
    for source in [DebugSourceNodeId::from(99), other.source_node.unwrap()] {
        let bytes = replace_payload(
            &package,
            &payload(&[PackageProcedureOccurrence::new(row.key, row.exec_node, Some(source))]),
        );
        assert!(Package::read_from_bytes(&bytes).is_err());
        let trusted = Package::read_from_bytes_trusted(&bytes).unwrap();
        assert!(trusted.debug_info().is_err());
    }
}

#[test]
fn source_attachment_can_precede_debug_but_final_readers_require_its_graph() {
    let Fixture { mut package, symbols, rows, .. } = fixture();
    let sections = core::mem::take(&mut package.sections);
    let mut package = package.with_procedure_occurrences(rows, &symbols).unwrap();
    let bytes = package.to_bytes();
    assert!(Package::read_from_bytes(&bytes).is_err());
    let trusted = Package::read_from_bytes_trusted(&bytes).unwrap();
    assert!(trusted.debug_info().is_err());
    package.sections = sections;
    assert!(Package::read_from_bytes(&package.to_bytes()).is_ok());
}

#[test]
fn checked_symbols_reject_decoded_key_and_implementation_mismatches() {
    let Fixture { package, symbols, rows, other_root, .. } = fixture();
    let row = *rows.iter().find(|row| row.exec_node != other_root).unwrap();
    for invalid in [
        PackageProcedureOccurrence::new(ProcedureKey::new(Word::default()), row.exec_node, None),
        PackageProcedureOccurrence::new(row.key, other_root, None),
    ] {
        let bytes = replace_payload(&package, &payload(&[invalid]));
        for decoded in [
            Package::read_from_bytes(&bytes).unwrap(),
            Package::read_from_bytes_trusted(&bytes).unwrap(),
        ] {
            assert!(decoded.check_naming(&symbols).is_err());
            assert!(
                decoded.validate_symbols(&ExactHome, symbols.namespace_plan(), LIMITS).is_err()
            );
        }
    }
}

#[test]
fn source_stripping_preserves_exact_execution_and_code_supply_commitment() {
    let Fixture { package, symbols, rows, .. } = fixture();
    let before = package.dependency_commitment();
    let package = package.with_procedure_occurrences(rows, &symbols).unwrap();
    assert_ne!(before, package.dependency_commitment());
    let code = package.code_commitment();
    let dependency = package.dependency_commitment();
    let artifact = package.artifacts_commitment();
    let package_commitment = package.commitment();
    let mut stripped = package.clone();
    stripped.strip_debug_info().unwrap();
    assert_eq!(stripped.code_commitment(), code);
    assert_eq!(stripped.dependency_commitment(), dependency);
    assert_ne!(stripped.artifacts_commitment(), artifact);
    assert_ne!(stripped.commitment(), package_commitment);
    for (before, after) in
        package.procedure_occurrences().iter().zip(stripped.procedure_occurrences())
    {
        assert_eq!(before.key(), after.key());
        assert_eq!(before.exec_node(), after.exec_node());
        assert_eq!(after.source_node(), None);
    }
    let advised = package.clone().with_advice_map(AdviceMap::default());
    assert_eq!(advised.procedure_occurrences(), package.procedure_occurrences());
}

#[test]
fn external_occurrences_retain_exact_placeholders_without_materializing_code() {
    let mut mast = MastForest::new();
    let root = ExternalNodeBuilder::new(Word::from([1_u32, 2, 3, 4]))
        .add_to_forest(&mut mast)
        .unwrap();
    mast.make_root(root);
    let home = NamespacePath::new(vec![CanonicalLabel::text("external-fixture").unwrap()]);
    let binding = ProcedureName::new(
        home.clone(),
        CallableProcedurePath::from_semantic_components(vec!["entry".into()]).unwrap(),
    )
    .unwrap();
    let key = binding.key();
    let symbols = PackageSymbols::new(
        home,
        PackageCallables::new([binding], [], [(key, ImplementationRoot::new(mast[root].digest()))])
            .unwrap(),
        Some(key),
    )
    .unwrap();
    let package = Package::create(
        PackageId::from("external"),
        Version::new(1, 0, 0),
        TargetType::Executable,
        Arc::new(mast),
        [],
        [],
        &symbols,
    )
    .unwrap()
    .with_procedure_occurrences([PackageProcedureOccurrence::new(key, root, None)], &symbols)
    .unwrap();
    let decoded = Package::read_from_bytes(&package.to_bytes()).unwrap();
    assert!(decoded.mast[decoded.procedure_occurrence(key).unwrap().exec_node()].is_external());
}
