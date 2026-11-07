// INSTRUCTION CYCLE COSTS
// ================================================================================================
use super::*;
use crate::testing::{FixtureNamespace, FixtureProgram};

/// Pins the instruction reference's raw cycle counts to emitted operations, including immediate
/// specializations, parser-expanded forms, and system-event overhead. Control rows and operation
/// packing/padding are deliberately outside these per-instruction counts.
///
/// Cost is measured by differencing programs containing the instruction once, twice and three
/// times: this cancels the entrypoint prologue exactly, and requiring the two deltas to agree
/// rules out any fusion between adjacent copies.
#[test]
fn instruction_cycle_costs_match_docs() {
    // (source, documented cycles)
    let cases: &[(&str, usize)] = &[
        // Assertions and tests
        ("assert", 1),
        ("assertz", 2),
        ("assert_eq", 2),
        ("assert_eqw", 11),
        ("u32assert", 3),
        ("u32assert2", 1),
        // Arithmetic and Boolean operations
        ("add", 1),
        ("add.0", 1),
        ("add.1", 1),
        ("add.2", 2),
        ("sub", 2),
        ("sub.0", 1),
        ("sub.2", 2),
        ("mul", 1),
        ("mul.0", 2),
        ("mul.1", 1),
        ("mul.2", 2),
        ("div", 2),
        ("div.1", 1),
        ("div.2", 2),
        ("neg", 1),
        ("inv", 1),
        ("pow2", 16),
        ("exp", 72),
        ("exp.u8", 17),
        ("exp.u16", 25),
        ("exp.u32", 41),
        ("exp.u63", 72),
        // exp.b: addition chains for selected small powers, EXPACC otherwise
        ("exp.0", 3),
        ("exp.1", 1),
        ("exp.2", 2),
        ("exp.3", 4),
        ("exp.4", 4),
        ("exp.5", 6),
        ("exp.6", 6),
        ("exp.7", 8),
        ("exp.8", 6),
        ("exp.16", 8),
        ("exp.256", 19),
        ("ilog2", 70),
        ("not", 1),
        ("and", 1),
        ("or", 1),
        ("xor", 7),
        // Comparison operations
        ("eq", 1),
        ("eq.0", 1),
        ("eq.2", 2),
        ("neq", 2),
        ("neq.0", 2),
        ("neq.2", 3),
        ("lt", 17),
        ("lt.2", 18),
        ("lt.0", 2),
        ("lte", 18),
        ("lte.2", 19),
        ("lte.0", 1),
        ("gt", 16),
        ("gt.2", 17),
        ("gt.0", 2),
        ("gte", 17),
        ("gte.2", 18),
        ("gte.0", 3),
        ("is_odd", 6),
        ("eqw", 15),
        // U32 arithmetic: immediate 1 costs two push operations, other immediates cost one.
        // Wrapping multiplication must discard the high limb with SWAP DROP, not just DROP.
        ("u32widening_add", 1),
        ("u32widening_add.0", 2),
        ("u32widening_add.1", 3),
        ("u32widening_add.2", 2),
        ("u32wrapping_mul", 3),
        ("u32wrapping_mul.0", 4),
        ("u32wrapping_mul.1", 5),
        ("u32wrapping_mul.2", 4),
        ("u32div", 2),
        ("u32div.2", 3),
        ("u32mod", 3),
        ("u32mod.2", 4),
        ("u32divmod", 1),
        ("u32divmod.2", 2),
        // These immediates are parser-expanded PUSH instructions, including unary u32not.b.
        ("u32and", 1),
        ("u32and.1", 3),
        ("u32and.2", 2),
        ("u32or", 6),
        ("u32not", 5),
        ("u32not.2", 6),
        // Immediate-zero shifts/rotations are a single NOOP. Other immediate powers of two
        // are pushed directly, without the PUSH.1 specialization or the dynamic POW2 sequence.
        ("u32shl", 19),
        ("u32shl.0", 1),
        ("u32shl.1", 4),
        ("u32shr", 18),
        ("u32shr.1", 3),
        ("u32rotl", 18),
        ("u32rotl.1", 3),
        ("u32rotr", 23),
        ("u32rotr.31", 3),
        ("u32popcnt", 36),
        // Advice hints contribute PUSH/EMIT/DROP plus ADVPOP before their verification code.
        ("u32clz", 52),
        ("u32ctz", 38),
        ("u32clo", 43),
        ("u32cto", 37),
        ("u32lt", 3),
        ("u32lte", 5),
        ("u32gt", 4),
        ("u32gte", 4),
        ("u32max", 7),
        ("u32max.0", 8),
        ("u32max.1", 9), // push.1 lowers to PAD INCR
        ("u32max.2", 8),
        ("u32max.4294967295", 8),
        // Extension field operations
        ("ext2add", 5),
        ("ext2sub", 7),
        ("ext2mul", 3),
        ("ext2neg", 4),
        ("ext2inv", 11),
        ("ext2div", 14),
        // Stack indexing and push specializations are not uniform across depths/immediates.
        ("push.0", 1),
        ("push.1", 2),
        ("push.2", 1),
        ("push.[0,1,2,3]", 5),
        ("padw", 4),
        ("dup.7", 1),
        ("dup.8", 3),
        ("dup.9", 1),
        ("dupw.3", 4),
        ("swap.1", 1),
        ("swap.2", 2),
        ("swap.9", 5),
        ("swap.10", 6),
        ("swapw.2", 1),
        ("swapdw", 1),
        ("movup.8", 1),
        ("movup.9", 4),
        ("movdn.8", 1),
        ("movdn.9", 4),
        ("movupw.2", 2),
        ("movupw.3", 3),
        ("movdnw.2", 2),
        ("movdnw.3", 3),
        ("reversew", 3),
        ("reversedw", 7),
        ("cswap", 1),
        ("cswapw", 1),
        // Memory/advice costs include their explicit address pushes and system-event lowering.
        ("mem_load", 1),
        ("mem_load.1", 3),
        ("mem_load.4", 2),
        ("mem_loadw_le", 1),
        ("mem_loadw_le.4", 2),
        ("mem_loadw_be", 4),
        ("mem_loadw_be.0", 5),
        ("mem_store", 2),
        ("mem_store.1", 4),
        ("mem_storew_le", 1),
        ("mem_storew_le.0", 2),
        ("mem_storew_be", 9),
        ("mem_storew_be.0", 8),
        ("mem_stream", 1),
        ("adv_push", 1),
        ("adv_pushw", 5),
        ("adv_loadw", 1),
        ("adv.push_mapvaln", 3),
        ("adv.push_mtnode", 3),
        ("adv.insert_compress", 3),
        ("emit", 1),
        ("emit.event(\"cost_probe\")", 3),
        ("trace", 3),
        ("trace.event(\"cost_probe\")", 5),
        ("compress", 1),
        ("hash", 18),
        ("hdword", 15),
        ("mtree_get", 13),
        ("mtree_set", 33),
        ("mtree_merge", 18),
        ("mtree_verify", 1),
    ];

    let ops_for = |instruction: &str, copies: usize| -> usize {
        let body = core::iter::repeat_n(instruction, copies).collect::<Vec<_>>().join("\n    ");
        emitted_raw_ops(&format!("begin\n    {body}\nend"))
    };

    let mut mismatches = Vec::new();
    for (instruction, documented) in cases {
        let (one, two, three) =
            (ops_for(instruction, 1), ops_for(instruction, 2), ops_for(instruction, 3));
        let (first, second) = (two - one, three - two);
        assert_eq!(
            first, second,
            "{instruction}: cost is not additive across copies ({first} then {second}); \
             the differencing measurement is not valid for this instruction"
        );
        if first != *documented {
            mismatches.push(format!("  {instruction}: documented {documented}, emits {first}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "instruction cycle costs are out of date:\n{}",
        mismatches.join("\n")
    );
}

/// Local addressing is ordinary memory-backed frame-pointer work. Its documented cost must not
/// depend on index 1, and scalar/word operations must include their respective load/store work.
/// Differencing copies within the same local procedure cancels its 14 frame-management operations
/// as well as the entrypoint prologue and retained invocation, without executing any instructions.
#[test]
fn local_instruction_cycle_costs_match_docs() {
    let cases = [
        ("locaddr.0", 4),
        ("locaddr.1", 4),
        ("loc_load.1", 5),
        ("loc_store.1", 6),
        ("loc_loadw_le.4", 5),
        ("loc_storew_le.4", 5),
        ("loc_loadw_be.4", 8),
        ("loc_storew_be.4", 11),
    ];
    for (instruction, documented) in cases {
        let ops_for = |copies| {
            let body = core::iter::repeat_n(instruction, copies).collect::<Vec<_>>().join("\n    ");
            emitted_raw_ops(&format!(
                "@locals(8)\nproc probe\n    {body}\nend\nbegin exec.probe end"
            ))
        };
        let (one, two, three) = (ops_for(1), ops_for(2), ops_for(3));
        assert_eq!(two - one, documented, "{instruction}");
        assert_eq!(three - two, documented, "{instruction}");
    }
}

fn emitted_raw_ops(source: &str) -> usize {
    let context = TestContext::default();
    let source = source_file!(&context, source);
    let module = context.parse_module(source).expect("parsing failed");
    let mut fixture_namespace = FixtureNamespace::assembly_tests();
    fixture_namespace.add_module(&module).expect("fixture metadata failed");
    let program = fixture_namespace
        .configure(Assembler::new(context.source_manager()), [&*module])
        .expect("fixture configuration failed")
        .assemble_program("program", module)
        .expect("assembly failed")
        .fixture_program();

    program
        .package()
        .mast_forest()
        .nodes()
        .iter()
        .filter_map(|node| node.get_basic_block())
        .map(|block| block.raw_operations().count())
        .sum()
}

#[test]
fn bare_exp_lowers_to_63_expacc_rows() -> Result<(), Report> {
    let context = TestContext::default();
    let module = context.parse_module("begin push.5 push.3 exp drop end")?;
    let mut fixture_namespace = FixtureNamespace::assembly_tests();
    fixture_namespace.add_module(&module)?;
    let program = fixture_namespace
        .configure(Assembler::new(context.source_manager()), [&*module])?
        .assemble_program("p", module)?
        .fixture_program();
    let ops: Vec<Operation> = program.package().mast_forest()[entry_node(&program)]
        .unwrap_basic_block()
        .operations()
        .copied()
        .collect();

    let start = ops.iter().position(|op| matches!(op, Operation::Expacc)).unwrap();
    assert_eq!(ops.iter().filter(|op| matches!(op, Operation::Expacc)).count(), 63);

    let end = start + 63;
    assert_matches!(ops.get(end), Some(Operation::Drop));
    assert_matches!(ops.get(end + 1), Some(Operation::Drop));
    assert_matches!(ops.get(end + 2), Some(Operation::Swap));
    assert_matches!(ops.get(end + 3), Some(Operation::Eqz));
    assert_matches!(ops.get(end + 4), Some(Operation::Assert(_)));

    Ok(())
}

#[test]
fn exp_imm_uses_exact_exponent_bit_length() -> Result<(), Report> {
    let context = TestContext::default();

    for pow in [(1_u64 << 63) - 1, 1_u64 << 63, Felt::ORDER_U64 - 2, Felt::ORDER_U64 - 1] {
        let source = format!("begin push.3 exp.{pow} drop end");
        let module = context.parse_module(source.as_str())?;
        let mut fixture_namespace = FixtureNamespace::assembly_tests();
        fixture_namespace.add_module(&module)?;
        let program = fixture_namespace
            .configure(Assembler::new(context.source_manager()), [&*module])?
            .assemble_program("p", module)?
            .fixture_program();
        let num_expacc = program.package().mast_forest()[entry_node(&program)]
            .unwrap_basic_block()
            .operations()
            .filter(|op| matches!(op, Operation::Expacc))
            .count();

        assert_eq!(num_expacc, pow.ilog2() as usize + 1, "unexpected row count for pow = {pow}");
    }

    Ok(())
}
