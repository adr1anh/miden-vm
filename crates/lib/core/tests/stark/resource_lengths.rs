//! Execute the production resource loaders without constructing a recursive proof.
//!
//! The private ACE and query-row entry points are exposed only in test modules made from their
//! complete production sources. This keeps malformed-length coverage independent of the proof
//! adapters while retaining the real lookup, length check, copy, and hash authentication code.

use miden_core::{
    Felt, Word,
    crypto::{
        hash::Eidos,
        merkle::{MerklePath, MerkleStore},
    },
    mast::error_code_from_msg,
};
use miden_crypto::hash::eidos::{BLOCK_LEN, domains::LMCS_LEAF};
use miden_processor::{ExecutionError, operation::OperationError};
use miden_utils_testing::Test;

use super::{pvm_layout_const, vm_layout_const};
use crate::helpers::{masm_push_word, masm_store_felts, read_memory_felt};

const ACE_LENGTH_ERROR: &str =
    "ACE circuit stream length does not match the compiled-in circuit length";
const ACE_DIGEST_ERROR: &str = "ACE circuit stream does not match the compiled-in circuit digest";
const ROW_LENGTH_ERRORS: [&str; 4] = [
    "preprocessed query leaf length mismatch",
    "main query leaf length mismatch",
    "aux query leaf length mismatch",
    "quotient query leaf length mismatch",
];
const FRI_LENGTH_ERROR: &str = "FRI layer leaf length mismatch";

#[derive(Clone, Copy, Debug)]
enum Relation {
    Vm,
    Pvm,
}

impl Relation {
    fn evaluator(self) -> &'static str {
        match self {
            Self::Vm => include_str!("../../asm/sys/vm/constraints_eval.masm"),
            Self::Pvm => include_str!("../../asm/sys/pvm/constraints_eval.masm"),
        }
    }

    fn evaluator_const(self, name: &str) -> u64 {
        let prefix = format!("const {name} = ");
        self.evaluator()
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix)?.parse().ok())
            .unwrap_or_else(|| panic!("{self:?} evaluator declares no integer constant {name}"))
    }

    fn compiled_ace_resource(self) -> (Word, usize) {
        let key = Word::new(core::array::from_fn(|index| {
            Felt::new_unchecked(self.evaluator_const(&format!("ACE_CIRCUIT_DIGEST_{index}")))
        }));
        let len = usize::try_from(self.evaluator_const("ACE_STREAM_FELTS"))
            .expect("the compiled ACE stream length fits in usize");
        (key, len)
    }

    fn deep_queries(self) -> &'static str {
        match self {
            Self::Vm => include_str!("../../asm/sys/vm/deep_queries.masm"),
            Self::Pvm => include_str!("../../asm/sys/pvm/deep_queries.masm"),
        }
    }

    fn parameters(self) -> &'static str {
        match self {
            Self::Vm => include_str!("../../asm/sys/vm/parameters.masm"),
            Self::Pvm => include_str!("../../asm/sys/pvm/parameters.masm"),
        }
    }

    fn layout_const(self, name: &str) -> u32 {
        match self {
            Self::Vm => vm_layout_const(name),
            Self::Pvm => pvm_layout_const(name),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Vm => "vm",
            Self::Pvm => "pvm",
        }
    }
}

fn assert_resource_error(test: Test, message: &str) {
    let error = match test.execute_for_output() {
        Ok(_) => panic!("malformed resource must fail with {message:?}"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            ExecutionError::OperationError {
                err: OperationError::FailedAssertion { err_code, err_msg: None },
                ..
            } if err_code == error_code_from_msg(message)
        ),
        "expected the resource assertion {message:?}, got {error:?}"
    );
}

fn ace_test(relation: Relation, key: Word, stream: Vec<Felt>) -> Test {
    let module = format!(
        "{}\n\
         pub proc load_resource_for_test()\n\
             exec.load_and_authenticate_ace_circuit\n\
         end\n",
        relation.evaluator(),
    );
    let source = "
        use test::resource
        begin
            exec.resource::load_resource_for_test
        end
    ";
    build_test!(source, &[], &[], MerkleStore::new(), [(key, stream)])
        .with_module("test::resource", module)
}

fn assert_exact_ace_stream_loads(relation: Relation, key: Word, stream: &[Felt]) {
    let (output, _) =
        ace_test(relation, key, stream.to_vec())
            .execute_for_output()
            .unwrap_or_else(|error| {
                panic!(
                    "{relation:?} exact ACE stream must load: {error:?}; \
                 length assertion code: {:?}; digest assertion code: {:?}",
                    error_code_from_msg(ACE_LENGTH_ERROR),
                    error_code_from_msg(ACE_DIGEST_ERROR),
                )
            });
    let destination = relation.layout_const("ACE_CIRCUIT_STREAM_PTR");
    for (index, expected) in stream.iter().enumerate() {
        assert_eq!(read_memory_felt(&output, destination + index as u32), *expected);
    }
}

#[test]
fn vm_ace_loader_authenticates_exact_embedded_stream() {
    let vm = miden_vm_stark::setup::ace::shared_recursive_circuit();
    assert_exact_ace_stream_loads(Relation::Vm, vm.commitment, &vm.instructions);
}

#[test]
fn pvm_ace_loader_authenticates_exact_embedded_stream() {
    let pvm = miden_air::precompiles::protocol::recursive_circuit();
    assert_exact_ace_stream_loads(Relation::Pvm, pvm.commitment, &pvm.instructions);
}

fn assert_ace_loader_rejects_short_or_long_values(relation: Relation) {
    let (key, compiled_len) = relation.compiled_ace_resource();
    // Length rejection precedes any semantic use of the values, so filler values isolate that
    // contract from drift between the embedded circuit and the generated evaluator.
    let truncated = vec![Felt::ZERO; compiled_len.checked_sub(1).expect("nonempty ACE stream")];
    assert_resource_error(ace_test(relation, key, truncated), ACE_LENGTH_ERROR);

    let appended = vec![Felt::ZERO; compiled_len + 1];
    assert_resource_error(ace_test(relation, key, appended), ACE_LENGTH_ERROR);
}

#[test]
fn vm_ace_loader_rejects_short_or_long_values() {
    assert_ace_loader_rejects_short_or_long_values(Relation::Vm);
}

#[test]
fn pvm_ace_loader_rejects_short_or_long_values() {
    assert_ace_loader_rejects_short_or_long_values(Relation::Pvm);
}

fn assert_ace_loader_rejects_wrong_content_at_compiled_length(relation: Relation) {
    let (key, compiled_len) = relation.compiled_ace_resource();
    let mut corrupted = vec![Felt::ZERO; compiled_len];
    corrupted[0] = Felt::ONE;
    assert_ne!(
        Eidos::hash_elements(&corrupted),
        key,
        "the same-length negative fixture must differ from the accepted generic Felt-sequence hash"
    );
    assert_resource_error(ace_test(relation, key, corrupted), ACE_DIGEST_ERROR);
}

#[test]
fn vm_ace_loader_rejects_wrong_content_at_compiled_length() {
    assert_ace_loader_rejects_wrong_content_at_compiled_length(Relation::Vm);
}

#[test]
fn pvm_ace_loader_rejects_wrong_content_at_compiled_length() {
    assert_ace_loader_rejects_wrong_content_at_compiled_length(Relation::Pvm);
}

fn lmcs_leaf(row: &[Felt]) -> Word {
    assert_eq!(row.len() % BLOCK_LEN, 0);
    row.as_chunks::<BLOCK_LEN>()
        .0
        .iter()
        .fold(Eidos::init_chaining_word(LMCS_LEAF, row.len() as u32), |cv, block| {
            Eidos::compress(cv, *block)
        })
}

fn add_path(store: &mut MerkleStore, leaf: Word, index: u32, depth: u8, seed: u32) -> Word {
    let siblings = (0..depth)
        .map(|level| {
            Word::new(core::array::from_fn(|limb| {
                Felt::from_u32(seed + 16 * u32::from(level) + limb as u32)
            }))
        })
        .collect();
    store
        .add_merkle_path(u64::from(index), leaf, MerklePath::new(siblings))
        .expect("synthetic Merkle path must be valid")
}

struct QueryRowFixture {
    source: String,
    module: String,
    store: MerkleStore,
    rows: [(Word, Vec<Felt>); 4],
    destination: u32,
}

impl QueryRowFixture {
    fn new(relation: Relation) -> Self {
        const FULL_DEPTH: u8 = 20;
        const PREPROCESSED_DEPTH: u8 = 19;
        const INDEX: u32 = (1 << PREPROCESSED_DEPTH) + 7;
        const QUERY_PTR: u32 = 1_000;
        const ALPHA_PTR: u32 = 2_000;
        let mut store = MerkleStore::new();
        let mut roots = Vec::new();
        let rows = ["PREPROCESSED", "MAIN", "AUX", "QUOTIENT"].map(|group| {
            let prefix = format!("pub const {group}_ROW_DOUBLE_WORDS = ");
            let blocks: usize = relation
                .parameters()
                .lines()
                .find_map(|line| line.trim().strip_prefix(&prefix)?.parse().ok())
                .expect("the relation declares its aligned row width");
            let group_index = roots.len() as u32;
            let row: Vec<_> = (0..8 * blocks)
                .map(|index| Felt::from_u32(100 * (group_index + 1) + 17 * index as u32 + 1))
                .collect();
            let leaf = lmcs_leaf(&row);
            let (index, depth) = if group_index == 0 {
                (7, PREPROCESSED_DEPTH)
            } else {
                (INDEX, FULL_DEPTH)
            };
            roots.push(add_path(&mut store, leaf, index, depth, 1_000 * (group_index + 1)));
            (leaf, row)
        });
        let destination = relation.layout_const("CURRENT_TRACE_ROW_PTR");
        let preprocessed_store = match relation {
            Relation::Vm => "mem_storew_le.PREPROCESSED_TRACE_COM_PTR".to_string(),
            Relation::Pvm => {
                format!("push.{} mem_storew_le", relation.layout_const("PREPROCESSED_COM_PTR"))
            },
        };
        // Only the VM layout carries the setup table's height in generic per-AIR memory.
        let height_setup = match relation {
            Relation::Vm => "push.16 exec.layout::set_and8_lookup_trace_length_log",
            Relation::Pvm => "",
        };
        let source = format!(
            "
            use {{
                AUX_TRACE_COM_PTR, COMPOSITION_POLY_COM_PTR, MAIN_TRACE_COM_PTR,
                PREPROCESSED_TRACE_COM_PTR, TMP2_PTR
            }} from miden::core::stark::constants
            use miden::core::sys::{relation}::layout
            use test::resource

            begin
                {height_setup}
                push.0.{index}.{depth}.{index} push.{query_ptr} mem_storew_le dropw
                push.0.0.5.3 push.{alpha_ptr} mem_storew_le dropw
                push.0.0.{alpha_ptr}.{destination} mem_storew_le.TMP2_PTR dropw
                {preprocessed_root} {preprocessed_store} dropw
                {main_root} mem_storew_le.MAIN_TRACE_COM_PTR dropw
                {aux_root} mem_storew_le.AUX_TRACE_COM_PTR dropw
                {quotient_root} mem_storew_le.COMPOSITION_POLY_COM_PTR dropw
                push.{query_ptr} padw
                exec.resource::load_query_row_for_test
                dropw dropw drop drop
            end
            ",
            relation = relation.name(),
            index = INDEX,
            depth = FULL_DEPTH,
            query_ptr = QUERY_PTR,
            alpha_ptr = ALPHA_PTR,
            preprocessed_root = masm_push_word(&roots[0]),
            main_root = masm_push_word(&roots[1]),
            aux_root = masm_push_word(&roots[2]),
            quotient_root = masm_push_word(&roots[3]),
        );
        let module = format!(
            "{}\n\
             pub proc load_query_row_for_test(\n\
                 scratch: word, query_ptr: ptr<word>,\n\
             ) -> (word, types::EvaluationPair, u32, ptr<word>)\n\
                 exec.load_query_row\n\
             end\n",
            relation.deep_queries(),
        );
        Self { source, module, store, rows, destination }
    }

    fn test(&self, rows: [(Word, Vec<Felt>); 4]) -> Test {
        build_test!(&self.source, &[], &[], self.store.clone(), rows)
            .with_module("test::resource", &self.module)
    }
}

#[test]
fn query_row_loaders_authenticate_exact_rows_and_reject_each_short_or_long_group() {
    for relation in [Relation::Vm, Relation::Pvm] {
        let fixture = QueryRowFixture::new(relation);
        let (output, _) = fixture
            .test(fixture.rows.clone())
            .execute_for_output()
            .unwrap_or_else(|error| panic!("{relation:?} exact query rows must load: {error:?}"));
        for (index, expected) in fixture.rows.iter().flat_map(|(_, row)| row).enumerate() {
            assert_eq!(read_memory_felt(&output, fixture.destination + index as u32), *expected);
        }

        for (group, error) in ROW_LENGTH_ERRORS.into_iter().enumerate() {
            let mut truncated = fixture.rows.clone();
            truncated[group].1.pop().expect("every row is nonempty");
            assert_resource_error(fixture.test(truncated), error);

            let mut appended = fixture.rows.clone();
            appended[group].1.push(Felt::ONE);
            assert_resource_error(fixture.test(appended), error);

            let mut corrupted = fixture.rows.clone();
            corrupted[group].1[0] += Felt::ONE;
            assert_resource_error(fixture.test(corrupted), &error.replace("length", "hash"));
        }
    }
}

fn fri_layer_test(row: Vec<Felt>) -> Test {
    const LAYER_PTR: u32 = 4_000;
    const REMAINDER_PTR: u32 = LAYER_PTR + 8;
    // A constant extension-valued row has a consistent source evaluation at every coset.
    let leaf = lmcs_leaf(&[11u32, 13, 11, 13, 11, 13, 11, 13].map(Felt::from_u32));
    let mut store = MerkleStore::new();
    let root = add_path(&mut store, leaf, 0, 2, 5_000);
    let source = format!(
        "
        use miden::core::pcs::fri::frie2f4
        begin
            {commitment}
            push.{layer_ptr} mem_storew_le dropw
            {metadata}
            padw padw
            push.{remainder_ptr}.{layer_ptr}.13.11.0.1.{layer_ptr}.{layer_ptr}
            exec.frie2f4::verify_query_layer
            drop dropw dropw dropw dropw
        end
        ",
        commitment = masm_push_word(&root),
        metadata = masm_store_felts(&[4u32, 2, 3, 5].map(Felt::from_u32), LAYER_PTR + 4),
        layer_ptr = LAYER_PTR,
        remainder_ptr = REMAINDER_PTR,
    );
    build_test!(&source, &[], &[], store, [(leaf, row)])
}

#[test]
fn fri_layer_authenticates_exact_row_and_rejects_short_or_long_values() {
    let row = [11u32, 13, 11, 13, 11, 13, 11, 13].map(Felt::from_u32).to_vec();
    fri_layer_test(row.clone())
        .execute_for_output()
        .unwrap_or_else(|error| panic!("the exact FRI layer row must load and fold: {error:?}"));

    let mut truncated = row.clone();
    truncated.pop().unwrap();
    assert_resource_error(fri_layer_test(truncated), FRI_LENGTH_ERROR);

    let mut appended = row.clone();
    appended.push(Felt::ONE);
    assert_resource_error(fri_layer_test(appended), FRI_LENGTH_ERROR);

    let mut corrupted = row;
    corrupted[0] += Felt::ONE;
    assert_resource_error(fri_layer_test(corrupted), "FRI layer leaf hash mismatch");
}
