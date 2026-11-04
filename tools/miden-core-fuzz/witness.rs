//! Shared bounded execution-witness fuzz policy and oracles.
//!
//! Inputs are a caller-owned `K_entry[32] || R_E[32]` prefix followed by replay-v6 bytes.
//! The prefix is a harness envelope, never part of the production witness format.

use miden_core::{
    ONE, Word,
    program::{EnvironmentRoot, ExecutionTarget, ProcedureKey},
    serde::{Deserializable, DeserializationError},
};
use miden_processor::{
    EnvironmentTraceLimits, ExecutionWitness, LedgerLimits, OpeningLimits, ReplayReadLimits,
    ResolutionLimits, SessionLimits,
};

const CALLER_TARGET_BYTES: usize = 2 * Word::SERIALIZED_SIZE;

// These are finite policies selected by this fuzz caller, independently of either the target
// prefix or replay payload. They target the small ordinary/deferred writer-owned seed fixtures;
// they are not production defaults or a package/environment admission policy.
const RESOLUTION_LIMITS: ResolutionLimits = ResolutionLimits::new(
    OpeningLimits {
        max_nodes: 65,
        max_depth: 64,
        max_list_children: 64,
        max_total_list_children: 256,
        max_encoded_bytes: 64 * 1024,
        max_storage_bytes: 256 * 1024,
    },
    LedgerLimits {
        max_occurrences: 256,
        max_total_list_children: 1024,
        max_encoded_bytes: 256 * 1024,
        max_library_rows: 4096,
        max_compression_requests: 4096,
        max_retained_bytes: 1024 * 1024,
        max_peak_bytes: 2 * 1024 * 1024,
    },
    SessionLimits {
        max_cached_keys: 128,
        max_requests: 1024,
        max_retained_bytes: 2 * 1024 * 1024,
        max_prepare_peak_bytes: 4 * 1024 * 1024,
    },
);
const TRACE_LIMITS: EnvironmentTraceLimits = EnvironmentTraceLimits {
    max_events: 1024,
    max_retained_bytes: 4 * 1024 * 1024,
    max_prepare_peak_bytes: 8 * 1024 * 1024,
    max_validation_work: 8 * 1024 * 1024,
};
const READ_LIMITS: ReplayReadLimits = ReplayReadLimits {
    max_wire_bytes: 4 * 1024 * 1024,
    max_validation_peak_bytes: 16 * 1024 * 1024,
};

fn read_witness(
    bytes: &[u8],
    target: ExecutionTarget,
) -> Result<ExecutionWitness, DeserializationError> {
    ExecutionWitness::read_from_bytes_with_limits(
        bytes,
        target,
        RESOLUTION_LIMITS,
        TRACE_LIMITS,
        READ_LIMITS,
    )
}

fn different_word(word: Word) -> Word {
    if word == Word::empty() {
        Word::new([ONE; 4])
    } else {
        Word::empty()
    }
}

/// Exercises the bounded witness reader and its canonical/negative oracles.
///
/// Returns `true` only after successful caller-envelope and replay decoding and completion of
/// every oracle. Rejected prefixes and payloads return `false`.
pub fn exercise(data: &[u8]) -> bool {
    // Fixed-size canonical identity decoding does not allocate. Never discover expected
    // authority by parsing the replay's embedded target, even for writer-produced seeds.
    let Some(caller_bytes) = data.get(..CALLER_TARGET_BYTES) else {
        return false;
    };
    let Ok(entry_key) = ProcedureKey::read_from_bytes(&caller_bytes[..Word::SERIALIZED_SIZE])
    else {
        return false;
    };
    let Ok(environment_root) =
        EnvironmentRoot::read_from_bytes(&caller_bytes[Word::SERIALIZED_SIZE..])
    else {
        return false;
    };
    let target = ExecutionTarget::new(entry_key, environment_root);
    // The production entry point rejects oversized complete payloads before decoding or
    // allocating. Its reader and explicit native policies bound malformed nested lengths too.
    let bytes = &data[CALLER_TARGET_BYTES..];
    if let Ok(witness) = read_witness(bytes, target) {
        assert_eq!(witness.execution_descriptor(), target);

        // STABILITY ORACLE (upgraded from crash-only): byte-level, since ExecutionWitness
        // has no PartialEq — decode -> encode -> decode -> encode must reproduce the
        // canonical encoding exactly. Catches encode non-determinism and
        // decode-fails-own-writer (scoped per the two-cycle-oracle rule).
        let mut canonical = witness
            .to_bytes_with_limits(TRACE_LIMITS, READ_LIMITS)
            .expect("decoded witness must fit the same explicit export limits");
        let redecoded = read_witness(&canonical, target).expect("canonical encoding must decode");
        let recanonical = redecoded
            .to_bytes_with_limits(TRACE_LIMITS, READ_LIMITS)
            .expect("canonical witness must fit the same explicit export limits");
        assert_eq!(recanonical, canonical, "decode -> encode must be byte-stable",);

        // A valid replay cannot choose its own authority. Exercise each independently changed
        // caller identity while keeping the exact canonical witness bytes unchanged.
        let wrong_entry = ExecutionTarget::new(
            ProcedureKey::new(different_word(entry_key.into_word())),
            environment_root,
        );
        let wrong_environment = ExecutionTarget::new(
            entry_key,
            EnvironmentRoot::new(different_word(environment_root.into_word())),
        );
        assert!(read_witness(&canonical, wrong_entry).is_err());
        assert!(read_witness(&canonical, wrong_environment).is_err());

        // Explicit zero policies must remain zero: wire rejection precedes parsing, and keyed
        // storage rejection precedes reservation. Neither may silently select a default.
        for read_limits in [
            ReplayReadLimits { max_wire_bytes: 0, ..READ_LIMITS },
            ReplayReadLimits {
                max_validation_peak_bytes: 0,
                ..READ_LIMITS
            },
        ] {
            assert!(
                ExecutionWitness::read_from_bytes_with_limits(
                    &canonical,
                    target,
                    RESOLUTION_LIMITS,
                    TRACE_LIMITS,
                    read_limits,
                )
                .is_err()
            );
        }

        canonical.push(0);
        assert!(read_witness(&canonical, target).is_err(), "trailing bytes must reject");
        true
    } else {
        false
    }
}
