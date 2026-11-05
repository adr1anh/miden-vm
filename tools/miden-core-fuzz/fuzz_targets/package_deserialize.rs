//! Fuzz target for Package deserialization.
//!
//! Run with: cargo +nightly fuzz run package_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::serde::{Deserializable, Serializable};
use miden_core_fuzz::naming::{SyntheticProfile, check_naming_admission, named_package_fixture};
use miden_mast_package::{Package, interface::serialization::CodecLimits};

const NAMING_LIMITS: CodecLimits =
    CodecLimits::new(4 * 1024 * 1024, 100_000, 100_000, 4 * 1024 * 1024);

fuzz_target!(|data: &[u8]| {
    let budget = data.len().saturating_mul(64);
    let profile = SyntheticProfile::packages();
    // Writer-generated named input keeps the semantic oracle reachable independently of hostile
    // input admission and corpus format. Equal-D public keys and a private root are retained.
    let (fixture, expected_naming) = named_package_fixture(data);
    let fixture_bytes = fixture.to_bytes();
    let fixture_safe = Package::read_from_bytes(&fixture_bytes).unwrap();
    let fixture_trusted = Package::read_from_bytes_trusted(&fixture_bytes).unwrap();
    assert_eq!(fixture_safe, fixture);
    assert_eq!(fixture_trusted, fixture);
    assert_eq!(
        check_naming_admission(&fixture_safe, &profile, &true, NAMING_LIMITS).unwrap(),
        expected_naming
    );
    assert_eq!(
        check_naming_admission(&fixture_trusted, &profile, &true, NAMING_LIMITS).unwrap(),
        expected_naming
    );

    // STABILITY ORACLE (upgraded from crash-only): Package has Eq, so the oracle is
    // VALUE-level — a successful decode must re-encode and decode again to an EQUAL
    // value. Seeded per the reachability rule (18 writer-produced .bin seeds committed).
    if let Ok(package) = Package::read_from_bytes(data) {
        let canonical = package.to_bytes();
        let redecoded =
            Package::read_from_bytes(&canonical).expect("canonical encoding must decode");
        assert_eq!(redecoded, package, "canonical re-encoding must decode identically");
        let trusted = Package::read_from_bytes_trusted(&canonical).unwrap();
        assert_eq!(trusted, package);
        let raw_trusted = Package::read_from_bytes_trusted(data)
            .expect("safe admission must also be readable through the trusted path");
        assert_eq!(raw_trusted, package);
        let naming = check_naming_admission(&package, &profile, &true, NAMING_LIMITS);
        assert_eq!(check_naming_admission(&redecoded, &profile, &true, NAMING_LIMITS), naming);
        assert_eq!(check_naming_admission(&trusted, &profile, &true, NAMING_LIMITS), naming);
        assert_eq!(check_naming_admission(&raw_trusted, &profile, &true, NAMING_LIMITS), naming);
    }
    let _ = Vec::<Package>::read_from_bytes_with_budget(data, budget);
    let _ = Option::<Package>::read_from_bytes_with_budget(data, budget);
});
