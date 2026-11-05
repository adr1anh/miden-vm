//! Bounded hostile bytes and valid fixtures for the detached callable v1 codec.
#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::{Felt, Word, program::ImplementationRoot};
use miden_core_fuzz::naming::SyntheticProfile;
use miden_mast_package::{
    CallableProcedurePath, NamespacePath, PackageCallables, ProcedureName,
    interface::serialization::CodecLimits,
};

const LIMITS: CodecLimits = CodecLimits::new(4096, 32, 32, 512);

fn path(components: Vec<String>) -> CallableProcedurePath {
    CallableProcedurePath::from_semantic_components(components).unwrap()
}

fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}

fn check(inventory: &PackageCallables, bytes: &[u8], profile: &SyntheticProfile) {
    assert_eq!(inventory.encode_v1(profile, &true, LIMITS).unwrap(), bytes);
    assert_eq!(&PackageCallables::decode_v1(bytes, profile, &true, LIMITS).unwrap(), inventory);
    if inventory.bindings().len() != 0 {
        assert!(PackageCallables::decode_v1(bytes, profile, &false, LIMITS).is_err());
        assert!(inventory.encode_v1(profile, &false, LIMITS).is_err());
    }
}

fuzz_target!(|data: &[u8]| {
    let profile = SyntheticProfile::callable_codec();
    // The codec rejects inputs over 4 KiB before parsing; generation reads only nine bytes.
    if let Ok(inventory) = PackageCallables::decode_v1(data, &profile, &true, LIMITS) {
        check(&inventory, data, &profile);
    }

    // At most four distinct declarations, four aliases and four optional shared-D selections.
    // K is derived from the complete home/path before any D is supplied.
    let mut bindings = Vec::new();
    let mut aliases = Vec::new();
    let mut selections = Vec::new();
    let value = Felt::from_u32(u32::from(byte(data, 5)));
    let implementation = ImplementationRoot::new(Word::new([value; 4]));
    for index in 0..1 + usize::from(byte(data, 0) % 4) {
        let flags = byte(data, index + 1);
        let home = profile.homes[usize::from(flags % 3)].clone();
        let prefix = ["public", "helpers", "callbacks", "$exec"][usize::from((flags >> 2) % 4)];
        let binding = ProcedureName::new(
            NamespacePath::new(home),
            path(vec![prefix.into(), format!("p{index}")]),
        )
        .unwrap();
        let key = binding.key();
        if flags & 16 != 0 {
            let target = if flags & 64 != 0 {
                bindings.first().map_or(key, ProcedureName::key)
            } else {
                key
            };
            aliases.push((path(vec!["alias".into(), format!("a{index}")]), target));
        }
        if flags & 32 != 0 {
            selections.push((key, implementation));
        }
        bindings.push(binding);
    }
    let inventory = PackageCallables::new(bindings, aliases, selections).unwrap();
    let mut bytes = inventory.encode_v1(&profile, &true, LIMITS).unwrap();
    check(&inventory, &bytes, &profile);
    bytes.push(0);
    assert!(PackageCallables::decode_v1(&bytes, &profile, &true, LIMITS).is_err());
    bytes.pop();

    // Mutate a valid payload too, so hostile inputs reach past version/framing checks.
    let index = usize::from(u16::from_le_bytes([byte(data, 6), byte(data, 7)])) % bytes.len();
    bytes[index] ^= byte(data, 8);
    if let Ok(mutated) = PackageCallables::decode_v1(&bytes, &profile, &true, LIMITS) {
        check(&mutated, &bytes, &profile);
    }
});
