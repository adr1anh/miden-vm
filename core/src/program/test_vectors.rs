//! Shared frozen fixtures; parsing performs no hashing or encoding.

use alloc::{collections::BTreeSet, vec::Vec};

const SOURCE: &str = include_str!("../../tests/fixtures/librarytree-vectors.txt");

pub(super) struct Vector {
    pub id: &'static str,
    pub domain_tag: u32,
    pub bytes: Option<Vec<u8>>,
    pub payload: Vec<u64>,
    pub digest: [u64; 4],
}

pub(super) fn vector(id: &str) -> Vector {
    vectors()
        .into_iter()
        .find(|vector| vector.id == id)
        .unwrap_or_else(|| panic!("missing LibraryTree vector {id}"))
}

pub(super) fn vectors() -> Vec<Vector> {
    let mut ids = BTreeSet::new();
    SOURCE
        .lines()
        .enumerate()
        .filter_map(|(line_number, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let fields = line.split('|').map(str::trim).collect::<Vec<_>>();
            assert_eq!(fields.len(), 5, "LibraryTree vector line {}", line_number + 1);
            let id = fields[0];
            assert!(
                !id.is_empty()
                    && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "invalid LibraryTree vector id {id}",
            );
            assert!(ids.insert(id), "duplicate LibraryTree vector {id}");
            let domain_tag =
                u32::try_from(parse_u64(fields[1])).expect("LibraryTree domain tag fits u32");
            let bytes = if fields[2] == "-" {
                None
            } else {
                Some(parse_bytes(fields[2]))
            };
            let payload = parse_numbers(fields[3]);
            let digest = parse_numbers(fields[4]).try_into().unwrap_or_else(|values: Vec<u64>| {
                panic!("vector {id} has {} digest limbs", values.len())
            });
            Some(Vector { id, domain_tag, bytes, payload, digest })
        })
        .collect()
}

fn parse_numbers(value: &str) -> Vec<u64> {
    if value.is_empty() {
        Vec::new()
    } else {
        value.split(',').map(parse_u64).collect()
    }
}

fn parse_u64(value: &str) -> u64 {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        assert!(
            !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid hexadecimal LibraryTree number {value}",
        );
        u64::from_str_radix(hex, 16).expect("LibraryTree hexadecimal number fits u64")
    } else {
        assert!(
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid decimal LibraryTree number {value}",
        );
        value.parse().expect("LibraryTree decimal number fits u64")
    }
}

fn parse_bytes(value: &str) -> Vec<u8> {
    assert!(
        !value.is_empty()
            && value.len().is_multiple_of(2)
            && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid LibraryTree canonical byte string",
    );
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let pair = core::str::from_utf8(pair).expect("ASCII hexadecimal pair");
            u8::from_str_radix(pair, 16).expect("LibraryTree hexadecimal byte")
        })
        .collect()
}
