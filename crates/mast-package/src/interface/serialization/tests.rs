use super::*;

type Error = CodecError<&'static str>;

#[test]
fn interface_codec_limits_count_aggregate_resources_and_allow_exact_boundaries() {
    let limits = CodecLimits::new(9, 2, 3, 4);
    assert_eq!(limits.max_bytes(), 9);
    assert_eq!(limits.max_records(), 2);
    assert_eq!(limits.max_components(), 3);
    assert_eq!(limits.max_blob_bytes(), 4);
    let mut budget = Budget::new(limits);
    budget.wire_bytes::<&str>(9).unwrap();
    budget.records::<&str>(1).unwrap();
    budget.records::<&str>(1).unwrap();
    budget.components::<&str>(3).unwrap();
    budget.blob_bytes::<&str>(1).unwrap();
    budget.blob_bytes::<&str>(3).unwrap();
    assert!(matches!(budget.wire_bytes::<&str>(10), Err(Error::LimitExceeded { .. })));
    assert!(matches!(budget.records::<&str>(1), Err(Error::LimitExceeded { .. })));
    assert!(matches!(budget.components::<&str>(1), Err(Error::LimitExceeded { .. })));
    assert!(matches!(budget.blob_bytes::<&str>(1), Err(Error::LimitExceeded { .. })));
}

#[test]
fn interface_codec_rejects_whole_input_before_any_reads() {
    let budget = Budget::new(CodecLimits::new(2, 0, 0, 0));
    assert!(matches!(
        Reader::new::<&str>(&[1, 0, 99], &budget),
        Err(Error::LimitExceeded {
            resource: "wire bytes",
            actual: 3,
            limit: 2
        })
    ));
    let mut reader = Reader::new::<&str>(&[1, 0], &budget).unwrap();
    assert_eq!(reader.u8::<&str>("first").unwrap(), 1);
    assert!(matches!(reader.finish::<&str>("test"), Err(Error::TrailingBytes("test"))));
}

#[test]
fn interface_codec_rejects_lower_bounds_and_layouts_before_reservation() {
    let budget = Budget::new(CodecLimits::new(6, 0, 0, 0));
    let reader = Reader::new::<&str>(&[0; 6], &budget).unwrap();
    assert_eq!(reader.count::<CanonicalLabel, &str>(1, 6, "labels").unwrap(), 1);
    assert!(matches!(
        reader.count::<CanonicalLabel, &str>(2, 6, "labels"),
        Err(Error::Truncated("labels"))
    ));
    assert!(reader.count::<CanonicalLabel, &str>(u32::MAX, 6, "labels").is_err());
    assert!(matches!(
        reader.count::<u8, &str>(2, usize::MAX, "minimum"),
        Err(Error::LengthOverflow("minimum"))
    ));
    let mut bytes = Vec::<u8>::new();
    assert!(matches!(
        reserve::<_, &str>(&mut bytes, usize::MAX, "oversize"),
        Err(Error::LengthOverflow("oversize"))
    ));
    assert!(bytes.is_empty());
    assert!(check_label_layout::<&str>(usize::MAX).is_err());
    assert!(check_label_layout::<&str>(u32::MAX as usize).is_err());
    assert!(checked_add::<&str>(usize::MAX, 1, "addition").is_err());
    if usize::BITS > u32::BITS {
        assert!(wire_len::<&str>(usize::MAX, "length").is_err());
    }
}

#[test]
fn interface_codec_writer_uses_checked_precomputed_size() {
    let budget = Budget::new(CodecLimits::new(5, 0, 0, 0));
    let mut writer = Writer::new::<&str>(5, &budget).unwrap();
    writer.u8::<&str>(1).unwrap();
    writer.u32::<&str>(0x0403_0201).unwrap();
    assert_eq!(writer.finish::<&str>().unwrap(), [1, 1, 2, 3, 4]);
    assert!(matches!(Writer::new::<&str>(6, &budget), Err(Error::LimitExceeded { .. })));
    let mut writer = Writer::new::<&str>(0, &budget).unwrap();
    assert!(matches!(writer.u8::<&str>(1), Err(Error::LengthOverflow(_))));
    assert!(matches!(
        Writer::new::<&str>(1, &budget).unwrap().finish::<&str>(),
        Err(Error::LengthOverflow(_))
    ));
}
