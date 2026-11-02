use crate::{ExecutionError, Felt, trace::parallel::MAX_TRACE_LEN};

// The existing trace cap also bounds the nullable one-based transport encoding.
const _: () = assert!(MAX_TRACE_LEN < u32::MAX as usize);

/// A zero-based logical position in the Controller region.
///
/// The trace-length cap itself is a valid end cursor. Appending any rows at that cursor fails;
/// keeping it representable lets a span end exactly at the existing cap.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ControllerRow(usize);

impl ControllerRow {
    pub(crate) fn new(position: usize) -> Result<Self, ExecutionError> {
        if position > MAX_TRACE_LEN {
            return Err(trace_len_exceeded());
        }
        Ok(Self(position))
    }

    pub(crate) fn position(self) -> usize {
        self.0
    }

    /// Checks the entire span before its rows or replay records are appended.
    pub(crate) fn checked_advance(self, rows: usize) -> Result<Self, ExecutionError> {
        let end = self.0.checked_add(rows).ok_or_else(trace_len_exceeded)?;
        Self::new(end)
    }

    /// Checks both the row-count multiplication and the resulting span.
    pub(crate) fn checked_advance_many(
        self,
        count: usize,
        rows_per_item: usize,
    ) -> Result<Self, ExecutionError> {
        let rows = count.checked_mul(rows_per_item).ok_or_else(trace_len_exceeded)?;
        self.checked_advance(rows)
    }

    pub(crate) fn logical_address(self) -> LogicalControllerAddress {
        LogicalControllerAddress(Some(self))
    }
}

/// A nullable one-based logical Controller address, before any physical prefix is applied.
///
/// Zero means absent; Controller row zero is present and encodes as one. Operation-log indices
/// are separate values and must never use this codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LogicalControllerAddress(Option<ControllerRow>);

impl LogicalControllerAddress {
    pub(crate) const ABSENT: Self = Self(None);

    pub(crate) fn from_felt(address: Felt) -> Result<Self, ExecutionError> {
        let encoded = address.as_canonical_u64();
        if encoded == 0 {
            return Ok(Self::ABSENT);
        }
        let position = usize::try_from(encoded - 1).map_err(|_| trace_len_exceeded())?;
        Ok(ControllerRow::new(position)?.logical_address())
    }

    pub(crate) fn to_felt(self) -> Felt {
        // MAX_TRACE_LEN is 2^29, so a checked position plus its one-based tag fits in u32.
        match self.0 {
            None => Felt::from_u32(0),
            Some(row) => Felt::from_u32(row.0 as u32 + 1),
        }
    }

    pub(crate) fn checked_advance(self, rows: usize) -> Result<Self, ExecutionError> {
        match self.0 {
            None => Ok(Self::ABSENT),
            Some(row) => Ok(row.checked_advance(rows)?.logical_address()),
        }
    }
}

fn trace_len_exceeded() -> ExecutionError {
    ExecutionError::TraceLenExceeded(MAX_TRACE_LEN)
}

/// A checked physical band in the final Chiplets trace. Its end may be the trace cap; its rows
/// cannot. Only the layout constructs these bands, after checking the complete stacked length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChipletBand {
    start: usize,
    len: usize,
}

impl ChipletBand {
    pub(crate) fn start(self) -> usize {
        self.start
    }

    pub(crate) fn len(self) -> usize {
        self.len
    }

    /// The caller indexes a row in this band, whose complete extent was checked by the layout.
    pub(crate) fn clock_at(self, row: usize) -> Felt {
        debug_assert!(row < self.len);
        Felt::from_u32((self.start + row + 1) as u32)
    }
}

/// A nullable physical address. It deliberately has no logical decoder or advance operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PhysicalControllerAddress(Felt);

impl PhysicalControllerAddress {
    pub(crate) fn to_felt(self) -> Felt {
        self.0
    }
}

/// Immutable ownership of physical Chiplets placement at final trace materialization.
///
/// Producers, snapshots and replay retain logical Controller addresses. The current relation
/// supplies a zero prefix; the Library integration will supply its real prefix through this same
/// constructor. Reserving a prefix here does not construct or authenticate a Library witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChipletsLayout {
    controller: ChipletBand,
    bitwise: ChipletBand,
    memory: ChipletBand,
    ace: ChipletBand,
    kernel_rom: ChipletBand,
    padding_start: usize,
    trace_len: usize,
}

impl ChipletsLayout {
    pub(crate) fn new(
        prefix_len: usize,
        controller_len: usize,
        bitwise_len: usize,
        memory_len: usize,
        ace_len: usize,
        kernel_rom_len: usize,
    ) -> Result<Self, ExecutionError> {
        let mut next = prefix_len;
        let mut band = |len| {
            let start = next;
            next = next.checked_add(len).ok_or_else(trace_len_exceeded)?;
            if next > MAX_TRACE_LEN {
                return Err(trace_len_exceeded());
            }
            Ok(ChipletBand { start, len })
        };
        let controller = band(controller_len)?;
        let bitwise = band(bitwise_len)?;
        let memory = band(memory_len)?;
        let ace = band(ace_len)?;
        let kernel_rom = band(kernel_rom_len)?;
        let padding_start = next;
        // Auxiliary connector columns require one padding row after the final chiplet.
        let trace_len = next.checked_add(1).ok_or_else(trace_len_exceeded)?;
        if trace_len > MAX_TRACE_LEN {
            return Err(trace_len_exceeded());
        }
        Ok(Self {
            controller,
            bitwise,
            memory,
            ace,
            kernel_rom,
            padding_start,
            trace_len,
        })
    }

    pub(crate) fn controller_address(
        self,
        address: LogicalControllerAddress,
    ) -> Result<PhysicalControllerAddress, ExecutionError> {
        match address.0 {
            None => Ok(PhysicalControllerAddress(Felt::from_u32(0))),
            Some(row) => {
                if row.position() >= self.controller.len {
                    return Err(ExecutionError::Internal(
                        "Controller address is outside its materialized band",
                    ));
                }
                Ok(PhysicalControllerAddress(self.controller.clock_at(row.position())))
            },
        }
    }

    pub(crate) fn controller(self) -> ChipletBand {
        self.controller
    }

    pub(crate) fn bitwise(self) -> ChipletBand {
        self.bitwise
    }

    pub(crate) fn memory(self) -> ChipletBand {
        self.memory
    }

    pub(crate) fn ace(self) -> ChipletBand {
        self.ace
    }

    pub(crate) fn kernel_rom(self) -> ChipletBand {
        self.kernel_rom
    }

    pub(crate) fn trace_len(self) -> usize {
        self.trace_len
    }

    pub(crate) fn padding(self, trace_len: usize) -> Result<ChipletBand, ExecutionError> {
        if trace_len > MAX_TRACE_LEN {
            return Err(trace_len_exceeded());
        }
        if trace_len < self.trace_len {
            return Err(ExecutionError::Internal("target Chiplets trace length too small"));
        }
        Ok(ChipletBand {
            start: self.padding_start,
            len: trace_len - self.padding_start,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_trace_len_exceeded<T>(result: Result<T, ExecutionError>) {
        assert!(matches!(result, Err(ExecutionError::TraceLenExceeded(MAX_TRACE_LEN))));
    }

    #[test]
    fn absent_and_controller_row_zero_have_distinct_encodings() {
        let row_zero = ControllerRow::default().logical_address();
        assert_ne!(LogicalControllerAddress::ABSENT, row_zero);
        assert_eq!(LogicalControllerAddress::ABSENT.to_felt(), Felt::from_u32(0));
        assert_eq!(row_zero.to_felt(), Felt::from_u32(1));
        assert_eq!(
            LogicalControllerAddress::from_felt(Felt::from_u32(0)).unwrap(),
            LogicalControllerAddress::ABSENT,
        );
        assert_eq!(LogicalControllerAddress::from_felt(Felt::from_u32(1)).unwrap(), row_zero,);
        assert_eq!(
            LogicalControllerAddress::ABSENT.checked_advance(usize::MAX).unwrap(),
            LogicalControllerAddress::ABSENT,
        );
    }

    #[test]
    fn exact_cap_end_cursor_remains_representable() {
        let last_row = ControllerRow::new(MAX_TRACE_LEN - 1).unwrap();
        let end = last_row.checked_advance(1).unwrap();
        assert_eq!(end.position(), MAX_TRACE_LEN);
        assert_eq!(end.checked_advance(0).unwrap(), end);
        assert_eq!(end.logical_address().to_felt(), Felt::from_u32(MAX_TRACE_LEN as u32 + 1),);
        assert_eq!(
            LogicalControllerAddress::from_felt(end.logical_address().to_felt()).unwrap(),
            end.logical_address(),
        );
        assert_trace_len_exceeded(end.checked_advance(1));
        assert_trace_len_exceeded(ControllerRow::new(MAX_TRACE_LEN + 1));
        assert_trace_len_exceeded(LogicalControllerAddress::from_felt(Felt::from_u32(
            MAX_TRACE_LEN as u32 + 2,
        )));
    }

    #[test]
    fn spans_check_multiplication_addition_and_exact_boundary() {
        let start = ControllerRow::new(MAX_TRACE_LEN - 8).unwrap();
        assert_eq!(start.checked_advance_many(2, 4).unwrap().position(), MAX_TRACE_LEN);
        assert_trace_len_exceeded(start.checked_advance_many(3, 4));
        assert_trace_len_exceeded(start.checked_advance(usize::MAX));
        assert_trace_len_exceeded(start.checked_advance_many(usize::MAX, 2));
        assert_eq!(start.checked_advance_many(0, usize::MAX).unwrap(), start);
        assert_eq!(start.position(), MAX_TRACE_LEN - 8);
    }

    #[test]
    fn logical_address_advance_checks_present_rows() {
        let address = ControllerRow::default().logical_address();
        assert_eq!(address.checked_advance(3).unwrap().to_felt(), Felt::from_u32(4));
        assert_trace_len_exceeded(address.checked_advance(MAX_TRACE_LEN + 1));
        assert_trace_len_exceeded(LogicalControllerAddress::from_felt(Felt::new_unchecked(
            u64::MAX - (1 << 32),
        )));
    }

    #[test]
    fn physical_layout_preserves_absence_and_zero_prefix_identity() {
        for prefix in [0, 13] {
            let layout = ChipletsLayout::new(prefix, 3, 2, 1, 0, 1).unwrap();
            assert_eq!(
                layout.controller_address(LogicalControllerAddress::ABSENT).unwrap().to_felt(),
                Felt::from_u32(0)
            );
            for row in 0..3 {
                let logical = ControllerRow::new(row).unwrap().logical_address();
                let physical = layout.controller_address(logical).unwrap().to_felt();
                assert_eq!(physical, Felt::from_u32((prefix + row + 1) as u32));
                if prefix == 0 {
                    assert_eq!(physical, logical.to_felt());
                }
            }
            assert_eq!(layout.bitwise().start(), prefix + 3);
            assert_eq!(layout.memory().start(), prefix + 5);
            assert_eq!(layout.ace().start(), prefix + 6);
            assert_eq!(layout.kernel_rom().start(), prefix + 6);
            assert_eq!(layout.trace_len(), prefix + 8);
            assert!(
                layout
                    .controller_address(ControllerRow::new(3).unwrap().logical_address())
                    .is_err()
            );
        }
    }

    #[test]
    fn physical_bounds_are_separate_from_representable_end_cursors() {
        let layout = ChipletsLayout::new(0, MAX_TRACE_LEN - 1, 0, 0, 0, 0).unwrap();
        let last = ControllerRow::new(MAX_TRACE_LEN - 2).unwrap().logical_address();
        assert_eq!(
            layout.controller_address(last).unwrap().to_felt(),
            Felt::from_u32(MAX_TRACE_LEN as u32 - 1)
        );
        assert_eq!(
            layout.padding(MAX_TRACE_LEN).unwrap().clock_at(0),
            Felt::from_u32(MAX_TRACE_LEN as u32)
        );
        let end_cursor = ControllerRow::new(MAX_TRACE_LEN).unwrap().logical_address();
        assert_eq!(LogicalControllerAddress::from_felt(end_cursor.to_felt()).unwrap(), end_cursor);
        assert!(layout.controller_address(end_cursor).is_err());
        assert_trace_len_exceeded(ChipletsLayout::new(0, MAX_TRACE_LEN, 0, 0, 0, 0));
        assert_trace_len_exceeded(ChipletsLayout::new(MAX_TRACE_LEN, 0, 0, 0, 0, 0));
        assert_trace_len_exceeded(ChipletsLayout::new(usize::MAX, 1, 0, 0, 0, 0));
        assert_trace_len_exceeded(ChipletsLayout::new(1, 1, usize::MAX, 0, 0, 0));
        assert_trace_len_exceeded(layout.padding(MAX_TRACE_LEN + 1));
        assert!(layout.padding(MAX_TRACE_LEN - 1).is_err());
    }
}
