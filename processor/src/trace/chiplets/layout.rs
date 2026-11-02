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
}
