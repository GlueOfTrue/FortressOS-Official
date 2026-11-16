//! Checked BAR metadata and mock MMIO lease validation. NO MMIO is mapped.
//! A BarGrant MUST be issued by a trusted PCI-resource broker in real kernel.
//! Creating one from arbitrary driver-supplied integers confers NO authority.

use crate::{PhysRange, RangeError, FRAME_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioError {
    Range(RangeError), InvalidDevice, InvalidGeneration, WrongDevice,
    WrongCache, OutsideBar, Overflow, Empty, WrongRights,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheMode { Uncached, WriteCombining }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarGrant {
    device: u64, generation: u64, range: PhysRange, cache: CacheMode,
}

/// Checked metadata, not an active virtual mapping or direct MMIO authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappedMmio {
    pub device: u64,
    pub generation: u64,
    pub request_start: u64,
    pub request_end: u64,
    pub page_start: u64,
    pub page_end: u64,
    pub cache: CacheMode,
}

impl BarGrant {
    /// Host-only trusted-inventory fixture. Production construction must be
    /// restricted to the PCI enumerator and a resource ownership proof.
    pub fn from_inventory(
        device: u64, generation: u64, start: u64,
        length: u64, cache: CacheMode,
    ) -> Result<Self, MmioError> {
        if device == 0 { return Err(MmioError::InvalidDevice); }
        if generation == 0 { return Err(MmioError::InvalidGeneration); }
        let range = PhysRange::new(start, length).map_err(MmioError::Range)?;
        Ok(Self { device, generation, range, cache })
    }

    /// Only verifies the byte span and the enclosing full 4KiB physical pages.
    /// Rejects any mapping that reaches outside its *exact* BAR, including page
    /// rounding and end overflow; never grants executable MMIO.
    pub fn validate(
        &self, device: u64, generation: u64,
        start: u64, length: u64, cache: CacheMode,
        executable: bool,
    ) -> Result<MappedMmio, MmioError> {
        if device != self.device || generation != self.generation {
            return Err(MmioError::WrongDevice);
        }
        if executable { return Err(MmioError::WrongRights); }
        if cache != self.cache { return Err(MmioError::WrongCache); }
        if length == 0 { return Err(MmioError::Empty); }
        let end = start.checked_add(length).ok_or(MmioError::Overflow)?;
        let page_start = start & !(FRAME_SIZE - 1);
        let page_end = if end % FRAME_SIZE == 0 {
            end
        } else {
            (end & !(FRAME_SIZE - 1)).checked_add(FRAME_SIZE)
                .ok_or(MmioError::Overflow)?
        };
        if page_start < self.range.start || page_end > self.range.end {
            return Err(MmioError::OutsideBar);
        }
        Ok(MappedMmio {
            device, generation, request_start: start, request_end: end,
            page_start, page_end, cache,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bar() -> BarGrant {
        BarGrant::from_inventory(
            17, 2, 0x9000_0000, 4 * FRAME_SIZE, CacheMode::Uncached,
        ).unwrap()
    }
    #[test]
    fn validated_unaligned_subspan_rounds_in_bar() {
        let m = bar().validate(17, 2, 0x9000_0123, 71, CacheMode::Uncached, false)
            .unwrap();
        assert_eq!((m.page_start, m.page_end), (0x9000_0000, 0x9000_1000));
    }
    #[test]
    fn refuses_outside_and_cross_page_bar() {
        assert_eq!(
            bar().validate(17, 2, 0x9000_3fff, 2, CacheMode::Uncached, false),
            Err(MmioError::OutsideBar),
        );
        assert_eq!(
            bar().validate(17, 2, 0x9000_4000, 1, CacheMode::Uncached, false),
            Err(MmioError::OutsideBar),
        );
        assert_eq!(
            bar().validate(17, 2, 0x8fff_ffff, 2, CacheMode::Uncached, false),
            Err(MmioError::OutsideBar),
        );
    }
    #[test]
    fn rejects_overflow_and_empty() {
        assert_eq!(
            bar().validate(17, 2, u64::MAX - 2, 8, CacheMode::Uncached, false),
            Err(MmioError::Overflow),
        );
        assert_eq!(
            bar().validate(17, 2, 0x9000_0000, 0, CacheMode::Uncached, false),
            Err(MmioError::Empty),
        );
    }
    #[test]
    fn wrong_identity_cache_and_exec_rejected() {
        assert_eq!(
            bar().validate(18, 2, 0x9000_0000, 16, CacheMode::Uncached, false),
            Err(MmioError::WrongDevice),
        );
        assert_eq!(
            bar().validate(17, 3, 0x9000_0000, 16, CacheMode::Uncached, false),
            Err(MmioError::WrongDevice),
        );
        assert_eq!(
            bar().validate(17, 2, 0x9000_0000, 16, CacheMode::WriteCombining, false),
            Err(MmioError::WrongCache),
        );
        assert_eq!(
            bar().validate(17, 2, 0x9000_0000, 16, CacheMode::Uncached, true),
            Err(MmioError::WrongRights),
        );
    }
    #[test]
    fn invalid_grants() {
        assert_eq!(
            BarGrant::from_inventory(0, 1, 0x1000, FRAME_SIZE, CacheMode::Uncached),
            Err(MmioError::InvalidDevice),
        );
        assert_eq!(
            BarGrant::from_inventory(1, 0, 0x1000, FRAME_SIZE, CacheMode::Uncached),
            Err(MmioError::InvalidGeneration),
        );
        assert_eq!(
            BarGrant::from_inventory(1, 1, 0x1001, FRAME_SIZE, CacheMode::Uncached),
            Err(MmioError::Range(RangeError::Unaligned)),
        );
    }
}
