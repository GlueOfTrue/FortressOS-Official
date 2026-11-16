#![no_std]
#![forbid(unsafe_code)]

//! Host-testable physical interval metadata. This does not access physical RAM,
//! install page tables, or grant DMA/MMIO access.

pub mod lifetime;
pub mod mmio;
pub mod revocable_mmio;
pub mod page_tables;
pub mod dma_controller;
pub mod iommu_tables;
pub mod k1_frames;
pub mod k1_paging;

pub const FRAME_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    Empty,
    Overflow,
    Unaligned,
    Overlap,
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysRange {
    pub start: u64,
    pub end: u64,
}

impl PhysRange {
    /// Builds a half-open physical range [start, start + len).
    /// Neither end nor any intermediate calculation may wrap u64.
    pub fn new(start: u64, len: u64) -> Result<Self, RangeError> {
        if len == 0 {
            return Err(RangeError::Empty);
        }
        let end = start.checked_add(len).ok_or(RangeError::Overflow)?;
        if start % FRAME_SIZE != 0 || end % FRAME_SIZE != 0 {
            return Err(RangeError::Unaligned);
        }
        Ok(Self { start, end })
    }

    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionClass {
    Usable,
    Reserved,
    BorrowedBoot,
    DeviceMmio,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub range: PhysRange,
    pub class: RegionClass,
}

/// A sorted fixed-capacity inventory. Insertion rejects overlapping regions,
/// even when they would otherwise belong to the same class.
pub struct RegionTable<const N: usize> {
    regions: [Option<Region>; N],
    len: usize,
}

impl<const N: usize> RegionTable<N> {
    pub const fn new() -> Self {
        Self { regions: [None; N], len: 0 }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub fn get(&self, index: usize) -> Option<Region> {
        if index < self.len {
            self.regions[index]
        } else {
            None
        }
    }

    pub fn insert(&mut self, region: Region) -> Result<(), RangeError> {
        // Enforce canonical ranges even if caller used a struct literal.
        if region.range.end <= region.range.start {
            return Err(RangeError::Empty);
        }
        if region.range.start % FRAME_SIZE != 0 || region.range.end % FRAME_SIZE != 0 {
            return Err(RangeError::Unaligned);
        }
        if self.len == N {
            return Err(RangeError::Full);
        }

        let mut pos = 0;
        while pos < self.len {
            let existing = self.regions[pos].expect("occupied prefix");
            if region.range.overlaps(existing.range) {
                return Err(RangeError::Overlap);
            }
            if existing.range.start > region.range.start {
                break;
            }
            pos += 1;
        }

        let mut i = self.len;
        while i > pos {
            self.regions[i] = self.regions[i - 1];
            i -= 1;
        }
        self.regions[pos] = Some(region);
        self.len += 1;
        Ok(())
    }
}

impl<const N: usize> Default for RegionTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(start: u64, len: u64) -> Region {
        Region {
            range: PhysRange::new(start, len).unwrap(),
            class: RegionClass::Reserved,
        }
    }

    #[test]
    fn sorted_nonoverlapping_regions() {
        let mut table = RegionTable::<3>::new();
        table.insert(region(0x4000, 0x1000)).unwrap();
        table.insert(region(0x1000, 0x2000)).unwrap();
        table.insert(region(0x3000, 0x1000)).unwrap();
        assert_eq!(table.get(0).unwrap().range.start, 0x1000);
        assert_eq!(table.get(2).unwrap().range.end, 0x5000);
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn overlapping_range_denied() {
        let mut table = RegionTable::<2>::new();
        table.insert(region(0x1000, 0x2000)).unwrap();
        assert_eq!(table.insert(region(0x2000, 0x1000)), Err(RangeError::Overlap));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn rejects_empty_overflow_and_unaligned() {
        assert_eq!(PhysRange::new(0, 0), Err(RangeError::Empty));
        assert_eq!(PhysRange::new(u64::MAX - 4095, 8192), Err(RangeError::Overflow));
        assert_eq!(PhysRange::new(1, 4096), Err(RangeError::Unaligned));
    }

    #[test]
    fn rejects_full_inventory_without_mutation() {
        let mut table = RegionTable::<1>::new();
        table.insert(region(0x1000, 0x1000)).unwrap();
        assert_eq!(table.insert(region(0x2000, 0x1000)), Err(RangeError::Full));
        assert_eq!(table.get(0).unwrap().range.start, 0x1000);
    }
}
