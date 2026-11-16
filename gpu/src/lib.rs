#![no_std]
#![forbid(unsafe_code)]

//! Pure single-threaded GPU PCI resource ownership model (G2-HOST only).
//! No PCI enumeration, hardware MMIO, DMA, IRQ, GPU firmware or scanout exists.
//! These tokens are NOT kernel capabilities and do not grant physical access.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GpuKind {
    Rtx3070ResearchCandidate,
    VirtioGpuTestOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidBdf,
    InvalidIncarnation,
    UnsupportedDevice,
    UnsupportedClass,
    MissingBar,
    InvalidBarIndex,
    IoBarNotMappable,
    InvalidBarLength,
    UnalignedBar,
    AddressOverflow,
    AddressOutOfRange,
    ForbiddenPhysicalRange,
    ResourceConflict,
    RegistryFull,
    StaleLease,
    GenerationExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciAddress {
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
}

impl PciAddress {
    pub fn new(segment: u16, bus: u8, device: u8, function: u8) -> Result<Self, Error> {
        if device > 31 || function > 7 {
            return Err(Error::InvalidBdf);
        }
        Ok(Self { segment, bus, device, function })
    }
    pub fn segment(self) -> u16 { self.segment }
    pub fn bus(self) -> u8 { self.bus }
    pub fn device(self) -> u8 { self.device }
    pub fn function(self) -> u8 { self.function }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciIdentity {
    pub address: PciAddress,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    /// Fresh nonzero identifier assigned on each logical teardown/reprobe.
    pub incarnation: u64,
}

impl PciIdentity {
    pub fn gpu_kind(self) -> Result<GpuKind, Error> {
        if self.incarnation == 0 {
            return Err(Error::InvalidIncarnation);
        }
        if self.class != 0x03 || (self.subclass != 0x00 && self.subclass != 0x02) {
            return Err(Error::UnsupportedClass);
        }
        match (self.vendor_id, self.device_id) {
            (0x10de, 0x2484 | 0x2488) => Ok(GpuKind::Rtx3070ResearchCandidate),
            (0x1af4, 0x1050) => Ok(GpuKind::VirtioGpuTestOnly),
            _ => Err(Error::UnsupportedDevice),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalRange {
    base: u64,
    end: u64, // exclusive
}

impl PhysicalRange {
    pub fn checked(base: u64, length: u64) -> Result<Self, Error> {
        if length == 0 { return Err(Error::InvalidBarLength); }
        let end = base.checked_add(length).ok_or(Error::AddressOverflow)?;
        Ok(Self { base, end })
    }
    pub fn base(self) -> u64 { self.base }
    pub fn end(self) -> u64 { self.end }
    pub fn overlaps(self, other: Self) -> bool {
        self.base < other.end && other.base < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind { Memory32, Memory64, IoPort }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryBar {
    index: u8,
    kind: BarKind,
    range: PhysicalRange,
}

impl MemoryBar {
    /// Input is a descriptor from a FUTURE trusted PCI inventory, not BAR
    /// probing or a right to map physical addresses. Sub-page BARs are denied
    /// by this conservative first-stage GPU MMIO policy.
    pub fn from_inventory(index: u8, kind: BarKind, base: u64, length: u64) -> Result<Self, Error> {
        if index >= 6 || (kind == BarKind::Memory64 && index == 5) {
            return Err(Error::InvalidBarIndex);
        }
        if kind == BarKind::IoPort { return Err(Error::IoBarNotMappable); }
        if base == 0 || length < 4096 || !length.is_power_of_two() {
            return Err(Error::InvalidBarLength);
        }
        if base % length != 0 { return Err(Error::UnalignedBar); }
        let range = PhysicalRange::checked(base, length)?;
        if kind == BarKind::Memory32 && range.end > (1u64 << 32) {
            return Err(Error::AddressOutOfRange);
        }
        Ok(Self { index, kind, range })
    }
    pub fn index(self) -> u8 { self.index }
    pub fn kind(self) -> BarKind { self.kind }
    pub fn range(self) -> PhysicalRange { self.range }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Claim { device: PciIdentity, bar: MemoryBar }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot { generation: u64, claim: Option<Claim> }

impl Slot {
    const EMPTY: Self = Self { generation: 1, claim: None };
}

/// Unforgeable by external safe Rust callers, but NOT a security capability:
/// there is no authoritative PCI inventory, concurrency or kernel issuer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarLease {
    slot: usize,
    generation: u64,
    device: PciIdentity,
}

/// Bounded fixed-capacity host fixture, requiring no heap and no unsafe code.
pub struct BarRegistry<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> BarRegistry<N> {
    pub const fn new() -> Self { Self { slots: [Slot::EMPTY; N] } }

    /// forbidden must eventually come from the trusted MEMORY inventory.
    /// An empty list does NOT authorize mapping; this model maps nothing.
    pub fn claim(
        &mut self,
        device: PciIdentity,
        bar: Option<MemoryBar>,
        forbidden: &[PhysicalRange],
    ) -> Result<BarLease, Error> {
        device.gpu_kind()?;
        let bar = bar.ok_or(Error::MissingBar)?;
        if forbidden.iter().any(|r| r.overlaps(bar.range)) {
            return Err(Error::ForbiddenPhysicalRange);
        }
        if self.slots.iter().filter_map(|s| s.claim).any(|c|
            c.bar.range.overlaps(bar.range)
            || (c.device.address == device.address && c.bar.index == bar.index)
        ) {
            return Err(Error::ResourceConflict);
        }
        let index = self.slots.iter().position(|s| s.claim.is_none())
            .ok_or(Error::RegistryFull)?;
        let generation = self.slots[index].generation;
        self.slots[index].claim = Some(Claim { device, bar });
        Ok(BarLease { slot: index, generation, device })
    }

    fn checked_claim(&self, lease: BarLease) -> Result<Claim, Error> {
        let slot = self.slots.get(lease.slot).ok_or(Error::StaleLease)?;
        if slot.generation != lease.generation {
            return Err(Error::StaleLease);
        }
        let claim = slot.claim.ok_or(Error::StaleLease)?;
        if claim.device != lease.device {
            return Err(Error::StaleLease);
        }
        Ok(claim)
    }

    pub fn inspect(&self, lease: BarLease) -> Result<MemoryBar, Error> {
        self.checked_claim(lease).map(|c| c.bar)
    }

    /// HOST-ONLY release; actual device release requires IRQ quiescence,
    /// DMA completion, CPU TLB and relevant IOMMU/IOTLB acknowledgment.
    pub fn release(&mut self, lease: BarLease) -> Result<(), Error> {
        self.checked_claim(lease)?;
        let slot = &mut self.slots[lease.slot];
        let next = slot.generation.checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        slot.generation = next;
        slot.claim = None;
        Ok(())
    }
}

impl<const N: usize> Default for BarRegistry<N> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtx() -> PciIdentity {
        PciIdentity {
            address: PciAddress::new(0, 1, 0, 0).unwrap(),
            vendor_id: 0x10de, device_id: 0x2484,
            class: 3, subclass: 0, incarnation: 1,
        }
    }
    fn bar(base: u64) -> MemoryBar {
        MemoryBar::from_inventory(0, BarKind::Memory64, base, 0x2000).unwrap()
    }

    #[test]
    fn upstream_rtx_ids_are_candidates_not_hardware_observations() {
        assert_eq!(rtx().gpu_kind(), Ok(GpuKind::Rtx3070ResearchCandidate));
        let mut d = rtx(); d.device_id = 0x2488;
        assert_eq!(d.gpu_kind(), Ok(GpuKind::Rtx3070ResearchCandidate));
    }
    #[test]
    fn virtual_gpu_is_explicitly_test_only() {
        let mut d = rtx(); d.vendor_id = 0x1af4; d.device_id = 0x1050;
        assert_eq!(d.gpu_kind(), Ok(GpuKind::VirtioGpuTestOnly));
    }
    #[test]
    fn unknown_pci_id_and_wrong_class_rejected() {
        let mut d = rtx(); d.device_id = 0x9999;
        assert_eq!(d.gpu_kind(), Err(Error::UnsupportedDevice));
        d = rtx(); d.class = 0x02;
        assert_eq!(d.gpu_kind(), Err(Error::UnsupportedClass));
    }
    #[test]
    fn zero_incarnation_and_invalid_bdf_rejected() {
        let mut d = rtx(); d.incarnation = 0;
        assert_eq!(d.gpu_kind(), Err(Error::InvalidIncarnation));
        assert_eq!(PciAddress::new(0, 0, 32, 0), Err(Error::InvalidBdf));
        assert_eq!(PciAddress::new(0, 0, 0, 8), Err(Error::InvalidBdf));
    }
    #[test]
    fn valid_mmio_bar_and_exclusive_bounds() {
        let b = MemoryBar::from_inventory(2, BarKind::Memory32, 0x80000000, 0x200000).unwrap();
        assert_eq!(b.range().end(), 0x80200000);
    }
    #[test]
    fn invalid_bar_index_io_and_missing_bar_rejected() {
        assert_eq!(MemoryBar::from_inventory(6, BarKind::Memory32, 0x100000, 4096),
            Err(Error::InvalidBarIndex));
        assert_eq!(MemoryBar::from_inventory(5, BarKind::Memory64, 0x100000, 4096),
            Err(Error::InvalidBarIndex));
        assert_eq!(MemoryBar::from_inventory(0, BarKind::IoPort, 0x100000, 4096),
            Err(Error::IoBarNotMappable));
        let mut r = BarRegistry::<1>::new();
        assert_eq!(r.claim(rtx(), None, &[]), Err(Error::MissingBar));
    }
    #[test]
    fn zero_small_non_power_of_two_and_unaligned_bar_rejected() {
        for len in [0, 512, 6144] {
            assert_eq!(MemoryBar::from_inventory(0, BarKind::Memory64, 0x80000000, len),
                Err(Error::InvalidBarLength));
        }
        assert_eq!(MemoryBar::from_inventory(0, BarKind::Memory64, 0x80001000, 0x2000),
            Err(Error::UnalignedBar));
    }
    #[test]
    fn overflow_and_32_bit_limit_rejected() {
        assert_eq!(PhysicalRange::checked(u64::MAX - 1, 4), Err(Error::AddressOverflow));
        assert_eq!(MemoryBar::from_inventory(0, BarKind::Memory64, u64::MAX - 4095, 4096),
            Err(Error::AddressOverflow));
        assert_eq!(MemoryBar::from_inventory(0, BarKind::Memory32, 0x1_0000_0000, 4096),
            Err(Error::AddressOutOfRange));
    }
    #[test]
    fn forbidden_reserved_memory_rejected_but_adjacent_allowed() {
        let protected = [PhysicalRange::checked(0x80001000, 4096).unwrap()];
        let mut r = BarRegistry::<1>::new();
        assert_eq!(r.claim(rtx(), Some(bar(0x80000000)), &protected),
            Err(Error::ForbiddenPhysicalRange));
        let adjacent = [PhysicalRange::checked(0x80002000, 4096).unwrap()];
        assert!(r.claim(rtx(), Some(bar(0x80000000)), &adjacent).is_ok());
    }
    #[test]
    fn duplicate_and_cross_device_overlap_rejected() {
        let mut r = BarRegistry::<3>::new();
        r.claim(rtx(), Some(bar(0x80000000)), &[]).unwrap();
        assert_eq!(r.claim(rtx(), Some(bar(0x80000000)), &[]),
            Err(Error::ResourceConflict));
        let mut second = rtx();
        second.address = PciAddress::new(0, 2, 0, 0).unwrap();
        assert_eq!(r.claim(second, Some(bar(0x80000000)), &[]),
            Err(Error::ResourceConflict));
    }
    #[test]
    fn fixed_capacity_rejects_extra_claim() {
        let mut r = BarRegistry::<1>::new();
        r.claim(rtx(), Some(bar(0x80000000)), &[]).unwrap();
        let mut second = rtx();
        second.address = PciAddress::new(0, 2, 0, 0).unwrap();
        assert_eq!(r.claim(second, Some(bar(0x90000000)), &[]),
            Err(Error::RegistryFull));
    }
    #[test]
    fn recycled_slot_does_not_resurrect_stale_lease() {
        let mut r = BarRegistry::<1>::new();
        let old = r.claim(rtx(), Some(bar(0x80000000)), &[]).unwrap();
        r.release(old).unwrap();
        let current = r.claim(rtx(), Some(bar(0x80000000)), &[]).unwrap();
        assert_ne!(old, current);
        assert_eq!(r.inspect(old), Err(Error::StaleLease));
        assert_eq!(r.release(old), Err(Error::StaleLease));
        assert!(r.inspect(current).is_ok());
    }
    #[test]
    fn reprobe_incarnation_rejects_old_token() {
        let mut r = BarRegistry::<1>::new();
        let old = r.claim(rtx(), Some(bar(0x80000000)), &[]).unwrap();
        r.release(old).unwrap();
        let mut next = rtx(); next.incarnation = 2;
        let newer = r.claim(next, Some(bar(0x80000000)), &[]).unwrap();
        assert_eq!(r.release(old), Err(Error::StaleLease));
        assert!(r.inspect(newer).is_ok());
    }
    #[test]
    fn counter_exhaustion_keeps_resource_claimed() {
        let mut r = BarRegistry::<1>::new();
        r.slots[0].generation = u64::MAX;
        let lease = r.claim(rtx(), Some(bar(0x80000000)), &[]).unwrap();
        assert_eq!(r.release(lease), Err(Error::GenerationExhausted));
        assert!(r.inspect(lease).is_ok());
    }
}
