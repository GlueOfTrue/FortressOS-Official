//! 04 MEMORY: bounded, allocation-free page ownership and revocation model.
//! Metadata only: no page table writes, CPU instructions, device IO or real DMA.
//! Ack methods assume trustworthy ARCH/IOMMU implementations, NOT provided here.

use crate::{RangeError, FRAME_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Range(RangeError), NotSealed, Sealed, Capacity, NoFreeFrame,
    InvalidOwner, InvalidDevice, NotOwned, WrongOwner, Stale,
    Busy, InvalidState, InvalidAck, InvalidRights, WxAlias,
    NoIommu, ExhaustedGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageClass { Free, Reserved, BorrowedBoot, Owned(u64) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameToken { slot: usize, generation: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MapToken { slot: usize, generation: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaToken { slot: usize, generation: u64 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rights { pub read: bool, pub write: bool, pub exec: bool }
impl Rights {
    pub const R: Self = Self { read: true, write: false, exec: false };
    pub const RW: Self = Self { read: true, write: true, exec: false };
    pub const RX: Self = Self { read: true, write: false, exec: true };
    fn valid(self) -> bool {
        (self.read || self.write || self.exec) && !(self.write && self.exec)
    }
}

#[derive(Clone, Copy)]
struct Page { phys: u64, generation: u64, class: PageClass, pins: u16 }
#[derive(Clone, Copy)]
struct Mapping {
    frame: FrameToken, owner: u64, rights: Rights, cpu_mask: u64,
    retiring: bool, pending_cpu: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmaPhase { Pinned, Mapped, Submitted, Completed, Revoking, Quarantined }
#[derive(Clone, Copy)]
struct Lease {
    frame: FrameToken, owner: u64, device: u64, cpu_mask: u64,
    phase: DmaPhase, pending_cpu: u64, quiesced: bool, iommu_ack: bool,
}

/// Bounded one-page-granule ledger. Register free/reserved/boot-borrowed frames
/// before seal(); no handle can survive a slot generation change.
/// CPU masks encode up to 64 simulated logical CPU invalidation requirements.
pub struct Ledger<const P: usize, const M: usize, const D: usize> {
    pages: [Option<Page>; P],
    count: usize,
    sealed: bool,
    maps: [Option<Mapping>; M],
    map_generations: [u64; M],
    leases: [Option<Lease>; D],
    lease_generations: [u64; D],
}

impl<const P: usize, const M: usize, const D: usize> Ledger<P, M, D> {
    pub const fn new() -> Self {
        Self {
            pages: [None; P], count: 0, sealed: false,
            maps: [None; M], map_generations: [1; M],
            leases: [None; D], lease_generations: [1; D],
        }
    }

    /// Atomically registers a physical page. Registration sort is performed only
    /// before any handles exist, to keep token slot indices stable afterwards.
    pub fn register_page(&mut self, phys: u64, class: PageClass)
        -> Result<(), Fault> {
        if self.sealed { return Err(Fault::Sealed); }
        if phys % FRAME_SIZE != 0 || phys.checked_add(FRAME_SIZE).is_none() {
            return Err(Fault::Range(RangeError::Unaligned));
        }
        if matches!(class, PageClass::Owned(0)) { return Err(Fault::InvalidOwner); }
        if self.count == P { return Err(Fault::Capacity); }
        let mut at = 0;
        while at < self.count {
            let other = self.pages[at].expect("contiguous registered prefix");
            if other.phys == phys { return Err(Fault::Range(RangeError::Overlap)); }
            if other.phys > phys { break; }
            at += 1;
        }
        for i in (at..self.count).rev() {
            self.pages[i + 1] = self.pages[i];
        }
        self.pages[at] = Some(Page { phys, generation: 1, class, pins: 0 });
        self.count += 1;
        Ok(())
    }
    pub fn seal(&mut self) -> Result<(), Fault> {
        if self.sealed { return Err(Fault::Sealed); }
        self.sealed = true;
        Ok(())
    }
    pub fn pages_count(&self) -> usize { self.count }

    fn page(&self, t: FrameToken) -> Result<&Page, Fault> {
        let p = self.pages.get(t.slot).and_then(|p| p.as_ref()).ok_or(Fault::Stale)?;
        if p.generation != t.generation { return Err(Fault::Stale); }
        Ok(p)
    }
    fn page_mut(&mut self, t: FrameToken) -> Result<&mut Page, Fault> {
        let p = self.pages.get_mut(t.slot).and_then(|p| p.as_mut()).ok_or(Fault::Stale)?;
        if p.generation != t.generation { return Err(Fault::Stale); }
        Ok(p)
    }
    fn owned(&self, t: FrameToken, owner: u64) -> Result<&Page, Fault> {
        if owner == 0 { return Err(Fault::InvalidOwner); }
        let p = self.page(t)?;
        match p.class {
            PageClass::Owned(o) if o == owner => Ok(p),
            PageClass::Owned(_) => Err(Fault::WrongOwner),
            _ => Err(Fault::NotOwned),
        }
    }
    fn referenced(&self, t: FrameToken) -> bool {
        self.maps.iter().flatten().any(|m| m.frame == t) ||
        self.leases.iter().flatten().any(|d| d.frame == t)
    }
    pub fn address(&self, t: FrameToken) -> Result<u64, Fault> {
        Ok(self.page(t)?.phys)
    }
    pub fn allocate(&mut self, owner: u64) -> Result<FrameToken, Fault> {
        if !self.sealed { return Err(Fault::NotSealed); }
        if owner == 0 { return Err(Fault::InvalidOwner); }
        for (slot, maybe) in self.pages.iter_mut().enumerate() {
            if let Some(p) = maybe {
                if p.class == PageClass::Free {
                    p.class = PageClass::Owned(owner);
                    return Ok(FrameToken { slot, generation: p.generation });
                }
            }
        }
        Err(Fault::NoFreeFrame)
    }
    pub fn free(&mut self, t: FrameToken, owner: u64) -> Result<(), Fault> {
        let p = *self.owned(t, owner)?;
        if p.pins != 0 || self.referenced(t) { return Err(Fault::Busy); }
        let new_gen = p.generation.checked_add(1).ok_or(Fault::ExhaustedGeneration)?;
        let p = self.page_mut(t)?;
        p.generation = new_gen;
        p.class = PageClass::Free;
        Ok(())
    }
    pub fn retype(&mut self, t: FrameToken, owner: u64, next_owner: u64)
        -> Result<FrameToken, Fault> {
        if next_owner == 0 { return Err(Fault::InvalidOwner); }
        let p = *self.owned(t, owner)?;
        if p.pins != 0 || self.referenced(t) { return Err(Fault::Busy); }
        let new_gen = p.generation.checked_add(1).ok_or(Fault::ExhaustedGeneration)?;
        let p = self.page_mut(t)?;
        p.generation = new_gen;
        p.class = PageClass::Owned(next_owner);
        Ok(FrameToken { slot: t.slot, generation: new_gen })
    }

    fn map_ref(&self, t: MapToken) -> Result<&Mapping, Fault> {
        if self.map_generations.get(t.slot).copied() != Some(t.generation) {
            return Err(Fault::Stale);
        }
        self.maps.get(t.slot).and_then(|x| x.as_ref()).ok_or(Fault::Stale)
    }
    fn map_mut(&mut self, t: MapToken) -> Result<&mut Mapping, Fault> {
        if self.map_generations.get(t.slot).copied() != Some(t.generation) {
            return Err(Fault::Stale);
        }
        self.maps.get_mut(t.slot).and_then(|x| x.as_mut()).ok_or(Fault::Stale)
    }

    /// Existing *retiring* aliases still count until all CPU TLB acks.
    pub fn map(&mut self, t: FrameToken, owner: u64, rights: Rights,
               cpu_mask: u64) -> Result<MapToken, Fault> {
        self.owned(t, owner)?;
        if !rights.valid() { return Err(Fault::InvalidRights); }
        if cpu_mask == 0 { return Err(Fault::InvalidAck); }
        if self.maps.iter().flatten().any(|m| m.frame == t &&
            ((m.rights.write && rights.exec) || (m.rights.exec && rights.write))) {
            return Err(Fault::WxAlias);
        }
        if rights.exec && self.leases.iter().flatten().any(|d| d.frame == t) {
            return Err(Fault::Busy);
        }
        let slot = self.maps.iter().position(Option::is_none).ok_or(Fault::Capacity)?;
        let result = MapToken { slot, generation: self.map_generations[slot] };
        self.maps[slot] = Some(Mapping {
            frame: t, owner, rights, cpu_mask, retiring: false, pending_cpu: 0,
        });
        Ok(result)
    }
    pub fn begin_unmap(&mut self, t: MapToken, owner: u64) -> Result<(), Fault> {
        let m = self.map_mut(t)?;
        if m.owner != owner { return Err(Fault::WrongOwner); }
        if m.retiring { return Err(Fault::InvalidState); }
        m.retiring = true;
        m.pending_cpu = m.cpu_mask;
        Ok(())
    }
    /// Trust boundary: only ARCH may supply an authenticated shootdown completion.
    pub fn ack_cpu_tlb(&mut self, t: MapToken, cpu: u8) -> Result<(), Fault> {
        if cpu >= 64 { return Err(Fault::InvalidAck); }
        let bit = 1u64 << cpu;
        let m = self.map_mut(t)?;
        if !m.retiring || m.pending_cpu & bit == 0 { return Err(Fault::InvalidAck); }
        // Check generation increment before mutating the last pending bit.
        if m.pending_cpu == bit {
            let next = t.generation.checked_add(1).ok_or(Fault::ExhaustedGeneration)?;
            self.maps[t.slot] = None;
            self.map_generations[t.slot] = next;
        } else {
            m.pending_cpu &= !bit;
        }
        Ok(())
    }

    fn lease(&self, t: DmaToken) -> Result<&Lease, Fault> {
        if self.lease_generations.get(t.slot).copied() != Some(t.generation) {
            return Err(Fault::Stale);
        }
        self.leases.get(t.slot).and_then(|x| x.as_ref()).ok_or(Fault::Stale)
    }
    fn lease_mut(&mut self, t: DmaToken) -> Result<&mut Lease, Fault> {
        if self.lease_generations.get(t.slot).copied() != Some(t.generation) {
            return Err(Fault::Stale);
        }
        self.leases.get_mut(t.slot).and_then(|x| x.as_mut()).ok_or(Fault::Stale)
    }
    pub fn dma_phase(&self, t: DmaToken) -> Result<DmaPhase, Fault> {
        Ok(self.lease(t)?.phase)
    }
    pub fn pin_dma(&mut self, frame: FrameToken, owner: u64,
                   device: u64, cpu_mask: u64) -> Result<DmaToken, Fault> {
        self.owned(frame, owner)?;
        if device == 0 { return Err(Fault::InvalidDevice); }
        if cpu_mask == 0 { return Err(Fault::InvalidAck); }
        if self.leases.iter().flatten().any(|d| d.frame == frame) {
            return Err(Fault::Busy);
        }
        if self.maps.iter().flatten().any(|m| m.frame == frame && m.rights.exec) {
            return Err(Fault::WxAlias);
        }
        let slot = self.leases.iter().position(Option::is_none).ok_or(Fault::Capacity)?;
        let pins = self.page(frame)?.pins.checked_add(1).ok_or(Fault::Capacity)?;
        self.page_mut(frame)?.pins = pins;
        let result = DmaToken { slot, generation: self.lease_generations[slot] };
        self.leases[slot] = Some(Lease {
            frame, owner, device, cpu_mask, phase: DmaPhase::Pinned,
            pending_cpu: 0, quiesced: false, iommu_ack: false,
        });
        Ok(result)
    }

    /// Domain identifier is an abstract simulation input, NOT a real IOMMU proof.
    pub fn map_dma(&mut self, t: DmaToken, iommu_domain: Option<u64>)
        -> Result<(), Fault> {
        if iommu_domain.unwrap_or(0) == 0 { return Err(Fault::NoIommu); }
        let d = self.lease_mut(t)?;
        if d.phase != DmaPhase::Pinned { return Err(Fault::InvalidState); }
        d.phase = DmaPhase::Mapped;
        Ok(())
    }
    pub fn submit_dma(&mut self, t: DmaToken) -> Result<(), Fault> {
        let d = self.lease_mut(t)?;
        if d.phase != DmaPhase::Mapped { return Err(Fault::InvalidState); }
        d.phase = DmaPhase::Submitted;
        Ok(())
    }
    pub fn complete_dma(&mut self, t: DmaToken) -> Result<(), Fault> {
        let d = self.lease_mut(t)?;
        if d.phase != DmaPhase::Submitted { return Err(Fault::InvalidState); }
        d.phase = DmaPhase::Completed;
        Ok(())
    }
    /// Unmapped pinned pages never reached device access, so cancellation is safe.
    pub fn cancel_unmapped(&mut self, t: DmaToken, owner: u64)
        -> Result<(), Fault> {
        let d = *self.lease(t)?;
        if d.owner != owner { return Err(Fault::WrongOwner); }
        if d.phase != DmaPhase::Pinned { return Err(Fault::InvalidState); }
        self.retire_lease(t, d)
    }
    pub fn begin_dma_revoke(&mut self, t: DmaToken, owner: u64)
        -> Result<(), Fault> {
        let d = self.lease_mut(t)?;
        if d.owner != owner { return Err(Fault::WrongOwner); }
        match d.phase {
            DmaPhase::Mapped | DmaPhase::Submitted | DmaPhase::Completed => {
                d.phase = DmaPhase::Revoking;
                d.pending_cpu = d.cpu_mask;
                d.quiesced = false;
                d.iommu_ack = false;
                Ok(())
            }
            _ => Err(Fault::InvalidState),
        }
    }
    /// Different trusted completions are required: device stop, IOTLB, CPU TLB.
    pub fn ack_device_stopped(&mut self, t: DmaToken) -> Result<(), Fault> {
        let d = self.lease_mut(t)?;
        if d.phase != DmaPhase::Revoking { return Err(Fault::InvalidState); }
        d.quiesced = true;
        Ok(())
    }
    pub fn ack_iommu(&mut self, t: DmaToken) -> Result<(), Fault> {
        let d = self.lease_mut(t)?;
        if d.phase != DmaPhase::Revoking || !d.quiesced {
            return Err(Fault::InvalidAck);
        }
        d.iommu_ack = true;
        Ok(())
    }
    pub fn ack_dma_cpu(&mut self, t: DmaToken, cpu: u8) -> Result<(), Fault> {
        if cpu >= 64 { return Err(Fault::InvalidAck); }
        let bit = 1u64 << cpu;
        let d = self.lease_mut(t)?;
        if d.phase != DmaPhase::Revoking || d.pending_cpu & bit == 0 {
            return Err(Fault::InvalidAck);
        }
        d.pending_cpu &= !bit;
        Ok(())
    }
    pub fn finish_dma_revoke(&mut self, t: DmaToken, owner: u64)
        -> Result<(), Fault> {
        let d = *self.lease(t)?;
        if d.owner != owner { return Err(Fault::WrongOwner); }
        if d.phase != DmaPhase::Revoking || !d.quiesced ||
           !d.iommu_ack || d.pending_cpu != 0 {
            return Err(Fault::Busy);
        }
        self.retire_lease(t, d)
    }
    /// Any missing/expired completion quarantines this frame indefinitely.
    pub fn quarantine_dma(&mut self, t: DmaToken) -> Result<(), Fault> {
        let d = self.lease_mut(t)?;
        match d.phase {
            DmaPhase::Pinned | DmaPhase::Mapped | DmaPhase::Submitted |
            DmaPhase::Completed | DmaPhase::Revoking => {
                d.phase = DmaPhase::Quarantined;
                Ok(())
            }
            _ => Err(Fault::InvalidState),
        }
    }
    fn retire_lease(&mut self, t: DmaToken, d: Lease) -> Result<(), Fault> {
        let next = t.generation.checked_add(1).ok_or(Fault::ExhaustedGeneration)?;
        if self.page(d.frame)?.pins == 0 { return Err(Fault::InvalidState); }
        self.page_mut(d.frame)?.pins -= 1;
        self.leases[t.slot] = None;
        self.lease_generations[t.slot] = next;
        Ok(())
    }
}

impl<const P: usize, const M: usize, const D: usize> Default for Ledger<P, M, D> {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    type L = Ledger<8, 8, 4>;
    fn one() -> (L, FrameToken) {
        let mut l = L::new();
        l.register_page(0x1000, PageClass::Free).unwrap();
        l.seal().unwrap();
        let f = l.allocate(7).unwrap();
        (l, f)
    }
    #[test]
    fn sorted_and_borrowed_preserved() {
        let mut l = L::new();
        l.register_page(0x9000, PageClass::Free).unwrap();
        l.register_page(0x1000, PageClass::BorrowedBoot).unwrap();
        l.register_page(0x3000, PageClass::Reserved).unwrap();
        l.register_page(0x5000, PageClass::Free).unwrap();
        assert_eq!(l.register_page(0x5000, PageClass::Free),
                   Err(Fault::Range(RangeError::Overlap)));
        l.seal().unwrap();
        let a = l.allocate(1).unwrap();
        let b = l.allocate(1).unwrap();
        assert_eq!((l.address(a).unwrap(), l.address(b).unwrap()), (0x5000, 0x9000));
        assert_eq!(l.allocate(1), Err(Fault::NoFreeFrame));
    }
    #[test]
    fn unaligned_invalid_owner_and_stale_generation() {
        let mut l = L::new();
        assert_eq!(l.register_page(0x1001, PageClass::Free),
                   Err(Fault::Range(RangeError::Unaligned)));
        assert_eq!(l.allocate(7), Err(Fault::NotSealed));
        l.register_page(0x1000, PageClass::Free).unwrap();
        l.seal().unwrap();
        assert_eq!(l.allocate(0), Err(Fault::InvalidOwner));
        let f = l.allocate(7).unwrap();
        assert_eq!(l.free(f, 8), Err(Fault::WrongOwner));
        l.free(f, 7).unwrap();
        assert_eq!(l.free(f, 7), Err(Fault::Stale));
        let g = l.allocate(9).unwrap();
        assert_ne!(f, g);
    }
    #[test]
    fn wx_alias_retiring_still_counts() {
        let (mut l, f) = one();
        let w = l.map(f, 7, Rights::RW, 0b11).unwrap();
        assert_eq!(l.map(f, 7, Rights::RX, 1), Err(Fault::WxAlias));
        l.begin_unmap(w, 7).unwrap();
        assert_eq!(l.free(f, 7), Err(Fault::Busy));
        l.ack_cpu_tlb(w, 0).unwrap();
        assert_eq!(l.map(f, 7, Rights::RX, 1), Err(Fault::WxAlias));
        assert_eq!(l.ack_cpu_tlb(w, 0), Err(Fault::InvalidAck));
        l.ack_cpu_tlb(w, 1).unwrap();
        assert_eq!(l.ack_cpu_tlb(w, 1), Err(Fault::Stale));
        let x = l.map(f, 7, Rights::RX, 1).unwrap();
        assert_eq!(l.map(f, 7, Rights::RW, 1), Err(Fault::WxAlias));
        l.begin_unmap(x, 7).unwrap();
        l.ack_cpu_tlb(x, 0).unwrap();
        l.free(f, 7).unwrap();
    }
    #[test]
    fn invalid_rights_and_cpu_ack_denied() {
        let (mut l, f) = one();
        assert_eq!(l.map(f, 7, Rights {read: true, write: true, exec: true}, 1),
                   Err(Fault::InvalidRights));
        assert_eq!(l.map(f, 7, Rights::R, 0), Err(Fault::InvalidAck));
        let m = l.map(f, 7, Rights::R, 0b101).unwrap();
        assert_eq!(l.begin_unmap(m, 8), Err(Fault::WrongOwner));
        assert_eq!(l.ack_cpu_tlb(m, 0), Err(Fault::InvalidAck));
        l.begin_unmap(m, 7).unwrap();
        assert_eq!(l.retype(f, 7, 8), Err(Fault::Busy));
        assert_eq!(l.ack_cpu_tlb(m, 1), Err(Fault::InvalidAck));
        l.ack_cpu_tlb(m, 0).unwrap();
        assert_eq!(l.retype(f, 7, 8), Err(Fault::Busy));
        l.ack_cpu_tlb(m, 2).unwrap();
        let g = l.retype(f, 7, 8).unwrap();
        assert_eq!(l.free(f, 7), Err(Fault::Stale));
        l.free(g, 8).unwrap();
    }
    #[test]
    fn dma_full_revocation_fences() {
        let (mut l, f) = one();
        let d = l.pin_dma(f, 7, 21, 0b11).unwrap();
        assert_eq!(l.free(f, 7), Err(Fault::Busy));
        l.map_dma(d, Some(4)).unwrap();
        l.submit_dma(d).unwrap();
        l.complete_dma(d).unwrap();
        l.begin_dma_revoke(d, 7).unwrap();
        assert_eq!(l.ack_iommu(d), Err(Fault::InvalidAck));
        l.ack_device_stopped(d).unwrap();
        l.ack_iommu(d).unwrap();
        assert_eq!(l.finish_dma_revoke(d, 7), Err(Fault::Busy));
        l.ack_dma_cpu(d, 0).unwrap();
        assert_eq!(l.finish_dma_revoke(d, 7), Err(Fault::Busy));
        l.ack_dma_cpu(d, 1).unwrap();
        l.finish_dma_revoke(d, 7).unwrap();
        assert_eq!(l.finish_dma_revoke(d, 7), Err(Fault::Stale));
        l.free(f, 7).unwrap();
    }
    #[test]
    fn no_iommu_and_pre_map_cancel() {
        let (mut l, f) = one();
        let d = l.pin_dma(f, 7, 21, 1).unwrap();
        assert_eq!(l.map_dma(d, None), Err(Fault::NoIommu));
        assert_eq!(l.map_dma(d, Some(0)), Err(Fault::NoIommu));
        assert_eq!(l.submit_dma(d), Err(Fault::InvalidState));
        assert_eq!(l.free(f, 7), Err(Fault::Busy));
        l.cancel_unmapped(d, 7).unwrap();
        l.free(f, 7).unwrap();
    }
    #[test]
    fn pinned_dma_blocks_executable_aliases_both_orders() {
        let (mut l, f) = one();
        let d = l.pin_dma(f, 7, 2, 1).unwrap();
        assert_eq!(l.map(f, 7, Rights::RX, 1), Err(Fault::Busy));
        l.cancel_unmapped(d, 7).unwrap();
        let m = l.map(f, 7, Rights::RX, 1).unwrap();
        assert_eq!(l.pin_dma(f, 7, 2, 1), Err(Fault::WxAlias));
        l.begin_unmap(m, 7).unwrap();
        assert_eq!(l.pin_dma(f, 7, 2, 1), Err(Fault::WxAlias));
        l.ack_cpu_tlb(m, 0).unwrap();
        let d = l.pin_dma(f, 7, 2, 1).unwrap();
        l.cancel_unmapped(d, 7).unwrap();
    }
    #[test]
    fn timeout_quarantine_refuses_free_or_retype() {
        let (mut l, f) = one();
        let d = l.pin_dma(f, 7, 2, 1).unwrap();
        l.map_dma(d, Some(2)).unwrap();
        l.submit_dma(d).unwrap();
        l.quarantine_dma(d).unwrap();
        assert_eq!(l.dma_phase(d), Ok(DmaPhase::Quarantined));
        assert_eq!(l.finish_dma_revoke(d, 7), Err(Fault::Busy));
        assert_eq!(l.ack_iommu(d), Err(Fault::InvalidAck));
        assert_eq!(l.free(f, 7), Err(Fault::Busy));
        assert_eq!(l.retype(f, 7, 8), Err(Fault::Busy));
    }
    #[test]
    fn stale_dma_handle_after_slot_reuse() {
        let (mut l, f) = one();
        let d = l.pin_dma(f, 7, 2, 1).unwrap();
        l.cancel_unmapped(d, 7).unwrap();
        let n = l.pin_dma(f, 7, 2, 1).unwrap();
        assert_ne!(d, n);
        assert_eq!(l.cancel_unmapped(d, 7), Err(Fault::Stale));
    }
    #[test]
    fn device_completion_not_invalidation() {
        let (mut l, f) = one();
        let d = l.pin_dma(f, 7, 2, 1).unwrap();
        l.map_dma(d, Some(1)).unwrap();
        l.submit_dma(d).unwrap();
        l.complete_dma(d).unwrap();
        l.begin_dma_revoke(d, 7).unwrap();
        l.ack_device_stopped(d).unwrap();
        l.ack_dma_cpu(d, 0).unwrap();
        assert_eq!(l.finish_dma_revoke(d, 7), Err(Fault::Busy));
        l.ack_iommu(d).unwrap();
        l.finish_dma_revoke(d, 7).unwrap();
    }
}
