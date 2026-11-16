//! Central revocable BAR broker: only the broker can perform MMIO reads.
//! CPU page mapping, synchronous TLB completion and volatile accesses are
//! supplied by a privileged kernel backend. Test fake is NOT hardware evidence.
//! Never permit an unmanaged direct-map alias or untrusted register caller.

use crate::{PhysRange, FRAME_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Empty, Overflow, Unaligned, InvalidDevice, InvalidVirtualAddress,
    Conflict, Protected, Capacity, Stale, NotMapped, InvalidAccess,
    BackendFailure,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State { Registered, Mapped, Revoking, Quarantined, Revoked }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle { slot: usize, generation: u64 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarSpec {
    pub device: u64, pub incarnation: u64, pub physical: u64,
    pub length: u64, pub virtual_base: u64,
}
#[derive(Clone, Copy)]
struct Record {
    spec: BarSpec, range: PhysRange, va_end: u64,
    generation: u64, state: State,
}

/// In production map_uc_readonly requires real supervisor-only RO+NX+UC PTEs.
/// unmap must clear PTEs, shootdown_sync must wait for all CPUs/PCIDs.
/// Failure of any operation may leave stale translations: broker quarantines.
/// A single global lock must serialize all broker operations on SMP.
pub trait Backend {
    fn map_uc_readonly(&mut self, va: u64, pa: u64, len: u64) -> Result<(), ()>;
    fn unmap(&mut self, va: u64, expected_pa: u64, len: u64) -> Result<(), ()>;
    fn shootdown_sync(&mut self, va: u64, len: u64) -> Result<(), ()>;
    fn read_volatile32(&mut self, va: u64) -> Result<u32, ()>;
    /// Authoritative current PCI lease validation (NOT cached metadata).
    fn pci_grant_current(&self, spec: BarSpec) -> bool;
}

/// Trusted PCI resource inventory is responsible for calling register.
/// The broker is not itself the PCI BAR sizing/config-space authority.
pub struct Broker<B: Backend, const N: usize, const P: usize> {
    backend: B, slots: [Option<Record>; N], count: usize,
    protected: [PhysRange; P],
}
impl<B: Backend, const N: usize, const P: usize> Broker<B, N, P> {
    pub fn new(backend: B, protected: [PhysRange; P]) -> Self {
        Self { backend, slots: [None; N], count: 0, protected }
    }
    pub fn register_from_trusted_pci(&mut self, spec: BarSpec) -> Result<Handle, Error> {
        if spec.device == 0 || spec.incarnation == 0 { return Err(Error::InvalidDevice); }
        if !self.backend.pci_grant_current(spec) {return Err(Error::Stale);}
        if spec.length == 0 { return Err(Error::Empty); }
        if (spec.physical | spec.virtual_base | spec.length) % FRAME_SIZE != 0 {
            return Err(Error::Unaligned);
        }
        let end = spec.physical.checked_add(spec.length).ok_or(Error::Overflow)?;
        let va_end = spec.virtual_base.checked_add(spec.length).ok_or(Error::Overflow)?;
        // Four-level x86-64 high-half canonical VA only; LA57 unsupported here.
        if spec.virtual_base < 0xffff_8000_0000_0000 ||
           va_end > 0xffff_ffff_ffff_f000 || va_end <= spec.virtual_base {
            return Err(Error::InvalidVirtualAddress);
        }
        let range = PhysRange { start: spec.physical, end };
        if self.protected.iter().any(|p| p.overlaps(range)) {
            return Err(Error::Protected);
        }
        for record in self.slots.iter().flatten() {
            let virtual_overlap = spec.virtual_base < record.va_end &&
                record.spec.virtual_base < va_end;
            if record.state != State::Revoked &&
                (range.overlaps(record.range) || virtual_overlap ||
                 (record.spec.device == spec.device &&
                  record.spec.incarnation == spec.incarnation)) {
                return Err(Error::Conflict);
            }
        }
        if self.count == N { return Err(Error::Capacity); }
        let slot = self.count;
        self.count += 1;
        self.slots[slot] = Some(Record {
            spec, range, va_end, generation: 1, state: State::Registered,
        });
        Ok(Handle { slot, generation: 1 })
    }
    fn get(&self, handle: Handle) -> Result<&Record, Error> {
        let s = self.slots.get(handle.slot).and_then(|s| s.as_ref())
            .ok_or(Error::Stale)?;
        if s.generation != handle.generation { return Err(Error::Stale); }
        Ok(s)
    }
    fn get_mut(&mut self, handle: Handle) -> Result<&mut Record, Error> {
        let s = self.slots.get_mut(handle.slot).and_then(|s| s.as_mut())
            .ok_or(Error::Stale)?;
        if s.generation != handle.generation { return Err(Error::Stale); }
        Ok(s)
    }
    pub fn state(&self, handle: Handle) -> Result<State, Error> {
        Ok(self.get(handle)?.state)
    }
    pub fn slot_state(&self, slot: usize) -> Option<State> {
        self.slots.get(slot).and_then(|r| r.as_ref()).map(|r| r.state)
    }
    pub fn activate(&mut self, handle: Handle) -> Result<(), Error> {
        let s = *self.get(handle)?;
        if !self.backend.pci_grant_current(s.spec) {return Err(Error::Stale);}
        if s.state != State::Registered { return Err(Error::NotMapped); }
        if self.backend.map_uc_readonly(s.spec.virtual_base, s.spec.physical,
                                        s.spec.length).is_err() {
            self.get_mut(handle)?.state = State::Quarantined;
            return Err(Error::BackendFailure);
        }
        self.get_mut(handle)?.state = State::Mapped;
        Ok(())
    }
    pub fn read32(&mut self, handle: Handle, offset: u64) -> Result<u32, Error> {
        let s = *self.get(handle)?;
        if !self.backend.pci_grant_current(s.spec) {return Err(Error::Stale);}
        if s.state != State::Mapped { return Err(Error::NotMapped); }
        if offset % 4 != 0 ||
           offset.checked_add(4).ok_or(Error::Overflow)? > s.spec.length {
            return Err(Error::InvalidAccess);
        }
        let addr = s.spec.virtual_base.checked_add(offset).ok_or(Error::Overflow)?;
        self.backend.read_volatile32(addr).map_err(|_| Error::BackendFailure)
    }
    /// Revocation linearizes when phase changes and token generation advances,
    /// BEFORE any unmap. On partial failure address space must be quarantined.
    pub fn revoke(&mut self, handle: Handle) -> Result<(), Error> {
        let record = *self.get(handle)?;
        if record.state != State::Registered && record.state != State::Mapped {
            return Err(Error::NotMapped);
        }
        let next = record.generation.checked_add(1).ok_or(Error::Overflow)?;
        {
            let s = self.get_mut(handle)?;
            s.state = State::Revoking;
            s.generation = next;
        }
        // Never exposed to CPU if still Registered; no PTE shootdown needed.
        if record.state == State::Registered {
            self.slots[handle.slot].as_mut().expect("occupied").state = State::Revoked;
            return Ok(());
        }
        if record.state != State::Mapped {
            self.slots[handle.slot].as_mut().expect("occupied").state = State::Quarantined;
            return Err(Error::NotMapped);
        }
        let a = self.backend.unmap(record.spec.virtual_base, record.spec.physical, record.spec.length);
        if a.is_err() {
            self.slots[handle.slot].as_mut().expect("occupied").state = State::Quarantined;
            return Err(Error::BackendFailure);
        }
        let b = self.backend.shootdown_sync(record.spec.virtual_base, record.spec.length);
        if b.is_err() {
            self.slots[handle.slot].as_mut().expect("occupied").state = State::Quarantined;
            return Err(Error::BackendFailure);
        }
        self.slots[handle.slot].as_mut().expect("occupied").state = State::Revoked;
        Ok(())
    }
    /// Called by the *trusted* PCI registry when a BAR resource is externally
    /// released. This must execute before the old physical aperture can be
    /// reassigned; polling asynchronously is NOT sufficient for revocation.
    pub fn revoke_expired(&mut self) -> Result<usize, Error> {
        let mut retired=0;
        for index in 0..self.count {
            let old=self.slots[index].expect("occupied prefix");
            if (old.state == State::Mapped || old.state == State::Registered) &&
               !self.backend.pci_grant_current(old.spec) {
                self.revoke(Handle{slot:index,generation:old.generation})?;
                retired+=1;
            }
        }
        Ok(retired)
    }

}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fake {
        mapped: bool, reads: usize, flushes: usize,
        pci_revoked: bool,
        fail_unmap: bool, fail_map: bool, fail_flush: bool,
    }
    impl Backend for Fake {
        fn map_uc_readonly(&mut self, _:u64, _:u64, _:u64)->Result<(),()>{
            if self.fail_map { return Err(()); }
            self.mapped=true;Ok(())
        }
        fn unmap(&mut self, _:u64, _:u64, _:u64)->Result<(),()>{
            if self.fail_unmap { return Err(()); }
            self.mapped=false;Ok(())
        }
        fn shootdown_sync(&mut self, _:u64, _:u64)->Result<(),()>{
            self.flushes+=1;
            if self.fail_flush { Err(()) } else { Ok(()) }
        }
        fn pci_grant_current(&self,_:BarSpec)->bool{!self.pci_revoked}
        fn read_volatile32(&mut self, _:u64)->Result<u32,()>{
            if !self.mapped { return Err(()); }
            self.reads+=1;Ok(0x4455_6677)
        }
    }
    fn spec()->BarSpec { BarSpec {
        device: 7, incarnation: 11, physical: 0xf000_0000,
        length: 2*FRAME_SIZE, virtual_base: 0xffff_9000_0000_0000,
    }}
    fn broker()->Broker<Fake,4,1>{
        Broker::new(Fake::default(), [PhysRange {start:0x1000,end:0x8000}])
    }
    #[test] fn revoke_blocks_copied_handle_and_flushes() {
        let mut b=broker();let h=b.register_from_trusted_pci(spec()).unwrap();
        let copied=h;
        b.activate(h).unwrap();
        assert_eq!(b.read32(h,0),Ok(0x4455_6677));
        b.revoke(h).unwrap();
        assert_eq!(b.read32(copied,0),Err(Error::Stale));
        assert_eq!(b.activate(copied),Err(Error::Stale));
        assert_eq!(b.revoke(copied),Err(Error::Stale));
        assert_eq!(b.backend.reads,1);
        assert_eq!(b.backend.flushes,1);
    }
    #[test] fn failed_shootdown_denies_access_and_keeps_slot() {
        let mut b=broker();let h=b.register_from_trusted_pci(spec()).unwrap();
        b.activate(h).unwrap();b.backend.fail_flush=true;
        assert_eq!(b.revoke(h),Err(Error::BackendFailure));
        assert_eq!(b.slot_state(0),Some(State::Quarantined));
        assert_eq!(b.read32(h,0),Err(Error::Stale));
        assert_eq!(b.register_from_trusted_pci(spec()),Err(Error::Conflict));
    }
    #[test] fn failed_unmap_quarantines_without_reads() {
        let mut b=broker();let h=b.register_from_trusted_pci(spec()).unwrap();
        b.activate(h).unwrap();b.backend.fail_unmap=true;
        assert_eq!(b.revoke(h),Err(Error::BackendFailure));
        assert_eq!(b.read32(h,0),Err(Error::Stale));
        assert_eq!(b.backend.reads,0);
    }
    #[test] fn partial_map_failure_cannot_be_activated() {
        let mut b=broker();let h=b.register_from_trusted_pci(spec()).unwrap();
        b.backend.fail_map=true;
        assert_eq!(b.activate(h),Err(Error::BackendFailure));
        assert_eq!(b.state(h),Ok(State::Quarantined));
        assert_eq!(b.read32(h,0),Err(Error::NotMapped));
    }
    #[test] fn offset_and_alias_checks() {
        let mut b=broker();let h=b.register_from_trusted_pci(spec()).unwrap();
        b.activate(h).unwrap();
        assert_eq!(b.read32(h,1),Err(Error::InvalidAccess));
        assert_eq!(b.read32(h,2*FRAME_SIZE-2),Err(Error::InvalidAccess));
        assert_eq!(b.read32(h,2*FRAME_SIZE),Err(Error::InvalidAccess));
        let mut other=spec();other.device=8;other.incarnation=12;
        other.physical=0xf100_0000;
        assert_eq!(b.register_from_trusted_pci(other),Err(Error::Conflict));
        other.virtual_base=0xffff_9000_0100_0000;
        assert!(b.register_from_trusted_pci(other).is_ok());
    }
    #[test] fn physical_protected_and_bad_geometry() {
        let mut b=broker();let mut s=spec();s.physical=0x1000;
        assert_eq!(b.register_from_trusted_pci(s),Err(Error::Protected));
        s=spec();s.length=0;
        assert_eq!(b.register_from_trusted_pci(s),Err(Error::Empty));
        s=spec();s.incarnation=0;
        assert_eq!(b.register_from_trusted_pci(s),Err(Error::InvalidDevice));
    }
}

#[cfg(test)]
mod external_revocation_tests {
    use super::*;
    struct Fake { pci_live: bool, reads: usize }
    impl Backend for Fake {
        fn map_uc_readonly(&mut self,_:u64,_:u64,_:u64)->Result<(),()>{Ok(())}
        fn unmap(&mut self,_:u64,_:u64,_:u64)->Result<(),()>{Ok(())}
        fn shootdown_sync(&mut self,_:u64,_:u64)->Result<(),()>{Ok(())}
        fn read_volatile32(&mut self,_:u64)->Result<u32,()>{self.reads+=1;Ok(1)}
        fn pci_grant_current(&self,_:BarSpec)->bool{self.pci_live}
    }
    #[test] fn external_registry_release_denies_stale_copy() {
        let backend=Fake {pci_live:true,reads:0};
        let mut broker: Broker<Fake,1,0>=Broker::new(backend,[]);
        let spec=BarSpec{device:1,incarnation:1,physical:0xf000_0000,
            length:FRAME_SIZE,virtual_base:0xffff_9000_0000_0000};
        let ticket=broker.register_from_trusted_pci(spec).unwrap();
        broker.activate(ticket).unwrap();
        broker.backend.pci_live=false;
        assert_eq!(broker.read32(ticket,0),Err(Error::Stale));
        assert_eq!(broker.backend.reads,0);
        // Teardown remains mandatory even after the upstream grant expired.
        assert_eq!(broker.revoke_expired(),Ok(1));
        assert_eq!(broker.read32(ticket,0),Err(Error::Stale));
    }
    #[test] fn unactivated_bar_revoke_never_requires_tlb_ack() {
        let backend=Fake {pci_live:true,reads:0};
        let mut broker:Broker<Fake,1,0>=Broker::new(backend,[]);
        let spec=BarSpec{device:1,incarnation:2,physical:0xf000_0000,
            length:FRAME_SIZE,virtual_base:0xffff_9000_0000_1000};
        let ticket=broker.register_from_trusted_pci(spec).unwrap();
        broker.revoke(ticket).unwrap();
        assert_eq!(broker.slot_state(0),Some(State::Revoked));
        assert_eq!(broker.read32(ticket,0),Err(Error::Stale));
    }

}
