//! K1 early physical frame allocator, no_std, no heap, no physical accesses.
//! Input BootExtent list MUST come from independently validated kernel-owned
//! BootInfoV0 values. Only Limine USABLE (=0) may become frame inventory;
//! BOOTLOADER_RECLAIMABLE (=5) is *never* granted by this allocator.
//!
//! One globally exclusive instance must own every allocatable physical frame.
//! Do not construct multiple pools from the same boot memory map.
//! Allocator is bounded by LIVE allocation slots, not total RAM size.

use crate::FRAME_SIZE;

pub const LIMINE_USABLE: u64 = 0;
pub const LIMINE_BOOTLOADER_RECLAIMABLE: u64 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootExtent {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedSpan {
    pub base: u64,
    pub length: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Empty, Overflow, Unaligned, Unsorted, Overlap, ProtectedOverlap,
    NoUsableMemory, RegionCapacity, SlotCapacity, Exhausted, InvalidOwner,
    WrongOwner, Stale, Busy, GenerationExhausted, InvalidKind,
    Unscrubbed, Quarantined, AliasWx, VaConflict, ClaimCapacity, RootQuarantined,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramePurpose { Data, PageTable }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameLease { slot: usize, generation: u64 }
#[derive(Clone, Copy)]
struct Cursor { next: u64, end: u64 }
#[derive(Clone, Copy)]
struct Entry {
    phys: u64, owner: u64, generation: u64,
    purpose: FramePurpose, pins: u32, live: bool,
    clean: bool, quarantined: bool, writable_aliases: u32, executable_aliases: u32,
}

/// Implemented by privileged trusted zeroing backend, never by untrusted users.
/// An Ok means ALL 4096 physical bytes are zero and visible to CPUs.
pub trait FrameZeroer {
    fn zero_physical_frame(&mut self, phys: u64) -> Result<(), ()>;
}
#[derive(Clone, Copy)]
struct VaClaim {
    id: u64, root: u64, generation: u64, va: u64,
    frame: Option<FrameLease>, write: bool, execute: bool,
    uncertain: bool,
}

/// R is max number of USABLE memory-map entries; LIVE is the maximum number
/// of simultaneously tracked page frames (including page-table frames).
pub struct FramePool<const R: usize, const LIVE: usize> {
    regions: [Option<Cursor>; R],
    region_count: usize,
    slots: [Option<Entry>; LIVE],
    slot_count: usize,
    // Authoritative for ALL MapLedger instances that use this FramePool.
    // One physical pool must be the UNIQUE kernel-wide frame/map issuer.
    claims: [Option<VaClaim>; LIVE],
    next_claim_id: u64,
}
fn checked_end(base: u64, length: u64) -> Result<u64, Error> {
    if length == 0 { return Err(Error::Empty); }
    base.checked_add(length).ok_or(Error::Overflow)
}
fn overlaps(a0: u64, a1: u64, b0: u64, b1: u64) -> bool {
    a0 < b1 && b0 < a1
}
impl<const R: usize, const LIVE: usize> FramePool<R,LIVE> {
    /// Requires complete, sorted, checked Limine map, plus extra explicit
    /// protected physical spans for loaded kernel, modules, stack if external,
    /// and all other borrowed resources. Overlap of USABLE with a protected
    /// span is rejected, not silently reclaimed.
    pub fn from_validated_boot(
        map: &[BootExtent], protected: &[ReservedSpan],
    ) -> Result<Self,Error> {
        let mut pool=Self {
            regions:[None;R], region_count:0,
            slots:[None;LIVE], slot_count:0,
            claims:[None;LIVE], next_claim_id:1,
        };
        let mut previous_base: Option<u64> = None;
        for (index,extent) in map.iter().enumerate() {
            let end=checked_end(extent.base,extent.length)?;
            if let Some(old)=previous_base {
                if extent.base < old {return Err(Error::Unsorted);}
            }
            previous_base=Some(extent.base);
            // Limine permits some non-USABLE overlap, never with USABLE.
            for earlier in &map[..index] {
                let earlier_end=checked_end(earlier.base,earlier.length)?;
                if overlaps(extent.base,end,earlier.base,earlier_end) &&
                   (extent.kind==LIMINE_USABLE ||
                    earlier.kind==LIMINE_USABLE ||
                    extent.kind==LIMINE_BOOTLOADER_RECLAIMABLE ||
                    earlier.kind==LIMINE_BOOTLOADER_RECLAIMABLE) {
                    return Err(Error::Overlap);
                }
            }
            if extent.kind != LIMINE_USABLE {continue;}
            if (extent.base | extent.length) & (FRAME_SIZE-1) != 0 {
                return Err(Error::Unaligned);
            }
            // Never allocate physical page zero even if firmware marks it usable.
            if extent.base == 0 {return Err(Error::ProtectedOverlap);}
            for p in protected {
                let p_end=checked_end(p.base,p.length)?;
                if overlaps(extent.base,end,p.base,p_end) {
                    return Err(Error::ProtectedOverlap);
                }
            }
            if pool.region_count==R {return Err(Error::RegionCapacity);}
            pool.regions[pool.region_count]=Some(Cursor{next:extent.base,end});
            pool.region_count+=1;
        }
        if pool.region_count==0 {return Err(Error::NoUsableMemory);}
        Ok(pool)
    }

    fn get(&self,lease:FrameLease)->Result<&Entry,Error>{
        let entry=self.slots.get(lease.slot).and_then(|s|s.as_ref())
            .ok_or(Error::Stale)?;
        if entry.generation!=lease.generation || !entry.live {
            return Err(Error::Stale);
        }
        Ok(entry)
    }
    fn get_mut(&mut self,lease:FrameLease)->Result<&mut Entry,Error>{
        let entry=self.slots.get_mut(lease.slot).and_then(|s|s.as_mut())
            .ok_or(Error::Stale)?;
        if entry.generation!=lease.generation || !entry.live {
            return Err(Error::Stale);
        }
        Ok(entry)
    }
    fn owned(&self,lease:FrameLease,owner:u64)->Result<&Entry,Error>{
        if owner==0 {return Err(Error::InvalidOwner);}
        let entry=self.get(lease)?;
        if entry.owner!=owner {return Err(Error::WrongOwner);}
        Ok(entry)
    }
    pub fn physical(&self,lease:FrameLease,owner:u64)->Result<u64,Error>{
        Ok(self.owned(lease,owner)?.phys)
    }
    pub fn purpose(&self,lease:FrameLease,owner:u64)
        -> Result<FramePurpose,Error> {
        Ok(self.owned(lease,owner)?.purpose)
    }
    pub fn allocate(&mut self,owner:u64,purpose:FramePurpose)
        -> Result<FrameLease,Error>{
        if owner==0 {return Err(Error::InvalidOwner);}
        // Reuse only previously freed (and fully invalidated) frame slots.
        for i in 0..self.slot_count {
            let entry=self.slots[i].as_mut().expect("contiguous slots");
            if !entry.live && !entry.quarantined {
                entry.live=true;
                entry.owner=owner;
                entry.purpose=purpose;
                entry.pins=0;
                entry.clean=false;
                entry.writable_aliases=0;
                entry.executable_aliases=0;
                return Ok(FrameLease{slot:i,generation:entry.generation});
            }
        }
        if self.slot_count==LIVE {return Err(Error::SlotCapacity);}
        for r in &mut self.regions[..self.region_count] {
            let c=r.as_mut().expect("contiguous regions");
            let next=c.next.checked_add(FRAME_SIZE).ok_or(Error::Overflow)?;
            if next<=c.end {
                let slot=self.slot_count;
                self.slot_count+=1;
                let phys=c.next;
                c.next=next;
                self.slots[slot]=Some(Entry {
                    phys, owner, generation:1, purpose, pins:0, live:true,
                    clean:false, quarantined:false, writable_aliases:0, executable_aliases:0,
                });
                return Ok(FrameLease{slot,generation:1});
            }
        }
        Err(Error::Exhausted)
    }
    /// An allocator frame may be freed ONLY after every map/CPU/device
    /// reference has retired. Page-table root lifetimes are managed by K1 VMM.
    pub fn free(&mut self,lease:FrameLease,owner:u64)->Result<(),Error>{
        let e=*self.owned(lease,owner)?;
        if e.pins!=0 {return Err(Error::Busy);}
        if e.quarantined {return Err(Error::Quarantined);}
        let next=e.generation.checked_add(1).ok_or(Error::GenerationExhausted)?;
        let entry=self.get_mut(lease)?;
        entry.live=false;
        entry.owner=0;
        entry.clean=false;
        entry.generation=next;
        Ok(())
    }
    /// Package-private ownership pin: the map manager issues this BEFORE PTE
    /// insertion and releases only after full matching TLB completion.
    pub(crate) fn pin_map(&mut self,lease:FrameLease,owner:u64)
        -> Result<(),Error> {
        let pins=self.owned(lease,owner)?.pins.checked_add(1)
            .ok_or(Error::SlotCapacity)?;
        self.get_mut(lease)?.pins=pins;
        Ok(())
    }
    pub(crate) fn unpin_after_tlb(&mut self,lease:FrameLease,owner:u64)
        -> Result<(),Error> {
        let pins=self.owned(lease,owner)?.pins;
        if pins==0 {return Err(Error::Busy);}
        self.get_mut(lease)?.pins=pins-1;
        Ok(())
    }

    /// Zero-before-exposure boundary. Backend must be privileged and perform
    /// an actual physical memory scrub. A failed/ambiguous scrub quarantines
    /// the frame and forbids reuse; no caller-supplied boolean "proof".
    pub fn scrub_owned<Z:FrameZeroer>(
        &mut self, lease:FrameLease, owner:u64, zeroer:&mut Z,
    )->Result<(),Error>{
        let e=*self.owned(lease,owner)?;
        if e.pins!=0 || e.quarantined {return Err(Error::Busy);}
        if e.purpose!=FramePurpose::Data {return Err(Error::InvalidKind);}
        if zeroer.zero_physical_frame(e.phys).is_err(){
            self.get_mut(lease)?.quarantined=true;
            return Err(Error::Quarantined);
        }
        self.get_mut(lease)?.clean=true;
        Ok(())
    }
    pub fn is_scrubbed(&self,lease:FrameLease,owner:u64)->Result<bool,Error>{
        let e=self.owned(lease,owner)?;
        if e.quarantined {return Err(Error::Quarantined);}
        Ok(e.clean)
    }
    fn claim_conflict(&self, root:u64,generation:u64,va:u64)->bool{
        self.claims.iter().flatten().any(|c|
            c.root==root && c.va==va)
    }
    fn root_uncertain(&self, root:u64,generation:u64)->bool{
        self.claims.iter().flatten().any(|c|
            c.root==root && c.uncertain)
    }
    fn free_claim_index(&self)->Result<usize,Error>{
        self.claims.iter().position(Option::is_none).ok_or(Error::ClaimCapacity)
    }
    fn issue_claim_id(&mut self)->Result<u64,Error>{
        let current=self.next_claim_id;
        self.next_claim_id=self.next_claim_id.checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        Ok(current)
    }
    /// Claims live in the shared pool, not an individual MapLedger. Thus a
    /// second ledger cannot defeat a guard reservation on the same PML4.
    pub(crate) fn reserve_guard(
        &mut self,root:u64,generation:u64,va:u64,
    )->Result<u64,Error>{
        if self.root_uncertain(root,generation){return Err(Error::RootQuarantined);}
        if self.claim_conflict(root,generation,va){return Err(Error::VaConflict);}
        let slot=self.free_claim_index()?;
        let id=self.issue_claim_id()?;
        self.claims[slot]=Some(VaClaim{
            id,root,generation,va,frame:None,
            write:false,execute:false,uncertain:false,
        });
        Ok(id)
    }
    pub(crate) fn release_guard(
        &mut self,root:u64,generation:u64,va:u64,id:u64,
    )->Result<(),Error>{
        let pos=self.claims.iter().position(|c|matches!(c,
            Some(g) if g.root==root&&g.generation==generation&&g.va==va
                 &&g.id==id&&g.frame.is_none()));
        let index=pos.ok_or(Error::Stale)?;
        self.claims[index]=None;
        Ok(())
    }
    /// Reserve W/X globally by FrameLease and VA by root generation *before*
    /// touching any page-table entry. On a failed write, quarantine_frame_map
    /// retains both the VA claim and global W/X reservation.
    pub(crate) fn begin_map(
        &mut self,root:u64,generation:u64,va:u64,
        frame:FrameLease,owner:u64,write:bool,execute:bool,
    )->Result<u64,Error>{
        if self.root_uncertain(root,generation){return Err(Error::RootQuarantined);}
        if self.claim_conflict(root,generation,va){return Err(Error::VaConflict);}
        let e=*self.owned(frame,owner)?;
        if e.purpose!=FramePurpose::Data{return Err(Error::InvalidKind);}
        if e.quarantined{return Err(Error::Quarantined);}
        if !e.clean{return Err(Error::Unscrubbed);}
        if (write && e.executable_aliases!=0) ||
           (execute && e.writable_aliases!=0) {return Err(Error::AliasWx);}
        let slot=self.free_claim_index()?;
        let id=self.issue_claim_id()?;
        let new_pins=e.pins.checked_add(1).ok_or(Error::SlotCapacity)?;
        let new_writes=e.writable_aliases.checked_add(u32::from(write))
            .ok_or(Error::SlotCapacity)?;
        let new_execs=e.executable_aliases.checked_add(u32::from(execute))
            .ok_or(Error::SlotCapacity)?;
        let physical=self.get_mut(frame)?;
        physical.pins=new_pins;
        physical.writable_aliases=new_writes;
        physical.executable_aliases=new_execs;
        self.claims[slot]=Some(VaClaim{
            id,root,generation,va,frame:Some(frame),
            write,execute,uncertain:false,
        });
        Ok(id)
    }
    pub(crate) fn quarantine_frame_map(
        &mut self,root:u64,generation:u64,va:u64,
        frame:FrameLease,id:u64,
    )->Result<(),Error>{
        let claim=self.claims.iter_mut().flatten().find(|c|
            c.root==root&&c.generation==generation&&c.va==va
            &&c.frame==Some(frame)&&c.id==id).ok_or(Error::Stale)?;
        claim.uncertain=true;
        self.get_mut(frame)?.quarantined=true;
        Ok(())
    }
    pub(crate) fn complete_unmap(
        &mut self,root:u64,generation:u64,va:u64,
        frame:FrameLease,owner:u64,id:u64,
    )->Result<(),Error>{
        let i=self.claims.iter().position(|c|matches!(c,Some(g)
            if g.root==root&&g.generation==generation&&g.va==va
            &&g.frame==Some(frame)&&g.id==id&&!g.uncertain)).ok_or(Error::Stale)?;
        let claim=self.claims[i].expect("occupied");
        let e=*self.owned(frame,owner)?;
        if e.quarantined{return Err(Error::Quarantined);}
        if e.pins==0 || (claim.write && e.writable_aliases==0) ||
           (claim.execute && e.executable_aliases==0){return Err(Error::Busy);}
        let entry=self.get_mut(frame)?;
        entry.pins-=1;
        if claim.write{entry.writable_aliases-=1;}
        if claim.execute{entry.executable_aliases-=1;}
        self.claims[i]=None;
        Ok(())
    }
    pub fn allocated_count(&self)->usize{
        self.slots[..self.slot_count].iter().flatten().filter(|s|s.live).count()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    type Pool=FramePool<8,12>;
    fn map()->[BootExtent;3] {
        [
            BootExtent{base:0x1000,length:0x4000,kind:0},
            BootExtent{base:0x8000,length:0x4000,kind:5},
            BootExtent{base:0x100000,length:0x10000,kind:6},
        ]
    }
    fn pool()->Pool {
        Pool::from_validated_boot(&map(),&[
            ReservedSpan{base:0x100000,length:0x10000}
        ]).unwrap()
    }
    #[test] fn only_usable_frames_are_allocated() {
        let mut p=pool();
        let mut addresses=[0u64;4];
        for addr in &mut addresses {
            let f=p.allocate(1,FramePurpose::Data).unwrap();
            *addr=p.physical(f,1).unwrap();
        }
        assert_eq!(addresses,[0x1000,0x2000,0x3000,0x4000]);
        assert_eq!(p.allocate(1,FramePurpose::Data),Err(Error::Exhausted));
    }
    #[test] fn stale_and_double_free_denied() {
        let mut p=pool();
        let f=p.allocate(1,FramePurpose::PageTable).unwrap();
        assert_eq!(p.free(f,2),Err(Error::WrongOwner));
        p.free(f,1).unwrap();
        assert_eq!(p.free(f,1),Err(Error::Stale));
        let g=p.allocate(1,FramePurpose::Data).unwrap();
        assert_eq!(p.physical(g,1),Ok(0x1000));
        assert_ne!(f,g);
        assert_eq!(p.free(f,1),Err(Error::Stale));
    }
    #[test] fn pinned_frame_never_reclaimed() {
        let mut p=pool();
        let f=p.allocate(7,FramePurpose::Data).unwrap();
        p.pin_map(f,7).unwrap();
        assert_eq!(p.free(f,7),Err(Error::Busy));
        p.unpin_after_tlb(f,7).unwrap();
        p.free(f,7).unwrap();
    }
    #[test] fn rejected_usable_overlap_with_boot_borrowed() {
        let m=[
            BootExtent{base:0x1000,length:0x4000,kind:0},
            BootExtent{base:0x3000,length:0x1000,kind:5},
        ];
        assert!(matches!(Pool::from_validated_boot(&m,&[]),Err(Error::Overlap)));
    }
    #[test] fn checked_wrap_zero_and_kernel_protection() {
        let m=[BootExtent{base:u64::MAX-1,length:0x2000,kind:0}];
        assert!(matches!(Pool::from_validated_boot(&m,&[]),Err(Error::Overflow)));
        let m=[BootExtent{base:0,length:0x1000,kind:0}];
        assert!(matches!(Pool::from_validated_boot(&m,&[]),Err(Error::ProtectedOverlap)));
        assert!(matches!(Pool::from_validated_boot(&map(),&[
            ReservedSpan{base:0x2000,length:0x1000}
        ]),Err(Error::ProtectedOverlap)));
    }
    #[test] fn no_usable_and_slot_limit_fail_closed() {
        let m=[BootExtent{base:0x1000,length:0x1000,kind:5}];
        assert!(matches!(Pool::from_validated_boot(&m,&[]),Err(Error::NoUsableMemory)));
        let mut p:FramePool<1,1>=FramePool::from_validated_boot(
            &[BootExtent{base:0x1000,length:0x2000,kind:0}],&[]).unwrap();
        let _=p.allocate(1,FramePurpose::Data).unwrap();
        assert_eq!(p.allocate(1,FramePurpose::Data),Err(Error::SlotCapacity));
    }
    struct FakeRam {
        contents:[u8;4096], fail:bool, zero_count:usize,
    }
    impl FrameZeroer for FakeRam {
        fn zero_physical_frame(&mut self, _:u64)->Result<(),()>{
            if self.fail {return Err(());}
            self.contents=[0;4096];
            self.zero_count+=1;
            Ok(())
        }
    }
    #[test]
    fn qa011_owner_reuse_requires_actual_zero_before_exposure() {
        let mut p=pool();
        let mut ram=FakeRam{contents:[0x5a;4096],fail:false,zero_count:0};
        let old=p.allocate(1,FramePurpose::Data).unwrap();
        assert_eq!(p.is_scrubbed(old,1),Ok(false));
        p.scrub_owned(old,1,&mut ram).unwrap();
        assert_eq!(ram.contents,[0u8;4096]);
        ram.contents.fill(0xa5); // previous owner writes secret sentinel
        p.free(old,1).unwrap();
        let fresh=p.allocate(2,FramePurpose::Data).unwrap();
        assert_eq!(p.physical(fresh,2),Ok(0x1000));
        assert_eq!(p.is_scrubbed(fresh,2),Ok(false));
        assert_eq!(ram.contents[0],0xa5);
        p.scrub_owned(fresh,2,&mut ram).unwrap();
        assert_eq!(p.is_scrubbed(fresh,2),Ok(true));
        assert_eq!(ram.contents,[0u8;4096]);
        assert_eq!(ram.zero_count,2);
    }
    #[test]
    fn qa011_scrub_failure_quarantines_reusable_frame() {
        let mut p=pool();
        let mut ram=FakeRam{contents:[0xde;4096],fail:true,zero_count:0};
        let frame=p.allocate(1,FramePurpose::Data).unwrap();
        assert_eq!(p.scrub_owned(frame,1,&mut ram),Err(Error::Quarantined));
        assert_eq!(p.free(frame,1),Err(Error::Quarantined));
        assert_eq!(p.is_scrubbed(frame,1),Err(Error::Quarantined));
        // Frame must never return to another owner after uncertain zeroing.
        let other=p.allocate(2,FramePurpose::Data).unwrap();
        assert_ne!(p.physical(other,2),Ok(0x1000));
    }

}
