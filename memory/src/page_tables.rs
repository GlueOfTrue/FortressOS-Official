//! x86-64 4-level 4KiB page-table editor for *actual PTE bytes*.
//! Backend provides real, owned zeroed table frames and their memory accesses.
//! No CR3 activation, CPU shootdown or PAT MSR validation is supplied here.
//! Not a complete VMM; LA57, 1GiB/2MiB splits and shared HHDM are rejected.
//! Mutations require an exclusive, trusted kernel lock; caller handles TLB fence.

use crate::FRAME_SIZE;
const P: u64 = 1;
const W: u64 = 1 << 1;
const U: u64 = 1 << 2;
const PWT: u64 = 1 << 3;
const PCD: u64 = 1 << 4;
const PS: u64 = 1 << 7;
const NX: u64 = 1 << 63;
const ADDR: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    Unaligned, NonCanonical, OutOfPhysicalRange, MissingTable,
    UnexpectedHugePage, UserAccessibleAncestor, ExecutableAncestor,
    AlreadyMapped, NotMapped, WrongPhysicalPage, IoFailure,
}
/// Actual page-table writes are delegated to an exclusively owned physical
/// table store. Each entry read/write must be coherent and real in production.
/// allocate_zeroed_table must reserve an owned frame of exactly 4096 bytes.
pub trait TableStore {
    fn root_table(&self) -> u64;
    fn allocate_zeroed_table(&mut self) -> Result<u64, Fault>;
    fn read_entry(&self, physical_table: u64, index: usize) -> Result<u64, Fault>;
    fn write_entry(&mut self, physical_table: u64, index: usize,
                   entry: u64) -> Result<(), Fault>;
}
pub fn canonical_high_half(addr: u64) -> bool {
    addr >= 0xffff_8000_0000_0000
}
fn address_valid(pa: u64) -> bool {
    pa & (FRAME_SIZE - 1) == 0 && pa & !ADDR == 0
}
fn indices(va: u64) -> [usize; 4] {
    [
        ((va >> 39) & 0x1ff) as usize,
        ((va >> 30) & 0x1ff) as usize,
        ((va >> 21) & 0x1ff) as usize,
        ((va >> 12) & 0x1ff) as usize,
    ]
}
/// UC assumes the kernel has independently verified IA32_PAT index 3 is UC
/// for (PAT=0, PCD=1, PWT=1). If PAT differs, do not invoke this mapper.
pub const fn uc_nx_supervisor_readonly_entry(pa: u64) -> u64 {
    (pa & ADDR) | P | PWT | PCD | NX
}
/// Caller must exclusively own the VA subtree and map every direct-map alias
/// of the BAR to compatible UC, or explicitly exclude the physical BAR there.
pub fn map_uc_page<T: TableStore>(io: &mut T, va: u64, pa: u64)
    -> Result<(), Fault> {
    if !canonical_high_half(va) { return Err(Fault::NonCanonical); }
    if va % FRAME_SIZE != 0 || pa % FRAME_SIZE != 0 { return Err(Fault::Unaligned); }
    if !address_valid(pa) || !address_valid(io.root_table()) {
        return Err(Fault::OutOfPhysicalRange);
    }
    let idx = indices(va);
    let mut table = io.root_table();
    for &i in idx[..3].iter() {
        let entry = io.read_entry(table, i)?;
        if entry & P == 0 {
            let child = io.allocate_zeroed_table()?;
            if !address_valid(child) { return Err(Fault::OutOfPhysicalRange); }
            // Page-table pages are supervisor-only; parent NX is kept clear
            // to permit other leaf mappings, while each MMIO leaf is NX.
            io.write_entry(table, i, child | P | W)?;
            table = child;
        } else {
            if entry & PS != 0 { return Err(Fault::UnexpectedHugePage); }
            if entry & U != 0 { return Err(Fault::UserAccessibleAncestor); }
            if entry & NX != 0 { return Err(Fault::ExecutableAncestor); }
            table = entry & ADDR;
            if !address_valid(table) { return Err(Fault::OutOfPhysicalRange); }
        }
    }
    let existing = io.read_entry(table, idx[3])?;
    if existing & P != 0 { return Err(Fault::AlreadyMapped); }
    io.write_entry(table, idx[3], uc_nx_supervisor_readonly_entry(pa))
}
/// Unmap the exact expected BAR page. Never clear a PTE that has been
/// reassigned to another owner. TLB flush MUST follow before freeing/retyping.
pub fn unmap_page<T: TableStore>(io: &mut T, va: u64, expected_pa: u64)
    -> Result<(), Fault> {
    if !canonical_high_half(va) { return Err(Fault::NonCanonical); }
    if va % FRAME_SIZE != 0 || expected_pa % FRAME_SIZE != 0 {
        return Err(Fault::Unaligned);
    }
    if !address_valid(expected_pa) { return Err(Fault::OutOfPhysicalRange); }
    let idx = indices(va);
    let mut table = io.root_table();
    for &i in idx[..3].iter() {
        let entry = io.read_entry(table, i)?;
        if entry & P == 0 { return Err(Fault::NotMapped); }
        if entry & PS != 0 { return Err(Fault::UnexpectedHugePage); }
        if entry & U != 0 { return Err(Fault::UserAccessibleAncestor); }
        table = entry & ADDR;
        if !address_valid(table) { return Err(Fault::OutOfPhysicalRange); }
    }
    let entry = io.read_entry(table, idx[3])?;
    if entry & P == 0 { return Err(Fault::NotMapped); }
    if entry & ADDR != expected_pa { return Err(Fault::WrongPhysicalPage); }
    if entry & U != 0 || entry & W != 0 || entry & NX == 0 ||
       entry & PWT == 0 || entry & PCD == 0 {
        return Err(Fault::WrongPhysicalPage);
    }
    io.write_entry(table, idx[3], 0)
}

/// Connects real PTE mutations to the revocable MMIO broker.
/// Flusher is a separate trusted 03 ARCH dependency: all-CPU shootdown must
/// finish synchronously, and read32 must issue a real volatile load.
/// This adapter does not invent successful invalidation acknowledgments.
pub trait CpuAccess {
    fn shootdown_all_cpus(&mut self, va: u64, len: u64) -> Result<(), ()>;
    fn volatile_read_u32(&mut self, va: u64) -> Result<u32, ()>;
    fn pat_index3_is_uc(&self) -> bool;
    /// Must have EFER.NXE enabled on every CPU which may use this address space.
    fn nxe_verified(&self) -> bool;
    fn pci_grant_current(&self, spec: crate::revocable_mmio::BarSpec) -> bool;
}
pub struct X86MmioBackend<T: TableStore, C: CpuAccess> {
    pub tables: T,
    pub cpu: C,
}
impl<T: TableStore, C: CpuAccess> crate::revocable_mmio::Backend
    for X86MmioBackend<T, C> {
    fn map_uc_readonly(&mut self, va: u64, pa: u64, len: u64) -> Result<(), ()> {
        if !self.cpu.pat_index3_is_uc() || !self.cpu.nxe_verified() || len == 0 ||
           (va | pa | len) % FRAME_SIZE != 0 { return Err(()); }
        let end = va.checked_add(len).ok_or(())?;
        let _ = pa.checked_add(len).ok_or(())?;
        let mut pos = va;
        while pos < end {
            let off = pos - va;
            map_uc_page(&mut self.tables, pos, pa + off).map_err(|_| ())?;
            pos = pos.checked_add(FRAME_SIZE).ok_or(())?;
        }
        Ok(())
    }
    fn unmap(&mut self, va: u64, expected_pa: u64, len: u64) -> Result<(), ()> {
        if len == 0 || (va | len) % FRAME_SIZE != 0 { return Err(()); }
        let end = va.checked_add(len).ok_or(())?;
        let _ = expected_pa.checked_add(len).ok_or(())?;
        let mut pos = va;
        while pos < end {
            let pa = expected_pa + (pos - va);
            unmap_page(&mut self.tables, pos, pa).map_err(|_| ())?;
            pos = pos.checked_add(FRAME_SIZE).ok_or(())?;
        }
        Ok(())
    }
    fn shootdown_sync(&mut self, va: u64, len: u64) -> Result<(), ()> {
        self.cpu.shootdown_all_cpus(va, len)
    }
    fn read_volatile32(&mut self, va: u64) -> Result<u32, ()> {
        self.cpu.volatile_read_u32(va)
    }
    fn pci_grant_current(&self, spec: crate::revocable_mmio::BarSpec) -> bool {
        self.cpu.pci_grant_current(spec)
    }
}
pub fn walk_leaf_pa<T: TableStore>(io: &T, va: u64) -> Result<u64, Fault> {
    if !canonical_high_half(va) { return Err(Fault::NonCanonical); }
    let idx=indices(va);
    let mut table=io.root_table();
    for &i in idx[..3].iter() {
        let e=io.read_entry(table,i)?;
        if e & P == 0 { return Err(Fault::NotMapped); }
        if e & PS != 0 { return Err(Fault::UnexpectedHugePage); }
        if e & U != 0 { return Err(Fault::UserAccessibleAncestor); }
        table=e & ADDR;
    }
    let e=io.read_entry(table,idx[3])?;
    if e & P == 0 { return Err(Fault::NotMapped); }
    Ok(e & ADDR)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct FakeStore {
        pages: [[u64;512]; 8], next: usize,
    }
    impl FakeStore {
        fn new()->Self{Self{pages:[[0;512];8],next:1}}
        fn root_index(p:u64)->usize{(p / FRAME_SIZE) as usize - 1}
    }
    impl TableStore for FakeStore {
        fn root_table(&self)->u64{FRAME_SIZE}
        fn allocate_zeroed_table(&mut self)->Result<u64,Fault>{
            if self.next>=8 {return Err(Fault::IoFailure);}
            self.next+=1;
            Ok((self.next as u64)*FRAME_SIZE)
        }
        fn read_entry(&self,p:u64,i:usize)->Result<u64,Fault>{
            if i>=512 {return Err(Fault::IoFailure);}
            self.pages.get(Self::root_index(p)).map(|a|a[i]).ok_or(Fault::MissingTable)
        }
        fn write_entry(&mut self,p:u64,i:usize,e:u64)->Result<(),Fault>{
            if i>=512 {return Err(Fault::IoFailure);}
            let table=self.pages.get_mut(Self::root_index(p)).ok_or(Fault::MissingTable)?;
            table[i]=e;Ok(())
        }
    }
    #[test] fn actual_leaf_entry_uc_nx_supervisor_readonly() {
        let mut s=FakeStore::new();
        let va=0xffff_9000_1000_0000;
        let pa=0xf000_0000;
        map_uc_page(&mut s,va,pa).unwrap();
        assert_eq!(walk_leaf_pa(&s,va),Ok(pa));
        let mut table=s.root_table();
        for i in indices(va)[..3].iter() {
            let e=s.read_entry(table,*i).unwrap();
            assert_eq!(e&U,0);
            table=e&ADDR;
        }
        let leaf=s.read_entry(table,indices(va)[3]).unwrap();
        assert_ne!(leaf & NX,0);
        assert_eq!(leaf & W,0);
        assert_eq!(leaf & U,0);
        assert_eq!(leaf & (PCD|PWT),PCD|PWT);
        assert_eq!(map_uc_page(&mut s,va,pa),Err(Fault::AlreadyMapped));
        unmap_page(&mut s,va,pa).unwrap();
        assert_eq!(walk_leaf_pa(&s,va),Err(Fault::NotMapped));
    }
    #[test] fn cannot_unmap_someone_elses_page() {
        let mut s=FakeStore::new();let va=0xffff_9000_0000_1000;
        map_uc_page(&mut s,va,0xf000_0000).unwrap();
        assert_eq!(unmap_page(&mut s,va,0xf000_1000),
                   Err(Fault::WrongPhysicalPage));
        assert_eq!(walk_leaf_pa(&s,va),Ok(0xf000_0000));
    }
    #[test] fn reject_high_half_cpl3_and_unaligned() {
        let mut s=FakeStore::new();
        assert_eq!(map_uc_page(&mut s,0x1000,0xf000_0000),
                   Err(Fault::NonCanonical));
        assert_eq!(map_uc_page(&mut s,0xffff_9000_0000_0001,0xf000_0000),
                   Err(Fault::Unaligned));
        assert_eq!(map_uc_page(&mut s,0xffff_9000_0000_0000,1),
                   Err(Fault::Unaligned));
    }
    #[derive(Default)]
    struct CpuFixture {
        pat: bool, nxe: bool, grant: bool, shootdowns: usize,
    }
    impl CpuAccess for CpuFixture {
        fn shootdown_all_cpus(&mut self,_:u64,_:u64)->Result<(),()> {
            self.shootdowns+=1;Ok(())
        }
        fn volatile_read_u32(&mut self,_:u64)->Result<u32,()> {Ok(0x1122_3344)}
        fn pat_index3_is_uc(&self)->bool{self.pat}
        fn nxe_verified(&self)->bool{self.nxe}
        fn pci_grant_current(&self,_:crate::revocable_mmio::BarSpec)->bool{self.grant}
    }
    #[test] fn complete_broker_adapter_denies_unverified_cpu_state() {
        use crate::revocable_mmio::{BarSpec,Broker,Error as BarError};
        let cpu=CpuFixture{pat:false,nxe:false,grant:true,shootdowns:0};
        let x86=X86MmioBackend{tables:FakeStore::new(),cpu};
        let mut broker:Broker<_,1,0>=Broker::new(x86,[]);
        let bar=BarSpec{
            device:8,incarnation:4,physical:0xf000_0000,
            length:FRAME_SIZE,virtual_base:0xffff_9000_0000_0000,
        };
        let ticket=broker.register_from_trusted_pci(bar).unwrap();
        assert_eq!(broker.activate(ticket),Err(BarError::BackendFailure));
        assert_eq!(broker.read32(ticket,0),Err(BarError::NotMapped));
        // Partial or rejected map remains quarantined; no retry with same token.
        assert_eq!(broker.activate(ticket),Err(BarError::NotMapped));
    }
    #[test] fn trusted_fixture_broker_writes_leaf_and_revokes() {
        use crate::revocable_mmio::{BarSpec,Broker,Error as BarError};
        let cpu=CpuFixture{pat:true,nxe:true,grant:true,shootdowns:0};
        let x86=X86MmioBackend{tables:FakeStore::new(),cpu};
        let mut broker:Broker<_,1,0>=Broker::new(x86,[]);
        let bar=BarSpec{
            device:8,incarnation:4,physical:0xf000_0000,
            length:FRAME_SIZE,virtual_base:0xffff_9000_0000_0000,
        };
        let ticket=broker.register_from_trusted_pci(bar).unwrap();
        broker.activate(ticket).unwrap();
        assert_eq!(broker.read32(ticket,0),Ok(0x1122_3344));
        broker.revoke(ticket).unwrap();
        assert_eq!(broker.read32(ticket,0),Err(BarError::Stale));
    }

}
