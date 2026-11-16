//! Intel VT-d second-level 4-level paging table *format and mutations*.
//! Uses legacy-compatible SL-PTE bits R=0, W=1, X=2; X intentionally clear.
//! This writes actual SLPT entries through a trusted TableStore, NOT VT-d
//! root/context/PASID programming, DMAR validation, or IOTLB invalidation.
//! A second-level table alone cannot isolate a device until attached to a
//! verified IOMMU domain and invalidation/translation completed in hardware.

use crate::page_tables::TableStore;
use crate::FRAME_SIZE;
const READ: u64 = 1;
const WRITE: u64 = 1 << 1;
const EXEC: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    InvalidIova, InvalidPhysical, Missing, Present, DifferentFrame,
    HugePage, Permission, MissingTable, Io,
}
fn indexes(addr:u64)->[usize;4] {
    [
        ((addr>>39)&511) as usize,
        ((addr>>30)&511) as usize,
        ((addr>>21)&511) as usize,
        ((addr>>12)&511) as usize,
    ]
}
fn valid_phys(pa:u64)->bool{
    pa & (FRAME_SIZE-1)==0 && pa & !ADDRESS == 0
}
/// Only 48-bit IOVAs / 4KiB leaves and a domain with verified 4-level AGAW.
/// Does not enable ATS/PRI/PASID, peer-to-peer DMA, or pass-through fallback.
pub fn install_slpte<S:TableStore>(tables:&mut S, iova:u64, phys:u64,
                                    device_may_write:bool)->Result<(),Fault>{
    if iova==0 || iova >= (1u64<<48) || iova%FRAME_SIZE!=0 {
        return Err(Fault::InvalidIova);
    }
    if !valid_phys(phys) {return Err(Fault::InvalidPhysical);}
    let mut table=tables.root_table();
    if !valid_phys(table) {return Err(Fault::MissingTable);}
    let ix=indexes(iova);
    for &n in ix[..3].iter(){
        let entry=tables.read_entry(table,n).map_err(|_|Fault::Io)?;
        if entry & (READ|WRITE) == 0 {
            let child=tables.allocate_zeroed_table().map_err(|_|Fault::Io)?;
            if !valid_phys(child) {return Err(Fault::InvalidPhysical);}
            // Intermediate tables allow R/W traversal; leaf is narrower.
            tables.write_entry(table,n,child|READ|WRITE).map_err(|_|Fault::Io)?;
            table=child;
        } else {
            if entry & HUGE != 0 {return Err(Fault::HugePage);}
            if entry & EXEC != 0 {return Err(Fault::Permission);}
            table=entry&ADDRESS;
            if !valid_phys(table) {return Err(Fault::InvalidPhysical);}
        }
    }
    let old=tables.read_entry(table,ix[3]).map_err(|_|Fault::Io)?;
    if old & (READ|WRITE) != 0 {return Err(Fault::Present);}
    let flags=READ|if device_may_write {WRITE} else {0};
    tables.write_entry(table,ix[3],phys|flags).map_err(|_|Fault::Io)
}
/// Remove *only* the expected physical page. Caller must then issue hardware
/// domain/IOTLB invalidation and wait for completion before unpin or reuse.
pub fn remove_slpte<S:TableStore>(tables:&mut S, iova:u64,
                                   expected_phys:u64)->Result<(),Fault>{
    let (table,n,old)=leaf(tables,iova)?;
    if !valid_phys(expected_phys) {return Err(Fault::InvalidPhysical);}
    if old&ADDRESS != expected_phys {return Err(Fault::DifferentFrame);}
    tables.write_entry(table,n,0).map_err(|_|Fault::Io)
}
fn leaf<S:TableStore>(tables:&S,iova:u64)->Result<(u64,usize,u64),Fault>{
    if iova==0 || iova >= (1u64<<48) || iova%FRAME_SIZE != 0 {
        return Err(Fault::InvalidIova);
    }
    let mut table=tables.root_table();
    let ix=indexes(iova);
    for &n in ix[..3].iter(){
        let entry=tables.read_entry(table,n).map_err(|_|Fault::Io)?;
        if entry & (READ|WRITE)==0 {return Err(Fault::Missing);}
        if entry & HUGE!=0 {return Err(Fault::HugePage);}
        table=entry&ADDRESS;
        if !valid_phys(table) {return Err(Fault::InvalidPhysical);}
    }
    let old=tables.read_entry(table,ix[3]).map_err(|_|Fault::Io)?;
    if old & (READ|WRITE)==0 {return Err(Fault::Missing);}
    Ok((table,ix[3],old))
}
/// Software oracle for second-level translation; not a QEMU/VT-d DMA test.
pub fn translate<S:TableStore>(tables:&S,iova:u64,
                                device_write:bool)->Result<u64,Fault>{
    if iova==0 || iova >= (1u64<<48) {return Err(Fault::InvalidIova);}
    let page=iova & !(FRAME_SIZE-1);
    let (_,_,entry)=leaf(tables,page)?;
    if entry & READ==0 || (device_write && entry & WRITE==0) ||
       entry & EXEC != 0 {return Err(Fault::Permission);}
    (entry&ADDRESS).checked_add(iova-page).ok_or(Fault::InvalidPhysical)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::page_tables::{Fault as PteFault,TableStore};
    struct T { pages:[[u64;512];8],count:usize }
    impl T {fn new()->Self{Self{pages:[[0;512];8],count:1}}
        fn index(p:u64)->usize{(p/FRAME_SIZE) as usize-1}}
    impl TableStore for T {
        fn root_table(&self)->u64{FRAME_SIZE}
        fn allocate_zeroed_table(&mut self)->Result<u64,PteFault>{
            if self.count>=8 {return Err(PteFault::IoFailure);}
            self.count+=1;Ok(self.count as u64*FRAME_SIZE)
        }
        fn read_entry(&self,p:u64,n:usize)->Result<u64,PteFault>{
            self.pages.get(Self::index(p)).and_then(|a|a.get(n))
                .copied().ok_or(PteFault::MissingTable)
        }
        fn write_entry(&mut self,p:u64,n:usize,e:u64)->Result<(),PteFault>{
            *self.pages.get_mut(Self::index(p)).and_then(|a|a.get_mut(n))
                .ok_or(PteFault::MissingTable)?=e;Ok(())
        }
    }
    #[test] fn mapped_dma_can_read_but_cannot_write_readonly() {
        let mut t=T::new();
        install_slpte(&mut t,0x8000,0x2000,false).unwrap();
        assert_eq!(translate(&t,0x8100,false),Ok(0x2100));
        assert_eq!(translate(&t,0x8100,true),Err(Fault::Permission));
        assert_eq!(translate(&t,0x9000,false),Err(Fault::Missing));
        assert_eq!(install_slpte(&mut t,0x8000,0x3000,true),Err(Fault::Present));
    }
    #[test] fn removal_rejects_wrong_physical_and_blocks_late_dma() {
        let mut t=T::new();
        install_slpte(&mut t,0x8000,0x2000,true).unwrap();
        assert_eq!(remove_slpte(&mut t,0x8000,0x3000),Err(Fault::DifferentFrame));
        assert_eq!(translate(&t,0x8000,true),Ok(0x2000));
        remove_slpte(&mut t,0x8000,0x2000).unwrap();
        assert_eq!(translate(&t,0x8000,true),Err(Fault::Missing));
    }
    #[test] fn disallow_unmapped_iova_and_bad_phys() {
        let mut t=T::new();
        assert_eq!(install_slpte(&mut t,0,0x2000,false),Err(Fault::InvalidIova));
        assert_eq!(install_slpte(&mut t,0x8000,0x2001,false),Err(Fault::InvalidPhysical));
        assert_eq!(translate(&t,0x1_0000_0000_0000,false),Err(Fault::InvalidIova));
    }
}
