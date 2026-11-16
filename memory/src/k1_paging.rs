//! K1 4KiB address-space mapper with tracked owned frame handles.
//! Four-level x86-64, LA57=off, NXE=on. Guest entry and TLB flush supplied
//! by 03 ARCH. Both PTE writes and metadata changes require an exclusive lock.
//! Root and lower-level table ownership must come from K1 PMM; inherited
//! Limine kernel-half tables remain BORROWED until independently copied.

use crate::{FRAME_SIZE,k1_frames::{FrameLease,FramePurpose,FramePool,Error as FrameError}};
use crate::page_tables::{TableStore,Fault as PteFault};

const P:u64=1;
const W:u64=1<<1;
const U:u64=1<<2;
const PS:u64=1<<7;
const NX:u64=1<<63;
const ADDR:u64=0x000f_ffff_ffff_f000;
const MAX_USER_PAGE:u64=0x0000_7fff_ffff_f000;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error {
    InvalidAddress, InvalidRights, WrongRoot, WrongSpace,
    AlreadyMapped, NotMapped, AliasWx, TableFailure,
    Unauthorized, Busy, Capacity, Stale, GenerationExhausted,
    Frames(FrameError), WrongFrame,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Rights {pub write:bool,pub execute:bool,pub user:bool}
impl Rights {
    pub const USER_RW:Self=Self{write:true,execute:false,user:true};
    pub const USER_RX:Self=Self{write:false,execute:true,user:true};
    pub const KERNEL_RW:Self=Self{write:true,execute:false,user:false};
    pub const KERNEL_RX:Self=Self{write:false,execute:true,user:false};
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Space {root:u64,identity:u64,generation:u64}
impl Space {
    /// Trusted constructor only after root is allocated by PMM and the
    /// hardware table store is initialized for EXACTLY this root.
    /// No boot ownership proof follows from these integers alone.
    pub fn from_trusted_root(root:u64,identity:u64,generation:u64)
        -> Result<Self,Error>{
        if root==0 || root&!ADDR!=0 || identity==0 || generation==0 {
            return Err(Error::WrongSpace);
        }
        Ok(Self{root,identity,generation})
    }
    pub fn root_physical(self)->u64{self.root}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct MappingHandle {slot:usize,generation:u64,space:Space,va:u64,claim_id:u64}
#[derive(Clone,Copy)]
struct Record {
    space:Space,va:u64,owner:u64,frame:Option<FrameLease>,
    rights:Rights,retiring:bool,claim_id:u64,
}
pub trait TlbInvalidate {
    /// Trusted backend returns success ONLY when this address-space
    /// incarnation is invalidated on every CPU/PCID that could cache it.
    fn invalidate_sync(&mut self,space:Space,virtual_page:u64)->Result<(),()>;
}
pub struct MapLedger<const N:usize> {
    maps:[Option<Record>;N],
    generations:[u64;N],
}
impl<const N:usize> MapLedger<N>{
    pub const fn new()->Self{
        Self{maps:[None;N],generations:[1;N]}
    }
    fn record(&self,h:MappingHandle)->Result<Record,Error>{
        if self.generations.get(h.slot).copied()!=Some(h.generation) {
            return Err(Error::Stale);
        }
        let record=self.maps.get(h.slot).and_then(|x|*x).ok_or(Error::Stale)?;
        if record.space!=h.space || record.va!=h.va || record.claim_id!=h.claim_id {
            return Err(Error::Stale);
        }
        Ok(record)
    }
    fn free_slot(&self)->Result<usize,Error>{
        self.maps.iter().position(Option::is_none).ok_or(Error::Capacity)
    }
    fn conflict(&self,space:Space,va:u64)->bool{
        self.maps.iter().flatten().any(|x|x.space==space && x.va==va)
    }
    /// Guard reservations have NO PTE and cannot be mapped until removed.
    /// Intended for user stacks and ring0 exception stack redzones.
    pub fn reserve_guard<T:TableStore,const R:usize,const L:usize>(
        &mut self,tables:&T,pool:&mut FramePool<R,L>,space:Space,va:u64,
    )->Result<MappingHandle,Error>{
        self.reserve_guard_with_privilege(tables,pool,space,va,true)
    }
    pub fn reserve_kernel_guard<T:TableStore,const R:usize,const L:usize>(
        &mut self,tables:&T,pool:&mut FramePool<R,L>,space:Space,va:u64,
    )->Result<MappingHandle,Error>{
        self.reserve_guard_with_privilege(tables,pool,space,va,false)
    }
    fn reserve_guard_with_privilege<T:TableStore,const R:usize,const L:usize>(
        &mut self,tables:&T,pool:&mut FramePool<R,L>,
        space:Space,va:u64,user:bool,
    )->Result<MappingHandle,Error>{
        ensure_space(tables,space)?;
        validate_va(va,user)?;
        if self.conflict(space,va){return Err(Error::AlreadyMapped);}
        if walk_leaf(tables,va)?.is_some(){return Err(Error::AlreadyMapped);}
        let slot=self.free_slot()?;
        let claim_id=pool.reserve_guard(space.root,space.generation,va)
            .map_err(|e|if e==FrameError::VaConflict{Error::AlreadyMapped}
                     else{Error::Frames(e)})?;
        let h=MappingHandle{slot,generation:self.generations[slot],space,va,claim_id};
        self.maps[slot]=Some(Record{
            space,va,owner:0,frame:None,
            rights:if user {Rights::USER_RW}else{Rights::KERNEL_RW},
            retiring:false,claim_id,
        });
        Ok(h)
    }
    pub fn map<T:TableStore,const R:usize,const L:usize>(
        &mut self,tables:&mut T,pool:&mut FramePool<R,L>,
        space:Space,va:u64,frame:FrameLease,owner:u64,rights:Rights,
    )->Result<MappingHandle,Error>{
        ensure_space(tables,space)?;
        validate_va(va,rights.user)?;
        if rights.write && rights.execute{return Err(Error::InvalidRights);}
        if self.conflict(space,va) {return Err(Error::AlreadyMapped);}
        // Inherited high-half Limine page-table descendants are BORROWED.
        // No kernel PTE writes until they are independently deep-cloned.
        if !rights.user {return Err(Error::Unauthorized);}
        if pool.purpose(frame,owner).map_err(Error::Frames)? != FramePurpose::Data {
            return Err(Error::WrongFrame);
        }
        let pa=pool.physical(frame,owner).map_err(Error::Frames)?;
        preflight_map_leaf(tables,va,rights)?;
        let slot=self.free_slot()?;
        let claim_id=pool.begin_map(space.root,space.generation,va,frame,owner,
                       rights.write,rights.execute).map_err(|e|match e{
            FrameError::VaConflict=>Error::AlreadyMapped,
            FrameError::AliasWx=>Error::AliasWx,
            other=>Error::Frames(other),
        })?;
        if write_leaf(tables,va,pa,rights).is_err(){
            // May already have committed a leaf before returning Err.
            // Quarantine physical frame and VA/root for all ledgers.
            pool.quarantine_frame_map(space.root,space.generation,va,frame,claim_id)
                .map_err(Error::Frames)?;
            return Err(Error::TableFailure);
        }
        let h=MappingHandle{slot,generation:self.generations[slot],space,va,claim_id};
        self.maps[slot]=Some(Record{
            space,va,owner,frame:Some(frame),rights,retiring:false,claim_id,
        });
        Ok(h)
    }
    /// After invalidation failure retains frame pin and stale-alias barrier.
    /// Reinvoke retire with the same mapping to retry only the shootdown.
    pub fn retire<T:TableStore,I:TlbInvalidate,const R:usize,const L:usize>(
        &mut self,tables:&mut T,pool:&mut FramePool<R,L>,
        invalidator:&mut I,h:MappingHandle,
    )->Result<(),Error>{
        let r=self.record(h)?;
        ensure_space(tables,r.space)?;
        let next=h.generation.checked_add(1).ok_or(Error::GenerationExhausted)?;
        if r.frame.is_none(){
            pool.release_guard(r.space.root,r.space.generation,r.va,r.claim_id)
                .map_err(Error::Frames)?;
            self.maps[h.slot]=None;
            self.generations[h.slot]=next;
            return Ok(());
        }
        let frame=r.frame.expect("mapping has a frame");
        if !r.retiring{
            let pa=pool.physical(frame,r.owner).map_err(Error::Frames)?;
            // Do NOT mark retiring if no PTE was cleared, but abort/fail
            // closed if the current translation is not the expected frame.
            if let Err(failure)=clear_leaf(tables,r.va,pa,r.rights){
                pool.quarantine_frame_map(r.space.root,r.space.generation,
                                          r.va,frame,r.claim_id).map_err(Error::Frames)?;
                return Err(failure);
            }
            self.maps[h.slot].as_mut().expect("live mapping").retiring=true;
        }
        if invalidator.invalidate_sync(r.space,r.va).is_err() {
            return Err(Error::Busy);
        }
        pool.complete_unmap(r.space.root,r.space.generation,r.va,frame,r.owner,r.claim_id)
            .map_err(Error::Frames)?;
        self.maps[h.slot]=None;
        self.generations[h.slot]=next;
        Ok(())
    }
}
impl<const N:usize> Default for MapLedger<N>{
    fn default()->Self{Self::new()}
}
fn indices(va:u64)->[usize;4]{
    [
        ((va>>39)&511) as usize,
        ((va>>30)&511) as usize,
        ((va>>21)&511) as usize,
        ((va>>12)&511) as usize,
    ]
}
fn ensure_space<T:TableStore>(tables:&T,space:Space)->Result<(),Error>{
    if space.root!=tables.root_table(){Err(Error::WrongRoot)}else{Ok(())}
}
fn validate_va(va:u64,user:bool)->Result<(),Error>{
    if va%FRAME_SIZE!=0{return Err(Error::InvalidAddress);}
    if user {
        if va==0 || va>MAX_USER_PAGE{return Err(Error::InvalidAddress);}
    }else if va<0xffff_8000_0000_0000 {
        return Err(Error::InvalidAddress);
    }
    Ok(())
}
fn walk_leaf<T:TableStore>(t:&T,va:u64)->Result<Option<u64>,Error>{
    let ix=indices(va);
    let mut table=t.root_table();
    for &i in ix[..3].iter(){
        let e=t.read_entry(table,i).map_err(|_|Error::TableFailure)?;
        if e&P==0{return Ok(None);}
        if e&PS!=0{return Err(Error::TableFailure);}
        table=e&ADDR;
    }
    let leaf=t.read_entry(table,ix[3]).map_err(|_|Error::TableFailure)?;
    if leaf&P==0 {Ok(None)} else {Ok(Some(leaf))}
}
/// Read-only preflight avoids quarantining an otherwise healthy root when
/// a user requests permissions already denied by an existing ancestor.
/// This is not a substitute for write-time checks: the lock must prevent PTE
/// races, and failed writes after preflight still quarantine the whole root.
fn preflight_map_leaf<T:TableStore>(
    t:&T,va:u64,rights:Rights,
)->Result<(),Error>{
    let ix=indices(va);
    let mut table=t.root_table();
    for &i in ix[..3].iter(){
        let entry=t.read_entry(table,i).map_err(|_|Error::TableFailure)?;
        if entry&P==0 {return Ok(());}
        if entry&PS!=0{return Err(Error::TableFailure);}
        if (entry&U!=0)!=rights.user ||
           (rights.write && entry&W==0) ||
           (rights.execute && entry&NX!=0) {
            return Err(Error::Unauthorized);
        }
        table=entry&ADDR;
    }
    let leaf=t.read_entry(table,ix[3]).map_err(|_|Error::TableFailure)?;
    if leaf&P!=0{return Err(Error::AlreadyMapped);}
    Ok(())
}
fn write_leaf<T:TableStore>(
    t:&mut T,va:u64,pa:u64,rights:Rights,
)->Result<(),Error>{
    if pa==0 || pa&!ADDR!=0{return Err(Error::WrongFrame);}
    let ix=indices(va);
    let mut table=t.root_table();
    for &i in ix[..3].iter(){
        let entry=t.read_entry(table,i).map_err(|_|Error::TableFailure)?;
        if entry&P==0{
            let child=t.allocate_zeroed_table().map_err(|_|Error::TableFailure)?;
            if child==0 || child&!ADDR!=0{return Err(Error::WrongFrame);}
            t.write_entry(table,i,child|P|W|
                if rights.user{U}else{0}).map_err(|_|Error::TableFailure)?;
            table=child;
        }else{
            if entry&PS!=0{return Err(Error::TableFailure);}
            if (entry&U!=0)!=rights.user {return Err(Error::Unauthorized);}
            if rights.write && entry&W==0 {return Err(Error::Unauthorized);}
            if rights.execute && entry&NX!=0 {return Err(Error::Unauthorized);}
            table=entry&ADDR;
        }
    }
    let old=t.read_entry(table,ix[3]).map_err(|_|Error::TableFailure)?;
    if old&P!=0{return Err(Error::AlreadyMapped);}
    let mut flags=P;
    if rights.user{flags|=U;}
    if rights.write{flags|=W;}
    if !rights.execute{flags|=NX;}
    t.write_entry(table,ix[3],pa|flags).map_err(|_|Error::TableFailure)
}
fn clear_leaf<T:TableStore>(
    t:&mut T,va:u64,pa:u64,rights:Rights,
)->Result<(),Error>{
    let ix=indices(va);
    let mut table=t.root_table();
    for &i in ix[..3].iter(){
        let e=t.read_entry(table,i).map_err(|_|Error::TableFailure)?;
        if e&P==0{return Err(Error::NotMapped);}
        if e&PS!=0{return Err(Error::TableFailure);}
        if (e&U!=0)!=rights.user{return Err(Error::Unauthorized);}
        table=e&ADDR;
    }
    let entry=t.read_entry(table,ix[3]).map_err(|_|Error::TableFailure)?;
    if entry&P==0{return Err(Error::NotMapped);}
    if entry&ADDR!=pa || (entry&U!=0)!=rights.user ||
       (entry&W!=0)!=rights.write || (entry&NX==0)!=rights.execute {
        return Err(Error::WrongFrame);
    }
    t.write_entry(table,ix[3],0).map_err(|_|Error::TableFailure)
}

/// Software permission walk (not proof of hardware CPL3/#PF). Enforces U/S
/// at EVERY level and write/NX at each level, including high-half ancestors.
pub fn user_can_access<T:TableStore>(
    t:&T,va:u64,write:bool,execute:bool,
)->Result<(),Error>{
    if va==0 || va>MAX_USER_PAGE+FRAME_SIZE-1{return Err(Error::Unauthorized);}
    let ix=indices(va);
    let mut table=t.root_table();
    for &i in ix[..3].iter(){
        let e=t.read_entry(table,i).map_err(|_|Error::TableFailure)?;
        if e&P==0{return Err(Error::NotMapped);}
        if e&PS!=0{return Err(Error::TableFailure);}
        if e&U==0 || (write && e&W==0) || (execute && e&NX!=0) {
            return Err(Error::Unauthorized);
        }
        table=e&ADDR;
    }
    let e=t.read_entry(table,ix[3]).map_err(|_|Error::TableFailure)?;
    if e&P==0{return Err(Error::NotMapped);}
    if e&U==0 || (write && e&W==0) || (execute && e&NX!=0){
        return Err(Error::Unauthorized);
    }
    Ok(())
}

/// Constructs a *new* physical PML4 root for a domain by copying only
/// supervisor high-half root entries. Kernel lower-level tables remain
/// BORROWED/SHARED: 02 must pin old Limine mappings until a deep copy exists.
/// One root is owned per domain, but shared kernel subtrees are not yet owned.
/// Caller supplies an already zeroed owned PML4 root and independently
/// verified source root; use only while both stay protected.
pub fn copy_borrowed_kernel_half<S:TableStore,D:TableStore>(
    source:&S,destination:&mut D,
)->Result<(),Error>{
    if source.root_table()==destination.root_table() {
        return Err(Error::WrongRoot);
    }
    for i in 0..512 {
        let old=destination.read_entry(destination.root_table(),i)
            .map_err(|_|Error::TableFailure)?;
        if old&P!=0{return Err(Error::AlreadyMapped);}
    }
    for i in 256..512 {
        let entry=source.read_entry(source.root_table(),i)
            .map_err(|_|Error::TableFailure)?;
        // U/S=0 on parent is a hard user isolation boundary, even if the
        // inherited lower-level kernel subtree had U=1 from boot firmware.
        let supervisor=entry & !U;
        destination.write_entry(destination.root_table(),i,supervisor)
            .map_err(|_|Error::TableFailure)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::k1_frames::{BootExtent,FramePurpose};
    #[derive(Clone)]
    struct Tables { data:[[u64;512];16],root:u64,next:usize }
    impl Tables {
        fn new(root:usize)->Self {
            Self{data:[[0;512];16],root:root as u64*FRAME_SIZE,next:8}
        }
        fn index(p:u64)->usize{(p/FRAME_SIZE)as usize-1}
    }
    impl TableStore for Tables {
        fn root_table(&self)->u64{self.root}
        fn allocate_zeroed_table(&mut self)->Result<u64,PteFault>{
            if self.next>=16{return Err(PteFault::IoFailure);}
            self.next+=1;
            let frame=self.next as u64*FRAME_SIZE;
            self.data[Self::index(frame)]=[0;512];
            Ok(frame)
        }
        fn read_entry(&self,p:u64,i:usize)->Result<u64,PteFault>{
            self.data.get(Self::index(p)).and_then(|r|r.get(i))
                .copied().ok_or(PteFault::MissingTable)
        }
        fn write_entry(&mut self,p:u64,i:usize,e:u64)->Result<(),PteFault>{
            *self.data.get_mut(Self::index(p)).and_then(|r|r.get_mut(i))
                .ok_or(PteFault::MissingTable)?=e;
            Ok(())
        }
    }
    struct Flush{fail:bool, count:usize}
    impl TlbInvalidate for Flush {
        fn invalidate_sync(&mut self,_:Space,_:u64)->Result<(),()>{
            self.count+=1;
            if self.fail{Err(())}else{Ok(())}
        }
    }
    struct Zero;
    impl crate::k1_frames::FrameZeroer for Zero {
        fn zero_physical_frame(&mut self,_:u64)->Result<(),()>{Ok(())}
    }
    fn scrub(pool:&mut FramePool<2,8>,frame:FrameLease){
        pool.scrub_owned(frame,1,&mut Zero).unwrap();
    }
    fn pool()->FramePool<2,8>{
        FramePool::from_validated_boot(
            &[BootExtent{base:0x1000,length:8*FRAME_SIZE,kind:0}],&[]
        ).unwrap()
    }
    fn space(root:u64)->Space{
        Space::from_trusted_root(root,1,1).unwrap()
    }
    #[test] fn isolated_user_leaf_has_user_nx_write_flags() {
        let mut p=pool();let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut t=Tables::new(1);let s=space(t.root_table());
        let mut m=MapLedger::<4>::new();
        let h=m.map(&mut t,&mut p,s,0x4000,f,1,Rights::USER_RW).unwrap();
        assert_eq!(user_can_access(&t,0x4000,true,false),Ok(()));
        assert_eq!(user_can_access(&t,0x4000,false,true),Err(Error::Unauthorized));
        assert_eq!(p.free(f,1),Err(FrameError::Busy));
        let mut flush=Flush{fail:false,count:0};
        m.retire(&mut t,&mut p,&mut flush,h).unwrap();
        assert_eq!(flush.count,1);
        assert_eq!(user_can_access(&t,0x4000,false,false),Err(Error::NotMapped));
        p.free(f,1).unwrap();
    }
    #[test] fn guard_pages_and_wx_alias_denied() {
        let mut p=pool();let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut t=Tables::new(1);let s=space(t.root_table());
        let mut m=MapLedger::<6>::new();
        let guard=m.reserve_guard(&t,&mut p,s,0x5000).unwrap();
        assert!(matches!(m.map(&mut t,&mut p,s,0x5000,f,1,Rights::USER_RW),
                         Err(Error::AlreadyMapped)));
        let write=m.map(&mut t,&mut p,s,0x6000,f,1,Rights::USER_RW).unwrap();
        assert!(matches!(m.map(&mut t,&mut p,s,0x7000,f,1,Rights::USER_RX),
                         Err(Error::AliasWx)));
        let mut flush=Flush{fail:false,count:0};
        m.retire(&mut t,&mut p,&mut flush,guard).unwrap();
        m.retire(&mut t,&mut p,&mut flush,write).unwrap();
        p.free(f,1).unwrap();
    }
    #[test] fn failed_tlb_ack_keeps_frame_pinned_and_alias_blocked() {
        let mut p=pool();let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut t=Tables::new(1);let s=space(t.root_table());
        let mut m=MapLedger::<4>::new();
        let h=m.map(&mut t,&mut p,s,0x4000,f,1,Rights::USER_RW).unwrap();
        let mut flush=Flush{fail:true,count:0};
        assert_eq!(m.retire(&mut t,&mut p,&mut flush,h),Err(Error::Busy));
        assert_eq!(p.free(f,1),Err(FrameError::Busy));
        assert!(matches!(m.map(&mut t,&mut p,s,0x8000,f,1,Rights::USER_RX),
                         Err(Error::AliasWx)));
        flush.fail=false;
        m.retire(&mut t,&mut p,&mut flush,h).unwrap();
        p.free(f,1).unwrap();
    }
    #[test] fn denies_kernel_mapping_in_user_half_and_user_in_kernel_half() {
        let mut p=pool();let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut t=Tables::new(1);let s=space(t.root_table());
        let mut m=MapLedger::<4>::new();
        assert_eq!(m.map(&mut t,&mut p,s,0x4000,f,1,Rights::KERNEL_RW),
                   Err(Error::InvalidAddress));
        assert_eq!(m.map(&mut t,&mut p,s,0xffff_9000_0000_0000,f,1,Rights::USER_RW),
                   Err(Error::InvalidAddress));
        assert_eq!(m.map(&mut t,&mut p,s,0,f,1,Rights::USER_RW),
                   Err(Error::InvalidAddress));
    }
    #[test] fn page_table_frame_cannot_be_user_payload_and_kernel_guard() {
        let mut p=pool();
        let f=p.allocate(1,FramePurpose::PageTable).unwrap();
        let mut t=Tables::new(1);
        let s=space(t.root_table());
        let mut m=MapLedger::<4>::new();
        assert_eq!(
            m.map(&mut t,&mut p,s,0x4000,f,1,Rights::USER_RW),
            Err(Error::WrongFrame));
        let guard=m.reserve_kernel_guard(&t,&mut p,s,0xffff_9000_0000_0000).unwrap();
        assert_eq!(
            m.map(&mut t,&mut p,s,0xffff_9000_0000_0000,f,1,Rights::KERNEL_RW),
            Err(Error::AlreadyMapped));
        let mut flush=Flush{fail:false,count:0};
        m.retire(&mut t,&mut p,&mut flush,guard).unwrap();
        assert_eq!(flush.count,0);
    }
    #[test] fn clone_only_high_half_and_supervisor_boundary() {
        let mut old=Tables::new(1);
        let mut new=Tables::new(2);
        old.write_entry(old.root_table(),256,0x3000|P|W|U).unwrap();
        old.write_entry(old.root_table(),0,0x4000|P|U).unwrap();
        copy_borrowed_kernel_half(&old,&mut new).unwrap();
        assert_eq!(new.read_entry(new.root_table(),256).unwrap(),0x3000|P|W);
        assert_eq!(new.read_entry(new.root_table(),0).unwrap(),0);
        assert_eq!(copy_borrowed_kernel_half(&old,&mut new),Err(Error::AlreadyMapped));
    }
    #[test]
    fn qa011_global_guard_denies_second_ledger_and_changed_generation() {
        let mut p=pool();
        let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut t=Tables::new(1);
        let s=space(t.root_table());
        let mut first=MapLedger::<4>::new();
        let mut second=MapLedger::<4>::new();
        let guard=first.reserve_guard(&t,&mut p,s,0x5000).unwrap();
        assert_eq!(
            second.map(&mut t,&mut p,s,0x5000,f,1,Rights::USER_RW),
            Err(Error::AlreadyMapped));
        let forged=Space::from_trusted_root(t.root_table(),1,99).unwrap();
        assert_eq!(
            second.map(&mut t,&mut p,forged,0x5000,f,1,Rights::USER_RW),
            Err(Error::AlreadyMapped));
        assert_eq!(walk_leaf(&t,0x5000),Ok(None));
        let mut flush=Flush{fail:false,count:0};
        first.retire(&mut t,&mut p,&mut flush,guard).unwrap();
        assert_eq!(flush.count,0);
    }
    #[test]
    fn qa008_global_pfn_wx_across_different_cr3_roots() {
        let mut p=pool();
        let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut a=Tables::new(1);
        let mut b=Tables::new(2);
        let sa=space(a.root_table());
        let sb=Space::from_trusted_root(b.root_table(),2,1).unwrap();
        let mut first=MapLedger::<4>::new();
        let mut second=MapLedger::<4>::new();
        let writable=first.map(&mut a,&mut p,sa,0x4000,f,1,Rights::USER_RW).unwrap();
        assert_eq!(
            second.map(&mut b,&mut p,sb,0x8000,f,1,Rights::USER_RX),
            Err(Error::AliasWx));
        let mut flush=Flush{fail:false,count:0};
        assert_eq!(second.retire(&mut b,&mut p,&mut flush,writable),Err(Error::Stale));
        first.retire(&mut a,&mut p,&mut flush,writable).unwrap();
        let executable=second.map(&mut b,&mut p,sb,0x8000,f,1,Rights::USER_RX).unwrap();
        second.retire(&mut b,&mut p,&mut flush,executable).unwrap();
        p.free(f,1).unwrap();
    }
    #[test]
    fn qa008_ancestor_write_bit_restricts_effective_permissions() {
        let mut p=pool();
        let first=p.allocate(1,FramePurpose::Data).unwrap();
        let second=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,first);
        scrub(&mut p,second);
        let mut t=Tables::new(1);
        let s=space(t.root_table());
        let mut manager=MapLedger::<4>::new();
        manager.map(&mut t,&mut p,s,0x4000,first,1,Rights::USER_RX).unwrap();
        let index=indices(0x4000)[0];
        let parent=t.read_entry(t.root_table(),index).unwrap();
        t.write_entry(t.root_table(),index,parent & !W).unwrap();
        assert_eq!(
            manager.map(&mut t,&mut p,s,0x8000,second,1,Rights::USER_RW),
            Err(Error::Unauthorized));
        assert_eq!(user_can_access(&t,0x4000,true,false),Err(Error::Unauthorized));
        // Denied ancestor permission is determined before any PTE mutation.
        // It must not leak/quarantine a healthy data frame.
        p.free(second,1).unwrap();
    }
    struct WriteThenError {
        inner:Tables,
        fired:bool,
    }
    impl TableStore for WriteThenError {
        fn root_table(&self)->u64{self.inner.root_table()}
        fn allocate_zeroed_table(&mut self)->Result<u64,PteFault>{
            self.inner.allocate_zeroed_table()
        }
        fn read_entry(&self,p:u64,i:usize)->Result<u64,PteFault>{
            self.inner.read_entry(p,i)
        }
        fn write_entry(&mut self,p:u64,i:usize,e:u64)->Result<(),PteFault>{
            self.inner.write_entry(p,i,e)?;
            // Injector: commit a writable user leaf, then report an error.
            if !self.fired && e & (P|U|W|NX)==(P|U|W|NX) {
                self.fired=true;
                return Err(PteFault::IoFailure);
            }
            Ok(())
        }
    }
    #[test]
    fn qa011_partial_present_pte_error_quarantines_root_and_frame() {
        let mut p=pool();
        let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut t=WriteThenError{inner:Tables::new(1),fired:false};
        let s=space(t.root_table());
        let mut a=MapLedger::<4>::new();
        let mut b=MapLedger::<4>::new();
        assert_eq!(
            a.map(&mut t,&mut p,s,0x4000,f,1,Rights::USER_RW),
            Err(Error::TableFailure));
        assert!(t.fired);
        assert!(walk_leaf(&t,0x4000).unwrap().is_some());
        assert_eq!(
            b.map(&mut t,&mut p,s,0x8000,f,1,Rights::USER_RX),
            Err(Error::Frames(FrameError::RootQuarantined)));
        let mut other=Tables::new(2);
        let other_space=Space::from_trusted_root(other.root_table(),2,1).unwrap();
        assert_eq!(
            b.map(&mut other,&mut p,other_space,0x8000,f,1,Rights::USER_RX),
            Err(Error::Frames(FrameError::Quarantined)));
        assert_eq!(p.free(f,1),Err(FrameError::Busy));
    }
    struct BorrowedTableView<'a> {
        storage:&'a core::cell::RefCell<[[u64;512];8]>,
        root:u64,
    }
    impl TableStore for BorrowedTableView<'_> {
        fn root_table(&self)->u64{self.root}
        fn allocate_zeroed_table(&mut self)->Result<u64,PteFault>{
            Err(PteFault::IoFailure)
        }
        fn read_entry(&self,pa:u64,n:usize)->Result<u64,PteFault>{
            self.storage.borrow()
                .get((pa/FRAME_SIZE) as usize-1)
                .and_then(|t|t.get(n)).copied()
                .ok_or(PteFault::MissingTable)
        }
        fn write_entry(&mut self,pa:u64,n:usize,e:u64)->Result<(),PteFault>{
            *self.storage.borrow_mut()
                .get_mut((pa/FRAME_SIZE) as usize-1)
                .and_then(|t|t.get_mut(n))
                .ok_or(PteFault::MissingTable)?=e;
            Ok(())
        }
    }
    #[test]
    fn qa011_borrowed_limine_descendants_are_immutable() {
        let storage=core::cell::RefCell::new([[0u64;512];8]);
        let mut old=BorrowedTableView{storage:&storage,root:FRAME_SIZE};
        let mut new=BorrowedTableView{storage:&storage,root:2*FRAME_SIZE};
        let va=0xffff_8000_0000_1000;
        let ix=indices(va);
        old.write_entry(FRAME_SIZE,ix[0],3*FRAME_SIZE|P|W).unwrap();
        old.write_entry(3*FRAME_SIZE,ix[1],4*FRAME_SIZE|P|W).unwrap();
        old.write_entry(4*FRAME_SIZE,ix[2],5*FRAME_SIZE|P|W).unwrap();
        copy_borrowed_kernel_half(&old,&mut new).unwrap();
        let mut p=pool();
        let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let s=Space::from_trusted_root(2*FRAME_SIZE,2,1).unwrap();
        let mut ledger=MapLedger::<4>::new();
        assert_eq!(
            ledger.map(&mut new,&mut p,s,va,f,1,Rights::KERNEL_RW),
            Err(Error::Unauthorized));
        assert_eq!(old.read_entry(5*FRAME_SIZE,ix[3]),Ok(0));
        assert_eq!(new.read_entry(5*FRAME_SIZE,ix[3]),Ok(0));
    }
    #[test]
    fn qa011_unscrubbed_cross_owner_frame_is_not_exposed() {
        let mut p=pool();
        let old=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,old);
        p.free(old,1).unwrap();
        let fresh=p.allocate(2,FramePurpose::Data).unwrap();
        assert_eq!(p.physical(fresh,2),Ok(0x1000));
        let mut t=Tables::new(1);
        let s=space(t.root_table());
        let mut ledger=MapLedger::<4>::new();
        assert_eq!(
            ledger.map(&mut t,&mut p,s,0x4000,fresh,2,Rights::USER_RW),
            Err(Error::Frames(FrameError::Unscrubbed)));
        assert_eq!(walk_leaf(&t,0x4000),Ok(None));
        p.scrub_owned(fresh,2,&mut Zero).unwrap();
        assert!(ledger.map(&mut t,&mut p,s,0x4000,fresh,2,Rights::USER_RW).is_ok());
    }

    #[test]
    fn qa011_foreign_stale_claim_handle_does_not_retire_new_ledger() {
        let mut p=pool();
        let f=p.allocate(1,FramePurpose::Data).unwrap();
        scrub(&mut p,f);
        let mut t=Tables::new(1);
        let s=space(t.root_table());
        let mut a=MapLedger::<4>::new();
        let mut b=MapLedger::<4>::new();
        let old=a.map(&mut t,&mut p,s,0x4000,f,1,Rights::USER_RW).unwrap();
        let mut flush=Flush{fail:false,count:0};
        a.retire(&mut t,&mut p,&mut flush,old).unwrap();
        let new=b.map(&mut t,&mut p,s,0x4000,f,1,Rights::USER_RW).unwrap();
        assert_ne!(old,new);
        assert_eq!(b.retire(&mut t,&mut p,&mut flush,old),Err(Error::Stale));
        assert!(walk_leaf(&t,0x4000).unwrap().is_some());
        b.retire(&mut t,&mut p,&mut flush,new).unwrap();
        p.free(f,1).unwrap();
    }

}
