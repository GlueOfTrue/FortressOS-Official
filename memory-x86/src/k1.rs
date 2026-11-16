//! K1 single-vCPU x86-64 CR3 bring-up. REAL privileged instructions,
//! NOT executed in host tests. Ownership proofs are caller obligations.
//! There is NO safe SMP or PCID implementation in this module yet.
//!
//! Bootstrap stage clones only the high-half PML4 entries from Limine's
//! borrowed CR3 and masks U/S in each PML4E. Lower-level kernel tables remain
//! BORROWED; reclaiming them or switching their cache permissions is forbidden
//! until 02 and 03 explicitly transfer ownership and validate all aliases.

use core::arch::asm;
use core::ptr::{write_volatile};
use core::sync::atomic::{fence,Ordering};
use fortress_memory_model::k1_frames::{FramePool,FramePurpose,Error as AllocError};
use fortress_memory_model::k1_paging::{self,Error as MapError,Space};
use fortress_memory_model::page_tables::{TableStore,Fault};
use crate::x86::{DirectMappedTableStore,PageFrameAllocator};

const ADDR:u64=0x000f_ffff_ffff_f000;
const PAGE:u64=4096;
const CR4_LA57:u64=1<<12;
const CR4_PCIDE:u64=1<<17;
const CR4_PGE:u64=1<<7;
const EFER:u32=0xc000_0080;
const EFER_NXE:u64=1<<11;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum K1Error {
    InvalidRoot, UnsupportedCpuMode, BadHhdm,
    Alloc(AllocError), Tables(Fault), Mapping(MapError),
    SmpNotReady,
}
impl<T:PageFrameAllocator+?Sized> PageFrameAllocator for &mut T {
    fn allocate_owned_table_frame(&mut self)->Result<u64,Fault>{
        (**self).allocate_owned_table_frame()
    }
}
pub struct PmmTableFrames<'a,const R:usize,const L:usize> {
    pool:&'a mut FramePool<R,L>,
    owner:u64,
}
impl<'a,const R:usize,const L:usize> PmmTableFrames<'a,R,L> {
    pub fn new(pool:&'a mut FramePool<R,L>,owner:u64)->Result<Self,K1Error>{
        if owner==0 {return Err(K1Error::Alloc(AllocError::InvalidOwner));}
        Ok(Self{pool,owner})
    }
}
impl<const R:usize,const L:usize> PageFrameAllocator for PmmTableFrames<'_,R,L>{
    fn allocate_owned_table_frame(&mut self)->Result<u64,Fault>{
        // No release function: table frames are held by this bootstrap
        // allocator for the lifetime of the CR3 they back.
        let f=self.pool.allocate(self.owner,FramePurpose::PageTable)
            .map_err(|_|Fault::IoFailure)?;
        self.pool.physical(f,self.owner).map_err(|_|Fault::IoFailure)
    }
}
struct RejectAllocator;
impl PageFrameAllocator for RejectAllocator {
    fn allocate_owned_table_frame(&mut self)->Result<u64,Fault>{
        Err(Fault::IoFailure)
    }
}

/// Actual live CPU CR3, not a simulated value.
///
/// # Safety
/// Ring 0 only, interrupts/quiescence per ARCH, x86-64 long mode.
pub unsafe fn read_cr3_physical()->u64{
    let cr3:u64;
    // SAFETY: the caller is CPL0.
    unsafe{asm!("mov {}, cr3",out(reg) cr3,options(nomem,nostack,preserves_flags));}
    cr3&ADDR
}
/// Reads CPU mode bits and EFER.NXE from hardware.
///
/// # Safety
/// Ring 0 only, supported x86-64 model, and no concurrent MSR changes.
pub unsafe fn basic_cpu_mode_ok()->bool{
    let cr4:u64;
    let eax:u32;
    let edx:u32;
    // SAFETY: privileged registers, only within caller-proven CPL0.
    unsafe {
        asm!("mov {}, cr4",out(reg) cr4,options(nomem,nostack,preserves_flags));
        asm!("rdmsr",in("ecx") EFER,out("eax") eax,out("edx") edx,
             options(nomem,nostack,preserves_flags));
    }
    let efer=((edx as u64)<<32)|(eax as u64);
    cr4 & (CR4_LA57|CR4_PCIDE|CR4_PGE)==0 && efer&EFER_NXE!=0
}

/// Own 4096-byte root, initialized by writing actual HHDM memory. The
/// returned root is NOT active; constructing it doesn't prove boot safety.
///
/// # Safety
/// BootInfoV0 has been validated; HHDM covers every PMM page; this frame is
/// exclusively owned, currently mapped writable, RAM not MMIO, and CPU is
/// in CPL0. Caller serializes the allocator.
pub unsafe fn allocate_zeroed_root<A:PageFrameAllocator>(
    allocator:&mut A,hhdm:u64,
)->Result<u64,K1Error>{
    if hhdm<0xffff_8000_0000_0000{return Err(K1Error::BadHhdm);}
    let root=allocator.allocate_owned_table_frame().map_err(K1Error::Tables)?;
    if root==0 || root&!ADDR!=0{return Err(K1Error::InvalidRoot);}
    let virtual_root=hhdm.checked_add(root).ok_or(K1Error::BadHhdm)?;
    if virtual_root<0xffff_8000_0000_0000 ||
       virtual_root.checked_add(PAGE-1).is_none() {
        return Err(K1Error::BadHhdm);
    }
    for i in 0..512usize {
        // SAFETY: caller guarantees this entire RAM page is HHDM writable.
        unsafe{write_volatile((virtual_root as *mut u64).add(i),0);}
    }
    fence(Ordering::SeqCst);
    Ok(root)
}

/// Build a domain root backed by a unique PMM-allocated physical PML4, but
/// keep bootloader lower-level kernel tables borrowed and pinned.
///
/// # Safety
/// source_cr3 is a validated, currently live CPL0 root; no concurrent source
/// PTE writers; both physical roots are reachable through stable validated
/// HHDM; allocator is the unique PMM owner. Caller must retain old Limine
/// page tables (and GDT/IDT, stacks and boot dependencies) while any clone
/// refers to them. No use on LA57/PCID/PGE system.
pub unsafe fn build_bootstrap_domain_root<A:PageFrameAllocator>(
    allocator:&mut A,hhdm:u64,source_cr3:u64,
    identity:u64,generation:u64,
)->Result<Space,K1Error>{
    // SAFETY: validated CPU state and caller's ring0 guarantee.
    if !unsafe{basic_cpu_mode_ok()} {return Err(K1Error::UnsupportedCpuMode);}
    if source_cr3==0 || source_cr3&!ADDR!=0{return Err(K1Error::InvalidRoot);}
    // SAFETY: caller-owned HHDM root and allocator.
    let newroot=unsafe{allocate_zeroed_root(allocator,hhdm)}?;
    // SAFETY: both stores map stable page-table RAM and do not overlap roots.
    let source=unsafe{DirectMappedTableStore::new(
        source_cr3,hhdm,RejectAllocator
    )}.map_err(K1Error::Tables)?;
    let mut dest=unsafe{DirectMappedTableStore::new(
        newroot,hhdm,allocator
    )}.map_err(K1Error::Tables)?;
    k1_paging::copy_borrowed_kernel_half(&source,&mut dest)
        .map_err(K1Error::Mapping)?;
    Space::from_trusted_root(newroot,identity,generation).map_err(K1Error::Mapping)
}

/// Switch to a *specific* physically real page-table root. CR3 write flushes
/// nonglobal translations on this CPU when PCIDE=0. For 03/04 single-CPU K1
/// ONLY. CR4.PGE/PCIDE and LA57 MUST be disabled, EFER.NXE enabled.
/// Cross-CPU retirement remains intentionally unsupported.
///
/// # Safety
/// Current thread, stack, kernel text, IDT/GDT/TSS, framebuffer diagnostic
/// and HHDM are present in newroot at compatible addresses and permissions;
/// parent Limine tables are pinned; interrupts are disabled; caller has
/// independently established this VM is one-vCPU. Invalid root can triple
/// fault immediately; never invoke on physical user machine by default.
pub unsafe fn activate_single_cpu_root(
    space:Space,verified_single_cpu:bool,
)->Result<u64,K1Error>{
    if !verified_single_cpu {return Err(K1Error::SmpNotReady);}
    // SAFETY: ring0 CPU state established by the caller.
    if !unsafe{basic_cpu_mode_ok()} {return Err(K1Error::UnsupportedCpuMode);}
    let root=space.root_physical();
    if root==0 || root&!ADDR!=0{return Err(K1Error::InvalidRoot);}
    let before=unsafe{read_cr3_physical()};
    fence(Ordering::SeqCst);
    // SAFETY: caller guarantees all currently executing kernel mappings
    // survive in this physical PML4; CPU is in CPL0.
    unsafe{asm!("mov cr3, {}",in(reg) root,options(nostack,preserves_flags));}
    fence(Ordering::SeqCst);
    Ok(before)
}
