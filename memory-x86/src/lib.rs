#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
//! Experimental *privileged* x86-64 backend for MEMORY 04.
//!
//! This is UNSAFE TCB code, unlike the no_std safe memory-model crate.
//! It can perform actual volatile writes to the active page-table memory,
//! actual volatile MMIO loads and an INVLPG on the local CPU, when connected
//! to a boot-validated HHDM and a genuine privileged SMP shootdown service.
//!
//! No PCI inventory / DMA-remap / VT-d root/context / DMAR / IRQ is installed.
//! These constructors must not be used until reviewed memory and CPU contracts
//! exist. An all-CPU ack is a *caller supplied* trusted service, not fabricated.

#[cfg(target_arch="x86_64")]
pub mod k1;

#[cfg(target_arch="x86_64")]
pub mod x86 {
    use core::arch::asm;
    use core::ptr::{read_volatile, write_volatile};
    use core::sync::atomic::{fence, Ordering};
    use fortress_memory_model::page_tables::{CpuAccess, Fault, TableStore};
    use fortress_memory_model::revocable_mmio::BarSpec;
    const FRAME: u64 = 4096;
    const ADDR: u64 = 0x000f_ffff_ffff_f000;


    /// Real privileged data-frame scrubber. Access is tied to an independently
    /// verified HHDM and exclusive PMM-owned RAM, never to arbitrary device BARs.
    /// CPU cache coherency and cross-core sharing are an ARCH integration gate.
    pub struct HhdmFrameZeroer { offset: u64 }
    impl HhdmFrameZeroer {
        /// # Safety
        /// Only ring0 may construct this. HHDM must cover every physical
        /// frame passed to zero_physical_frame, and the PMM must prove it is
        /// exclusively owned RAM, not borrowed Limine or MMIO.
        pub unsafe fn new(validated_hhdm:u64)->Result<Self,()>{
            if validated_hhdm<0xffff_8000_0000_0000 ||
               validated_hhdm & (FRAME-1)!=0 {return Err(());}
            Ok(Self{offset:validated_hhdm})
        }
    }
    impl fortress_memory_model::k1_frames::FrameZeroer for HhdmFrameZeroer {
        fn zero_physical_frame(&mut self, phys:u64)->Result<(),()>{
            if phys==0 || phys&(FRAME-1)!=0{return Err(());}
            let va=self.offset.checked_add(phys).ok_or(())?;
            if va<0xffff_8000_0000_0000 ||
               va.checked_add(FRAME-1).is_none() {return Err(());}
            for index in 0..512usize {
                // SAFETY: the caller constructed this under validated
                // ring0 HHDM+exclusive PMM ownership preconditions.
                unsafe{write_volatile((va as *mut u64).add(index),0);}
            }
            fence(Ordering::SeqCst);
            Ok(())
        }
    }

    /// A privileged PMM service must return exclusively owned, zeroable
    /// physical table frames, never borrowed boot/firmware or device pages.
    pub trait PageFrameAllocator {
        fn allocate_owned_table_frame(&mut self) -> Result<u64, Fault>;
    }

    pub struct DirectMappedTableStore<A> {
        root_phys: u64,
        hhdm_base: u64,
        alloc: A,
    }

    impl<A:PageFrameAllocator> DirectMappedTableStore<A> {
        /// # Safety
        /// Caller guarantees: ring0; root_phys is 4KiB-aligned, owned and
        /// correct for the intended current CR3 address space; every page-table
        /// frame returned by allocator is mapped RW at hhdm_base+phys;
        /// HHDM covers full 4KiB pages and has stable mapping/lifetime;
        /// no concurrent PTE writers exist; frame metadata/PAT verified.
        /// THIS DOES NOT validate bootstrap paging or create a safe HHDM.
        pub unsafe fn new(root_phys:u64,hhdm_base:u64,alloc:A)->Result<Self,Fault>{
            if root_phys & !ADDR != 0 || root_phys == 0 ||
               hhdm_base < 0xffff_8000_0000_0000 {
                return Err(Fault::OutOfPhysicalRange);
            }
            Ok(Self {root_phys,hhdm_base,alloc})
        }
        fn ptr_for(&self, table:u64, index:usize)->Result<*mut u64,Fault>{
            if table & !ADDR != 0 || index>=512 {return Err(Fault::OutOfPhysicalRange);}
            let addr=self.hhdm_base.checked_add(table).ok_or(Fault::OutOfPhysicalRange)?
                .checked_add((index as u64)*8).ok_or(Fault::OutOfPhysicalRange)?;
            if addr<0xffff_8000_0000_0000{return Err(Fault::OutOfPhysicalRange);}
            Ok(addr as *mut u64)
        }
    }

    impl<A:PageFrameAllocator> TableStore for DirectMappedTableStore<A> {
        fn root_table(&self)->u64{self.root_phys}
        fn allocate_zeroed_table(&mut self)->Result<u64,Fault>{
            let p=self.alloc.allocate_owned_table_frame()?;
            if p==0||p&!ADDR !=0{return Err(Fault::OutOfPhysicalRange);}
            // This is a real 4KiB zeroing pass via verified HHDM.
            // Safe only under the unsafe constructor's caller obligations.
            for n in 0..512 {
                let ptr=self.ptr_for(p,n)?;
                // SAFETY: constructor contract promises owned mapped table page.
                unsafe{write_volatile(ptr,0);}
            }
            fence(Ordering::SeqCst);
            Ok(p)
        }
        fn read_entry(&self,table:u64,index:usize)->Result<u64,Fault>{
            let ptr=self.ptr_for(table,index)?;
            // SAFETY: validated under unsafe constructor and caller lock.
            Ok(unsafe{read_volatile(ptr)})
        }
        fn write_entry(&mut self,table:u64,index:usize,entry:u64)->Result<(),Fault>{
            let ptr=self.ptr_for(table,index)?;
            // SAFETY: validated under unsafe constructor and caller lock.
            unsafe{write_volatile(ptr,entry);}
            fence(Ordering::SeqCst);
            Ok(())
        }
    }

    /// 03 ARCH must provide synchronous per-CPU, ASID/PCID/global translation
    /// invalidation. Return Ok only after every affected CPU completes.
    pub trait SmpShootdown {
        fn shootdown_all_affected_cpus(&mut self,va:u64,len:u64)->Result<(),()>;
        /// Must check IA32_PAT MSR index3 maps to UC on ALL participating CPUs.
        fn verified_pat_index3_uc_on_all_cpus(&self)->bool;
        fn verified_efer_nxe_on_all_cpus(&self)->bool;
        /// Live authoritative PCI grant check, never copied BAR metadata.
        fn pci_grant_current(&self, spec: BarSpec)->bool;
    }
    pub struct PrivilegedCpuAccess<S> { smp:S }
    impl<S:SmpShootdown> PrivilegedCpuAccess<S> {
        /// # Safety
        /// Must run only in ring0 with a protected SMP shootdown implementation,
        /// with all MMIO BAR mappings owned exclusively by the MEMORY broker.
        pub unsafe fn new(smp:S)->Self{Self{smp}}
    }
    impl<S:SmpShootdown> CpuAccess for PrivilegedCpuAccess<S> {
        fn pat_index3_is_uc(&self)->bool{
            self.smp.verified_pat_index3_uc_on_all_cpus()
        }
        fn nxe_verified(&self)->bool{
            self.smp.verified_efer_nxe_on_all_cpus()
        }
        fn pci_grant_current(&self,spec:BarSpec)->bool{
            self.smp.pci_grant_current(spec)
        }
        fn shootdown_all_cpus(&mut self,va:u64,len:u64)->Result<(),()>{
            if va % FRAME != 0 || len == 0 || len % FRAME != 0{return Err(());}
            let end=va.checked_add(len).ok_or(())?;
            // Caller must rendezvous with ALL remote users, not just local CPU.
            self.smp.shootdown_all_affected_cpus(va,len)?;
            let mut p=va;
            while p<end {
                // SAFETY: this type must be initialized at CPL0.
                unsafe{asm!("invlpg [{ptr}]",ptr=in(reg)p,options(nostack,preserves_flags));}
                p=p.checked_add(FRAME).ok_or(())?;
            }
            fence(Ordering::SeqCst);
            Ok(())
        }
        fn volatile_read_u32(&mut self,va:u64)->Result<u32,()>{
            if va<0xffff_8000_0000_0000 || va%4!=0 {return Err(());}
            let ptr=va as *const u32;
            // SAFETY: broker contract must ensure live UC/NX mapped BAR, backed
            // by a trusted resource owner, with no concurrent revocation.
            Ok(unsafe{read_volatile(ptr)})
        }
    }
}
