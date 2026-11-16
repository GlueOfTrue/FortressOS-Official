//! Experimental K1 guest path adapted from BUILD 01's pinned integration.
//! The fixture links BOOT, ARCH and MEMORY in the integrated source tree.
//! Single vCPU, IF=0, PCID/PGE/LA57 disabled; Limine subtrees remain pinned.
//! Checks a real root switch, local invalidation and terminal CPL0 #PF.
//! CPL3 permissions and SMP shootdown are outside its scope.
use core::{arch::{asm,global_asm},ptr::addr_of,sync::atomic::{fence,Ordering}};
use fortress_arch_x86_entry::{
    install_boot_cpu,snapshot_cpu,
    traps::{install_terminal_reporter,terminal_stub_address,read_cr2,TerminalTrapHead},
    TrapTargets,KERNEL_CS,TSS_SELECTOR,
};
use fortress_memory_model::{
    k1_frames::FramePurpose,
    k1_paging::{self,MapLedger,Rights,Space,TlbInvalidate,Error as MapError},
    page_tables::{TableStore,Fault},
};
use fortress_memory_x86::{
    k1::{self,build_bootstrap_domain_root,activate_single_cpu_root},
    x86::{DirectMappedTableStore,HhdmFrameZeroer,PageFrameAllocator},
};
use crate::bootinfo::BootInfoV0;

const OWNER:u64=0x4b31;
const RW:u64=0x0000_0000_4000_1000;
const RX:u64=0x0000_0000_4000_2000;
const GUARD:u64=0x0000_0000_4000_0000;
const PRESENT:u64=1;
const WRITABLE:u64=2;
const USER:u64=4;
const NO_EXEC:u64=1<<63;
const ADDR:u64=0x000f_ffff_ffff_f000;
const RSP0_BYTES:usize=16*1024;

#[repr(align(16))]
struct Stack([u8;RSP0_BYTES]);
static mut RSP0:Stack=Stack([0;RSP0_BYTES]);

fn die(msg:&str)->! {
    crate::serial::log(format_args!("FORTRESS_K1_FAIL {}\n",msg));
    crate::fortress_g1_debug_exit(0x11);
    crate::halt()
}

// IDT entry has a hardware frame and no Rust call ABI. No stack or
// registers need restoring because this unexpected path always terminates.
global_asm!(
    r#"
    .section .text.k1_fallback,"ax"
    .global fortress_k1_external_fallback
fortress_k1_external_fallback:
    mov dx, 0xf4
    mov al, 0x12
    out dx, al
1:  cli
    hlt
    jmp 1b
    "#,
);

extern "C" {
    fn fortress_k1_external_fallback();
}

extern "C" fn report(frame:*const TerminalTrapHead)->! {
    // SAFETY: ARCH hands off a normalized terminal trap head from the live IDT.
    let frame=unsafe{frame.read()};
    // SAFETY: terminal ring0 #PF context, CR2 read before logging.
    let cr2=unsafe{read_cr2()};
    // SAFETY: CPL0 and same boot CPU while IF=0.
    let cr3=unsafe{k1::read_cr3_physical()};
    crate::serial::log(format_args!(
        "FORTRESS_K1_PF vector={} error={} cr2={:#x} cpl={} cr3={:#x}\n",
        frame.vector,frame.error,cr2,frame.cs&3,cr3
    ));
    if frame.vector!=14 || frame.error!=0 || frame.cs&3!=0 || cr2!=RW ||
       cr3==0 || cr3!=unsafe{K1_EXPECTED_ROOT} {
        die("WRONG_PAGE_FAULT");
    }
    crate::serial::line("FORTRESS_K1_TERMINAL_REJECT_OK");
    crate::fortress_g1_debug_exit(0x11);
    crate::halt()
}

// Published before intentional fault; read only from the terminal reporter.
static mut K1_EXPECTED_ROOT:u64=0;

struct Queue {pa:[u64;12],len:usize,next:usize}
impl Queue {
    fn new()->Self {Self{pa:[0;12],len:0,next:0}}
    fn push(&mut self,p:u64){
        if self.len==self.pa.len(){die("TABLE_QUEUE_FULL");}
        self.pa[self.len]=p;
        self.len+=1;
    }
}
impl PageFrameAllocator for Queue {
    fn allocate_owned_table_frame(&mut self)->Result<u64,Fault>{
        if self.next>=self.len {return Err(Fault::IoFailure);}
        let p=self.pa[self.next];
        self.next+=1;
        Ok(p)
    }
}
fn leaf<T:TableStore>(t:&T,va:u64)->u64{
    let mut pt=t.root_table();
    for shift in [39u32,30,21] {
        let idx=((va>>shift)&511)as usize;
        let entry=t.read_entry(pt,idx).unwrap_or_else(|_|die("TABLE_READ_FAILED"));
        if entry&PRESENT==0 || entry&(1<<7)!=0{die("MISSING_ANCESTOR");}
        pt=entry&ADDR;
    }
    t.read_entry(pt,((va>>12)&511)as usize)
        .unwrap_or_else(|_|die("LEAF_READ_FAILED"))
}

struct LocalInvalidate {performed:bool, root:u64}
impl TlbInvalidate for LocalInvalidate {
    fn invalidate_sync(&mut self,space:Space,va:u64)->Result<(),()> {
        if va!=RW || space.root_physical()!=self.root || self.performed {
            return Err(());
        }
        // SAFETY: ring0 single CPU, no PCID/PGE, no remote tasks/cpus;
        // preflight confirms live physical CR3 matches the exact Space root.
        if unsafe{k1::read_cr3_physical()}!=self.root{return Err(());}
        fence(Ordering::SeqCst);
        unsafe{asm!("invlpg [{page}]",page=in(reg)va,options(nostack,preserves_flags));}
        fence(Ordering::SeqCst);
        self.performed=true;
        Ok(())
    }
}
fn install_arch(){
    let mut exceptions=[0u64;32];
    for (slot,handler) in exceptions.iter_mut().zip(crate::exceptions::handler_addresses()){
        *slot=handler;
    }
    for vector in [6u8,8,13,14]{
        exceptions[vector as usize]=terminal_stub_address(vector)
            .unwrap_or_else(||die("MISSING_ARCH_EXCEPTION_STUB"));
    }
    let targets=TrapTargets{exceptions,
        external_fallback:fortress_k1_external_fallback as usize as u64};
    // SAFETY: validated one-vCPU QEMU test with IF=0, dedicated pinned BSS
    // RSP0 and shared borrowed high-half kernel mappings kept until halt.
    unsafe {
        let before=snapshot_cpu();
        if !install_terminal_reporter(report){die("ARCH_REPORTER_ALREADY_USED");}
        let base=addr_of!(RSP0.0)as u64;
        if install_boot_cpu(base+RSP0_BYTES as u64,targets).is_err(){
            die("ARCH_INSTALL_REJECT");
        }
        let after=snapshot_cpu();
        if !after.owned_tables || before.owned_tables ||
           after.cs!=KERNEL_CS || after.tr!=TSS_SELECTOR ||
           before.idt_base==after.idt_base || after.cr3!=before.cr3 {
            die("ARCH_HARDWARE_READBACK_FAILED");
        }
        crate::serial::log(format_args!(
            "FORTRESS_K1_ARCH cs={} tr={} idt={:#x} cr3={:#x}\n",
            after.cs,after.tr,after.idt_base,after.cr3
        ));
    }
}

pub fn run(info:&'static BootInfoV0)->!{
    install_arch();
    let mut pool = crate::boot_memory::frame_pool::<32>(info)
        .unwrap_or_else(|_|die("PMM_ADOPTION_FAILED"));
    let mut queue=Queue::new();
    for _ in 0..9 {
        let frame=pool.allocate(OWNER,FramePurpose::PageTable)
            .unwrap_or_else(|_|die("TABLE_FRAME_UNAVAILABLE"));
        queue.push(pool.physical(frame,OWNER)
            .unwrap_or_else(|_|die("TABLE_FRAME_NOT_OWNED")));
    }
    let before=unsafe{k1::read_cr3_physical()};
    if !unsafe{k1::basic_cpu_mode_ok()} {die("UNSUPPORTED_LIMINE_CPU_MODE");}
    let space=unsafe{
        build_bootstrap_domain_root(&mut queue,info.hhdm_offset,before,1,1)
    }.unwrap_or_else(|_|die("OWNED_PML4_BUILD_FAILED"));
    if space.root_physical()==before{die("CR3_NOT_NEW");}
    let mut tables=unsafe{
        DirectMappedTableStore::new(space.root_physical(),info.hhdm_offset,&mut queue)
    }.unwrap_or_else(|_|die("OWNED_TABLE_STORE_FAILED"));
    // Verify all borrowed kernel PML4 mappings remained supervisor-only.
    let mut inherited=0usize;
    for i in 256..512 {
        let entry=tables.read_entry(space.root_physical(),i)
            .unwrap_or_else(|_|die("KERNEL_PML4_READ_FAILED"));
        if entry&PRESENT!=0 {
            inherited+=1;
            if entry&USER!=0 {die("KERNEL_HALF_USER_BIT");}
        }
    }
    if inherited==0{die("NO_BORROWED_KERNEL_HALF");}
    let mut zeroer=unsafe{HhdmFrameZeroer::new(info.hhdm_offset)}
        .unwrap_or_else(|_|die("HHDM_ZEROER_UNAVAILABLE"));
    let rw=pool.allocate(OWNER,FramePurpose::Data)
        .unwrap_or_else(|_|die("NO_RW_DATA"));
    pool.scrub_owned(rw,OWNER,&mut zeroer)
        .unwrap_or_else(|_|die("RW_NOT_SCRUBBED"));
    let rx=pool.allocate(OWNER,FramePurpose::Data)
        .unwrap_or_else(|_|die("NO_RX_DATA"));
    pool.scrub_owned(rx,OWNER,&mut zeroer)
        .unwrap_or_else(|_|die("RX_NOT_SCRUBBED"));
    let mut ledger=MapLedger::<8>::new();
    ledger.reserve_guard(&tables,&mut pool,space,GUARD)
        .unwrap_or_else(|_|die("GUARD_RESERVE_FAILED"));
    let rw_map=ledger.map(&mut tables,&mut pool,space,RW,rw,OWNER,Rights::USER_RW)
        .unwrap_or_else(|_|die("RW_MAP_FAILED"));
    ledger.map(&mut tables,&mut pool,space,RX,rx,OWNER,Rights::USER_RX)
        .unwrap_or_else(|_|die("RX_MAP_FAILED"));
    if ledger.map(&mut tables,&mut pool,space,0x4000_3000,rw,OWNER,Rights::USER_RX)
        !=Err(MapError::AliasWx) {
        die("GLOBAL_WX_ALIAS_ACCEPTED");
    }
    let p_rw=leaf(&tables,RW);
    let p_rx=leaf(&tables,RX);
    let p_guard=leaf(&tables,GUARD);
    if p_rw&(PRESENT|WRITABLE|USER|NO_EXEC)!=(PRESENT|WRITABLE|USER|NO_EXEC) ||
       p_rx&(PRESENT|WRITABLE|USER|NO_EXEC)!=(PRESENT|USER) ||
       p_guard&PRESENT!=0 {
        die("ACTUAL_PTE_RIGHTS_MISMATCH");
    }
    if k1_paging::user_can_access(&tables,RW,true,false).is_err() ||
       k1_paging::user_can_access(&tables,RW,false,true).is_ok() ||
       k1_paging::user_can_access(&tables,RX,true,false).is_ok() ||
       k1_paging::user_can_access(&tables,RX,false,true).is_err(){
        die("EFFECTIVE_PERM_WALK_MISMATCH");
    }
    crate::serial::log(format_args!(
        "FORTRESS_K1_PTE_CHECK rw={:#x} rx={:#x} guard={:#x} borrowed={}\n",
        p_rw,p_rx,p_guard,inherited
    ));
    let old=unsafe{activate_single_cpu_root(space,true)}
        .unwrap_or_else(|_|die("CR3_ACTIVATION_FAILED"));
    let after=unsafe{k1::read_cr3_physical()};
    let snap=unsafe{snapshot_cpu()};
    if old!=before || after!=space.root_physical() ||
       (snap.cr3&ADDR)!=after || snap.cs!=KERNEL_CS || snap.tr!=TSS_SELECTOR ||
       !snap.owned_tables {
        die("LIVE_CR3_READBACK_FAILED");
    }
    unsafe{K1_EXPECTED_ROOT=after;}
    crate::serial::log(format_args!(
        "FORTRESS_K1_CR3 old={:#x} new={:#x} cs={} tr={}\n",
        old,after,snap.cs,snap.tr
    ));
    // Hardware read populates the active translation cache, not a fake TableStore.
    let value=unsafe{core::ptr::read_volatile(RW as *const u64)};
    if value!=0{die("FRAME_ZERO_FAIL");}
    crate::serial::line("FORTRESS_K1_HW_READ_ZERO");
    let mut invalidate=LocalInvalidate{performed:false,root:after};
    ledger.retire(&mut tables,&mut pool,&mut invalidate,rw_map)
        .unwrap_or_else(|_|die("ACTUAL_UNMAP_OR_TLB_FAILED"));
    if !invalidate.performed || leaf(&tables,RW)&PRESENT!=0 {
        die("PTE_UNMAP_OR_INVLPG_NOT_OBSERVED");
    }
    crate::serial::log(format_args!(
        "FORTRESS_K1_INVLPG_DONE cr3={:#x} va={:#x} leaf={:#x}\n",
        after,RW,leaf(&tables,RW)
    ));
    crate::serial::line("FORTRESS_K1_EXPECT_PAGE_FAULT");
    // SAFETY: this is a deliberately invalid supervisor memory read on a
    // disposable one-vCPU QEMU fixture. ARCH #PF must terminate with exit35.
    let _unexpected=unsafe{core::ptr::read_volatile(RW as *const u64)};
    die("STALE_TLB_TRANSLATION_ACCEPTED")
}
