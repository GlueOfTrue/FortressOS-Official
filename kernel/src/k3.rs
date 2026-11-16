//! One-CPU fixture for live process isolation and return to CPL3.
use fortress_cap_ipc::{CapTable, DomainId, ObjectKind, Rights};
use fortress_memory_x86::k1::{activate_single_cpu_root, read_cr3_physical};
use fortress_process::identity::{AddressSpaceId, FaultReason, ProcessTable, RetirementWitness};
use fortressos_scheduler::Scheduler;
use super::{k3_elf::FixtureImage, k3_entry::{self, Active, Observed}, k3_memory::{self, Domain}};

const A: &[u8] = include_bytes!(env!("K3_A_ELF"));
const B: &[u8] = include_bytes!(env!("K3_B_ELF"));
const FIRST: u64 = 0x4b33_5f42_5f4f_4b31;
const REPLY: u64 = 0x4b33_5f52_4554_4f4b;
static mut SUPERVISOR: u64 = 0xabcd;

pub(super) fn fail(reason: &str) -> ! {
    crate::serial::log(format_args!("FORTRESS_K3_FAIL {reason}\n"));
    crate::fortress_g1_debug_exit(0x12);
    crate::halt()
}
fn check(test: bool, why: &str) { if !test { fail(why); } }
fn take<T, E: core::fmt::Debug>(r: Result<T, E>) -> T {
    r.unwrap_or_else(|e| {
        crate::serial::log(format_args!("FORTRESS_K3_ERROR {e:?}\n"));
        fail(core::any::type_name::<E>())
    })
}
pub(super) fn log_b(step: u8, f: &Observed) {
    crate::serial::log(format_args!(
        "FORTRESS_K3_B step={step} vector={} error={} cs={:#x} ss={:#x} rip={:#x} rsp={:#x} flags={:#x} live_flags={:#x} cr3={:#x} rax={:#x}\n",
        f.vector, f.error, f.cs, f.ss, f.rip, f.rsp, f.flags, f.live_flags, f.cr3, f.rax,
    ));
}

pub(super) fn execute(d: &Domain, img: &FixtureImage<'_>, arg: u64, mode: u64, reply: Option<(u64,u64)>) -> Observed {
    // Both roots map identical supervisor-only kernel code and stacks.
    unsafe {
        take(fortress_arch_x86_entry::update_rsp0(d.rsp0));
        take(activate_single_cpu_root(d.space, true));
        let cr3 = d.space.root_physical();
        check(read_cr3_physical() == cr3, "ROOT_READBACK");
        k3_entry::run(Active { cr3, rsp0:d.rsp0, entry:img.entry,
            end:img.entry + img.bytes.len() as u64, user_rsp:k3_memory::USER_RSP }, arg, mode, reply)
    }
}

fn reject_elf() {
    let mut bytes = [0u8; 8192];
    let data = bytes.get_mut(..A.len()).unwrap_or_else(|| fail("ELF_SIZE"));
    data.copy_from_slice(A);
    data[0] = 0;
    check(FixtureImage::parse(data).is_err(), "BAD_MAGIC_ADMITTED");
    data[0] = 0x7f;
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    data[phoff+4..phoff+8].copy_from_slice(&7u32.to_le_bytes());
    check(FixtureImage::parse(data).is_err(), "WX_ELF_ADMITTED");
    crate::serial::line("FORTRESS_K3_REJECT elf=INVALID wx=DENIED");
}

pub fn run(info: &crate::bootinfo::BootInfoV0) -> ! {
    let a_image = take(FixtureImage::parse(A));
    let b_image = take(FixtureImage::parse(B));
    let (boot, [ad, bd], ist) = k3_memory::prepare(info, &a_image, &b_image);
    k3_entry::install(ad.rsp0, ist.df, ist.nmi, ist.mc);
    let [kr, ar, br] = [boot.root_physical(), ad.space.root_physical(), bd.space.root_physical()];
    check(kr != ar && kr != br && ar != br, "ROOT_ALIAS");
    crate::serial::log(format_args!("FORTRESS_K3_ROOTS boot={kr:#x} a={ar:#x} b={br:#x}\n"));
    reject_elf();

    let mut procs = ProcessTable::<2>::new();
    let mut caps = CapTable::<2, 2>::new();
    let mut sched = Scheduler::<2, 1>::new();
    let b = take(procs.start(take(AddressSpaceId::new(br, 1))));
    let bt = take(sched.create(0, 1));
    let sup = core::ptr::addr_of!(SUPERVISOR) as u64;
    let cases = [
        ("supervisor-read", sup, 0, 14, 5), ("supervisor-write", sup, 1, 14, 7),
        ("peer-read", k3_memory::PEER_PROBE, 0, 14, 4), ("ud", 0, 0, 6, 0),
    ];
    let mut stale: Option<(fortress_process::identity::ProcessId, fortress_cap_ipc::CapHandle)> = None;
    for (i, (case, target, mode, vec, err)) in cases.into_iter().enumerate() {
        let a = take(procs.start(take(AddressSpaceId::new(ar, i as u64 + 1))));
        let d = DomainId::new(a.slot().into(), a.generation()).unwrap();
        let (obj, h) = take(caps.bootstrap(d, ObjectKind::Generic, Rights::READ));
        if let Some((old, old_h)) = stale {
            check(old.slot() == a.slot() && h.slot() == old_h.slot()
                && h.generation() != old_h.generation() && procs.get(old).is_err()
                && caps.authorize(d, old_h, Rights::READ).is_err()
                && caps.authorize(old_h.domain(), old_h, Rights::READ).is_err(), "STALE_AUTHORITY");
        }
        take(caps.authorize(d, h, Rights::READ));
        let at = take(sched.create(0, 1));
        take(sched.enqueue(at));
        check(take(sched.dispatch(0)) == Some(at)
            && take(procs.require_runnable(a)).address_space.root_frame() == ar, "A_DISPATCH");
        let f = execute(&ad, &a_image, target, mode, None);
        check(f.vector == vec && f.error == err && (vec != 14 || f.cr2 == target), "A_FAULT");
        crate::serial::log(format_args!(
            "FORTRESS_K3_A case={case} vector={} error={} cs={:#x} ss={:#x} rip={:#x} rsp={:#x} flags={:#x} cr2={:#x} cr3={:#x} target={target:#x}\n",
            f.vector, f.error, f.cs, f.ss, f.rip, f.rsp, f.flags, f.cr2, f.cr3,
        ));
        take(procs.fault(a, if vec == 14 { FaultReason::PageFault } else { FaultReason::InvalidOpcode }));
        check(take(sched.exit_running(0)) == at, "A_EXIT");
        unsafe {
            check(take(activate_single_cpu_root(boot, true)) == ar && read_cr3_physical() == kr, "A_QUIESCE");
        }
        // Same immutable fixture image and ownership; never reissue its pages
        // to a peer. CR3 switch flushed translations before recycling the ID.
        take(caps.revoke(d, h));
        take(caps.retire_object(obj));
        take(sched.reap(at));
        take(procs.reap(a, RetirementWitness {
            threads_quiesced: true, cpu_translation_invalidated: true, grants_revoked: true,
        }));
        check(procs.get(a).is_err() && caps.authorize(d, h, Rights::READ).is_err(), "REAP");
        stale = Some((a, h));
    }
    crate::serial::line("FORTRESS_K3_REAP pid=STALE cap=STALE");
    take(sched.enqueue(bt));
    check(take(sched.dispatch(0)) == Some(bt)
        && take(procs.require_runnable(b)).address_space.root_frame() == br, "B_DISPATCH");
    let f = execute(&bd, &b_image, 0, 0, Some((FIRST, REPLY)));
    check(f.vector == k3_entry::INT && f.error == 0 && f.rax == FIRST + 1, "B_REPLY");
    log_b(2, &f);
    take(procs.exit(b));
    check(take(sched.exit_running(0)) == bt, "B_EXIT");
    crate::serial::line("FORTRESS_K3_DONE");
    crate::fortress_g1_debug_exit(0x10);
    crate::halt()
}
