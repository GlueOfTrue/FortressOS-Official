//! Test-only single-CPU IPC. Fixture phases reenter their ELF with scalar
//! arguments; general register continuation and a stable syscall ABI are separate.
use fortress_cap_ipc::{
    ipc::{Ipc, IpcError, IpcPolicy}, CapHandle, CapTable, DomainId, Error as CapError,
    ObjectId, ObjectKind, Rights, TransferPolicy,
};
use fortress_memory_model::k1_paging::Space;
use fortress_memory_x86::k1::{activate_single_cpu_root, read_cr3_physical};
use fortress_process::identity::{AddressSpaceId, ProcessError, ProcessId, ProcessTable, RetirementWitness};
use fortressos_scheduler::{Error as SchedError, Scheduler, ThreadId, ThreadState, WaitReason};

use super::{k3, k3_elf::FixtureImage, k3_entry, k3_memory::{self, Domain}};

const A: &[u8] = include_bytes!(env!("K3_A_ELF"));
const B: &[u8] = include_bytes!(env!("K3_B_ELF"));
const PAYLOAD: u64 = 0x4b34_5f50_4159_4c44;
const DENIED: u64 = 1;
const CPU: usize = 0;
const DEADLINE: u64 = 16;
type Caps = CapTable<1, 3>;
type Queue = Ipc<1, 8>;
type Processes = ProcessTable<2>;
type Threads = Scheduler<2, 1>;

struct Task {
    pid: ProcessId,
    tid: ThreadId,
    subject: DomainId,
}

struct Route {
    sender: DomainId,
    receiver: DomainId,
    endpoint: ObjectId,
}

impl Route {
    fn matches(&self, sender: DomainId, receiver: DomainId, endpoint: ObjectId) -> bool {
        sender == self.sender && receiver == self.receiver && endpoint == self.endpoint
    }
}

impl TransferPolicy for Route {
    fn permit(&self, from: DomainId, to: DomainId, object: ObjectId, rights: Rights) -> bool {
        self.matches(to, from, object) && rights == Rights::SEND
    }
}

impl IpcPolicy for Route {
    fn allow_enqueue(&self, sender: DomainId, receiver: DomainId, endpoint: ObjectId) -> bool {
        self.matches(sender, receiver, endpoint)
    }
    fn allow_delivery(&self, sender: DomainId, receiver: DomainId, endpoint: ObjectId) -> bool {
        self.matches(sender, receiver, endpoint)
    }
    fn allow_response(&self, sender: DomainId, receiver: DomainId, endpoint: ObjectId) -> bool {
        self.matches(sender, receiver, endpoint)
    }
}

fn fail(reason: &str) -> ! {
    crate::serial::log(format_args!("FORTRESS_K4_FAIL {reason}\n"));
    crate::fortress_g1_debug_exit(0x12);
    crate::halt()
}

fn check(ok: bool, reason: &str) {
    if !ok { fail(reason); }
}

fn take<T, E: core::fmt::Debug>(value: Result<T, E>, reason: &str) -> T {
    value.unwrap_or_else(|error| {
        crate::serial::log(format_args!("FORTRESS_K4_ERROR {error:?}\n"));
        fail(reason);
    })
}

fn task(procs: &mut Processes, sched: &mut Threads, domain: &Domain) -> Task {
    let space = take(AddressSpaceId::new(domain.space.root_physical(), 1), "SPACE");
    let pid = take(procs.start(space), "PROCESS");
    let subject = DomainId::new(u32::from(pid.slot()), pid.generation())
        .unwrap_or_else(|| fail("SUBJECT"));
    Task { pid, tid: take(sched.create(0, 1), "THREAD"), subject }
}

fn dispatch(procs: &Processes, sched: &mut Threads, task: &Task, domain: &Domain) {
    let space = take(procs.require_runnable(task.pid), "NOT_RUNNABLE").address_space;
    check(
        space.root_frame() == domain.space.root_physical()
            && take(sched.dispatch(CPU), "DISPATCH") == Some(task.tid),
        "DISPATCH_IDENTITY",
    );
}

enum Call { Send, Echo, Amplify, Confirm }

fn enter(boot: Space, domain: &Domain, image: &FixtureImage<'_>, call: Call, arg: u64) -> u64 {
    let (phase, mode, operation) = match call {
        Call::Send => ("send", 0, 0x40),
        Call::Echo => ("echo", 0, 0x41),
        Call::Amplify => ("amplify", 1, 0x42),
        Call::Confirm => ("done", 2, 0x43),
    };
    let f = k3::execute(domain, image, arg, mode, None);
    // SAFETY: All roots pin the same supervisor mappings and guarded stacks.
    // PCID/PGE are disabled, so this quiesces the previous user translation.
    let old = take(unsafe { activate_single_cpu_root(boot, true) }, "QUIESCE");
    check(
        old == domain.space.root_physical()
            && unsafe { read_cr3_physical() } == boot.root_physical()
            && f.cr3 == old && f.vector == k3_entry::INT && f.error == 0
            && f.rax == operation && f.rsi == mode,
        "SYSCALL_ORIGIN",
    );
    crate::serial::log(format_args!(
        "FORTRESS_K4_TRAP phase={phase} vector={} error={} cs={:#x} ss={:#x} rip={:#x} rsp={:#x} flags={:#x} cr3={:#x} rax={:#x} rdi={:#x}\n",
        f.vector, f.error, f.cs, f.ss, f.rip, f.rsp, f.flags, f.cr3, f.rax, f.rdi,
    ));
    f.rdi
}

fn payload(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap_or_else(|_| fail("PAYLOAD_SIZE")))
}

fn test_denials(caps: &mut Caps, queue: &mut Queue, route: &Route, send: CapHandle, recv: CapHandle, now: u64) {
    let (a, b) = (route.sender, route.receiver);
    let bytes = PAYLOAD.to_le_bytes();
    check(
        queue.enqueue(caps, a, send, a, &bytes, now, DEADLINE, route) == Err(IpcError::WrongPeer)
            && queue.outstanding() == 0,
        "WRONG_RECIPIENT",
    );
    let id = take(queue.enqueue(caps, a, send, b, &bytes, now, DEADLINE, route), "CANCEL_QUEUE");
    let delivery = take(queue.receive(caps, b, recv, now, route), "CANCEL_RECEIVE");
    check(delivery.is_some_and(|item| item.id == id), "CANCEL_ID");
    take(queue.cancel(a, id), "CANCEL");
    check(
        queue.reply(caps, b, recv, id, &bytes, now, route) == Err(IpcError::NotFound)
            && matches!(queue.collect(caps, a, id, now, route), Err(IpcError::NotFound)),
        "CANCEL_LATE_REPLY",
    );

    let queued = take(caps.derive(a, send, Rights::SEND, Rights::SEND), "QUEUE_DELEGATE");
    take(queue.enqueue(caps, a, queued, b, &bytes, now, DEADLINE, route), "REVOKE_QUEUE");
    take(caps.revoke(a, queued), "REVOKE_QUEUED");
    check(
        take(queue.receive(caps, b, recv, now, route), "REVOKED_RECEIVE").is_none()
            && queue.outstanding() == 0,
        "REVOKED_DELIVERED",
    );
    let inflight = take(caps.derive(a, send, Rights::SEND, Rights::SEND), "REPLY_DELEGATE");
    check(
        inflight.slot() == queued.slot() && inflight.generation() != queued.generation()
            && matches!(caps.authorize(a, queued, Rights::SEND), Err(CapError::InvalidHandle)),
        "STALE_HANDLE",
    );
    let id = take(queue.enqueue(caps, a, inflight, b, &bytes, now, DEADLINE, route), "REPLY_QUEUE");
    let delivery = take(queue.receive(caps, b, recv, now, route), "REPLY_RECEIVE");
    check(delivery.is_some_and(|item| item.id == id && item.from == a), "DELIVERY_ID");
    take(caps.revoke(a, inflight), "REVOKE_INFLIGHT");
    check(
        queue.reply(caps, b, recv, id, &bytes, now, route) == Err(IpcError::PolicyDenied)
            && matches!(queue.collect(caps, a, id, now, route), Err(IpcError::NotFound))
            && queue.outstanding() == 0,
        "REVOKED_REPLIED",
    );
}

pub fn run(info: &crate::bootinfo::BootInfoV0) -> ! {
    let a_image = take(FixtureImage::parse(A), "ELF_A");
    let b_image = take(FixtureImage::parse(B), "ELF_B");
    let (boot, [ad, bd], ist) = k3_memory::prepare(info, &a_image, &b_image);
    k3_entry::install(ad.rsp0, ist.df, ist.nmi, ist.mc);
    let (kr, ar, br) = (boot.root_physical(), ad.space.root_physical(), bd.space.root_physical());
    check(kr != ar && kr != br && ar != br, "ROOT_ALIAS");
    crate::serial::log(format_args!("FORTRESS_K4_ROOTS boot={kr:#x} a={ar:#x} b={br:#x}\n"));

    let mut procs = Processes::new();
    let mut sched = Threads::new();
    let a = task(&mut procs, &mut sched, &ad);
    let b = task(&mut procs, &mut sched, &bd);
    let mut caps = Caps::new();
    let server = Rights::RECEIVE | Rights::REPLY | Rights::TRANSFER | Rights::SEND;
    let (endpoint, recv) = take(caps.bootstrap(b.subject, ObjectKind::Endpoint, server), "ENDPOINT");
    let route = Route { sender: a.subject, receiver: b.subject, endpoint };
    let offer = take(caps.prepare_transfer(b.subject, recv, a.subject, Rights::SEND, Rights::SEND), "OFFER");
    let send = take(caps.commit_transfer(b.subject, offer, &route), "TRANSFER");
    let mut queue = Queue::new();

    take(sched.enqueue(a.tid), "RUN_A");
    dispatch(&procs, &mut sched, &a, &ad);
    let submitted = enter(boot, &ad, &a_image, Call::Send, 0);
    check(submitted == PAYLOAD, "SEND_PAYLOAD");
    let now = sched.now();
    let request = take(
        queue.enqueue(&caps, a.subject, send, b.subject, &submitted.to_le_bytes(), now, DEADLINE, &route),
        "SEND_QUEUE",
    );

    check(
        queue.enqueue(&caps, a.subject, send, b.subject, &submitted.to_le_bytes(), now, DEADLINE, &route)
            == Err(IpcError::Full) && queue.outstanding() == 1,
        "QUEUE_OVERFLOW",
    );

    let wait = WaitReason::Ipc(request.value());
    let old = take(sched.observe_wake(a.tid), "OLD_EPOCH");
    take(sched.wake(a.tid), "EARLY_WAKE");
    check(
        sched.park_running(CPU, old, wait, None) == Err(SchedError::LostWakeAvoided)
            && take(sched.cpu_running(CPU), "CPU_STATE") == Some(a.tid)
            && matches!(queue.collect(&caps, a.subject, request, now, &route), Err(IpcError::NotReady)),
        "EARLY_WAKE_LOST",
    );
    let epoch = take(sched.observe_wake(a.tid), "WAIT_EPOCH");
    check(
        take(sched.park_running(CPU, epoch, wait, None), "PARK") == a.tid
            && take(sched.inspect(a.tid), "PARK_STATE").state
                == (ThreadState::Blocked { reason: wait, deadline: None }),
        "WRONG_WAIT",
    );
    crate::serial::log(format_args!("FORTRESS_K4_BLOCK request={}\n", request.value()));

    take(sched.enqueue(b.tid), "RUN_B");
    dispatch(&procs, &mut sched, &b, &bd);
    let delivery = take(queue.receive(&caps, b.subject, recv, now, &route), "B_RECEIVE")
        .unwrap_or_else(|| fail("B_EMPTY"));
    check(delivery.id == request && delivery.from == a.subject, "B_WRONG_REQUEST");
    let echoed = enter(boot, &bd, &b_image, Call::Echo, payload(delivery.payload()));
    check(echoed == submitted, "ECHO_PAYLOAD");
    take(queue.reply(&caps, b.subject, recv, request, &echoed.to_le_bytes(), now, &route), "B_REPLY");
    check(take(sched.exit_running(CPU), "B_EXIT") == b.tid, "B_CURRENT");
    take(sched.wake(a.tid), "REPLY_WAKE");
    crate::serial::log(format_args!("FORTRESS_K4_WAKE request={}\n", request.value()));

    dispatch(&procs, &mut sched, &a, &ad);
    let response = take(queue.collect(&caps, a.subject, request, now, &route), "A_COLLECT");
    check(response.id == request && queue.outstanding() == 0, "A_WRONG_RESPONSE");
    let requested = enter(boot, &ad, &a_image, Call::Amplify, payload(response.payload()));
    check(requested == u64::from(Rights::WRITE.bits()), "WRONG_EXPANSION");
    let wider = Rights::SEND | Rights::WRITE;
    check(caps.derive(a.subject, send, wider, wider) == Err(CapError::Amplification), "RIGHTS_EXPANSION");
    crate::serial::log(format_args!("FORTRESS_K4_DENY rights={requested:#x}\n"));
    check(enter(boot, &ad, &a_image, Call::Confirm, DENIED) == DENIED, "DENY_UNCONFIRMED");
    check(take(sched.exit_running(CPU), "A_EXIT") == a.tid, "A_CURRENT");

    // Deterministic adverse interleavings on the same authority and queue.
    // These checks run in the guest kernel, without sending payloads to an ELF.
    test_denials(&mut caps, &mut queue, &route, send, recv, now);
    crate::serial::line("FORTRESS_K4_NEGATIVE wrong_peer=DENIED canceled=DENIED revoked_queued=DENIED revoked_inflight=DENIED stale=DENIED early_wake=RETAINED overflow=DENIED");

    check(take(caps.revoke(b.subject, recv), "ENDPOINT_REVOKE") == 2, "REVOKE_SCOPE");
    take(caps.retire_object(endpoint), "ENDPOINT_RETIRE");
    check(
        matches!(caps.authorize(a.subject, send, Rights::SEND), Err(CapError::InvalidHandle))
            && matches!(caps.authorize(b.subject, recv, Rights::RECEIVE), Err(CapError::InvalidHandle)),
        "CAPS_STILL_USABLE",
    );
    for task in [a, b] {
        take(procs.exit(task.pid), "PROC_EXIT");
        take(sched.reap(task.tid), "THREAD_REAP");
        take(procs.reap(task.pid, RetirementWitness {
            threads_quiesced: true,
            cpu_translation_invalidated: true,
            grants_revoked: true,
        }), "PROC_REAP");
        check(procs.get(task.pid) == Err(ProcessError::StaleProcess), "PROC_STILL_USABLE");
    }
    take(sched.validate(), "FINAL_SCHEDULER");
    check(sched.runnable_count() == 0 && take(sched.cpu_running(CPU), "FINAL_CPU").is_none(), "FINAL_STATE");
    crate::serial::line("FORTRESS_K4_REAP process=STALE handle=STALE");
    crate::serial::line("FORTRESS_K4_DONE");
    crate::fortress_g1_debug_exit(0x10);
    crate::halt()
}
