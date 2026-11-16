//! Memory ownership for the one-vCPU K3 guest. The original Limine root
//! is borrowed during preparation, then abandoned and kept physically pinned.
use core::{
    arch::asm,
    mem::MaybeUninit,
    ptr::{addr_of_mut, copy_nonoverlapping},
};

use fortress_memory_model::{
    k1_frames::{FrameLease, FramePool, FramePurpose},
    k1_paging::{self, MapLedger, Rights, Space},
    page_tables::{Fault, TableStore},
};
use fortress_memory_x86::{
    k1::{self, PmmTableFrames},
    x86::{DirectMappedTableStore, HhdmFrameZeroer, PageFrameAllocator},
};

use super::k3_elf::{FixtureImage, TEXT_VA};
use crate::bootinfo::BootInfoV0;

const PAGE: u64 = 4096;
const ADDR: u64 = 0x000f_ffff_ffff_f000;
const PRESENT: u64 = 1;
const WRITE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const HUGE_PAT: u64 = 1 << 12;
const NX: u64 = 1 << 63;
const WP: u64 = 1 << 16;
const STACK_BASE: u64 = 0xffff_fd00_0000_0000;
const STACK_PAGES: u64 = 2;
const STACK_SLOTS: u64 = 5;
const STACK_STRIDE: u64 = (STACK_PAGES + 2) * PAGE;
const KERNEL_OWNER: u64 = 1;
const OWNERS: [u64; 2] = [2, 3];
pub const USER_RSP: u64 = 0x0080_0000;
pub const PEER_PROBE: u64 = 0x0090_0000;

pub struct Domain {
    pub space: Space,
    pub rsp0: u64,
}

pub struct Ist {
    pub df: u64,
    pub nmi: u64,
    pub mc: u64,
}

type Pool = FramePool<64, 48>;
type Ledger = MapLedger<24>;

// The fixture runs once, then halts. Keep the sole PMM and its active map
// claims alive for that entire time. No reclamation or reinitialization.
static mut OWNERSHIP: MaybeUninit<(Pool, Ledger)> = MaybeUninit::uninit();

fn require(result: bool, reason: &'static str) {
    if !result {
        crate::fatal(reason);
    }
}

fn checked<T, E>(result: Result<T, E>, reason: &'static str) -> T {
    result.unwrap_or_else(|_| crate::fatal(reason))
}

fn index(va: u64, depth: usize) -> usize {
    ((va >> [39, 30, 21, 12][depth]) & 511) as usize
}

fn read(tables: &impl TableStore, pa: u64, slot: usize) -> u64 {
    checked(tables.read_entry(pa, slot), "K3_TABLE_READ")
}

fn write(tables: &mut impl TableStore, pa: u64, slot: usize, entry: u64) {
    checked(tables.write_entry(pa, slot, entry), "K3_TABLE_WRITE");
}

fn owned_space(pool: &mut Pool, hhdm: u64, parent: u64, owner: u64) -> Space {
    let mut alloc = checked(PmmTableFrames::new(pool, owner), "K3_ROOT_ALLOC");
    // SAFETY: The root and its descendants are pinned and reached through
    // the validated active HHDM. The only vCPU has interrupts disabled.
    checked(
        unsafe { k1::build_bootstrap_domain_root(&mut alloc, hhdm, parent, owner, 1) },
        "K3_ROOT_BUILD",
    )
}

struct TableQueue<const N: usize> {
    frames: [u64; N],
    next: usize,
}

impl<const N: usize> TableQueue<N> {
    fn new(pool: &mut Pool, owner: u64) -> Self {
        Self {
            frames: core::array::from_fn(|_| {
                let table = checked(pool.allocate(owner, FramePurpose::PageTable), "K3_TABLE_ALLOC");
                checked(pool.physical(table, owner), "K3_TABLE_OWNER")
            }),
            next: 0,
        }
    }
}

impl<const N: usize> PageFrameAllocator for TableQueue<N> {
    fn allocate_owned_table_frame(&mut self) -> Result<u64, Fault> {
        let pa = *self.frames.get(self.next).ok_or(Fault::IoFailure)?;
        self.next += 1;
        Ok(pa)
    }
}

fn tables<const N: usize>(
    root: Space,
    hhdm: u64,
    queue: TableQueue<N>,
) -> DirectMappedTableStore<TableQueue<N>> {
    // SAFETY: Every queued frame was allocated by the single PMM and is
    // writable through the current, pinned HHDM for the duration of setup.
    checked(
        unsafe { DirectMappedTableStore::new(root.root_physical(), hhdm, queue) },
        "K3_TABLE_BACKEND",
    )
}

fn new_table(tables: &mut impl TableStore) -> u64 {
    checked(tables.allocate_zeroed_table(), "K3_TABLE_ZERO")
}

fn data_frame(
    pool: &mut Pool,
    owner: u64,
    zeroer: &mut HhdmFrameZeroer,
) -> (FrameLease, u64) {
    let frame = checked(pool.allocate(owner, FramePurpose::Data), "K3_FRAME_ALLOC");
    checked(pool.scrub_owned(frame, owner, zeroer), "K3_FRAME_SCRUB");
    (frame, checked(pool.physical(frame, owner), "K3_FRAME_OWNER"))
}

fn install_stacks(
    tables: &mut impl TableStore,
    pool: &mut Pool,
    zeroer: &mut HhdmFrameZeroer,
    ledger: &mut Ledger,
    space: Space,
) -> [u64; STACK_SLOTS as usize] {
    let root = tables.root_table();
    let root_slot = index(STACK_BASE, 0);
    require(read(tables, root, root_slot) == 0, "K3_STACK_SLOT_BUSY");
    let l3 = new_table(tables);
    let l2 = new_table(tables);
    let l1 = new_table(tables);
    // The whole subtree lies within a single 2 MiB range. All descendants
    // and both shared ancestors are supervisor-only and NX.
    write(tables, root, root_slot, l3 | PRESENT | WRITE | NX);
    write(tables, l3, index(STACK_BASE, 1), l2 | PRESENT | WRITE | NX);
    write(tables, l2, index(STACK_BASE, 2), l1 | PRESENT | WRITE | NX);

    core::array::from_fn(|slot| {
        let guard_low = STACK_BASE + slot as u64 * STACK_STRIDE;
        let stack_top = guard_low + (1 + STACK_PAGES) * PAGE;
        for guard in [guard_low, stack_top] {
            checked(
                ledger.reserve_kernel_guard(tables, pool, space, guard),
                "K3_STACK_GUARD",
            );
        }
        for page in 1..=STACK_PAGES {
            let (_, pa) = data_frame(pool, KERNEL_OWNER, zeroer);
            let slot = index(guard_low + page * PAGE, 3);
            write(tables, l1, slot, pa | PRESENT | WRITE | NX);
            require(
                read(tables, l1, slot) == pa | PRESENT | WRITE | NX,
                "K3_STACK_LEAF",
            );
        }
        stack_top
    })
}

fn huge_size(depth: usize) -> u64 {
    match depth {
        1 => 1 << 30,
        2 => 1 << 21,
        _ => crate::fatal("K3_HUGE_PAGE_LEVEL"),
    }
}

/// Clone one page-table path before unmapping the known direct-map alias.
/// Split a huge page only on the owned copy, preserving each neighbor's
/// address, access rights, and cache attributes.
fn close_hhdm_alias(tables: &mut impl TableStore, va: u64, pa: u64) {
    let mut parent = tables.root_table();
    for depth in 0..3 {
        let slot = index(va, depth);
        let old = read(tables, parent, slot);
        require(old & PRESENT != 0, "K3_ALIAS_MISSING");
        let child = new_table(tables);
        let flags;
        if old & HUGE == 0 {
            let borrowed = old & ADDR;
            require(borrowed != 0, "K3_ALIAS_TABLE_ZERO");
            for i in 0..512 {
                let entry = read(tables, borrowed, i);
                write(tables, child, i, entry);
            }
            flags = old & !ADDR;
        } else {
            let size = huge_size(depth);
            let base = old & ADDR & !(size - 1);
            let raw_phys = old & ADDR & !HUGE_PAT;
            require(raw_phys == base, "K3_ALIAS_HUGE_ALIGNMENT");
            let attrs = old & !ADDR;
            let child_attrs = if depth == 1 {
                attrs | (old & HUGE_PAT)
            } else {
                (attrs & !HUGE) | ((old & HUGE_PAT) >> 5)
            };
            for i in 0..512 {
                write(tables, child, i, (base + i as u64 * (size / 512)) | child_attrs);
            }
            flags = old & (PRESENT | WRITE | USER | NX);
        }
        write(tables, parent, slot, child | flags);
        parent = child;
    }
    let slot = index(va, 3);
    let leaf = read(tables, parent, slot);
    require(leaf & PRESENT != 0 && leaf & ADDR == pa, "K3_ALIAS_WRONG_PAGE");
    write(tables, parent, slot, 0);
    require(read(tables, parent, slot) == 0, "K3_ALIAS_REMOVE");
}

fn audit_kernel_aliases(
    tables: &impl TableStore,
    parent: u64,
    depth: usize,
    texts: [u64; 2],
    budget: &mut usize,
) {
    require(*budget != 0, "K3_ALIAS_AUDIT_BUDGET");
    *budget -= 1;
    for slot in if depth == 0 { 256..512 } else { 0..512 } {
        let entry = read(tables, parent, slot);
        if entry & PRESENT == 0 {
            continue;
        }
        if depth == 0 {
            require(entry & (USER | HUGE) == 0, "K3_KERNEL_PARENT_RIGHTS");
        }
        if depth == 3 || entry & HUGE != 0 {
            let size = if depth == 3 { PAGE } else { huge_size(depth) };
            let base = entry & ADDR & !(size - 1);
            require(
                texts.iter().all(|pa| *pa < base || *pa - base >= size),
                "K3_EXECUTABLE_FRAME_HAS_KERNEL_ALIAS",
            );
        } else {
            let child = entry & ADDR;
            require(child != 0, "K3_KERNEL_TABLE_ZERO");
            audit_kernel_aliases(tables, child, depth + 1, texts, budget);
        }
    }
}

struct UserFrames {
    text: FrameLease,
    text_pa: u64,
    stack: FrameLease,
    peer: Option<FrameLease>,
}

fn user_frames(
    pool: &mut Pool,
    hhdm: u64,
    owner: u64,
    image: &FixtureImage<'_>,
    zeroer: &mut HhdmFrameZeroer,
    peer: bool,
) -> UserFrames {
    let (text, text_pa) = data_frame(pool, owner, zeroer);
    let dest = hhdm.checked_add(text_pa).unwrap_or_else(|| crate::fatal("K3_HHDM_OVERFLOW"));
    require(image.bytes.len() as u64 <= PAGE, "K3_ELF_COPY_SIZE");
    // SAFETY: This freshly scrubbed PMM frame has no user mappings and is
    // reachable through the validated boot HHDM. ELF bytes are separate.
    unsafe { copy_nonoverlapping(image.bytes.as_ptr(), dest as *mut u8, image.bytes.len()) };
    UserFrames {
        text,
        text_pa,
        stack: data_frame(pool, owner, zeroer).0,
        peer: peer.then(|| data_frame(pool, owner, zeroer).0),
    }
}

fn user_space(
    pool: &mut Pool,
    ledger: &mut Ledger,
    hhdm: u64,
    boot: Space,
    id: usize,
    frames: UserFrames,
    rsp0: u64,
) -> Domain {
    let owner = OWNERS[id];
    let space = owned_space(pool, hhdm, boot.root_physical(), owner);
    let queue = TableQueue::<5>::new(pool, owner);
    let mut tables = tables(space, hhdm, queue);
    for guard in [USER_RSP - 2 * PAGE, USER_RSP] {
        checked(ledger.reserve_guard(&tables, pool, space, guard), "K3_USER_GUARD");
    }
    for (va, frame, rights) in [
        (TEXT_VA, Some(frames.text), Rights::USER_RX),
        (USER_RSP - PAGE, Some(frames.stack), Rights::USER_RW),
        (PEER_PROBE, frames.peer, Rights::USER_RW),
    ] {
        if let Some(frame) = frame {
            checked(
                ledger.map(&mut tables, pool, space, va, frame, owner, rights),
                "K3_USER_PTE",
            );
        }
    }
    require(
        k1_paging::user_can_access(&tables, TEXT_VA, false, true).is_ok()
            && k1_paging::user_can_access(&tables, TEXT_VA, true, false).is_err()
            && k1_paging::user_can_access(&tables, USER_RSP - PAGE, true, false).is_ok()
            && k1_paging::user_can_access(&tables, USER_RSP - PAGE, false, true).is_err()
            && k1_paging::user_can_access(&tables, PEER_PROBE, false, false).is_ok() == (id == 1),
        "K3_USER_PTE_ACCESS",
    );
    Domain { space, rsp0 }
}

pub fn prepare(
    info: &BootInfoV0,
    a: &FixtureImage<'_>,
    b: &FixtureImage<'_>,
) -> (Space, [Domain; 2], Ist) {
    require(unsafe { k1::basic_cpu_mode_ok() }, "K3_CPU_MODE");
    let cr0: u64;
    // SAFETY: This is the one-vCPU fixture's ring0 boot entry.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    require(cr0 & WP != 0, "K3_CR0_WP_DISABLED");
    let mut pool = checked(crate::boot_memory::frame_pool::<48>(info), "K3_PMM");
    let mut ledger = Ledger::new();
    let hhdm = info.hhdm_offset;
    // SAFETY: BOOT validated the Limine-derived memory map and HHDM. Every
    // scrub target comes from the unique PMM's non-reserved frame inventory.
    let mut zeroer = checked(unsafe { HhdmFrameZeroer::new(hhdm) }, "K3_HHDM");
    let a = user_frames(&mut pool, hhdm, OWNERS[0], a, &mut zeroer, false);
    let b = user_frames(&mut pool, hhdm, OWNERS[1], b, &mut zeroer, true);
    let text_pages = [a.text_pa, b.text_pa];
    let borrowed_root = unsafe { k1::read_cr3_physical() };
    let boot = owned_space(&mut pool, hhdm, borrowed_root, KERNEL_OWNER);
    let queue = TableQueue::<9>::new(&mut pool, KERNEL_OWNER);
    let mut boot_tables = tables(boot, hhdm, queue);
    let stacks = install_stacks(&mut boot_tables, &mut pool, &mut zeroer, &mut ledger, boot);
    for pa in text_pages {
        let alias = hhdm.checked_add(pa).unwrap_or_else(|| crate::fatal("K3_HHDM_OVERFLOW"));
        close_hhdm_alias(&mut boot_tables, alias, pa);
    }
    audit_kernel_aliases(&boot_tables, boot.root_physical(), 0, text_pages, &mut 4096);
    // SAFETY: Only the inactive root's text direct-map aliases changed.
    // Its inherited supervisor tables and the executing kernel stack stay
    // pinned. PCID/PGE are disabled, so this discards old alias translations.
    let previous = checked(unsafe { k1::activate_single_cpu_root(boot, true) }, "K3_KERNEL_CR3");
    require(
        previous == borrowed_root && unsafe { k1::read_cr3_physical() } == boot.root_physical(),
        "K3_KERNEL_CR3_READBACK",
    );
    let domains = [
        user_space(&mut pool, &mut ledger, hhdm, boot, 0, a, stacks[0]),
        user_space(&mut pool, &mut ledger, hhdm, boot, 1, b, stacks[1]),
    ];
    // SAFETY: This one-shot boot path is the sole writer. No pointers to the
    // storage escape; prepared frame leases remain pinned until VM shutdown.
    unsafe { addr_of_mut!(OWNERSHIP).write(MaybeUninit::new((pool, ledger))) };
    (boot, domains, Ist { df: stacks[2], nmi: stacks[3], mc: stacks[4] })
}
