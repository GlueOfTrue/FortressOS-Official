//! Experimental, private G1 adapter. Not an approved cross-module ABI.
//! All fields contain values, not bootloader-owned pointers.
pub const BOOT_MAGIC: u64 = 0x4654_5253_424f_4f54; // "FTRSBOOT"
pub const BOOT_VERSION: u32 = 0;
pub const MAX_REGIONS: usize = 256;
pub const MAX_MODULES: usize = 16;
pub const FLAG_FRAMEBUFFER: u32 = 1;
pub const FLAG_RSDP: u32 = 2;

pub const USABLE: u64 = 0;
pub const ACPI_RECLAIMABLE: u64 = 2;
pub const ACPI_NVS: u64 = 3;
pub const BOOTLOADER_RECLAIMABLE: u64 = 5;
pub const EXECUTABLE_AND_MODULES: u64 = 6;
pub const FRAMEBUFFER: u64 = 7;
pub const RESERVED_MAPPED: u64 = 8;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}
impl MemoryRegion {
    pub const EMPTY: Self = Self { base: 0, length: 0, kind: 0 };
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ModuleRegion {
    pub physical_base: u64,
    pub file_size: u64, // actual bytes returned by Limine
    pub length: u64, // inclusive ownership window [physical_base, base+length), 4KiB-rounded
}
impl ModuleRegion {
    pub const EMPTY: Self = Self { physical_base: 0, file_size: 0, length: 0 };
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FramebufferInfo {
    pub physical_base: u64,
    pub virtual_base: u64, // ephemeral HHDM mapping until MEMORY replaces page tables
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_size: u8,
    pub red_shift: u8,
    pub green_size: u8,
    pub green_shift: u8,
    pub blue_size: u8,
    pub blue_shift: u8,
}
impl FramebufferInfo {
    pub const EMPTY: Self = Self {
        physical_base: 0, virtual_base: 0, width: 0, height: 0, pitch: 0,
        bpp: 0, memory_model: 0, red_size: 0, red_shift: 0,
        green_size: 0, green_shift: 0, blue_size: 0, blue_shift: 0,
    };
}

#[repr(C)]
pub struct BootInfoV0 {
    pub magic: u64,
    pub version: u32,
    pub struct_size: u32,
    pub region_count: u32,
    pub module_count: u32,
    pub flags: u32,
    pub reserved: u32,
    pub kernel_physical_base: u64,
    pub kernel_virtual_base: u64,
    pub kernel_size: u64,
    pub hhdm_offset: u64,
    pub rsdp_physical: u64,
    pub framebuffer: FramebufferInfo,
    pub regions: [MemoryRegion; MAX_REGIONS],
    pub modules: [ModuleRegion; MAX_MODULES],
}
impl BootInfoV0 {
    pub const fn empty() -> Self {
        Self {
            magic: BOOT_MAGIC, version: BOOT_VERSION,
            struct_size: core::mem::size_of::<Self>() as u32,
            region_count: 0, module_count: 0, flags: 0, reserved: 0,
            kernel_physical_base: 0, kernel_virtual_base: 0, kernel_size: 0,
            hhdm_offset: 0, rsdp_physical: 0,
            framebuffer: FramebufferInfo::EMPTY,
            regions: [MemoryRegion::EMPTY; MAX_REGIONS],
            modules: [ModuleRegion::EMPTY; MAX_MODULES],
        }
    }
    pub fn region_slice(&self) -> &[MemoryRegion] {
        &self.regions[..(self.region_count as usize).min(MAX_REGIONS)]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BootError {
    Header, MissingMemory, TooManyRegions, TooManyModules,
    EmptyRange, RangeOverflow, BadAlignment, Unsorted,
    OverlappingUsable, KernelRange, ModuleRange, ModuleOverlap,
    RsdpRange, FramebufferFormat, FramebufferGeometry, FramebufferRange,
    NoncanonicalAddress, RamOverlap,
}

fn end(base: u64, len: u64) -> Result<u64, BootError> {
    if len == 0 { return Err(BootError::EmptyRange); }
    base.checked_add(len).ok_or(BootError::RangeOverflow)
}

fn overlaps(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    let ae = a.saturating_add(alen);
    let be = b.saturating_add(blen);
    a < be && b < ae
}

pub fn validate_regions(regions: &[MemoryRegion]) -> Result<(), BootError> {
    if regions.is_empty() { return Err(BootError::MissingMemory); }
    if regions.len() > MAX_REGIONS { return Err(BootError::TooManyRegions); }
    for (i, r) in regions.iter().enumerate() {
        end(r.base, r.length)?;
        if (r.kind == USABLE || r.kind == BOOTLOADER_RECLAIMABLE)
            && ((r.base | r.length) & 0xfff != 0)
        { return Err(BootError::BadAlignment); }
        if i > 0 && r.base < regions[i - 1].base { return Err(BootError::Unsorted); }
        for other in &regions[..i] {
            // Limine explicitly permits overlaps among non-usable regions.
            if overlaps(r.base, r.length, other.base, other.length)
                && (r.kind == USABLE || r.kind == BOOTLOADER_RECLAIMABLE
                    || other.kind == USABLE || other.kind == BOOTLOADER_RECLAIMABLE)
            { return Err(BootError::OverlappingUsable); }
        }
    }
    Ok(())
}


pub fn page_round_up(len: u64) -> Result<u64, BootError> {
    if len == 0 { return Err(BootError::EmptyRange); }
    len.checked_add(4095).map(|v| v & !4095).filter(|&v| v != 0)
        .ok_or(BootError::RangeOverflow)
}

// G1 is deliberately restricted to the 48-bit canonical VA profile. Revisit
// with ARCH before supporting 5-level paging / a wider higher-half mapping.
pub fn canonical48(v: u64) -> bool {
    (v >> 47 == 0) || (v >> 47 == 0x1ffff)
}

fn overlaps_reclaimable_ram(regions: &[MemoryRegion], base: u64, len: u64) -> bool {
    regions.iter().any(|r| (r.kind == USABLE || r.kind == BOOTLOADER_RECLAIMABLE)
        && overlaps(base, len, r.base, r.length))
}

pub fn checked_owned_span(regions: &[MemoryRegion], base: u64, len: u64)
    -> Result<(), BootError>
{
    end(base, len)?;
    if overlaps_reclaimable_ram(regions, base, len) {
        return Err(BootError::RamOverlap);
    }
    Ok(())
}

pub fn framebuffer_len(fb: &FramebufferInfo) -> Result<u64, BootError> {
    if fb.width == 0 || fb.height == 0 || fb.width > 16384 || fb.height > 16384 {
        return Err(BootError::FramebufferGeometry);
    }
    if fb.bpp != 32 || fb.memory_model != 1 ||
        fb.red_size != 8 || fb.green_size != 8 || fb.blue_size != 8 ||
        fb.red_shift > 24 || fb.green_shift > 24 || fb.blue_shift > 24
    { return Err(BootError::FramebufferFormat); }
    let rm = 0xffu32 << fb.red_shift;
    let gm = 0xffu32 << fb.green_shift;
    let bm = 0xffu32 << fb.blue_shift;
    if (rm & gm) != 0 || (rm & bm) != 0 || (gm & bm) != 0 {
        return Err(BootError::FramebufferFormat);
    }
    let row = fb.width.checked_mul(4).ok_or(BootError::FramebufferGeometry)?;
    if fb.pitch < row || (fb.pitch & 3) != 0 ||
        (fb.physical_base & 3) != 0 || (fb.virtual_base & 3) != 0
    { return Err(BootError::FramebufferGeometry); }
    fb.pitch.checked_mul(fb.height).filter(|&n| n <= 512 * 1024 * 1024)
        .ok_or(BootError::FramebufferGeometry)
}

pub fn validate(info: &BootInfoV0) -> Result<(), BootError> {
    if info.magic != BOOT_MAGIC || info.version != BOOT_VERSION ||
        info.struct_size != core::mem::size_of::<BootInfoV0>() as u32 ||
        info.reserved != 0 || (info.flags & !(FLAG_FRAMEBUFFER | FLAG_RSDP)) != 0
    { return Err(BootError::Header); }
    if info.region_count as usize > MAX_REGIONS { return Err(BootError::TooManyRegions); }
    if info.module_count as usize > MAX_MODULES { return Err(BootError::TooManyModules); }
    let regions = info.region_slice();
    validate_regions(regions)?;

    // Executable Address + linker PT_LOAD envelope is our G1 source of truth.
    // Illustrative Limine memmap types 6/7 MUST NOT determine exact ownership.
    if (info.kernel_physical_base | info.kernel_size) & 4095 != 0 ||
        info.kernel_virtual_base < 0xffff_ffff_8000_0000 ||
        info.hhdm_offset == 0 || !canonical48(info.kernel_virtual_base) ||
        !canonical48(info.hhdm_offset) ||
        info.kernel_size == 0
    { return Err(BootError::KernelRange); }
    checked_owned_span(regions, info.kernel_physical_base, info.kernel_size)
        .map_err(|_| BootError::KernelRange)?;
    let last_kernel_va = info.kernel_virtual_base
        .checked_add(info.kernel_size - 1).ok_or(BootError::KernelRange)?;
    if !canonical48(last_kernel_va) { return Err(BootError::KernelRange); }

    for (i, m) in info.modules[..info.module_count as usize].iter().enumerate() {
        if (m.physical_base & 4095) != 0 ||
            page_round_up(m.file_size).ok() != Some(m.length)
        { return Err(BootError::ModuleRange); }
        checked_owned_span(regions, m.physical_base, m.length)
            .map_err(|_| BootError::ModuleRange)?;
        if overlaps(m.physical_base, m.length, info.kernel_physical_base, info.kernel_size) ||
            info.modules[..i].iter().any(|prev|
                overlaps(m.physical_base, m.length, prev.physical_base, prev.length))
        { return Err(BootError::ModuleOverlap); }
    }
    if info.flags & FLAG_RSDP != 0 {
        // The rev-6 RSDP pointer is HHDM-mapped, but ACPI checksum and table
        // lifetime are NOT verified in G1; expose location only, not validity.
        if info.rsdp_physical == 0 || end(info.rsdp_physical, 20).is_err() {
            return Err(BootError::RsdpRange);
        }
    }
    if info.flags & FLAG_FRAMEBUFFER != 0 {
        let fb = &info.framebuffer;
        let len = framebuffer_len(fb)?;
        let last_va = fb.virtual_base.checked_add(len - 1)
            .ok_or(BootError::FramebufferRange)?;
        if !canonical48(fb.virtual_base) || !canonical48(last_va) ||
            fb.physical_base.checked_add(info.hhdm_offset) != Some(fb.virtual_base) ||
            checked_owned_span(regions, fb.physical_base, len).is_err() ||
            // Dedicated framebuffer response is not proof of exclusive MMIO.
            // Reject any alias to the loaded kernel or padded module backing.
            overlaps(fb.physical_base, len, info.kernel_physical_base, info.kernel_size) ||
            info.modules[..info.module_count as usize].iter().any(|m|
                overlaps(fb.physical_base, len, m.physical_base, m.length))
        { return Err(BootError::FramebufferRange); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn map() -> [MemoryRegion; 3] {
        [
            MemoryRegion { base: 0x1000, length: 0x2000, kind: USABLE },
            MemoryRegion { base: 0x100000, length: 0x40000, kind: EXECUTABLE_AND_MODULES },
            MemoryRegion { base: 0xe0000000, length: 0x400000, kind: FRAMEBUFFER },
        ]
    }
    fn valid() -> BootInfoV0 {
        let mut b = BootInfoV0::empty();
        b.region_count = 3;
        b.regions[..3].copy_from_slice(&map());
        b.kernel_physical_base = 0x100000;
        b.kernel_virtual_base = 0xffffffff80000000;
        b.kernel_size = 0x20000;
        b.hhdm_offset = 0xffff800000000000;
        b
    }
    #[test] fn accepts_valid_minimal() { assert_eq!(validate(&valid()), Ok(())); }
    #[test] fn rejects_usable_overlap() {
        let mut m = map(); m[1] = MemoryRegion{base:0x2000,length:0x2000,kind:USABLE};
        assert_eq!(validate_regions(&m), Err(BootError::OverlappingUsable));
    }
    #[test] fn rejects_overflow() {
        let m = [MemoryRegion{base:u64::MAX-1,length:8,kind:1}];
        assert_eq!(validate_regions(&m), Err(BootError::RangeOverflow));
    }
    #[test] fn rejects_bad_alignment() {
        let m = [MemoryRegion{base:0x1001,length:0x1000,kind:USABLE}];
        assert_eq!(validate_regions(&m), Err(BootError::BadAlignment));
    }
    #[test] fn permits_reserved_overlap() {
        let m = [
            MemoryRegion{base:0x1000,length:0x1000,kind:1},
            MemoryRegion{base:0x1800,length:0x1000,kind:EXECUTABLE_AND_MODULES},
        ];
        assert_eq!(validate_regions(&m), Ok(()));
    }
    #[test] fn rejects_bad_pitch() {
        let fb = FramebufferInfo{width:800,height:600,pitch:100, bpp:32,memory_model:1,
          red_size:8,green_size:8,blue_size:8,red_shift:16,green_shift:8,blue_shift:0,
          ..FramebufferInfo::EMPTY};
        assert_eq!(framebuffer_len(&fb), Err(BootError::FramebufferGeometry));
    }
    #[test] fn rejects_overlap_rgb_masks() {
        let fb = FramebufferInfo{width:800,height:600,pitch:3200,bpp:32,memory_model:1,
          red_size:8,green_size:8,blue_size:8,red_shift:16,green_shift:16,blue_shift:0,
          ..FramebufferInfo::EMPTY};
        assert_eq!(framebuffer_len(&fb), Err(BootError::FramebufferFormat));
    }
    #[test] fn rejects_module_over_kernel() {
        let mut b = valid(); b.module_count = 1;
        b.modules[0] = ModuleRegion { physical_base:0x110000,file_size:0x1000,length:0x1000 };
        assert_eq!(validate(&b), Err(BootError::ModuleOverlap));
    }
    #[test] fn ignores_illustrative_kernel_region_boundaries() {
        let mut b = valid(); b.kernel_size = 0x80000;
        assert_eq!(validate(&b), Ok(()));
    }
    #[test] fn rejects_kernel_overlap_with_usable_ram() {
        let mut b = valid();
        b.regions[1] = MemoryRegion { base:0x100000,length:0x40000,kind:USABLE };
        assert_eq!(validate(&b), Err(BootError::KernelRange));
    }
    #[test] fn rejects_kernel_phys_overflow() {
        let mut b = valid(); b.kernel_physical_base = 0xffff_ffff_ffff_f000;
        assert_eq!(validate(&b), Err(BootError::KernelRange));
    }
    #[test] fn accepts_module_without_illustrative_region() {
        let mut b = valid();
        b.module_count = 1;
        b.modules[0] = ModuleRegion { physical_base:0x200000,file_size:17,length:0x1000 };
        assert_eq!(validate(&b), Ok(()));
    }
    #[test] fn rejects_page_rounded_module_overlap() {
        let mut b = valid();
        b.module_count = 2;
        b.modules[0] = ModuleRegion { physical_base:0x200000,file_size:4097,length:0x2000 };
        b.modules[1] = ModuleRegion { physical_base:0x201000,file_size:1,length:0x1000 };
        assert_eq!(validate(&b), Err(BootError::ModuleOverlap));
    }
    #[test] fn rejects_module_size_overflow() {
        let mut b = valid();
        b.module_count = 1;
        b.modules[0] = ModuleRegion { physical_base:0x200000,file_size:u64::MAX,length:0 };
        assert_eq!(validate(&b), Err(BootError::ModuleRange));
    }
    #[test] fn rejects_unsorted_entries() {
        let m = [MemoryRegion{base:0x3000,length:0x1000,kind:1},
                 MemoryRegion{base:0x1000,length:0x1000,kind:1}];
        assert_eq!(validate_regions(&m), Err(BootError::Unsorted));
    }
    #[test] fn ignores_illustrative_framebuffer_region() {
        let mut b = valid();
        b.framebuffer = FramebufferInfo { physical_base:0xd0000000,
            virtual_base:0xffff8000d0000000, width:800,height:600,pitch:3200,
            bpp:32,memory_model:1,red_size:8,green_size:8,blue_size:8,
            red_shift:16,green_shift:8,blue_shift:0, ..FramebufferInfo::EMPTY };
        b.flags = FLAG_FRAMEBUFFER;
        assert_eq!(validate(&b), Ok(()));
    }
    #[test] fn rejects_framebuffer_inside_usable_ram() {
        let mut b = valid();
        b.framebuffer = FramebufferInfo { physical_base:0x1000,
            virtual_base:0xffff800000001000, width:4,height:4,pitch:16,
            bpp:32,memory_model:1,red_size:8,green_size:8,blue_size:8,
            red_shift:16,green_shift:8,blue_shift:0, ..FramebufferInfo::EMPTY };
        b.flags = FLAG_FRAMEBUFFER;
        assert_eq!(validate(&b), Err(BootError::FramebufferRange));
    }
    fn tiny_fb(physical_base: u64) -> FramebufferInfo {
        FramebufferInfo { physical_base,
            virtual_base: 0xffff800000000000u64 + physical_base,
            width: 8, height: 8, pitch: 32, bpp: 32, memory_model: 1,
            red_size: 8, green_size: 8, blue_size: 8,
            red_shift: 16, green_shift: 8, blue_shift: 0,
        }
    }
    #[test] fn rejects_framebuffer_kernel_alias_even_if_reserved() {
        let mut b = valid();
        b.flags = FLAG_FRAMEBUFFER;
        b.framebuffer = tiny_fb(b.kernel_physical_base + 0x1000);
        assert_eq!(validate(&b), Err(BootError::FramebufferRange));
    }
    #[test] fn rejects_framebuffer_alias_to_module_padding_page() {
        let mut b = valid();
        b.module_count = 1;
        b.modules[0] = ModuleRegion { physical_base:0x200000,
            file_size: 4097, length: 0x2000 };
        b.flags = FLAG_FRAMEBUFFER;
        b.framebuffer = tiny_fb(0x201000); // beyond file bytes, inside pinned backing
        assert_eq!(validate(&b), Err(BootError::FramebufferRange));
    }
    #[test] fn accepts_disjoint_framebuffer_and_module() {
        let mut b = valid();
        b.module_count = 1;
        b.modules[0] = ModuleRegion { physical_base:0x200000,
            file_size: 4097, length: 0x2000 };
        b.flags = FLAG_FRAMEBUFFER;
        b.framebuffer = tiny_fb(0xd0000000);
        assert_eq!(validate(&b), Ok(()));
    }
    #[test] fn page_rounding_checks_overflow() {
        assert_eq!(page_round_up(4097), Ok(8192));
        assert_eq!(page_round_up(0), Err(BootError::EmptyRange));
        assert_eq!(page_round_up(u64::MAX), Err(BootError::RangeOverflow));
    }
}
