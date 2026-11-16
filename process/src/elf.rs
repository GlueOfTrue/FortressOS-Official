//! Narrow, static x86_64 ELF64 allowlist for native user images.
//! Parsing is metadata validation ONLY. The VMM must copy checked ranges,
//! zero BSS, allocate distinct user page tables and enforce U/S, NX, W^X
//! across all aliases; no physical memory is mapped by this module.
use core::convert::TryInto;

pub const PAGE_SIZE: u64 = 4096;
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROGRAM_HEADERS: usize = 24;
pub const MAX_LOAD_SEGMENTS: usize = 8;
pub const MAX_MAPPED_BYTES: u64 = 16 * 1024 * 1024;
pub const USER_START: u64 = 0x1000;
pub const USER_END: u64 = 0x0000_8000_0000_0000;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    Truncated,
    TooLarge,
    BadMagic,
    UnsupportedClass,
    UnsupportedMachine,
    UnsupportedType,
    BadHeader,
    UnsupportedProgramHeader,
    TooManySegments,
    NoLoadSegment,
    BadAlignment,
    FileOutOfBounds,
    MemoryOutOfBounds,
    OverlappingPages,
    MemoryQuota,
    WritableExecutable,
    ExecutableStack,
    EntryNotExecutable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadSegment {
    pub file_offset: u64,
    pub file_size: u64,
    pub virtual_address: u64,
    pub memory_size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}
impl LoadSegment {
    pub fn page_range(&self) -> Result<(u64, u64), ElfError> {
        let start = self.virtual_address & !(PAGE_SIZE - 1);
        let end = self.virtual_address.checked_add(self.memory_size)
            .and_then(|x| x.checked_add(PAGE_SIZE - 1))
            .ok_or(ElfError::MemoryOutOfBounds)? & !(PAGE_SIZE - 1);
        Ok((start, end))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserImage {
    pub entry: u64,
    segments: [Option<LoadSegment>; MAX_LOAD_SEGMENTS],
    count: usize,
}
impl UserImage {
    pub fn load_segments(&self) -> impl Iterator<Item = LoadSegment> + '_ {
        self.segments[..self.count].iter().filter_map(|x| *x)
    }
    pub const fn segment_count(&self) -> usize { self.count }
}
fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}
fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off.checked_add(8)?)?.try_into().ok()?))
}

/// Accept ELF64 little-endian x86_64 ET_EXEC, no interpreter, TLS or dynamic
/// linker. A real loader must additionally verify image provenance/signature.
pub fn parse_elf64(b: &[u8]) -> Result<UserImage, ElfError> {
    if b.len() > MAX_IMAGE_BYTES { return Err(ElfError::TooLarge); }
    if b.len() < 64 { return Err(ElfError::Truncated); }
    if b.get(0..4) != Some(&b"\x7fELF"[..]) { return Err(ElfError::BadMagic); }
    if b[4] != 2 || b[5] != 1 || b[6] != 1 ||
        !(b[7] == 0 || b[7] == 3) || b[8] != 0
    {
        return Err(ElfError::UnsupportedClass);
    }
    if u16_at(b, 16) != Some(2) { return Err(ElfError::UnsupportedType); }
    if u16_at(b, 18) != Some(0x3e) { return Err(ElfError::UnsupportedMachine); }
    if u32_at(b, 20) != Some(1) ||
        u16_at(b, 52) != Some(64) || u16_at(b, 54) != Some(56)
    {
        return Err(ElfError::BadHeader);
    }
    let entry = u64_at(b, 24).ok_or(ElfError::Truncated)?;
    let phoff = u64_at(b, 32).ok_or(ElfError::Truncated)?;
    let phcount = usize::from(u16_at(b, 56).ok_or(ElfError::Truncated)?);
    if phcount == 0 || phcount > MAX_PROGRAM_HEADERS {
        return Err(ElfError::BadHeader);
    }
    let phsize = (phcount as u64).checked_mul(56).ok_or(ElfError::BadHeader)?;
    if phoff.checked_add(phsize).filter(|end| *end <= b.len() as u64).is_none() {
        return Err(ElfError::BadHeader);
    }

    let mut image = UserImage { entry, segments: [None; MAX_LOAD_SEGMENTS], count: 0 };
    let mut mapped = 0_u64;
    for i in 0..phcount {
        let off = usize::try_from(phoff + (i as u64) * 56)
            .map_err(|_| ElfError::BadHeader)?;
        let kind = u32_at(b, off).ok_or(ElfError::Truncated)?;
        let flags = u32_at(b, off + 4).ok_or(ElfError::Truncated)?;
        match kind {
            PT_NULL | PT_NOTE | PT_PHDR => continue,
            PT_GNU_STACK => {
                if flags & PF_X != 0 { return Err(ElfError::ExecutableStack); }
                continue;
            }
            PT_DYNAMIC | PT_INTERP | PT_TLS => return Err(ElfError::UnsupportedProgramHeader),
            PT_LOAD => (),
            _ => return Err(ElfError::UnsupportedProgramHeader),
        }
        if image.count == MAX_LOAD_SEGMENTS { return Err(ElfError::TooManySegments); }
        if flags & !7 != 0 || flags & PF_R == 0 || flags & (PF_W | PF_X) == (PF_W | PF_X) {
            return Err(ElfError::WritableExecutable);
        }
        let file_offset = u64_at(b, off + 8).ok_or(ElfError::Truncated)?;
        let virtual_address = u64_at(b, off + 16).ok_or(ElfError::Truncated)?;
        let file_size = u64_at(b, off + 32).ok_or(ElfError::Truncated)?;
        let memory_size = u64_at(b, off + 40).ok_or(ElfError::Truncated)?;
        let alignment = u64_at(b, off + 48).ok_or(ElfError::Truncated)?;
        if alignment < PAGE_SIZE || !alignment.is_power_of_two() ||
            virtual_address % alignment != file_offset % alignment
        {
            return Err(ElfError::BadAlignment);
        }
        if file_size > memory_size || file_offset.checked_add(file_size)
            .filter(|end| *end <= b.len() as u64).is_none()
        {
            return Err(ElfError::FileOutOfBounds);
        }
        if memory_size == 0 || virtual_address < USER_START ||
            virtual_address.checked_add(memory_size)
                .filter(|end| *end <= USER_END).is_none()
        {
            return Err(ElfError::MemoryOutOfBounds);
        }
        let segment = LoadSegment {
            file_offset, file_size, virtual_address, memory_size,
            readable: true, writable: flags & PF_W != 0, executable: flags & PF_X != 0,
        };
        let (first, last) = segment.page_range()?;
        mapped = mapped.checked_add(last - first).ok_or(ElfError::MemoryQuota)?;
        if mapped > MAX_MAPPED_BYTES { return Err(ElfError::MemoryQuota); }
        for prev in image.load_segments() {
            let (a, z) = prev.page_range()?;
            // Reject physical page sharing across segments of different
            // permissions (including disjoint bytes in the same 4KiB page).
            if first < z && a < last { return Err(ElfError::OverlappingPages); }
        }
        image.segments[image.count] = Some(segment);
        image.count += 1;
    }
    if image.count == 0 { return Err(ElfError::NoLoadSegment); }
    // Never transfer to an entry in BSS, a data page or kernel space.
    if !image.load_segments().any(|s|
        s.executable &&
        entry >= s.virtual_address &&
        entry < s.virtual_address.saturating_add(s.file_size)
    ) { return Err(ElfError::EntryNotExecutable); }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;
    fn wr16(b: &mut [u8], o: usize, v: u16) { b[o..o+2].copy_from_slice(&v.to_le_bytes()); }
    fn wr32(b: &mut [u8], o: usize, v: u32) { b[o..o+4].copy_from_slice(&v.to_le_bytes()); }
    fn wr64(b: &mut [u8], o: usize, v: u64) { b[o..o+8].copy_from_slice(&v.to_le_bytes()); }
    fn sample() -> Vec<u8> {
        let mut b = vec![0u8; 0x3000];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; b[5] = 1; b[6] = 1;
        wr16(&mut b, 16, 2);
        wr16(&mut b, 18, 0x3e);
        wr32(&mut b, 20, 1);
        wr64(&mut b, 24, 0x401000);
        wr64(&mut b, 32, 64);
        wr16(&mut b, 52, 64);
        wr16(&mut b, 54, 56);
        wr16(&mut b, 56, 2);
        // First page: executable, read-only text.
        wr32(&mut b, 64, 1);
        wr32(&mut b, 68, 5);
        wr64(&mut b, 72, 0x1000);
        wr64(&mut b, 80, 0x401000);
        wr64(&mut b, 96, 16);
        wr64(&mut b, 104, 0x1000);
        wr64(&mut b, 112, 0x1000);
        // Second page: read/write, with zero-filled BSS tail.
        let o = 120;
        wr32(&mut b, o, 1);
        wr32(&mut b, o + 4, 6);
        wr64(&mut b, o + 8, 0x2000);
        wr64(&mut b, o + 16, 0x403000);
        wr64(&mut b, o + 32, 4);
        wr64(&mut b, o + 40, 0x1000);
        wr64(&mut b, o + 48, 0x1000);
        b[0x1000] = 0xc3;
        b
    }
    #[test]
    fn accepts_two_allowlisted_segments() {
        let b = sample();
        let img = parse_elf64(&b).unwrap();
        assert_eq!(img.entry, 0x401000);
        assert_eq!(img.segment_count(), 2);
        assert_eq!(img.load_segments().nth(1).unwrap().memory_size, 0x1000);
    }
    #[test]
    fn rejects_wx_kernel_entry_overlaps_and_bad_entry() {
        let mut b = sample();
        wr32(&mut b, 68, 7);
        assert_eq!(parse_elf64(&b), Err(ElfError::WritableExecutable));
        let mut b = sample();
        wr64(&mut b, 80, 0xffff_ffff_8000_0000);
        assert_eq!(parse_elf64(&b), Err(ElfError::MemoryOutOfBounds));
        let mut b = sample();
        wr64(&mut b, 120 + 16, 0x401000);
        assert_eq!(parse_elf64(&b), Err(ElfError::OverlappingPages));
        let mut b = sample();
        wr64(&mut b, 24, 0x403000);
        assert_eq!(parse_elf64(&b), Err(ElfError::EntryNotExecutable));
    }
    #[test]
    fn rejects_truncation_overflow_dynamic_and_executable_stack() {
        assert_eq!(parse_elf64(&sample()[..20]), Err(ElfError::Truncated));
        let mut b = sample();
        wr64(&mut b, 32, u64::MAX - 20);
        assert_eq!(parse_elf64(&b), Err(ElfError::BadHeader));
        let mut b = sample();
        wr32(&mut b, 120, PT_DYNAMIC);
        assert_eq!(parse_elf64(&b), Err(ElfError::UnsupportedProgramHeader));
        let mut b = sample();
        wr32(&mut b, 120, PT_GNU_STACK);
        wr32(&mut b, 124, 7);
        assert_eq!(parse_elf64(&b), Err(ElfError::ExecutableStack));
        let mut b = sample();
        wr64(&mut b, 64 + 32, 0x3001);
        assert_eq!(parse_elf64(&b), Err(ElfError::FileOutOfBounds));
    }
}
