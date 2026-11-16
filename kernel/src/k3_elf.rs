//! QEMU K3 loader profile for independently built static user programs.
//! PROCESS 08 validates ELF metadata before the fixture derives map inputs.
use fortress_process::elf::{parse_elf64, ElfError, PAGE_SIZE};

pub const TEXT_VA: u64 = 0x0040_0000;

#[derive(Debug, PartialEq, Eq)]
pub enum FixtureElfError {
    Elf(ElfError),
    UnsupportedLayout,
}

/// Verified input to the fixture's single RX mapping. The memory owner must
/// populate a zeroed frame and publish it with no writable alias.
#[derive(Debug)]
pub struct FixtureImage<'a> {
    pub entry: u64,
    pub bytes: &'a [u8],
}

impl<'a> FixtureImage<'a> {
    pub fn parse(elf: &'a [u8]) -> Result<Self, FixtureElfError> {
        let image = parse_elf64(elf).map_err(FixtureElfError::Elf)?;
        let mut segments = image.load_segments();
        let segment = segments
            .next()
            .ok_or(FixtureElfError::UnsupportedLayout)?;
        if segments.next().is_some()
            || image.entry != TEXT_VA
            || segment.virtual_address != TEXT_VA
            || !segment.readable
            || segment.writable
            || !segment.executable
            || segment.memory_size > PAGE_SIZE
            || segment.file_size == 0
        {
            return Err(FixtureElfError::UnsupportedLayout);
        }
        let start = usize::try_from(segment.file_offset)
            .map_err(|_| FixtureElfError::UnsupportedLayout)?;
        let size = usize::try_from(segment.file_size)
            .map_err(|_| FixtureElfError::UnsupportedLayout)?;
        let end = start
            .checked_add(size)
            .ok_or(FixtureElfError::UnsupportedLayout)?;
        let bytes = elf.get(start..end).ok_or(FixtureElfError::UnsupportedLayout)?;
        Ok(Self {
            entry: image.entry,
            bytes,
        })
    }
}
