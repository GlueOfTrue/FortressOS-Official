//! Minimal deterministic FAT32 ESP disk; wholly contained in an ordinary file.
//! Deliberately never opens host block devices.
use std::fs;
use std::path::Path;

const SECTOR: usize = 512;
const SECTORS: usize = 131_072; // 64 MiB
const RESERVED: usize = 32;
const FAT_SECTORS: usize = 1_009;
const FIRST_DATA: usize = RESERVED + FAT_SECTORS * 2;
const CLUSTERS: usize = SECTORS - FIRST_DATA;
const EFI_CLUSTER: u32 = 3;
const BOOT_CLUSTER: u32 = 4;
const FILE_START: u32 = 5;
const FILE_NAME: &[u8; 11] = b"BOOTX64 EFI";

fn put16(b: &mut [u8], off: usize, value: u16) {
    b[off..off + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(b: &mut [u8], off: usize, value: u32) {
    b[off..off + 4].copy_from_slice(&value.to_le_bytes());
}
fn cluster_offset(cluster: u32) -> usize {
    (FIRST_DATA + cluster as usize - 2) * SECTOR
}
fn fat_set(bytes: &mut [u8], cluster: u32, next: u32) {
    for i in 0..2 {
        let offset = (RESERVED + i * FAT_SECTORS) * SECTOR + cluster as usize * 4;
        put32(bytes, offset, next);
    }
}
fn directory_entry(
    bytes: &mut [u8],
    dir: u32,
    index: usize,
    name: &[u8; 11],
    attr: u8,
    first: u32,
    size: u32,
) {
    let off = cluster_offset(dir) + index * 32;
    bytes[off..off + 11].copy_from_slice(name);
    bytes[off + 11] = attr;
    put16(bytes, off + 20, (first >> 16) as u16);
    put16(bytes, off + 26, first as u16);
    put32(bytes, off + 28, size);
}
fn build(efi: &[u8]) -> Result<Vec<u8>, String> {
    let required = efi.len().div_ceil(SECTOR);
    if efi.is_empty()
        || required > CLUSTERS - 3
        || required + FILE_START as usize > (FAT_SECTORS * SECTOR / 4)
    {
        return Err("EFI binary too large or empty for fixed FAT32 image".into());
    }
    let mut bytes = vec![0u8; SECTORS * SECTOR];
    {
        let b = &mut bytes[..SECTOR];
        b[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        b[3..11].copy_from_slice(b"FORTRESS");
        put16(b, 11, 512);
        b[13] = 1; // sectors per cluster
        put16(b, 14, RESERVED as u16);
        b[16] = 2; // FATs
        put32(b, 32, SECTORS as u32);
        put32(b, 36, FAT_SECTORS as u32);
        put32(b, 44, 2); // root dir
        put16(b, 48, 1); // FSInfo
        put16(b, 50, 6); // backup boot
        b[64] = 0x80;
        b[66] = 0x29;
        put32(b, 67, 0xF04A_0001);
        b[71..82].copy_from_slice(b"FORTRESSOS ");
        b[82..90].copy_from_slice(b"FAT32   ");
        b[510..512].copy_from_slice(&[0x55, 0xaa]);
    }
    bytes.copy_within(0..SECTOR, 6 * SECTOR);
    for sector in [1, 7] {
        let b = &mut bytes[sector * SECTOR..(sector + 1) * SECTOR];
        put32(b, 0, 0x4161_5252);
        put32(b, 484, 0x6141_7272);
        put32(b, 488, 0xffff_ffff);
        put32(b, 492, 0xffff_ffff);
        put32(b, 508, 0xaa55_0000);
    }
    fat_set(&mut bytes, 0, 0x0fff_fff8);
    fat_set(&mut bytes, 1, 0x0fff_ffff);
    for c in [2, EFI_CLUSTER, BOOT_CLUSTER] {
        fat_set(&mut bytes, c, 0x0fff_ffff);
    }
    for n in 0..required {
        let cluster = FILE_START + n as u32;
        let next = if n + 1 == required {
            0x0fff_ffff
        } else {
            cluster + 1
        };
        fat_set(&mut bytes, cluster, next);
    }
    directory_entry(&mut bytes, 2, 0, b"EFI        ", 0x10, EFI_CLUSTER, 0);
    directory_entry(
        &mut bytes,
        EFI_CLUSTER,
        0,
        b".          ",
        0x10,
        EFI_CLUSTER,
        0,
    );
    directory_entry(&mut bytes, EFI_CLUSTER, 1, b"..         ", 0x10, 2, 0);
    directory_entry(
        &mut bytes,
        EFI_CLUSTER,
        2,
        b"BOOT       ",
        0x10,
        BOOT_CLUSTER,
        0,
    );
    directory_entry(
        &mut bytes,
        BOOT_CLUSTER,
        0,
        b".          ",
        0x10,
        BOOT_CLUSTER,
        0,
    );
    directory_entry(
        &mut bytes,
        BOOT_CLUSTER,
        1,
        b"..         ",
        0x10,
        EFI_CLUSTER,
        0,
    );
    directory_entry(
        &mut bytes,
        BOOT_CLUSTER,
        2,
        FILE_NAME,
        0x20,
        FILE_START,
        efi.len() as u32,
    );
    let off = cluster_offset(FILE_START);
    bytes[off..off + efi.len()].copy_from_slice(efi);
    Ok(bytes)
}
pub fn write_esp(efi: &Path, dest: &Path) -> Result<(), String> {
    let binary = fs::read(efi).map_err(|e| format!("cannot read EFI binary: {e}"))?;
    fs::write(dest, build(&binary)?)
        .map_err(|e| format!("cannot write ESP {}: {e}", dest.display()))
}
pub fn verify_esp(dest: &Path) -> Result<(), String> {
    let bytes = fs::read(dest).map_err(|e| format!("cannot read ESP: {e}"))?;
    verify_bytes(&bytes)
}
fn verify_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != SECTORS * SECTOR
        || bytes[510..512] != [0x55, 0xaa]
        || &bytes[82..90] != b"FAT32   "
        || bytes[13] != 1
        || u16::from_le_bytes(bytes[11..13].try_into().unwrap()) != 512
        || u32::from_le_bytes(bytes[36..40].try_into().unwrap()) != FAT_SECTORS as u32
    {
        return Err("invalid FAT32 image header".into());
    }
    let boot = cluster_offset(BOOT_CLUSTER) + 2 * 32;
    if &bytes[boot..boot + 11] != FILE_NAME || bytes[boot + 11] != 0x20 {
        return Err("EFI/BOOT/BOOTX64.EFI directory entry missing".into());
    }
    let size = u32::from_le_bytes(bytes[boot + 28..boot + 32].try_into().unwrap()) as usize;
    if size == 0 || size > CLUSTERS * SECTOR {
        return Err("invalid BOOTX64.EFI size".into());
    }
    let first = u16::from_le_bytes(bytes[boot + 26..boot + 28].try_into().unwrap()) as u32
        | ((u16::from_le_bytes(bytes[boot + 20..boot + 22].try_into().unwrap()) as u32) << 16);
    if first != FILE_START || &bytes[cluster_offset(first)..cluster_offset(first) + 2] != b"MZ" {
        return Err("EFI binary location/header corrupted".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_layout_and_corruption() {
        let mut b = build(b"MZdummy").unwrap();
        assert!(verify_bytes(&b).is_ok());
        b[510] = 0;
        assert!(verify_bytes(&b).is_err());
    }
    #[test]
    fn refuses_empty_image() {
        assert!(build(b"").is_err());
    }
}
