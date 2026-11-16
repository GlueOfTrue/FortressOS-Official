//! Minimal FFI for the pinned Limine base revision 6, request revision 0.
//! Layout and IDs: https://github.com/limine-bootloader/limine-protocol
use core::ptr;

pub const START: [u64; 4] = [
    0xf6b8f4b39de7d1ae, 0xfab91a6940fcb9cf,
    0x785c6ed015d3e316, 0x181e920a7852b9d9,
];
pub const END: [u64; 2] = [0xadc0e0531bb10d03, 0x9572709f31764c62];
pub const BASE: [u64; 3] = [0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, 6];
const MAGIC0: u64 = 0xc7b1dd30df4c8b88;
const MAGIC1: u64 = 0x0a82e883a194f07b;

#[repr(C)]
pub struct Request<T> {
    id: [u64; 4],
    revision: u64,
    response: *const T, // written by the loader before jumping to the kernel
}
impl<T> Request<T> {
    pub const fn new(a: u64, b: u64) -> Self {
        Self { id: [MAGIC0, MAGIC1, a, b], revision: 0, response: ptr::null() }
    }
}
pub unsafe fn response<T>(r: *const Request<T>) -> Option<&'static T> {
    // Safety: caller must guarantee the request is in loaded/writable PT_LOAD
    // and the loader's HHDM response remains mapped and pinned.
    let p = unsafe { ptr::read_volatile(ptr::addr_of!((*r).response)) };
    unsafe { p.as_ref() }
}

#[repr(C)]
pub struct MemMapResponse {
    pub revision: u64, pub entry_count: u64,
    pub entries: *const *const MemMapEntry,
}
#[repr(C)]
pub struct MemMapEntry { pub base: u64, pub length: u64, pub kind: u64 }

#[repr(C)]
pub struct HhdmResponse { pub revision: u64, pub offset: u64 }
#[repr(C)]
pub struct ExecutableAddressResponse {
    pub revision: u64, pub physical_base: u64, pub virtual_base: u64,
}
#[repr(C)]
pub struct RsdpResponse { pub revision: u64, pub address: u64 }
#[repr(C)]
pub struct ModuleResponse {
    pub revision: u64, pub module_count: u64,
    pub modules: *const *const FilePrefix,
}
#[repr(C)]
pub struct FilePrefix {
    pub revision: u64, pub address: u64, pub size: u64,
}
#[repr(C)]
pub struct FramebufferResponse {
    pub revision: u64, pub framebuffer_count: u64,
    pub framebuffers: *const *const RawFramebuffer,
}
#[repr(C)]
pub struct RawFramebuffer {
    pub address: u64, pub width: u64, pub height: u64, pub pitch: u64,
    pub bpp: u16, pub memory_model: u8,
    pub red_size: u8, pub red_shift: u8,
    pub green_size: u8, pub green_shift: u8,
    pub blue_size: u8, pub blue_shift: u8,
}
pub const MEMMAP_ID: (u64, u64) = (0x67cf3d9d378a806f, 0xe304acdfc50c3c62);
pub const HHDM_ID: (u64, u64) = (0x48dcf1cb8ad2b852, 0x63984e959a98244b);
pub const EXEC_ID: (u64, u64) = (0x71ba76863cc55f63, 0xb2644a48c516a487);
pub const RSDP_ID: (u64, u64) = (0xc5e77b6b397e7b43, 0x27637845accdcf3c);
pub const MODULE_ID: (u64, u64) = (0x3e7e279702be32af, 0xca1c4f3bd1280cee);
pub const FB_ID: (u64, u64) = (0x9d5827dcd881dd75, 0xa3148604f6fab11b);
