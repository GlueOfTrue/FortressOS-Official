OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}
SECTIONS
{
    . = 0xffffffff80000000;
    __kernel_start = .;
    .text : ALIGN(0x1000) {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :text
    .rodata : ALIGN(0x1000) {
        *(.rodata .rodata.*)
    } :rodata
    .limine_requests : ALIGN(0x1000) {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :data
    .data : ALIGN(0x1000) {
        *(.data .data.*)
        /* Keep file-backed GOT entries before the zero-fill tail. */
        *(.got .got.*)
    } :data
    .bss : ALIGN(0x1000) {
        *(COMMON)
        *(.bss .bss.*)
    } :data
    . = ALIGN(0x1000);
    __kernel_end = .;
    ASSERT(__kernel_end > __kernel_start, "kernel has no loadable span")
    /DISCARD/ : {
        *(.eh_frame .eh_frame.*)
        *(.note .note.*)
        *(.comment)
    }
}
