OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    code PT_LOAD FLAGS(5);
}

SECTIONS
{
    . = 0x00400000;
    .text : ALIGN(0x1000) {
        KEEP(*(.text.k3_fixture))
    } :code
    ASSERT(SIZEOF(.text) > 0 && SIZEOF(.text) <= 0x1000,
           "a K3 process must fit in one nonempty executable page")
    ASSERT(_start == ADDR(.text), "a K3 process entry must start its code page")

    .shstrtab 0 : { *(.shstrtab) }

    /DISCARD/ : {
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.data .data.*)
        *(.bss .bss.*)
        *(.eh_frame .eh_frame.*)
        *(.note .note.*)
        *(.comment)
    }
}
