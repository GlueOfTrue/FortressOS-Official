.section .text.k3_fixture,"ax",@progbits
.global _start
.type _start,@function
_start:
    test rsi, rsi
    jne .Lfail
    movabs rdx, 0x4b345f5041594c44
    cmp rdi, rdx
    jne .Lfail

    # Echo the actual payload delivered by the kernel in RDI.
    mov eax, 0x41
    int 0x80
.Lfail:
    ud2
.size _start, .-_start
