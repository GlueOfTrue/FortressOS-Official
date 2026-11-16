.section .text.k3_fixture,"ax",@progbits
.global _start
.type _start,@function
_start:
    # RSI selects the cooperative continuation after the kernel schedules A.
    test rsi, rsi
    jz .Lsend
    cmp rsi, 1
    je .Lcheck_echo
    cmp rsi, 2
    jne .Lfail

    # Confirm the response to the disallowed rights expansion.
    cmp rdi, 1
    jne .Lfail
    mov eax, 0x43
    int 0x80
    jmp .Lfail

.Lsend:
    movabs rdi, 0x4b345f5041594c44
    mov eax, 0x40
    int 0x80
    jmp .Lfail

.Lcheck_echo:
    movabs rdx, 0x4b345f5041594c44
    cmp rdi, rdx
    jne .Lfail
    mov edi, 2                         # Rights::WRITE
    mov eax, 0x42

    int 0x80
.Lfail:
    ud2
.size _start, .-_start
