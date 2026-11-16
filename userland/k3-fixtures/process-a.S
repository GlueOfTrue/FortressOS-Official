.section .text.k3_fixture,"ax",@progbits
.global _start
.type _start,@function
_start:
    # RDI selects a fixture address. Zero selects the #UD case.
    test rdi, rdi
    jz 2f
    cmp rsi, 1
    je 1f
    mov rax, [rdi]
    jmp 2f
1:
    mov byte ptr [rdi], 0x5a
2:
    ud2
.size _start, .-_start
