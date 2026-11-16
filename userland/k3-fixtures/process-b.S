.section .text.k3_fixture,"ax",@progbits
.global _start
.type _start,@function
_start:
    movabs rax, 0x4b335f425f4f4b31
    std
    int 0x80
    # A valid return keeps this process running at CPL3.
    cld
    movabs rcx, 0x4b335f5245544f4b
    cmp rax, rcx
    jne 1f
    movabs rax, 0x4b335f425f4f4b32
    int 0x80
1:
    ud2
.size _start, .-_start
