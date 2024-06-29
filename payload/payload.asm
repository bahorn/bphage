BITS 64


_main:
    endbr64
    jmp $_main - 11
_inf:
    jmp _inf
    nop
    nop
    nop
