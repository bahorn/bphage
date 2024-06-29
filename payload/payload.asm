BITS 64

%define _dlopen $_main - 22
%define _dlsym $_main - 11


_main:
    endbr64
    push rbp
    push rbx
    call _wrap
_inf:
    jmp _inf
    nop
    nop
    nop

_wrap:
    endbr64
    xor rax, rax
    mov rsi, 1
    lea rdi, [rel _str_libssl]
    call _dlopen
    ret

_str_libssl:
    db "/usr/lib/x86_64-linux-gnu/libssl.so"
    db 0
