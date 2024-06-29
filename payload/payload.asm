BITS 64

%define _dlopen $_main - 22
%define _dlsym $_main - 11

%define _libcrypto [rbp + 0x8]
%define _libssl [rbp + 0x10]

_main:
    endbr64
; define variables
    mov rax, 0x1337
    push rax
    push rax

    push rbp
    mov rbp, rsp
    sub rsp, 0x18

; load libcrypto RTLD_LAZY
    xor rax, rax
    mov rsi, 1
    lea rdi, [rel _str_libcrypto]
    call _dlopen_wrap
    mov [rbp + 0x8], rax
; load libssl RTLD_LAZY
    xor rax, rax
    mov rsi, 1
    lea rdi, [rel _str_libssl]
    call _dlopen_wrap
    mov [rbp + 0x10], rax

; lets get some symbols
    xor rax, rax
    lea rsi, [rel _str_BIO_ctrl]
    mov rdi, _libssl
    call _dlsym_wrap

; we need to resovle the following symbols:
; BIO_ctrl
; TLS_client_method
; BIO_new_ssl_connect
; BIO_read
; BIO_puts
; SSL_CTX_new

_inf:
    jmp _inf
    nop
    nop
    nop

_dlopen_wrap:
    endbr64
    call _dlopen
    ret

_dlsym_wrap:
    endbr64
    call _dlsym
    ret

_str_libssl:
    db "/usr/lib/x86_64-linux-gnu/libssl.so"
    db 0

_str_libcrypto:
    db "/usr/lib/x86_64-linux-gnu/libcrypto.so"
    db 0

; symbols we need to resolve
_str_BIO_ctrl:
    db "BIO_ctrl"
    db 0

_str_TLS_client_method:
    db "TLS_client_method"
    db 0

_str_BIO_new_ssl_connect:
    db "BIO_new_ssl_connect"
    db 0

_str_BIO_read:
    db "BIO_read"
    db 0

_str_BIO_puts:
    db "BIO_puts"
    db 0

_str_SSL_CTX_new:
    db "SSL_CTX_new"
    db 0
