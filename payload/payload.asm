BITS 64

%macro resolve_symbol 2
    lea rsi, [rel %2]
    mov rdi, %1
    call _dlsym
%endmacro

%macro dlopen 2
    mov rsi, %2
    lea rdi, [rel %1]
    call _dlopen
%endmacro

%define _dlopen $_main - 22
%define _dlsym $_main - 11

%define RTLD_LAZY 1
%define BIO_C_SET_CONNECT 100
%define SYS_write 0x1

; Setup our stack layout
%define _libcrypto [rsp + 0x8]
%define _libssl [rsp + 0x10]
; used as a scratch value until we hit BIO_new_ssl_connect()
%define _sbio [rsp + 0x18]
%define _bio_read [rsp + 0x20]
%define _read_loop [rsp + 0x28]
%define _buf [rsp + 0x30]

_main:
    push rbp
; define variables
    mov rbp, rsp
    sub rsp, 0x440

; load libcrypto RTLD_LAZY
    dlopen _str_libcrypto, RTLD_LAZY
    mov _libcrypto, rax

; load libssl RTLD_LAZY
    dlopen _str_libssl, RTLD_LAZY
    mov _libssl, rax

; lets get some symbols, and setup the libssl context
    resolve_symbol _libssl, _str_TLS_client_method
    call rax
    mov _sbio, rax

    resolve_symbol _libssl, _str_SSL_CTX_new
    mov rdi, _sbio
    call rax
    mov _sbio, rax

    resolve_symbol _libssl, _str_BIO_new_ssl_connect
    mov rdi, _sbio
    call rax
    mov _sbio, rax

    resolve_symbol _libssl, _str_BIO_ctrl
    lea rcx, [rel _str_host]
    xor rdx, rdx
    mov rsi, BIO_C_SET_CONNECT
    mov rdi, _sbio
    call rax

    resolve_symbol _libssl, _str_BIO_puts
    lea rsi, [rel _str_req]
    mov rdi, _sbio
    call rax

    resolve_symbol _libssl, _str_BIO_read
    mov _bio_read, rax

; reading the data twice, as the second read gets the contents.
    mov ecx, 2
two_loop:
    mov _read_loop, ecx
    mov rdx, 1024
    lea rsi, _buf
    mov rdi, _sbio
    mov rax, _bio_read
    call rax

    mov ecx, _read_loop
    loop two_loop

; print it!
    mov rdx, rax
    lea rsi, _buf
    mov rdi, 1
    mov rax, SYS_write
    syscall
_inf:
    jmp _inf

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

_str_host:
    db "binary.golf:443"
    db 0

_str_req:
    db "GET /5/5 HTTP/1.1"
    db 0x0a
    db "Host: binary.golf"
    db 0x0a
    db 0x0a
    db 0
