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
%define BIO_C_SET_CONNECT 0x64

; rsp - buffer - we are just trashing the stack
; r12 - loop counter
; r13 - BIO_read
; r14 - libssl handle
; r15 - sbio / scratch

_main:
; just need to push one value, but we'll overwrite the stack that was allocated
; before us.
    push rbp

; load libssl RTLD_LAZY
    dlopen _str_libssl, RTLD_LAZY
    mov r14, rax

; lets get some symbols, and setup the libssl context
    resolve_symbol r14, _str_TLS_client_method
    call rax
    mov r15, rax

    resolve_symbol r14, _str_SSL_CTX_new
    mov rdi, r15
    call rax
    mov r15, rax

    resolve_symbol r14, _str_BIO_new_ssl_connect
    mov rdi, r15
    call rax
    mov r15, rax

    resolve_symbol r14, _str_BIO_ctrl
    lea rcx, [rel _str_host]
    xor rdx, rdx
    mov rsi, BIO_C_SET_CONNECT
    mov rdi, r15
    call rax

    resolve_symbol r14, _str_BIO_puts
    lea rsi, [rel _str_req]
    mov rdi, r15
    call rax

    resolve_symbol r14, _str_BIO_read
    mov r13, rax

; reading the data twice, as the second read gets the contents.
    mov r12, 2
two_loop:
    mov rsi, rsp
    mov rdi, r15
    mov rax, r13
    ; assuming rdi doesn't have the top bit set, else this fails!
    mov rdx, rdi
    call rax
    
    dec r12
    jne two_loop

; print it!
    mov rdx, rax
    mov rsi, rsp
    mov rdi, 1
    ; 1 is SYS_write
    mov rax, rdi
    syscall

_inf:
    jmp _inf

_str_libssl:
    db "/usr/lib/x86_64-linux-gnu/libssl.so"
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
