BITS 64

; The syscalls we need.
%assign SYS_write           1
%assign SYS_open            2
%assign SYS_memfd_create    319
%assign SYS_execveat        322

; This Macro provides the best way of moving values between two registers,
; assuming you haven't completely trashed rsp.
%macro  regcopy 2
        push    %2
        pop     %1
%endmacro

%macro  rslvsym 2
        pop     rsi
        push    rsi
        add     rsi, %2 - _str_libssl
        regcopy rdi, %1
        call    _dlsym
%endmacro


_patch_start:
        jmp     _patch_code

_dlopen:
        ; These are the opcodes for a relative jmp
        db      0xff, 0x25
_dlopen_target:
_step_1:
        db 0, 0
        db 0, 0
_dlopen_end:

_dlsym:
        db      0xff, 0x25
_dlsym_target:
_step_2:
        db 0, 0
        db 0, 0
_dlsym_end:

; +---------------------------------------------------------------------------+
; |What are we implementing?                                                  |
; +---------------------------------------------------------------------------+
; To give a rougth explaination of our patch, here is the C version I wrote to
; figure out all the calls I needed to make:
; +---------------------------------------------------------------------------+
; |   1   │ #include <unistd.h>                                               |
; |   2   │ #include <openssl/ssl.h>                                          |
; |   3   │                                                                   |
; |   4   │ #define HOSTNAME "binary.golf:443"                                |
; |   5   │ #define REQ "GET /5/5 HTTP/1.1\r\nHost: " HOSTNAME "\r\n\r\n"     |
; |   6   │                                                                   |
; |   7   │ #define BUFLEN 1024                                               |
; |   8   │                                                                   |
; |   9   │ int main()                                                        |
; |  10   │ {                                                                 |
; |  11   │     BIO *sbio = NULL;                                             |
; |  12   │     char tmpbuf[BUFLEN];                                          |
; |  13   │     SSL_CTX *ctx;                                                 |
; |  14   │     SSL_CONF_CTX *cctx;                                           |
; |  15   │     SSL *ssl;                                                     |
; |  16   │                                                                   |
; |  17   │     const void *m = TLS_client_method();                          |
; |  18   │     ctx = SSL_CTX_new(m);                                         |
; |  19   │     sbio = BIO_new_ssl_connect(ctx);                              |
; |  20   │     BIO_ctrl(sbio, BIO_C_SET_CONNECT, 0, HOSTNAME);               |
; |  21   │     BIO_puts(sbio, REQ);                                          |
; |  22   │     BIO_read(sbio, tmpbuf, BUFLEN);                               |
; |  23   │     size_t len = BIO_read(sbio, tmpbuf, BUFLEN);                  |
; |  24   │     write(1, tmpbuf, len);                                        |
; |  25   │ }                                                                 |
; +---------------------------------------------------------------------------+
; Overall, pretty simple. `BIO_ctrl()` sits behind a macro when you follow
; tutorials, but thats what setting the hostname calls under the hood.
; It'll malloc everything by itself, so as long as we are fine trashing the
; stack we don't need to really do any other memory allocations.
; 
; Should note I had to pay a lot of attention to the SYS V ABI[6], which heavily
; restricted which registers I could use, as many registers get trashed when we
; call into libssl and libc.
;
; So throughout this code I primaily used the following registers:
; * rsp - buffer - we are just trashing the stack to store the request.
; * rbx - libssl handle
; * rbp - BIO_read, scratch
; As they do not get trashed by the calls.
;
; [6] https://wiki.osdev.org/System_V_ABI
_patch_code:
        ; load libssl RTLD_LAZY
        ; This implements:
        ; > mov esi, RTLD_LAZY, as RTLD_LAZY is 1
        ; But saves 1 byte compared to that. (5 vs 4)
        xor     esi, esi
        inc     esi

        lea     rdi, [rel _str_libssl]
        push    rdi
        call    _dlopen
        regcopy rbx, rax

        ; lets get some symbols, and setup the libssl context
        rslvsym rbx, _str_TLS_client_method
        regcopy rdi, rbp
        call    rax
        regcopy rbp, rax

        rslvsym rbx, _str_SSL_CTX_new
        regcopy rdi, rbp
        call    rax
        regcopy rbp, rax

        rslvsym rbx, _str_BIO_new_ssl_connect
        regcopy rdi, rbp
        call    rax
        regcopy rbp, rax

        %assign BIO_C_SET_CONNECT 0x64

        rslvsym rbx, _str_BIO_ctrl
        lea     rcx, [rel _str_host]
        xor     edx, edx
        mov     sil, BIO_C_SET_CONNECT
        regcopy rdi, rbp
        call    rax

        rslvsym rbx, _str_BIO_puts
        lea     rsi, [rel _str_req]
        regcopy rdi, rbp
        call    rax

        rslvsym rbx, _str_BIO_read

        regcopy rdi, rbp
        regcopy rbp, rax
        regcopy rsi, rsp

        push rdi
        push rsi

        ; Reading the data twice, as the second read gets the contents.
        ; I decided to unroll this as it required slightly less bytes.
        ; Taking lower bits of rax, which will be part of the address for
        ; BIO_read.
        ; Another one of the more questionable optimizations.
        xchg    dx, ax
        call    rbp

        pop rsi
        pop rdi

        ; rax is the len of the headers, which is big enough to hold the 
        ; contents.
        ; we can use xchg as eax is about to get trashed.
        xchg    edx, eax
        call    rbp
    
        ; Write to stdout
        xchg    edx, eax
        regcopy rsi, rsp
        mov     al, SYS_write
        mov     edi, eax
        syscall

; Don't want to crash and exit() requires far more code and we have completely
; trashed large amounts of code so not safe to return.
_inf:
        jmp     _inf


; +---------------------------------------------------------------------------+
; |Strings                                                                    |
; +---------------------------------------------------------------------------+
; Sadly, we need a lot of strings, I'd love to come up with a way of either
; generating these or something else, but tbh more work than the benefit.
_str_libssl:
        ; You can drop the .3 on some distros, but needed it to be reliable.
        ; Older distros do not have libssl3, so it might need to be changed to
        ; 1.1.
        db      "libssl.so.3", 0

; symbols we need to resolve
_str_TLS_client_method:
        db      "TLS_client_method", 0

_str_SSL_CTX_new:
        db      "SSL_CTX_new", 0

_str_BIO_new_ssl_connect:
        db      "BIO_new_ssl_connect", 0

_str_BIO_ctrl:
        db      "BIO_ctrl", 0

_str_BIO_puts:
        db      "BIO_puts", 0

_str_BIO_read:
        db      "BIO_read", 0

_str_req:
        db      "GET /5/5 HTTP/1.1"
        db      0x0a
        db      "Host:"
        db      "binary.golf:443"
        db      0x0a
        db      0x0a
; sending this as part of the request to save a byte.
; I would place it on the host line, but libssl doesn't like the newlines, so
; this is the best approach I have.
_str_host:
        db      "binary.golf:443", 0
_patch_end:
;
; *insert hexdump here when ready for submission*
;
; enj0y!
; EOT
