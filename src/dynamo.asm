;                      [ dynamo.asm - bah - July 2024 ]
;
; This is a BGGP5 entry that modifies a copy of `bash` in memory to inject code
; that downloads and displays the BGGP5 file.
;
; The idea here is that to use `libssl` and `dlopen` we need glibc setup, which
; takes a ton of space. So the trick here is this that we can save a ton of
; space if we just replace `main()` in an already existing binary.
;
; `bash` is used because its widely available by default on most distros, and
; already imports dlopen() and dlsym() from libc.
;
; To implement this, we need to:
; * Find the offset to `main()` so we can replace it.
; * Discover an address we can use to call `dlopen()` and `dlsym()`.
;
; The trick to finding `main()`'s offset is to:
; * look at the entrypoint (_start)
; * extract the offset just in a `lea` instruction right before
;   `__libc_start_main`, as it is passed to it.
;
; Next, to find the symbols we need:
; * the `.dynamic` section stores entries for the symbol strtab, symtab and
;   relocations.
; * With those, we can iterate through the relocations and discover which
;   symbol corresponds to the relocation.
; * With a symbol, we can check its name and compare against our target.
;
; With those, we just overwrite `main` with our payload and add references to
; the offsets we discovered.
; Then we can execute our modified file in memory by writing it to a memfd, and
; `fexecve()`'ing it.
;
; Our payload is pretty simple, as it is mostly derived from the smallest C
; implementation I could write to use `libssl` to connect to the site, just
; having to resolve a few symbols along the way.
;
; Anyway, enj0y the code!
;
; - bah

BITS 64

; Only ELF section we care about
%define SHT_DYNAMIC         0x06
; members of .dynamic we care about.
%define DT_NULL             0
%define DT_STRTAB           5
%define DT_SYMTAB           6
%define DT_JMPREL           23

; syscalls we need
%define SYS_read            0
%define SYS_write           1
%define SYS_open            2
%define SYS_memfd_create    319
%define SYS_execveat        322

; for execveat
%define AT_EMPTY_PATH       0x1000

; constants used by the patch
%define RTLD_LAZY           1
%define BIO_C_SET_CONNECT   0x64

; 5mb, as a yolo
%define STACKSPACE          0x500000

; useful offsets
%define e_entry_offset      24
; e_entry + 27 is the lea we want.
%define main_offset         27
; 31 is the rip offset we need
%define main_rip_offset     31

; Macros, these two are used for the patch
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

; register usage
; rsp - points the buffer we are using to start the copy of bash.
; r12 - length of the bash binary
; r13 - offset to main

_start:
    push rbp
    sub rsp, STACKSPACE

; open the binary, dump into the stack
_open_bin:
    xor rdx, rdx
    xor rsi, rsi
    lea rdi, [rel _str_bash]
    mov rax, SYS_open
    syscall

    mov rdx, STACKSPACE
    mov rsi, rsp
    mov rdi, rax
    mov rax, SYS_read
    syscall
    mov r12, rax

_discover_main:
    xor rdx, rdx
    mov rax, [rsp + e_entry_offset]
    mov r13, rax
    add rax, rsp
    add rax, main_offset
    ; so rax is now a signed 32bit int.
    mov rax, [rax]
    cdqe
    add r13, rax
    add r13, main_rip_offset
    jmp _inf

_find_rela:


_setup_memfd:
    xor rsi, rsi
    lea rdi, [rel _str_BIO_ctrl]
    mov rax, SYS_memfd_create
    syscall

_write_memfd:
    mov rdx, r12
    mov r12, rax
    mov rsi, rsp
    mov rdi, rax
    mov rax, SYS_write
    syscall

_execve_memfd:
    mov r8, AT_EMPTY_PATH
    xor r10, r10
    xor rdx, rdx
    lea rsi, [rel _str_null]
    mov rdi, r12
    mov rax, SYS_execveat
    syscall

; end of the code
    jmp _inf

; move into ELF header
_str_bash:
    db "/bin/bash"
_str_null:
    db 0

; Now lets move onto the patch we are applying to bash!

%define _dlopen $_patch - 14
%define _dlsym $_patch - 7

; rsp - buffer - we are just trashing the stack
; r12 - loop counter
; r13 - BIO_read
; r14 - libssl handle
; r15 - sbio / scratch

_patch:
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
    mov r12d, 2
read_twice:
    mov rsi, rsp
    mov rdi, r15
    mov rax, r13
    ; assuming rdi doesn't have the top bit set, else this fails!
    mov rdx, rdi
    call rax
    
    dec r12d
    jne read_twice

; print it!
    mov dl, al
    mov rsi, rsp

    mov al, 1
    mov rdi, rax
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
