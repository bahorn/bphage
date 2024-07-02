;
;                       ------------------------------
;                      [ dynamo.asm - bah - July 2024 ]
;                       ------------------------------
;
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

; useful offsets for discovering main()
%define e_entry_offset      24
; e_entry + 27 is the lea we want.
%define main_offset         27
; 31 is the rip offset we need
%define main_rip_offset     31

; useful offsets for discovering relocations
%define e_shoff_offset      40
%define e_shentsize_offset  58
%define sh_type_offset      4
%define dynamic_offset      24


; just the first 4 bytes of symbol names we are looking for
; nothing should clash with these.
%define DLOP                0x706f6c64
%define DLSY                0x79736c64


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


; THIS IS THE HEADER FROM
; https://www.muppetlabs.com/~breadbox/software/tiny/tiny-x64.asm.txt
; with minor changes to store a string an jump to my _start.
;
; The license it was provided under is the following:
; Copyright (C) 2021 Brian Raiter <breadbox@muppetlabs.com>
; Licensed under the GPL 2 or later.
    org 0x500000000

    db 0x7F                    ; e_ident
_fake_start:
    db "ELF"                   ; 3 REX prefixes (no effect)
    jmp _start
_str_bash:
    db "/bin/bash"
_str_null:
    db 0
    dw 2                       ; e_type
    dw 62                      ; e_machine
    dd 1                       ; e_version
phdr:
    dd 1                       ; e_entry       ; p_type
    dd 5                                       ; p_flags
    dq phdr - $$               ; e_phoff       ; p_offset
    dq phdr                    ; e_shoff       ; p_vaddr
    dd 0                       ; e_flags       ; p_paddr
    dw 0x40                    ; e_ehsize
    dw 0x38                    ; e_phentsize
    dw 1                       ; e_phnum       ; p_filesz
    dw 0x40                    ; e_shentsize
    dw 0                       ; e_shnum
    dw 0                       ; e_shstrndx
    dq 0x00400001                              ; p_memsz
    dq 0                                       ; p_align

; END HEADER


; register usage
; rsp - points the buffer we are using to start the copy of bash.
; r12 - length of the bash binary
; r13 - offset to main
; r14 - offset to dlopen
; r15 - offset to dlsym

_start:
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


;; Looking for .dynamic.
; Assumptions:
; * We will always find it.
; * It is not the first section
_find_dynamic:

; we use these to compute offsets, only for this loop.
    mov rsi, [rsp + e_shoff_offset]
    xor rdi, rdi
    mov di, [rsp + e_shentsize_offset]

    mov rax, rsp
    add rax, rsi
_find_dynamic_loop:
    add rax, rdi
    mov ebx, [rax + sh_type_offset]
    cmp ebx, SHT_DYNAMIC
    jne  _find_dynamic_loop

    mov rbx, [rax + dynamic_offset]


;; Finding offsets by reading .dynamic
;
; Register usage:
; rbx - pointer into relocation table
; rsi - d_tag
; rdi - d_val
; rcx - loop counter
; rsp - buffer

; r8  - strtab_offset
; r9  - symtab_offset
; r10 - jmprel_offset

; setup this loop
    add rbx, rsp
    mov ecx, 1024

_read_sht_dynamic:
; d_tag
    mov rsi, [rbx]
; d_val
    mov rdi, [rbx + 8]


; Implementing a case statement here
    cmp rsi, DT_NULL
    je  _read_sht_dynamic_done

    cmp rsi, DT_STRTAB
    jne _case_symtab_test
    mov r8, rdi

_case_symtab_test:
    cmp rsi, DT_SYMTAB
    jne _case_jmprel_test
    mov r9, rdi

_case_jmprel_test:
    cmp rsi, DT_JMPREL
    jne _read_sht_dynamic_tail
    mov r10, rdi

    add r10, rsp

_read_sht_dynamic_tail:
    add rbx, 16
    loop _read_sht_dynamic

_read_sht_dynamic_done:

; now lets finally resolve dlopen and dlsym
    xor r14, r14
    xor r15, r15
_process_relocs:
    xor rdi, rdi
    ; rela_offset
    mov rsi, [r10]
    ; rela idx
    mov edi, [r10 + 12]

    ; st_name
    xor rax, rax
    imul rdi, 24
    add rdi, rsp
    add rdi, r9
    mov eax, [rdi]

    ; relname offset
    mov ebx, eax
    add rbx, r8
    add rbx, rsp

    ; now we need to strcmp against one of target values.
    ; we only need to read 4 bytes to check.
    mov ebx, [rbx]
    cmp ebx, DLOP
    jne _case_dlsy
    mov r14, rsi

_case_dlsy:
    cmp ebx, DLSY
    jne _process_relocs_loop_tail
    mov r15, rsi

_process_relocs_loop_tail:
    add r10, 24
    cmp r15, 0
    je  _process_relocs

    cmp r14, 0
    je  _process_relocs

_apply_patches:
; memcpy the _patch in
    mov rcx, _patch_end - _patch_start
    lea rsi, [rel _patch_start]
    mov rdi, rsp
    add rdi, r13
    rep movsb

; start off with getting the offset to main in our buffer
    mov rdx, r13
    add rdx, rsp

; set the dlopen and dlsym jumps
; our last usage of r13, so fine to trash it.
    add r13, 9
    sub r14, r13
    mov [rdx + _dlopen_target - _patch_start], r14d

    add r13, (16 - 9)
    sub r15, r13
    mov [rdx + _dlsym_target - _patch_start], r15d

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

; end of the line

; Now lets move onto the patch we are applying to bash!

; rsp - buffer - we are just trashing the stack
; r12 - loop counter
; r13 - BIO_read
; r14 - libssl handle
; r15 - sbio / scratch

_patch_start:
    jmp _patch_code

; these are the opcodes for bnd jmp
_dlopen:
    db 0xf2, 0xff, 0x25
_dlopen_target:
    dd 0x41424344

_dlsym:
    db 0xf2, 0xff, 0x25
_dlsym_target:
    dd 0x41434344

_patch_code:
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
    mov rdx, 1024
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

_patch_end:
