;
;                       ------------------------------
;                      [ dynamo.asm - bah - July 2024 ]
;                       ------------------------------
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
%define e_shentsize         64
%define sh_type_offset      4
%define dynamic_offset      24


; just the first 4 bytes of symbol names we are looking for
; nothing should clash with these.
%define DLOP                0x706f6c64
%define DLSY                0x79736c64


; Macros used for the patch
%macro resolve_symbol 2
    lea rsi, [rel %2]
    mov rdi, %1
    call _dlsym
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
; r14 - offset to dlopen
; r15 - offset to dlsym

_start:
    sub rsp, STACKSPACE

; open the binary, dump into the stack
_open_bin:
    ; we don't need to clear out rdx or rsi as they are 0 initially.
    ; xor rdx, rdx
    ; xor rsi, rsi
    lea rdi, [rel _str_bash]
    lea eax, [ecx + SYS_open]
    syscall
; eax should be 3 here.

    mov edx, STACKSPACE
    mov rsi, rsp
    mov edi, eax
    xor eax, eax ; SYS_read = 0
    syscall
    mov r12, rax

;; Looking for .dynamic.
; Assumptions:
; * We will always find it.
; * It is not the first section
_find_dynamic:

; we use these to compute offsets, only for this loop.
    mov rax, [rsp + e_shoff_offset]
_find_dynamic_loop:
    add rax, e_shentsize
    mov ebx, [rsp + rax + sh_type_offset]
    cmp ebx, SHT_DYNAMIC
    jne _find_dynamic_loop

; offset into a 5mb file, can't be that large.
    mov ebx, [rsp + rax + dynamic_offset]


;; Finding offsets by reading .dynamic
;
; Register usage:
; rbx - offset into relocation table
; rsi - d_tag
; rdi - d_val
; rsp - buffer
; r8  - strtab_offset
; r9  - symtab_offset
; r10 - jmprel_offset

; setup this loop
_read_sht_dynamic:
; d_tag, only care about the lower bits
    mov esi, [rsp + rbx]
; d_val
    mov rdi, [rsp + rbx + 8]

; Implementing a case statement here
    cmp esi, DT_STRTAB
    jne _case_symtab_test
    mov r8, rdi

_case_symtab_test:
    cmp esi, DT_SYMTAB
    jne _case_jmprel_test
    mov r9, rdi

_case_jmprel_test:
    cmp esi, DT_JMPREL
    jne _read_sht_dynamic_tail
    mov r10, rdi

_read_sht_dynamic_tail:
    add rbx, 16
    test rsi, rsi
    jnz  _read_sht_dynamic


; now lets finally resolve dlopen and dlsym

; we shouldn't need to zero out r14 and r15, as they aren't used up to this
; point, so they should be zero.
; xor r14, r14
; xor r15, r15

_process_relocs:
    ; rela_offset
    mov esi, [rsp + r10]
    ; rela idx
    mov edi, [rsp + r10 + 12]
    add r10, 24

    ; st_name
    imul edi, 24
    add edi, r9d
    mov ebx, [rdi + rsp]
    
    ; relname offset
    add rbx, r8

    ; now we need to strcmp against one of target values.
    ; we only need to read 4 bytes to check.
    mov ebx, [rsp + rbx]
    cmp ebx, DLOP
    jne _case_dlsy
    mov r14d, esi

_case_dlsy:
    cmp ebx, DLSY
    jne _process_relocs_loop_tail
    mov r15d, esi

_process_relocs_loop_tail:
; checking if either are 0.
    test r15, r15
    jz  _process_relocs

    test r14, r15
    jz  _process_relocs

_discover_main:
    mov rax, [rsp + e_entry_offset]
    mov rbx, rax
    add rax, main_offset

    movsxd rax, [rsp + rax]
    add rax, main_rip_offset
    add rbx, rax

; start off with getting the offset to main in our buffer
    mov rdx, rbx
    add rdx, rsp
_apply_patches:
; memcpy the _patch in
    mov ecx, _patch_end - _patch_start
    lea rsi, [rel _patch_start]
    mov rdi, rdx
    rep movsb

; set the dlopen and dlsym jumps
; our last usage of rbx, so fine to trash it.
    add rbx, _dlopen_end - _patch_start
    sub r14, rbx
    add rbx, (_dlsym_end - _dlsym)
    sub r15, rbx
    
    mov [rdx + _dlopen_target - _patch_start], r14d
    mov [rdx + _dlsym_target - _patch_start], r15d

_setup_memfd:
    xor esi, esi
    lea rdi, [rel _str_memfd_name]
    mov eax, SYS_memfd_create
    syscall

_write_memfd:
    mov rdx, r12
    mov r12, rax
    mov rsi, rsp
    mov rdi, rax
    mov al, SYS_write
    syscall

_execve_memfd:
    mov r8d, AT_EMPTY_PATH
    xor r10, r10
    xor edx, edx
    lea rsi, [rel _str_memfd_name]
    mov rdi, r12
    mov eax, SYS_execveat
    syscall

; we can move probably 2 or more instructions into the fake values we are using
; for dlopen and dlsym

; we will now be in the patch after the execveat(), so lets move onto that!

; rsp - buffer - we are just trashing the stack
; r12 - loop counter
; r13 - BIO_read
; r14 - libssl handle
; r15 - sbio / scratch

; we want to remove this, need to adjust our offset calculations earlier.
_patch_start:
    jmp _patch_code

; these are the opcodes for a relative jmp
_dlopen:
    db 0xff, 0x25
_dlopen_target:
_str_memfd_name:
    dd 0x00000000
_dlopen_end:

_dlsym:
    db 0xff, 0x25
_dlsym_target:
    dd 0x61626364
_dlsym_end:

_patch_code:
; just need to push one value to keep the stack aligned for the functions we
; will be calling but we'll overwrite the stack that was allocated before us.
    push rbp

; load libssl RTLD_LAZY
    ; mov esi, RTLD_LAZY, as RTLD_LAZY is 1
    ; this saves 1 byte compared to that. (5 vs 4)
    xor esi, esi
    inc esi

    lea rdi, [rel _str_libssl]
    call _dlopen
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
; we need to use ebx here, as cx gets trashed by the call.
    mov ebx, 2
read_twice:
    mov rsi, rsp
    mov rdi, r15
    mov rax, r13
    mov dx, 1024
    call rax
    
    dec ebx
    jne read_twice

; print it!
    mov dl, al
    mov rsi, rsp

    mov al, SYS_write
    mov edi, eax
    syscall

_inf:
    jmp _inf

_str_libssl:
    db "libssl.so.3"
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
