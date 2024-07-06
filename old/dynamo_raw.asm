;
;                       ------------------------------
;                      [ dynamo.asm - bah - July 2024 ]
;                       ------------------------------
;
;              "could go to hell... but we'll probably be fine!"
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

%macro regcopy 2
    push %2
    pop %1
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
_str_memfd_name:
    db 0
    dw 2                       ; e_type
    dw 62                      ; e_machine
    dd 1                       ; e_version
phdr:
    dd 1                       ; e_entry       ; p_type
    dd 5                                       ; p_flags
    dq phdr - $$               ; e_phoff       ; p_offset
    dq phdr                    ; e_shoff       ; p_vaddr

; 6 bytes we can use, down to 4 because of the jump we need to do, as there is
; no benefit from using it at the end, as that will require a long jump making
; the savings pointless.
_header_save:
    add al, SYS_open
    syscall
    jmp _read_bin

    dw 0x38                    ; e_phentsize
    dw 1                       ; e_phnum       ; p_filesz
    dw 0x40                    ; e_shentsize
    dw 0                       ; e_shnum
    dw 0                       ; e_shstrndx
    dq 0x00400001                              ; p_memsz
; we can apparenly just skip this?
;   dq 0                                       ; p_align

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
    jmp _header_save

_read_bin:
; eax should be 3 here.
    mov edx, STACKSPACE
    regcopy rsi, rsp
    xchg edi, eax
    xchg eax, ebx ; EBX should be 0, so got SYS_read
    syscall
    ; mov r12, rax

;; Looking for .dynamic.
; Assumptions:
; * We will always find it.
; * It is not the first section
_find_dynamic:

; we use these to compute offsets, only for this loop.
    mov eax, [rsp + e_shoff_offset]
_find_dynamic_loop:
    add eax, e_shentsize
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
; rbp - strtab_offset
; rax - symtab_offset
; rcx - jmprel_offset

; setup this loop
_read_sht_dynamic:
; d_tag, only care about the lower bits
    mov esi, [rsp + rbx]
; d_val
    mov edi, [rsp + rbx + 8]

; Implementing a case statement here
    cmp esi, DT_STRTAB
    cmove ebp, edi

    cmp esi, DT_SYMTAB
    cmove eax, edi

    cmp esi, DT_JMPREL
    cmove ecx, edi

_read_sht_dynamic_tail:
    add ebx, 16
    test esi, esi
    jnz  _read_sht_dynamic


; now lets finally resolve dlopen and dlsym

; we shouldn't need to zero out r14 and r15, as they aren't used up to this
; point, so they should be zero.
; xor r14, r14
; xor r15, r15

; input regs:
; rbp - strtab_offset
; rax - symtab_offset
; rcx - jmprel_offset

; rsi, rsp, rdi, rbx, rbp, rax, rcx
; r14, r15
_process_relocs:
    ; rela_offset
    mov esi, [rsp + rcx]
    ; rela idx
    mov edi, [rsp + rcx + 12]
    add ecx, 24

    ; st_name
    imul edi, 24
    add edi, eax
    mov ebx, [rsp + rdi]
    
    ; relname offset
    add ebx, ebp

    ; now we need to strcmp against one of target values.
    ; we only need to read 4 bytes to check.
    mov ebx, [rsp + rbx]
    cmp ebx, DLOP
    cmove r14d, esi

_case_dlsy:
    cmp ebx, DLSY
    cmove r15d, esi

_process_relocs_loop_tail:
; checking if either are 0.
    test r15, r15
    jz  _process_relocs

    test r14, r14
    jz  _process_relocs

_discover_main:
    mov eax, [rsp + e_entry_offset]
    regcopy rbx, rax
    add eax, main_offset

    movsxd rax, [rsp + rax]
    ; doing some assumptions here that this won't overflow.
    add al, main_rip_offset
    add ebx, eax

; start off with getting the offset to main in our buffer
    regcopy rdx, rbx
    add rdx, rsp
_apply_patches:
; memcpy the _patch in
    mov ecx, _patch_end - _patch_start
    lea rsi, [rel _patch_start]
    regcopy rdi, rdx
    rep movsb

; set the dlopen and dlsym jumps
; our last usage of rbx, so fine to trash it.
    add ebx, _dlopen_end - _patch_start
    sub r14, rbx
    add ebx, (_dlsym_end - _dlsym)
    sub r15, rbx
    
    mov [rdx + _dlopen_target - _patch_start], r14d
    mov [rdx + _dlsym_target - _patch_start], r15d

_setup_memfd:
    xor esi, esi
    lea rdi, [rel _str_memfd_name]
    mov eax, SYS_memfd_create
    syscall
; eax should be 4 now    

_write_memfd:
    ; we can just use a large size
    neg edx
    regcopy rsi, rsp
    xchg edi, eax
    mov al, SYS_write
    syscall

_execve_memfd:
    mov r8w, AT_EMPTY_PATH
    ; r10 was never used and is 0
    lea rsi, [rel _str_memfd_name]
    ; rdi is the same as write()
    mov eax, SYS_execveat
    jmp _finish_exec
; we can move probably 2 or more instructions into the fake values we are using
; for dlopen and dlsym

; we will now be in the patch after the execveat(), so lets move onto that!

; rsp - buffer - we are just trashing the stack
; rbx - libssl handle, loop counter
; rbp - BIO_read, scratch

; we want to remove this, need to adjust our offset calculations earlier.
_patch_start:
    jmp _patch_code

; these are the opcodes for a relative jmp
_dlopen:
    db 0xff, 0x25
_dlopen_target:
    db "abcd"
_dlopen_end:

_dlsym:
    db 0xff, 0x25
_dlsym_target:
_finish_exec:
    xor edx, edx ; db 0x31, 0xd2
    syscall      ; db 0x0f, 0x05
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
    regcopy rbx, rax

; lets get some symbols, and setup the libssl context
    resolve_symbol rbx, _str_TLS_client_method
    call rax
    regcopy rbp, rax

    resolve_symbol rbx, _str_SSL_CTX_new
    regcopy rdi, rbp
    call rax
    regcopy rbp, rax

    resolve_symbol rbx, _str_BIO_new_ssl_connect
    regcopy rdi, rbp
    call rax
    regcopy rbp, rax

    resolve_symbol rbx, _str_BIO_ctrl
    lea rcx, [rel _str_host]
    xor edx, edx
    mov sil, BIO_C_SET_CONNECT
    regcopy rdi, rbp
    call rax

    resolve_symbol rbx, _str_BIO_puts
    lea rsi, [rel _str_req]
    regcopy rdi, rbp
    call rax

    push rsp
    push rbp

    resolve_symbol rbx, _str_BIO_read
    regcopy rbp, rax

; reading the data twice, as the second read gets the contents.
    pop rdi
    pop rsi
    ; setting to the lower bits of bp, which will read enough hopefully.
    mov dx, bp
    call rbp

    regcopy rsi, rsp
    ; rax is the len of the headers, which is big enough to hold the contents.
    ; we can use xchg as eax is about to get trashed.
    xchg edx, eax
    call rbp
    
; print it!
    xchg edx, eax
    regcopy rsi, rsp
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

_str_req:
    db "GET /5/5 HTTP/1.1"
    db 0x0a
    db "Host:"
    db "binary.golf"
    db 0x0a
    db 0x0a
; sending this as part of the request to save bytes lol
; I would place it on the host line, but libssl doesn't like the newlines.
_str_host:
    db "binary.golf:443"
    db 0
_patch_end:
