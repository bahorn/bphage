; +---------------------------------------------------------------------------+
; |                    _           _                                          |
; |                   | |         | |                                         |
; |                   | |__  ____ | |__  _____  ____ _____                    |
; |                   |  _ \|  _ \|  _ \(____ |/ _  | ___ |                   |
; |                   | |_) ) |_| | | | / ___ ( (_| | ____|                   |
; |                   |____/|  __/|_| |_\_____|\___ |_____)                   |
; |                         |_|               (_____|                         |
; |                                                                           |
; +---------------------------------------------------------------------------+
; |                   bah / July 2024 / #BGGP5 / 637 bytes                    |
; +---------------------------------------------------------------------------+
; |                     nasm -f bin bphage.asm -o bphage                      |
; +---------------------------------------------------------------------------+
;
; Welcome adventurer, to my source and writeup!
;
; This is an ELF entry for #BGGP5 that runs on AMD64 linux machines.
;
; This works by modifying `main()` in `/bin/bash` to:
; * use `dlopen()` on `libssl`
; * resolve various symbols in `libssl`
; * connect to binary.golf:443 over TLS with libssl
; * send a HTTP request for /5/5
; * and write() out the contents to stdout
;
; You might be wondering why we'd go through the effort, when we could just
; do dynamic linking normally and not bother patching?
;
; The idea was that dynamic linking normally required a pretty hefty amount of
; headers (prior work[1] got 32bit ELFs down to 300 bytes, resolving only
; `exit()`, which is also out of date as you'd need to use GNU_HASH this time
; due to recent glibc changes.). And you'd still need to do setup glibc.
;
; I hope this is interesting, was my first time golfing a binary. Messed up
; my sleeping pattern hacking on this, listening to Chappell Roan on repeat!
;
; - bah
;
; [1] https://www.muppetlabs.com/~breadbox/software/tiny/somewhat.html
; _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
; +---------------------------------------------------------------------------+
; |An overview                                                                |
; +---------------------------------------------------------------------------+
;
; To summerize some of my code size optimization approaches:
; * use 32bit/16bit/8bit versions of registers where it made sense and lowered
;   the code size.
; * Instructions like test, cmove, xchg when they made sense.
; * Using only the main registers, not ones like r8, etc, due to their increased
;   size.
; * push/pop to do register swaps, allowing it to be done in 2 bytes.
; * no error checking, and a ton of assumptions :)
; * used spare space in the ELF header.
; * Trying to reuse registers, only applying small modifications to use less
;   instructions to set a suitable value, paying close attention to which ones
;   are free at a point time or not going to be trashed by something else.
; * In the loader portion, many of the registers are initially zero, which makes
;   things easier!
;
; Got a lot of those ideas from looking around and seeing what other people did,
; so thanks to all those golfers. The answers in [2] were pretty handy for some
; ideas.
;
; For checking instruction size, I mainly used the good old defuse.ca web 
; assembler, but i gather netspooky has a pretty nice repl called scare which is
; probably a better choice.
;
; Feel free to try and improve this! I'd love to see if actual dynamic linking
; could work (I think it might be viable on 32bit at least) and some compression
; for the patch.
;
; [2] https://codegolf.stackexchange.com/questions/132981/
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

; We need to resolve a symbol in the patch.
%macro  rsvlsym 2
        lea     rsi, [rel %2]
        mov     rdi, %1
        call    _dlsym
%endmacro

; +---------------------------------------------------------------------------+
; |The ELF header                                                             |
; +---------------------------------------------------------------------------+
; I started off with the header from [3] by Brian Raiter, licensed under the
; GPL 2 or later.
;
; The primary changes I made were replacing the start code to store the string
; "/bin/bash", and used some free bytes I saw being used in another entry to
; do a syscall and save 2 bytes overall.
;
; [3] https://www.muppetlabs.com/~breadbox/software/tiny/tiny-x64.asm.txt
        org     0x500000000

        db      0x7F                    ; e_ident
_fake_start:
        db      "ELF"                   ; 3 REX prefixes (no effect)
        jmp     _start
_str_bash:
        ; Some free space we can use, which has a nice null byte at the end
        db      "/bin/bash"
_str_memfd_name:
        ; Wanted a empty string to use as a name.
        db      0

        dw      2                       ; e_type
        dw      62                      ; e_machine
        dd      1                       ; e_version
phdr:
        dd      1                       ; e_entry       ; p_type
        dd      5                                       ; p_flags
        dq      phdr - $$               ; e_phoff       ; p_offset
        dq      phdr                    ; e_shoff       ; p_vaddr

; 6 bytes we can use, down to 4 because of the jump we need to do, as there is
; no benefit from using it at the end, as that will require a long jump making
; the savings pointless.
; I learnt this trick from reading mndz's entry [4].
;
; [4] https://github.com/0x6d6e647a/bggp-2024/blob/main/elf64.asm
_header_save:
        add     al, SYS_open
        syscall
        jmp     _read_bin

        dw      0x38                    ; e_phentsize
        dw      1                       ; e_phnum       ; p_filesz
        dw      0x40                    ; e_shentsize
        dw      0                       ; e_shnum
        dw      0                       ; e_shstrndx
        dq      0x00400001                              ; p_memsz
        ; p_align can be whatever

; END HEADER

; Register usage through the loader:
; * rsp - points the buffer we are using to start the copy of bash.
; * r14 - offset to dlopen
; * r15 - offset to dlsym

; +---------------------------------------------------------------------------+
; | Reading /bin/bash                                                         |
; +---------------------------------------------------------------------------+
; The first thing we need to do is get a copy of bash into memory.
; We'll use the stack to store it, but the rest of this is pretty normal.
; Just some syscalls to open/read it, and some code in the ELF header to save
; 2 bytes.
_start:
        ; Pushing the stack down, so we have space to store bash in it.
        ; Using 5MB, which should be fine in most cases, and be fine with the
        ; common stack sizes on linux.
        %assign STACKSPACE 0x500000
        sub     rsp, STACKSPACE

_open_bin:
        ; we don't need to clear out rdx or rsi as they are 0 initially.
        lea     rdi, [rel _str_bash]
        jmp     _header_save

_read_bin:
        ; eax should be 3 here.
        mov     edx, STACKSPACE
        regcopy rsi, rsp
        xchg    edi, eax
        xchg    eax, ebx ; EBX should be 0, so got SYS_read
        syscall

; +---------------------------------------------------------------------------+
; | Finding .dynamic                                                          |
; +---------------------------------------------------------------------------+
; We need to find the .dynamic section, and have two ways of doing that:
; * look at the program headers for PT_DYNAMIC
; * look at the section headers for SHT_DYNAMIC
; No real advantage to using either, essentially the same code for both.
;
; So we'll be using SHT_DYNAMIC, only because I implemented it first.
_find_dynamic:
        ; Only ELF section we care about
        %assign SHT_DYNAMIC 0x06
        %assign e_shoff_offset 40
        %assign e_shentsize 64
        %assign sh_type_offset 4
        %assign dynamic_offset 24
        ; we use these to compute offsets, only for this loop.
        mov     eax, [rsp + e_shoff_offset]
_find_dynamic_loop:
        add     eax, e_shentsize
        cmp     dword [rsp + rax + sh_type_offset], SHT_DYNAMIC
        jne     _find_dynamic_loop

        ; Offset into a 5mb file, so completely fine to use a 32bit reg here.
        mov     ebx, [rsp + rax + dynamic_offset]

; +---------------------------------------------------------------------------+
; | Discovering strtab, symtab and the relocations                            |
; +---------------------------------------------------------------------------+
; Finding offsets to the three entries in .dynamic that we need.
;
; The dynamic section is a table of the struct of two 8 byte values, d_tag and
; d_val.
; d_tag is just the name we are looking for, with d_val being the value.
; So through this we want to find the offsets for the strtab (so we can verify
; the name of a symbol), symtab (to get check the name) and the JMPREL
; relocations.
;
; JMPREL will point to a symbol, and a symbol will point to an offset in the
; strtab, so we need all of those to check the name for a relocation.
;
; The relocations we find can then be used to get the address that a pointer to
; the target function will be written to.
;
; Register usage:
; * rbx - offset into relocation table
; * rsi - d_tag
; * rdi - d_val
; * rsp - the start of /bin/bash
; * rbp - strtab_offset
; * rax - symtab_offset
; * rcx - jmprel_offset
_read_sht_dynamic:
        ; members of .dynamic we care about.
        %assign DT_STRTAB 5
        %assign DT_SYMTAB 6
        %assign DT_JMPREL 23

        ; d_tag, only care about the lower bits
        mov     esi, [rsp + rbx]
        ; d_val
        mov     edi, [rsp + rbx + 8]

        cmp     esi, DT_STRTAB
        cmove   ebp, edi

        cmp     esi, DT_SYMTAB
        cmove   eax, edi

        cmp     esi, DT_JMPREL
        cmove   ecx, edi

_read_sht_dynamic_tail:
        add     ebx, 16
        test    esi, esi
        jnz     _read_sht_dynamic

; +---------------------------------------------------------------------------+
; | Finding `dlopen()` and `dlsym()`                                          |
; +---------------------------------------------------------------------------+
; Now we have all values from .dynamic, we can now find the symbols we want.
; We'll do that by iterating through the relocations, looking up which symbol it
; refers to and checking the first 4 bytes of the symbols name against our
; targets.
;
; I came up with the trick involving checking just some bytes from the target
; symbol myself, but when I was reading through the writeup by Amethyst [5] I 
; found out netspooky used a similar trick in BGGP2.
; Though I have to use 4 bytes instead of two here.
;
; [5] https://amethyst.systems/blog/posts/entry-for-bggp5/
;
; register usage:
; * rbp - strtab_offset
; * rax - symtab_offset
; * rcx - jmprel_offset, modified to iterate through each entry in the table.
; * rsi - rela_offset
; * rdi - rela_idx and the 
; * r14 - offset to dlopen
; * r15 - offset to dlsym
_process_relocs:
        ; rela_offset
        mov     esi, [rsp + rcx]
        ; rela idx
        mov     edi, [rsp + rcx + 12]
        add     ecx, 24

        ; st_name
        imul    edi, 24
        add     edi, eax
        mov     ebx, [rsp + rdi]
    
        ; relname offset
        add     ebx, ebp
        
        ; just the first 4 bytes of symbol names we are looking for
        ; nothing should clash with these.
        %assign DLOP 0x706f6c64
        %assign DLSY 0x79736c64
        ; now we need to strcmp against one of target values.
        ; we only need to read 4 bytes to check.
        cmp     dword [rsp + rbx], DLOP
        cmove   r14d, esi

        cmp     dword [rsp + rbx], DLSY
        cmove   r15d, esi

_process_relocs_loop_tail:
        ; test reg, reg is just a easy way to check if a register is zero, in
        ; less bytes than a compare.
        test    r15, r15
        jz      _process_relocs

        test    r14, r14
        jz      _process_relocs

; +---------------------------------------------------------------------------+
; |Finding the offset to main()                                               |
; +---------------------------------------------------------------------------+
; Lets consider the disassembly for _start, which the ELFs e_entry will point  
; to:                                                                          
;   +--------------------------------------------------------------------+
;   |   0x0000000000032ef0 <+0>:     endbr64                             |:
;   |   0x0000000000032ef4 <+4>:     xor    ebp,ebp                      |:
;   |   0x0000000000032ef6 <+6>:     mov    r9,rdx                       |:
;   |   0x0000000000032ef9 <+9>:     pop    rsi                          |:
;   |   0x0000000000032efa <+10>:    mov    rdx,rsp                      |:
;   |   0x0000000000032efd <+13>:    and    rsp,0xfffffffffffffff0       |:
;   |   0x0000000000032f01 <+17>:    push   rax                          |:
;   |   0x0000000000032f02 <+18>:    push   rsp                          |:
;   |   0x0000000000032f03 <+19>:    xor    r8d,r8d                      |:
;   |   0x0000000000032f06 <+22>:    xor    ecx,ecx                      |:
;   |   0x0000000000032f08 <+24>:    lea    rdi,[rip+0xffffffffffffe471] |:
;   |   0x0000000000032f0f <+31>:    call   QWORD PTR [rip+0x119ed3]     |:
;   |   0x0000000000032f15 <+37>:    hlt                                 |:
;   +--------------------------------------------------------------------+:
;    ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
;                                                                             
; At +27, there is a lea instruction that loads an argument into rdi, right
; before calling a function.
;
; What could that be? Well its an offset to `main()`, as it is calling
; `__libc_start_main()`. :D
_discover_main:
        ; useful offsets for discovering main()
        %assign e_entry_offset 24
        ; e_entry + 27 is the lea we want.
        %assign main_offset 27
        ; 31 is the rip offset we need
        %assign main_rip_offset 31

        mov     eax, [rsp + e_entry_offset]
        regcopy rbx, rax
        add     eax, main_offset

        movsxd  rax, [rsp + rax]
        ; doing some assumptions here that this won't overflow.
        add     al, main_rip_offset
        add     ebx, eax

        ; start off with getting the offset to main in our buffer
        regcopy rdx, rbx
        add     rdx, rsp

; +---------------------------------------------------------------------------+
; |Applying the patches                                                       |
; +---------------------------------------------------------------------------+
; So, to patch the binary we want to copy our code into main(), which we'll use
; our previously obtained offset for and memcpy it in.
;
; Then we just need to patch the jump table we have at the start of the code to
; contain references to dlopen() and dlsym(), so we can freely use those in our
; patch.
_apply_patches:
        ; memcpy the _patch in
        mov     ecx, _patch_end - _patch_start
        lea     rsi, [rel _patch_start]
        regcopy rdi, rdx
        rep movsb

        ; set the dlopen and dlsym jumps
        ; our last usage of rbx, so fine to trash it.
        add     ebx, _dlopen_end - _patch_start
        sub     r14, rbx
        add     ebx, (_dlsym_end - _dlsym)
        sub     r15, rbx
    
        mov     [rdx + _dlopen_target - _patch_start], r14d
        mov     [rdx + _dlsym_target - _patch_start], r15d

; +---------------------------------------------------------------------------+
; |Executing the patched code                                                 |
; +---------------------------------------------------------------------------+
; Now we have patched the code, we can use a memfd to execute the code.
; Creating a memfd is pretty simple, just a basic syscall
_setup_memfd:
        xor     esi, esi
        lea     rdi, [rel _str_memfd_name]
        mov     eax, SYS_memfd_create
        syscall

; This one requires a bit of an explaination.
;
; write() takes its count (size_t) in (r|e)dx, and can write up to that or up to
; 0x7ffff000 bytes.
; It will also stop if it hits unmapped memory, which is what we are relying on.
; We really just need edx to larger than 0x500000, so then it'll copy
; everything.
; Which is why we use neg here, as we want to clear the top bits of rdx, and it
; will currently be rsp + an offset.
; Some values did seem to cause a segfault when I tried with inc and a few other
; instructions, but neg here seems reliable and I've never had a crash with it.
;
; For example if we run with strace we can see:
; write(4, "\177ELF\2\1\1\0\0\0\0\0\0\0"..., 3020150576) = 5251072
;
; Where hex(5251072) is 0x502000, our stack size and some change.
; 3020150576 is some random large value, which changes every execution, which we
; just made reliably large.
;
; eax comes from the setting up the memfd and is our fd, so can xchg it into edx
; as we trash it one line later to set the syscall number.
_write_memfd:
        neg     edx
        regcopy rsi, rsp
        xchg    edi, eax
        mov     al, SYS_write
        syscall

; To execute the memfd, we use execveat(), which is how the libc function 
; fexecve() is implemented.
_execve_memfd:
        %assign AT_EMPTY_PATH 0x1000
        mov     r8w, AT_EMPTY_PATH
        ; r10 was never used and is 0
        lea     rsi, [rel _str_memfd_name]
        ; rdi is the same as write()
        mov     eax, SYS_execveat
        jmp     _finish_exec

; we will now be in the patch after the execveat(), so lets move onto that!
; We slightly overly code as we have some extra bytes avaliable in the jump
; tables.
_patch_start:
        jmp     _patch_code

_dlopen:
        ; These are the opcodes for a relative jmp
        db      0xff, 0x25
_dlopen_target:
        ; We'll be overwriting the destination when we copy this into the target
        ; binary, so we can actually use them for stuff while we are trying to
        ; set that up.
        db      "abcd"
_dlopen_end:

_dlsym:
        db      0xff, 0x25
_dlsym_target:
_finish_exec:
        ; We have 4 bytes here that are free, so we'll use the space to save 2
        ; bytes.
        ; Sadly, I couldn't find a use for the "abcd" just above this as I
        ; couldn't find a 2 byte instruction to fill the space, or find a way
        ; to use the `and` 0x25 gives use (requires a 4 byte opperand)
        xor     edx, edx    ; db 0x31, 0xd2
        syscall             ; db 0x0f, 0x05
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
        ; just need to push one value to keep the stack aligned for the
        ; functions we will be calling, but we'll overwrite the stack that was
        ; allocated before us to store our responses from the server.
        push    rbp

        ; load libssl RTLD_LAZY
        ; This implements:
        ; > mov esi, RTLD_LAZY, as RTLD_LAZY is 1
        ; But saves 1 byte compared to that. (5 vs 4)
        xor     esi, esi
        inc     esi

        lea     rdi, [rel _str_libssl]
        call    _dlopen
        regcopy rbx, rax

        ; lets get some symbols, and setup the libssl context
        rsvlsym rbx, _str_TLS_client_method
        call    rax
        regcopy rbp, rax

        rsvlsym rbx, _str_SSL_CTX_new
        regcopy rdi, rbp
        call    rax
        regcopy rbp, rax

        rsvlsym rbx, _str_BIO_new_ssl_connect
        regcopy rdi, rbp
        call    rax
        regcopy rbp, rax


        %assign BIO_C_SET_CONNECT 0x64

        rsvlsym rbx, _str_BIO_ctrl
        lea     rcx, [rel _str_host]
        xor     edx, edx
        mov     sil, BIO_C_SET_CONNECT
        regcopy rdi, rbp
        call    rax

        rsvlsym rbx, _str_BIO_puts
        lea     rsi, [rel _str_req]
        regcopy rdi, rbp
        call    rax

        push    rsp
        push    rbp

        rsvlsym rbx, _str_BIO_read
        regcopy rbp, rax

        ; Reading the data twice, as the second read gets the contents.
        ; I decided to unroll this as it required slightly less bytes.
        pop     rdi
        pop     rsi
        ; setting to the lower bits of bp, which will read enough hopefully.
        mov     dx, bp
        call    rbp

        regcopy rsi, rsp
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
        db      "libssl.so.3", 0

; symbols we need to resolve
_str_BIO_ctrl:
        db      "BIO_ctrl", 0

_str_TLS_client_method:
        db      "TLS_client_method", 0

_str_BIO_new_ssl_connect:
        db      "BIO_new_ssl_connect", 0

_str_BIO_read:
        db      "BIO_read", 0

_str_BIO_puts:
        db      "BIO_puts", 0

_str_SSL_CTX_new:
        db      "SSL_CTX_new", 0

_str_req:
        db      "GET /5/5 HTTP/1.1"
        db      0x0a
        db      "Host:"
        db      "binary.golf"
        db      0x0a
        db      0x0a
; sending this as part of the request to save a byte.
; I would place it on the host line, but libssl doesn't like the newlines, so
; this is the best approach I have.
_str_host:
        db      "binary.golf:443", 0
_patch_end:
;
;     +-------------------------------------------------------------------+ 
;     |00000000: 7f45 4c46 eb42 2f62 696e 2f62 6173 6800  .ELF.B/bin/bash.|:
;     |00000010: 0200 3e00 0100 0000 0100 0000 0500 0000  ..>.............|:
;     |00000020: 1800 0000 0000 0000 1800 0000 0500 0000  ................|:
;     |00000030: 0402 0f05 eb22 3800 0100 4000 0000 0000  ....."8...@.....|:
;     |00000040: 0100 4000 0000 0000 4881 ec00 0050 0048  ..@.....H....P.H|:
;     |00000050: 8d3d b0ff ffff ebd8 ba00 0050 0054 5e97  .=.........P.T^.|:
;     |00000060: 930f 058b 4424 2883 c040 837c 0404 0675  ....D$(..@.|...u|:
;     |00000070: f68b 5c04 188b 341c 8b7c 1c08 83fe 050f  ..\...4..|......|:
;     |00000080: 44ef 83fe 060f 44c7 83fe 170f 44cf 83c3  D.....D.....D...|:
;     |00000090: 1085 f675 e08b 340c 8b7c 0c0c 83c1 186b  ...u..4..|.....k|:
;     |000000a0: ff18 01c7 8b1c 3c01 eb81 3c1c 646c 6f70  ......<...<.dlop|:
;     |000000b0: 440f 44f6 813c 1c64 6c73 7944 0f44 fe4d  D.D..<.dlsyD.D.M|:
;     |000000c0: 85ff 74d1 4d85 f674 cc8b 4424 1850 5b83  ..t.M..t..D$.P[.|:
;     |000000d0: c01b 4863 0404 041f 01c3 535a 4801 e2b9  ..Hc......SZH...|:
;     |000000e0: 4e01 0000 488d 3544 0000 0052 5ff3 a483  N...H.5D...R_...|:
;     |000000f0: c308 4929 de83 c306 4929 df44 8972 0444  ..I)....I).D.r.D|:
;     |00000100: 897a 0a31 f648 8d3d 03ff ffff b83f 0100  .z.1.H.=.....?..|:
;     |00000110: 000f 05f7 da54 5e97 b001 0f05 6641 b800  .....T^.....fA..|:
;     |00000120: 1048 8d35 e7fe ffff b842 0100 00eb 0aeb  .H.5.....B......|:
;     |00000130: 0cff 2561 6263 64ff 2531 d20f 0555 31f6  ..%abcd.%1...U1.|:
;     |00000140: ffc6 488d 3da7 0000 00e8 e3ff ffff 505b  ..H.=.........P[|:
;     |00000150: 488d 35ae 0000 0048 89df e8d8 ffff ffff  H.5....H........|:
;     |00000160: d050 5d48 8d35 d300 0000 4889 dfe8 c5ff  .P]H.5....H.....|:
;     |00000170: ffff 555f ffd0 505d 488d 3598 0000 0048  ..U_..P]H.5....H|:
;     |00000180: 89df e8b0 ffff ff55 5fff d050 5d48 8d35  .......U_..P]H.5|:
;     |00000190: 6800 0000 4889 dfe8 9bff ffff 488d 0dca  h...H.......H...|:
;     |000001a0: 0000 0031 d240 b664 555f ffd0 488d 3581  ...1.@.dU_..H.5.|:
;     |000001b0: 0000 0048 89df e87c ffff ff48 8d35 8700  ...H...|...H.5..|:
;     |000001c0: 0000 555f ffd0 5455 488d 355c 0000 0048  ..U_..TUH.5\...H|:
;     |000001d0: 89df e860 ffff ff50 5d5f 5e66 89ea ffd5  ...`...P]_^f....|:
;     |000001e0: 545e 92ff d592 545e b001 89c7 0f05 ebfe  T^....T^........|:
;     |000001f0: 6c69 6273 736c 2e73 6f2e 3300 4249 4f5f  libssl.so.3.BIO_|:
;     |00000200: 6374 726c 0054 4c53 5f63 6c69 656e 745f  ctrl.TLS_client_|:
;     |00000210: 6d65 7468 6f64 0042 494f 5f6e 6577 5f73  method.BIO_new_s|:
;     |00000220: 736c 5f63 6f6e 6e65 6374 0042 494f 5f72  sl_connect.BIO_r|:
;     |00000230: 6561 6400 4249 4f5f 7075 7473 0053 534c  ead.BIO_puts.SSL|:
;     |00000240: 5f43 5458 5f6e 6577 0047 4554 202f 352f  _CTX_new.GET /5/|:
;     |00000250: 3520 4854 5450 2f31 2e31 0a48 6f73 743a  5 HTTP/1.1.Host:|:
;     |00000260: 6269 6e61 7279 2e67 6f6c 660a 0a62 696e  binary.golf..bin|:
;     |00000270: 6172 792e 676f 6c66 3a34 3433 00         ary.golf:443.   |:
;     +-------------------------------------------------------------------+:
;      :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
;
; enj0y!
; EOT
