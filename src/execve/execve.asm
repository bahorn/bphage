BITS 64
        org         0x5_00_00_00_00

_ehdr:
        db          0x7F                    ; e_ident
_fake_start:
        db          "ELF"                   ; 3 REX prefixes (no effect)

_step1: ; 12 bytes spare here
        lea         rdi, [rel argv_0]       ; 7 bytes
        add         al, 59                  ; 2 bytes
        push        rcx                     ; 1 byte
        jmp         _step2                  ; 2 bytes

        dw          2                       ; e_type
        dw          62                      ; e_machine
        dd          1                       ; e_version
phdr:
        dd          1                       ; e_entry       ; p_type
        dd          5                                       ; p_flags
        dq          phdr - $$               ; e_phoff       ; p_offset
        dq          phdr                    ; e_shoff       ; p_vaddr

_step3: ; another spare slot for 6 bytes
        push        rcx                     ; 1 byte
        push        rdi                     ; 1 byte
        push        rsp                     ; 1 byte
        pop         rsi                     ; 1 byte
        syscall                             ; 2 bytes

        dw          0x38                    ; e_phentsize
        dw          1                       ; e_phnum       ; p_filesz
        dw          0x40                    ; e_shentsize
        dw          0                       ; e_shnum
        dw          0                       ; e_shstrndx
        dq          0x00400001                              ; p_memsz

_step2: ; also p_align
        push        rdi                     ; 1 byte
        pop         rcx                     ; 1 byte
        add         cl, argv_1 - argv_0     ; 3 bytes
        push rcx                            ; 1 byte
        add         cl, argv_2 - argv_1     ; 3 bytes
        jmp         _step3                  ; 2 bytes

argv_0:
        db          "/bin/curl", 0
argv_1:
        db          "-L", 0
argv_2: ; including "https://" in the url (8 bytes) is 1 byte more expensive
        ; than including -L
        db          "binary.golf/5/5"
