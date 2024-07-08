; A very simple dictionary based decompression algorithm, pretty similar to lz77
; but we always use references.
BITS 64

_start:
    ; we only need to set rdi once, as it'll get pushed up
    push rsp
    pop rdi
    xor eax, eax

loop:
    mov bx, [rel data + rax * 2]
    mov cl, bl

    test cl, cl
    jz done

    ; rdi is already set
    shr ebx, 8
    lea rsi, [rel blob + rbx]
    rep movsb
    
    inc eax
    jmp loop

done:
    jmp done

data:
    db 4, 0
    db 4, 6
    db 4, 0
    db 4, 6
    ; little endian, so fine to do this.
    db 0

blob:
    db "hell"
    db "owor"
    db "ld"
