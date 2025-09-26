.section .text
.global user_copy
user_copy:
    // Arguments: rdi (dst), rsi (src), rdx (size)
    mov rcx, rdx        // copy size to rcx
    cld                 // clear direction flag(DF=0) for forward direction
    // copy rcx bytes from [rsi] to [rdi]
    rep movsb           // copy bytes from src to dst
    mov rax, rcx        // return remain bytes
    ret
