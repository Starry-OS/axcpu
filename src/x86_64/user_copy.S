.section .text
.global user_copy
user_copy:
    // Arguments: rdi (dst), rsi (src), rdx (size)
    stac                // disable SMAP (allow kernel to access user memory)
    mov rcx, rdx        // copy size to rcx
    rep movsb           // copy bytes from src to dst
    clac                // re-enable SMAP
    ret
