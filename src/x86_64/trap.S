.equ NUM_INT, 256

.altmacro
.macro DEF_HANDLER, i
.Ltrap_handler_\i:
.if \i == 8 || (\i >= 10 && \i <= 14) || \i == 17
    # error code pushed by CPU
    push    \i          # interrupt vector
    jmp     .Ltrap_common
.else
    push    0           # fill in error code in TrapFrame
    push    \i          # interrupt vector
    jmp     .Ltrap_common
.endif
.endm

.macro DEF_TABLE_ENTRY, i
    .quad .Ltrap_handler_\i
.endm

.section .text
.code64
_trap_handlers:
.set i, 0
.rept NUM_INT
    DEF_HANDLER %i
    .set i, i + 1
.endr

.section .text
.code64
trap_common_entry:
.Ltrap_common:
    cld
    # CPU在进入异常时，会检查特权级，如果从低特权级进入高特权级，会自动切换栈（从TSS中获取并更新rsp和ss，同时将ss和rsp依次入栈）
    # CPU依次将RFLAGS、CS、RIP入栈
    # 在某些异常（如页错误）中，CPU还会将错误码入栈，在其他异常中，我们会在trap_handler_i中手动入栈0作为错误码

    # 检查CS寄存器，判断是否从用户态进入内核态
    test    byte ptr [rsp + 3 * 8], 3   # swap GS if it comes from user space
    jz      .Lsave_trap_frame                          # 来自内核态
    # 来自用户态
    swapgs
.Lsave_trap_frame:
    # 保留空间和fs_base占用的空间
    # 此时保留空间保存了原始的内核栈
    sub     rsp, 16                     # reserve space for fs_base
    # TODO: fs_base
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rdi
    push    rsi
    push    rbp
    push    rbx
    push    rdx
    push    rcx
    push    rax

    // 检查CS，判断是否来自用户态
    test    byte ptr [rsp + 20 * 8], 3
    jnz     go_back_to_kernel     // 来自用户态，恢复原本的内核栈
    // 来自内核态

.Ltrap_from_kernel:
    mov     rdi, rsp
    call    x86_trap_handler

    pop     rax
    pop     rcx
    pop     rdx
    pop     rbx
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    add     rsp, 16                     # pop fs_base
    test    byte ptr [rsp + 3 * 8], 3   # swap GS back if return to user space
    jz      2f
    swapgs
2:
    add     rsp, 16                     # pop vector, error_code
    iretq

.section .text
.code64
go_back_to_kernel:
    mov     rsp, [rsp + 16 * 8]  # rsp = __pad
    // 恢复callee-saved寄存器
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

.section .rodata
.global trap_handler_table
trap_handler_table:
.set i, 0
.rept NUM_INT
    DEF_TABLE_ENTRY %i
    .set i, i + 1
.endr

.global enter_user
.section .text
.code64
enter_user:
    // 现在是内核态，我们用类似协程的方式进入用户态
    // 参数是&mut TrapFrame (rdi)，表示用户的TrapFrame

    // 目前是内核栈，我们在栈上保存内核态的状态
    // 保存callee-saved寄存器
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    // 现在可以保存内核栈到TrapFrame中
    mov [rdi + 16 * 8], rsp  // 保存内核栈指针到__pad
    // mov gs:[offset __PERCPU_TSS + {tss_rsp0_offset}], rsp
    // TODO: TLS

    // 从TrapFrame中加载用户态的寄存器
    // 为了方便起见，我们把rsp设置为TrapFrame的地址，然后依次pop即可
    mov rsp, rdi      // 切换到用户的TrapFrame
    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15
    // 跳过fs_base, pad, vector, error_code
    add rsp, (4 + 5) * 8
    // rsp现在指向TrapFrame的顶部
    // 设置内核栈到TSS中
    mov gs:[offset __PERCPU_TSS + {tss_rsp0_offset}], rsp
    sub rsp, 5 * 8
    // rsp现在指向RIP
    swapgs
    // 依次pop RIP, CS, RFLAGS, RSP, SS
    iretq            // 跳转到用户态

.section .text
.code64
.global syscall_entry
syscall_entry:
    swapgs                                                      // switch to kernel gs
    mov     gs:[offset __PERCPU_USER_RSP_OFFSET], rsp           // save user rsp
    mov     rsp, gs:[offset __PERCPU_TSS + {tss_rsp0_offset}]   // switch to kernel stack

    sub     rsp, 8                                  // skip user ss
    push    gs:[offset __PERCPU_USER_RSP_OFFSET]    // user rsp
    push    r11                                     // rflags
    push    {ucode64}                               // cs
    push    rcx                                     // rip

    // 没有错误代码，压入0
    push    0
    // 压入伪造的trap_vector，我们约定使用0x80(LEGACY_SYSCALL_VECTOR)作为syscall的trap_vector
    push    0x80
    jmp     .Lsave_trap_frame
