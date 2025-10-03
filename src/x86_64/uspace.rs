//! Structures and functions for user space.

use memory_addr::VirtAddr;
use x86::{
    controlregs::{cr2, cr4},
    irq::{BREAKPOINT_VECTOR, INVALID_OPCODE_VECTOR, PAGE_FAULT_VECTOR},
};

use crate::{
    asm::{read_thread_pointer, write_thread_pointer},
    trap::{ExceptionKind, ReturnReason},
    x86_64::trap::{err_code_to_flags, IRQ_VECTOR_END, IRQ_VECTOR_START},
    TrapFrame,
};

const LEGACY_SYSCALL_VECTOR: u8 = 0x80;

/// Context to enter user space.
#[derive(Debug, Clone)]
pub struct UserContext(TrapFrame);

impl UserContext {
    /// Creates an empty context with all registers set to zero.
    pub const fn empty() -> Self {
        unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
    }

    /// Creates a new context with the given entry point, user stack pointer,
    /// and the argument.
    pub fn new(entry: usize, ustack_top: VirtAddr, arg0: usize) -> Self {
        use x86_64::registers::rflags::RFlags;

        use crate::GdtStruct;
        Self(TrapFrame {
            rdi: arg0 as _,
            rip: entry as _,
            cs: GdtStruct::UCODE64_SELECTOR.0 as _,
            rflags: RFlags::INTERRUPT_FLAG.bits(), // IOPL = 0, IF = 1
            rsp: ustack_top.as_usize() as _,
            ss: GdtStruct::UDATA_SELECTOR.0 as _,
            ..Default::default()
        })
    }

    /// Creates a new context from the given [`TrapFrame`].
    ///
    /// It copies almost all registers except `CS` and `SS` which need to be
    /// set to the user segment selectors.
    pub const fn from(mut tf: TrapFrame) -> Self {
        use crate::GdtStruct;
        tf.cs = GdtStruct::UCODE64_SELECTOR.0 as _;
        tf.ss = GdtStruct::UDATA_SELECTOR.0 as _;
        Self(tf)
    }

    /// Enter user space.
    ///
    /// It restores the user registers and jumps to the user entry point
    /// (saved in `sepc`).
    ///
    /// This function returns when an exception or syscall occurs.
    pub fn run(&mut self) -> ReturnReason {
        extern "C" {
            fn enter_user(tf: &mut TrapFrame);
        }

        let tf = &mut self.0;
        crate::asm::disable_irqs();
        unsafe { enter_user(tf) };

        // Trap handling for user space
        // switch_to_kernel_fs_base(tf);
        let ret = match tf.vector as u8 {
            // Page fault
            PAGE_FAULT_VECTOR => {
                let vaddr = va!(unsafe { cr2() });
                let access_flags = err_code_to_flags(tf.error_code)
                    .unwrap_or_else(|e| panic!("Invalid #PF error code: {:#x}", e));
                ReturnReason::PageFault(vaddr, access_flags)
            }
            // Syscall
            LEGACY_SYSCALL_VECTOR => ReturnReason::Syscall,
            // Hardware IRQs
            IRQ_VECTOR_START..=IRQ_VECTOR_END => {
                handle_trap!(IRQ, tf.vector as _);
                ReturnReason::Interrupt
            }
            // Other exceptions
            _ => ReturnReason::Exception(ExceptionInfo {
                trap_vector: tf.vector,
                rip: tf.rip,
                error_code: tf.error_code,
                cr4: unsafe { cr4() }.bits(),
            }),
        };
        // switch_to_user_fs_base(tf);
        crate::asm::enable_irqs();
        ret
    }

    /// Enters user space.
    ///
    /// It restores the user registers and jumps to the user entry point
    /// (saved in `rip`).
    /// When an exception or syscall occurs, the kernel stack pointer is
    /// switched to `kstack_top`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it changes processor mode and the stack.
    pub unsafe fn enter_uspace(&self, kstack_top: VirtAddr) -> ! {
        crate::asm::disable_irqs();
        assert_eq!(super::gdt::read_tss_rsp0(), kstack_top);
        switch_to_user_fs_base(&self.0);
        unsafe {
            core::arch::asm!("
                mov     rsp, {tf}
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
                add     rsp, 32     // skip fs_base, vector, error_code
                swapgs
                iretq",
            tf = in(reg) &self.0,
            options(noreturn),
            )
        }
    }
}

// TLS support functions
#[cfg(feature = "tls")]
#[percpu::def_percpu]
static KERNEL_FS_BASE: usize = 0;

/// Switches to kernel FS base for TLS support.
pub fn switch_to_kernel_fs_base(tf: &mut TrapFrame) {
    if tf.is_user() {
        tf.fs_base = read_thread_pointer() as _;
        #[cfg(feature = "tls")]
        unsafe {
            write_thread_pointer(KERNEL_FS_BASE.read_current())
        };
    }
}

/// Switches to user FS base for TLS support.
pub fn switch_to_user_fs_base(tf: &TrapFrame) {
    if tf.is_user() {
        #[cfg(feature = "tls")]
        KERNEL_FS_BASE.write_current(read_thread_pointer());
        unsafe { write_thread_pointer(tf.fs_base as _) };
    }
}

impl core::ops::Deref for UserContext {
    type Target = TrapFrame;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for UserContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExceptionInfo {
    pub trap_vector: u64,
    pub rip: u64,
    pub error_code: u64,
    pub cr4: usize,
}

impl ExceptionInfo {
    pub fn kind(&self) -> ExceptionKind {
        match self.trap_vector as u8 {
            BREAKPOINT_VECTOR => ExceptionKind::Breakpoint,
            INVALID_OPCODE_VECTOR => ExceptionKind::IllegalInstruction,
            _ => ExceptionKind::Other,
        }
    }
}
