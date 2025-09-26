//! Structures and functions for user space.

use core::ops::{Deref, DerefMut};

use memory_addr::VirtAddr;
use x86::{
    controlregs::{cr2, cr4},
    irq::{BREAKPOINT_VECTOR, INVALID_OPCODE_VECTOR, PAGE_FAULT_VECTOR},
};

pub use crate::uspace_common::{ExceptionKind, ReturnReason};
use crate::{
    TrapFrame,
    asm::{read_thread_pointer, write_thread_pointer},
    x86_64::trap::{IRQ_VECTOR_END, IRQ_VECTOR_START, err_code_to_flags},
};

const LEGACY_SYSCALL_VECTOR: u8 = 0x80;

/// Context to enter user space.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
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

    /// Enters user space.
    ///
    /// It restores the user registers and jumps to the user entry point
    /// (saved in `rip`).
    ///
    /// This function returns when an exception or syscall occurs.
    pub fn run(&mut self) -> ReturnReason {
        extern "C" {
            fn enter_user(tf: &mut TrapFrame);
        }

        let tf = &mut self.0;
        crate::asm::disable_irqs();
        switch_to_user_fs_base(tf);
        unsafe { enter_user(tf) };
        switch_to_kernel_fs_base(tf);
        // Trap handling for user space
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
        crate::asm::enable_irqs();
        ret
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

impl Deref for UserContext {
    type Target = TrapFrame;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UserContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Information about an exception that occurred in user space.
#[derive(Debug, Clone, Copy)]
pub struct ExceptionInfo {
    /// The trap vector number.
    pub trap_vector: u64,
    /// The instruction pointer at which the exception occurred.
    pub rip: u64,
    /// The error code associated with the exception, if any.
    pub error_code: u64,
    /// The value of the CR4 register at the time of the exception.
    pub cr4: usize,
}

impl ExceptionInfo {
    /// Returns a generalized kind of this exception.
    pub fn kind(&self) -> ExceptionKind {
        match self.trap_vector as u8 {
            BREAKPOINT_VECTOR => ExceptionKind::Breakpoint,
            INVALID_OPCODE_VECTOR => ExceptionKind::IllegalInstruction,
            _ => ExceptionKind::Other,
        }
    }
}
