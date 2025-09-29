//! Structures and functions for user space.

use core::{
    arch::naked_asm,
    mem::offset_of,
    ops::{Deref, DerefMut},
};

use aarch64_cpu::registers::{ESR_EL1, FAR_EL1, Readable};
use tock_registers::LocalRegisterCopy;
use memory_addr::VirtAddr;

pub use crate::uspace_common::{ExceptionKind, ReturnReason};

use crate::{
    trap::PageFaultFlags,
    TrapFrame,
    aarch64::trap::{TrapKind,data_abort_access_flags, is_valid_page_fault},
};

/// Context to enter user space.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct UserContext {
    tf: TrapFrame,
    sp_el1: u64,
}

#[inline(always)]
fn handle_data_abort_lower(ctx: &UserContext, iss: u64) -> ReturnReason {
    let access_flags = data_abort_access_flags(iss) | PageFaultFlags::USER;
    let vaddr = va!(FAR_EL1.get() as usize);
    if !is_valid_page_fault(iss)
    {
        panic!(
            "Invalid Data Abort ISS {:#x} @ {:#x}, fault_vaddr={:#x}, ESR={:#x} ({:?}):\n{:#x?}\n{}",
            iss,
            ctx.tf.elr,
            vaddr,
            ESR_EL1.get(),
            access_flags,
            ctx.tf,
            ctx.tf.backtrace()
        );
    }

    ReturnReason::PageFault(vaddr, access_flags)
}

#[inline(always)]
fn handle_instruction_abort_lower(ctx: &UserContext, iss: u64) -> ReturnReason {
    let access_flags = PageFaultFlags::EXECUTE | PageFaultFlags::USER;
    let vaddr = va!(FAR_EL1.get() as usize);
    if !is_valid_page_fault(iss) {
        panic!(
            "Invalid Lower Instruction Abort ISS {:#x} @ {:#x}, fault_vaddr={:#x}, ESR={:#x} ({:?}):\n{:#x?}\n{}",
            iss,
            ctx.tf.elr,
            vaddr,
            ESR_EL1.get(),
            access_flags,
            ctx.tf,
            ctx.tf.backtrace()
        );
    }
    ReturnReason::PageFault(vaddr, access_flags)
}

impl UserContext {
    /// Creates an empty context with all registers set to zero.
    pub const fn empty() -> Self {
        Self { tf: TrapFrame::new(), sp_el1: 0}
    }

    /// Creates a new context with the given entry point, user stack pointer,
    /// and the argument.
    pub fn new(entry: usize, ustack_top: VirtAddr, arg0: usize) -> Self {
        let mut r = [0u64; 31];
        r[0] = arg0 as u64;
        Self {
            tf: TrapFrame {
                r,
                usp: ustack_top.as_usize() as u64, // 假设 VirtAddr 有 as_u64 方法
                tpidr: 0,
                elr: entry as u64,
                spsr: 0, // recommend to set to 0
            },
            sp_el1: 0, // stack pointer for EL1, will be set in _enter_user
        }
    }

    /// Creates a new context from the given [`TrapFrame`].
    pub const fn from(tf: TrapFrame) -> Self {
        Self {tf, sp_el1: 0 }
    }

    /// Enters user space.
    ///
    /// It restores the user registers and jumps to the user entry point
    /// (saved in `elr`).
    ///
    /// This function returns when an exception or syscall occurs.
    pub fn run(&mut self) -> ReturnReason {
        crate::asm::disable_irqs();
        let tp_kind = unsafe { enter_user(self) };
        let ret = match tp_kind {
            TrapKind::Irq => {
                handle_trap!(IRQ,0);
                ReturnReason::Interrupt
            },
            TrapKind::Synchronous => {
                let esr = ESR_EL1.extract();
                let iss = esr.read(ESR_EL1::ISS);
                match esr.read_as_enum(ESR_EL1::EC) {
                    Some(ESR_EL1::EC::Value::SVC64) => {
                        ReturnReason::Syscall
                    }
                    Some(ESR_EL1::EC::Value::DataAbortLowerEL) =>
                        handle_data_abort_lower(&self, iss),
                    Some(ESR_EL1::EC::Value::InstrAbortLowerEL) =>
                        handle_instruction_abort_lower(&self, iss),
                    _ => {
                        let stval = aarch64_cpu::registers::FAR_EL1.get() as usize;
                        ReturnReason::Exception(ExceptionInfo {
                            esr,
                            stval,
                        })
                    }
                }
            }
            _ => ReturnReason::Unknown,
        };
        crate::asm::enable_irqs();
        ret
    }
}

impl Deref for UserContext {
    type Target = TrapFrame;

    fn deref(&self) -> &Self::Target {
        &self.tf
    }
}

impl DerefMut for UserContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tf
    }
}

impl From<TrapFrame> for UserContext {
    fn from(tf: TrapFrame) -> Self {
        Self::from(tf)
    }
}

#[derive(Debug, Clone, Copy)]
/// Information about an exception that occurred in user space.
pub struct ExceptionInfo {
    /// The exception class.
    pub esr: LocalRegisterCopy<u64, ESR_EL1::Register>,
    /// The faulting address.
    pub stval: usize,
}

impl ExceptionInfo {
    /// Returns a generalized kind for this exception.
    pub fn kind(&self) -> ExceptionKind {
        match self.esr.read_as_enum(ESR_EL1::EC) {
            Some(ESR_EL1::EC::Value::BreakpointLowerEL) => ExceptionKind::Breakpoint,
            Some(ESR_EL1::EC::Value::IllegalExecutionState) => ExceptionKind::IllegalInstruction,
            Some(ESR_EL1::EC::Value::PCAlignmentFault)
            | Some(ESR_EL1::EC::Value::SPAlignmentFault) => ExceptionKind::Misaligned,
            _ => ExceptionKind::Other,
        }
    }
}

#[unsafe(naked)]
unsafe extern "C" fn enter_user(_ctx: &mut UserContext) -> TrapKind {
    naked_asm!(
        "
        // -- save kernel context --
        sub     sp, sp, 12 * 8
        stp     x29, x30, [sp, 10 * 8]
        stp     x27, x28, [sp, 8 * 8]
        stp     x25, x26, [sp, 6 * 8]
        stp     x23, x24, [sp, 4 * 8]
        stp     x21, x22, [sp, 2 * 8]
        stp     x19, x20, [sp]

        mov     x8,  sp
        str     x8,  [x0, {sp_el1}]  // save sp_el1 to ctx.sp_el1

        // -- restore user context --
        mov     sp,   x0
        b  _user_entry
        "
        ,
        sp_el1 = const offset_of!(UserContext, sp_el1),
    )
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn _user_trap_entry() -> ! {
    naked_asm!(
        "
        ldr     x8, [sp, {sp_el1}]  // load ctx.sp_el1 to x8
        mov     sp, x8
        ldp     x19, x20, [sp]
        ldp     x21, x22, [sp, 2 * 8]
        ldp     x23, x24, [sp, 4 * 8]
        ldp     x25, x26, [sp, 6 * 8]
        ldp     x27, x28, [sp, 8 * 8]
        ldp     x29, x30, [sp, 10 * 8]
        add     sp, sp, 12 * 8
        ret
    ",
        sp_el1 = const offset_of!(UserContext, sp_el1),
    )
}
