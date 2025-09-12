//! Structures and functions for user space.

use memory_addr::VirtAddr;

use crate::TrapFrame;

/// Context to enter user space.
pub struct UspaceContext(TrapFrame);

impl UspaceContext {
    /// Creates an empty context with all registers set to zero.
    pub const fn empty() -> Self {
        unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
    }

    /// Creates a new context with the given entry point, user stack pointer,
    /// and the argument.
    pub fn new(entry: usize, ustack_top: VirtAddr, arg0: usize) -> Self {
        use aarch64_cpu::registers::SPSR_EL1;
        let mut regs = [0; 31];
        regs[0] = arg0 as _;
        Self(TrapFrame {
            r: regs,
            usp: ustack_top.as_usize() as _,
            tpidr: 0,
            elr: entry as _,
            spsr: (SPSR_EL1::M::EL0t
                + SPSR_EL1::D::Masked
                + SPSR_EL1::A::Masked
                + SPSR_EL1::I::Unmasked
                + SPSR_EL1::F::Masked)
                .value,
        })
    }

    /// Creates a new context from the given [`TrapFrame`].
    pub const fn from(trap_frame: &TrapFrame) -> Self {
        Self(*trap_frame)
    }

    /// Enters user space.
    ///
    /// It restores the user registers and jumps to the user entry point
    /// (saved in `elr`).
    /// When an exception or syscall occurs, the kernel stack pointer is
    /// switched to `kstack_top`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it changes processor mode and the stack.
    pub unsafe fn enter_uspace(&self, kstack_top: VirtAddr) -> ! {
        crate::asm::disable_irqs();
        // We do not handle traps that occur at the current exception level,
        // so the kstack ptr(`sp_el1`) will not change during running in user space.
        // Then we don't need to save the `sp_el1` to the taskctx.
        unsafe {
            core::arch::asm!(
                "
                mov     sp, x1
                
                // backup kernel tpidr_el0
                mrs     x1, tpidr_el0
                msr     tpidrro_el0, x1
                
                ldp     x11, x12, [x0, 33 * 8]
                ldp     x9, x10, [x0, 31 * 8]
                msr     sp_el0, x9
                msr     tpidr_el0, x10
                msr     elr_el1, x11
                msr     spsr_el1, x12

                ldr     x30, [x0, 30 * 8]
                ldp     x28, x29, [x0, 28 * 8]
                ldp     x26, x27, [x0, 26 * 8]
                ldp     x24, x25, [x0, 24 * 8]
                ldp     x22, x23, [x0, 22 * 8]
                ldp     x20, x21, [x0, 20 * 8]
                ldp     x18, x19, [x0, 18 * 8]
                ldp     x16, x17, [x0, 16 * 8]
                ldp     x14, x15, [x0, 14 * 8]
                ldp     x12, x13, [x0, 12 * 8]
                ldp     x10, x11, [x0, 10 * 8]
                ldp     x8, x9, [x0, 8 * 8]
                ldp     x6, x7, [x0, 6 * 8]
                ldp     x4, x5, [x0, 4 * 8]
                ldp     x2, x3, [x0, 2 * 8]
                ldp     x0, x1, [x0]
                eret",
                in("x0") &self.0,
                in("x1") kstack_top.as_usize() ,
                options(noreturn),
            )
        }
    }
}

impl core::ops::Deref for UspaceContext {
    type Target = TrapFrame;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for UspaceContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}



use crate::trap::{ExceptionKind, ReturnReason};
use core::ops::{Deref, DerefMut};

#[derive(Debug, Clone, Copy)]
pub struct ExceptionInfo {
    // pub e: E,
    pub stval: usize,
}

impl ExceptionInfo {
    pub fn kind(&self) -> ExceptionKind {
        // match self.e {
        //     E::Breakpoint => ExceptionKind::Breakpoint,
        //     E::IllegalInstruction => ExceptionKind::IllegalInstruction,
        //     E::InstructionMisaligned | E::LoadMisaligned | E::StoreMisaligned => {
        //         ExceptionKind::Misaligned
        //     }
        //     _ => ExceptionKind::Other,
        // }

        ExceptionKind::Other
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct UserContext {
    tf: TrapFrame,
    sp_el1: u64,
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
        Self {
            tf,
            sp_el1: 0,   // 默认初始化
        }
    }
}


use crate::aarch64::trap::handle_instruction_abort;

impl UserContext {
    pub fn run(&mut self) -> ReturnReason {
        extern "C" {
            pub fn task_in(base: usize) -> u16;
        }

        // test  => 0x82000004
        // let addr: *mut u64 = 0xffff_0000_45a0_0000 as *mut u64;
        // unsafe {
        //     core::ptr::write_volatile(addr, 0);
        // }

        let base_addr: usize = self as *mut Self as usize;
        let ret: u16 = unsafe { task_in(base_addr) };
        
        // 读取 ESR
        let esr = unsafe {
            let esr_val: u32;
            core::arch::asm!("mrs {0:x}, esr_el1", out(reg) esr_val);
            esr_val
        };
        let ec = (esr >> 26) & 0x3f;
        let iss = esr & 0x01ff_ffff; // 低 25 位

        info!("reason: {:#x}, esr: {:#x} <ec: {:#x} iss: {:#b}>", ret, esr, ec, iss);

        match ec {
            0x15 => { // SVC call
                ReturnReason::Syscall
            },
            0x20 => { // Translation fault, level 1.
                let ttbr0_el1: u64;
                unsafe {
                    core::arch::asm!(
                        "mrs {0}, ttbr0_el1",
                        out(reg) ttbr0_el1
                    );
                }

                handle_instruction_abort(self, iss as u64, true);

                info!("TTBR0_EL1 = {:#x}", ttbr0_el1);
                info!("{:#?}", self);
                panic!("Translation fault, level 1.");
            }
            _ => ReturnReason::Unknown
        }

    }

    pub fn new(entry: usize, ustack_top: VirtAddr, _arg0: usize) -> Self {
        info!("new ctx: entry={:#x}, ustack_top={:#x}", entry, ustack_top.as_usize());
        Self {
            tf: TrapFrame {
                r: [0u64; 31],
                usp: ustack_top.as_usize() as u64, // 假设 VirtAddr 有 as_u64 方法
                tpidr: 0,
                elr: entry as u64,       // 用户入口地址
                spsr: 0 | (0b0000<<4),        // 可根据 EL 设置初值   // 0001 0000 1100 0111 0000
            },
            sp_el1: 0,                  // EL1 栈指针
        }
    }
}