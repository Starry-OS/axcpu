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


use page_table_entry::MappingFlags;
use aarch64_cpu::registers::FAR_EL1;
use aarch64_cpu::registers::ESR_EL1;
use aarch64_cpu::registers::Readable;

fn handle_instruction_abort_lower(tf: &TrapFrame, iss: u64, is_user: bool)-> ReturnReason {
    let mut access_flags = MappingFlags::EXECUTE;
    if is_user {
        access_flags |= MappingFlags::USER;
    }
    let vaddr = va!(FAR_EL1.get() as usize);

    // Only handle Translation fault and Permission fault
    if !matches!(iss & 0b111100, 0b0100 | 0b1100) // IFSC or DFSC bits
    {
        panic!(
            "Unhandled {} Instruction Abort @ {:#x}, fault_vaddr={:#x}, ESR={:#x} ({:?}):\n{:#x?}\n{}",
            if is_user { "EL0" } else { "EL1" },
            tf.elr,
            vaddr,
            ESR_EL1.get(),
            access_flags,
            tf,
            tf.backtrace()
        );
    } else {
        ReturnReason::PageFault(vaddr, access_flags)
    }
}


fn handle_data_abort_lower(tf: &TrapFrame, iss: u64, is_user: bool)-> ReturnReason {
    let wnr = (iss & (1 << 6)) != 0; // WnR: Write not Read
    let cm = (iss & (1 << 8)) != 0; // CM: Cache maintenance
    let mut access_flags = if wnr & !cm {
        MappingFlags::WRITE
    } else {
        MappingFlags::READ
    };
    if is_user {
        access_flags |= MappingFlags::USER;
    }
    let vaddr = va!(FAR_EL1.get() as usize);

    // Only handle Translation fault and Permission fault
    if !matches!(iss & 0b111100, 0b0100 | 0b1100) // IFSC or DFSC bits
    {
        panic!(
            "Unhandled {} Data Abort @ {:#x}, fault_vaddr={:#x}, ESR={:#x} ({:?}):\n{:#x?}\n{}",
            if is_user { "EL0" } else { "EL1" },
            tf.elr,
            vaddr,
            ESR_EL1.get(),
            access_flags,
            tf,
            tf.backtrace()
        );
    } else {
        ReturnReason::PageFault(vaddr, access_flags)
    }
}


/// Compare two memory regions as u64 words, dump both if any difference found.
///
/// # Safety
/// Caller must ensure both addr1 and addr2 are valid for `num_words * 8` bytes.
pub unsafe fn compare_and_dump_u64(addr1: usize, addr2: usize, num_words: usize) -> bool {
    let ptr1 = addr1 as *const u64;
    let ptr2 = addr2 as *const u64;

    let mut equal = true;

    for i in 0..num_words {
        let val1 = *ptr1.add(i);
        let val2 = *ptr2.add(i);
        if val1 != val2 {
            equal = false;
            break;
        }
    }

    if !equal {
        warn!("Memory regions differ, dumping contents:");

        warn!("Region 1 at {:#x}:", addr1);
        for i in 0..num_words {
            let val = *ptr1.add(i);
            warn!("  [{:02}] = {:#018x}", i, val);
        }

        warn!("Region 2 at {:#x}:", addr2);
        for i in 0..num_words {
            let val = *ptr2.add(i);
            warn!("  [{:02}] = {:#018x}", i, val);
        }
    }

    equal
}


impl UserContext {
    pub fn run(&mut self) -> ReturnReason {
        extern "C" {
            pub fn task_in(base: usize) -> u16;
        }

        let base_addr: usize = self as *mut Self as usize;
        let el1_sp = self.sp_el1;

        warn!("task in {:#x}, elr: {:#x}, el1 stack {:#x}", 
            base_addr, self.tf.elr, el1_sp);
        
        let _: u16 = unsafe { task_in(base_addr) };
        let esr = ESR_EL1.extract();
        let iss = esr.read(ESR_EL1::ISS);

        match esr.read_as_enum(ESR_EL1::EC) {
            Some(ESR_EL1::EC::Value::SVC64) => {
                info!("task return because syscall ...");
                ReturnReason::Syscall
            },
            Some(ESR_EL1::EC::Value::InstrAbortLowerEL) => {
                info!("task return because InstrAbortLowerEL ...");
                handle_instruction_abort_lower(&self.tf, iss, true)
            }
            Some(ESR_EL1::EC::Value::DataAbortLowerEL) => {
                info!("task return because DataAbortLowerEL ...");
                handle_data_abort_lower(&self.tf, iss, true)
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