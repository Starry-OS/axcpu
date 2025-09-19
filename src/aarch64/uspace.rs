//! Structures and functions for user space.
use core::{
    arch::naked_asm,
    mem::offset_of,
    ops::{Deref, DerefMut},
};

use aarch64_cpu::registers::{ESR_EL1, FAR_EL1, Readable};
use memory_addr::VirtAddr;
use page_table_entry::MappingFlags;

use crate::{
    TrapFrame,
    aarch64::trap::TrapKind,
    trap::{ExceptionKind, ReturnReason},
};

#[derive(Debug, Clone, Copy)]
pub struct ExceptionInfo {
    pub esr: u64,
    pub stval: usize,
}

impl ExceptionInfo {
    pub fn kind(&self) -> ExceptionKind {
        let esr: tock_registers::LocalRegisterCopy<u64, ESR_EL1::Register> =
            tock_registers::LocalRegisterCopy::new(self.esr);
        match esr.read_as_enum(ESR_EL1::EC) {
            Some(ESR_EL1::EC::Value::BreakpointLowerEL) => ExceptionKind::Breakpoint,
            Some(ESR_EL1::EC::Value::IllegalExecutionState) => ExceptionKind::IllegalInstruction,
            Some(ESR_EL1::EC::Value::PCAlignmentFault)
            | Some(ESR_EL1::EC::Value::SPAlignmentFault) => ExceptionKind::Misaligned,
            _ => ExceptionKind::Other,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct UserContext {
    tf: TrapFrame,
    sp_el1: u64,
}

impl UserContext {
    pub fn run(&mut self) -> ReturnReason {
        let tp_kind = unsafe { _enter_user(self) };
        trace!("Returned from user space with TrapKind: {:?}", tp_kind);

        if matches!(tp_kind, TrapKind::Irq) {
            handle_trap!(IRQ, 0);
            return ReturnReason::Interrupt;
        }

        let esr = ESR_EL1.extract();
        let iss = esr.read(ESR_EL1::ISS);

        match esr.read_as_enum(ESR_EL1::EC) {
            Some(ESR_EL1::EC::Value::SVC64) => ReturnReason::Syscall,
            Some(ESR_EL1::EC::Value::InstrAbortLowerEL) => {
                handle_instruction_abort_lower(&self.tf, iss, true)
            }
            Some(ESR_EL1::EC::Value::BreakpointLowerEL)
            | Some(ESR_EL1::EC::Value::IllegalExecutionState)
            | Some(ESR_EL1::EC::Value::PCAlignmentFault)
            | Some(ESR_EL1::EC::Value::SPAlignmentFault) => {
                ReturnReason::Exception(ExceptionInfo {
                    esr: esr.get(),
                    stval: FAR_EL1.get() as usize,
                })
            }
            Some(ESR_EL1::EC::Value::DataAbortLowerEL) => {
                info!("task return because DataAbortLowerEL ...");
                handle_data_abort_lower(&self.tf, iss, true)
            }
            _ => ReturnReason::Unknown,
        }
    }

    pub fn new(entry: usize, ustack_top: VirtAddr, arg0: usize) -> Self {
        info!(
            "new ctx: entry={:#x}, ustack_top={:#x}",
            entry,
            ustack_top.as_usize()
        );
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
            sp_el1: 0, // 默认初始化
        }
    }
}

fn handle_instruction_abort_lower(tf: &TrapFrame, iss: u64, is_user: bool) -> ReturnReason {
    let mut access_flags = MappingFlags::EXECUTE;
    if is_user {
        access_flags |= MappingFlags::USER;
    }
    let vaddr = va!(FAR_EL1.get() as usize);

    // Only handle Translation fault and Permission fault
    if !matches!(iss & 0b111100, 0b0100 | 0b1100)
    // IFSC or DFSC bits
    {
        panic!(
            "Unhandled {} Instruction Abort @ {:#x}, fault_vaddr={:#x}, ESR={:#x} \
             ({:?}):\n{:#x?}\n{}",
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

fn handle_data_abort_lower(tf: &TrapFrame, iss: u64, is_user: bool) -> ReturnReason {
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
    if !matches!(iss & 0b111100, 0b0100 | 0b1100)
    // IFSC or DFSC bits
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

#[unsafe(naked)]
unsafe extern "C" fn _enter_user(_ctx: &mut UserContext) -> TrapKind {
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

        mrs     x8, tpidr_el0
        msr     tpidrro_el0, x8

        ldp     x8,  x9,   [sp, {elr_el1}] 
        msr     elr_el1,   x8
        msr     spsr_el1,  x9

        ldp     x8,  x9,   [sp, {sp_el0}] 
        msr     sp_el0,    x8
        msr     tpidr_el0, x9

        ldr     x30,      [sp, 30 * 8]
        ldp     x28, x29, [sp, 28 * 8]
        ldp     x26, x27, [sp, 26 * 8]
        ldp     x24, x25, [sp, 24 * 8]
        ldp     x22, x23, [sp, 22 * 8]
        ldp     x20, x21, [sp, 20 * 8]
        ldp     x18, x19, [sp, 18 * 8]
        ldp     x16, x17, [sp, 16 * 8]
        ldp     x14, x15, [sp, 14 * 8]
        ldp     x12, x13, [sp, 12 * 8]
        ldp     x10, x11, [sp, 10 * 8]
        ldp     x8, x9,   [sp, 8 * 8]
        ldp     x6, x7,   [sp, 6 * 8]
        ldp     x4, x5,   [sp, 4 * 8]
        ldp     x2, x3,   [sp, 2 * 8]
        ldp     x0, x1,   [sp]
        eret
        ",
        sp_el1 = const offset_of!(UserContext, sp_el1),
        elr_el1 = const offset_of!(TrapFrame, elr),
        sp_el0 = const offset_of!(TrapFrame, usp),
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
