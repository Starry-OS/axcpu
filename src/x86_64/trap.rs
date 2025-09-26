use x86::{controlregs::cr2, irq::*};
use x86_64::structures::{idt::PageFaultErrorCode, tss::TaskStateSegment};

use super::{context::TrapFrame, GdtStruct};
use crate::trap::PageFaultFlags;

#[unsafe(no_mangle)]
#[percpu::def_percpu]
static USER_RSP_OFFSET: usize = 0;

core::arch::global_asm!(
    include_str!("trap.S"),
    tss_rsp0_offset = const core::mem::offset_of!(TaskStateSegment, privilege_stack_table),
    ucode64 = const GdtStruct::UCODE64_SELECTOR.0,
);


pub(crate) const IRQ_VECTOR_START: u8 = 0x20;
pub(crate) const IRQ_VECTOR_END: u8 = 0xff;

fn handle_breakpoint(rip: u64) {
    debug!("Exception(Breakpoint) @ {rip:#x} ");
}

fn handle_page_fault(tf: &TrapFrame) {
    let access_flags = err_code_to_flags(tf.error_code)
        .unwrap_or_else(|e| panic!("Invalid #PF error code: {:#x}", e));
    let vaddr = va!(unsafe { cr2() });
    if handle_trap!(PAGE_FAULT, vaddr, access_flags) {
        return;
    }
    panic!(
        "Unhandled {} #PF @ {:#x}, fault_vaddr={:#x}, error_code={:#x} ({:?}):\n{:#x?}\n{}",
        if tf.is_user() { "user" } else { "kernel" },
        tf.rip,
        vaddr,
        tf.error_code,
        access_flags,
        tf,
        tf.backtrace()
    );
}

/// Trap handler for kernel space.
#[unsafe(no_mangle)]
fn x86_trap_handler(tf: &mut TrapFrame) {
    #[cfg(feature = "uspace")]
    super::uspace::switch_to_kernel_fs_base(tf);
    match tf.vector as u8 {
        PAGE_FAULT_VECTOR => handle_page_fault(tf),
        BREAKPOINT_VECTOR => handle_breakpoint(tf.rip),
        GENERAL_PROTECTION_FAULT_VECTOR => {
            panic!(
                "#GP @ {:#x}, error_code={:#x}:\n{:#x?}\n{}",
                tf.rip,
                tf.error_code,
                tf,
                tf.backtrace()
            );
        }
        IRQ_VECTOR_START..=IRQ_VECTOR_END => {
            handle_trap!(IRQ, tf.vector as _);
        }
        _ => {
            panic!(
                "Unhandled exception {} ({}, error_code={:#x}) @ {:#x}:\n{:#x?}\n{}",
                tf.vector,
                vec_to_str(tf.vector),
                tf.error_code,
                tf.rip,
                tf,
                tf.backtrace()
            );
        }
    }
    #[cfg(feature = "uspace")]
    super::uspace::switch_to_user_fs_base(tf);
}

fn vec_to_str(vec: u64) -> &'static str {
    if vec < 32 {
        EXCEPTIONS[vec as usize].mnemonic
    } else {
        "Unknown"
    }
}

pub(crate) fn err_code_to_flags(err_code: u64) -> Result<PageFaultFlags, u64> {
    let code = PageFaultErrorCode::from_bits_truncate(err_code);
    let reserved_bits = (PageFaultErrorCode::CAUSED_BY_WRITE
        | PageFaultErrorCode::USER_MODE
        | PageFaultErrorCode::INSTRUCTION_FETCH
        | PageFaultErrorCode::PROTECTION_VIOLATION)
        .complement();
    if code.intersects(reserved_bits) {
        Err(err_code)
    } else {
        let mut flags = PageFaultFlags::empty();
        if code.contains(PageFaultErrorCode::CAUSED_BY_WRITE) {
            flags |= PageFaultFlags::WRITE;
        } else {
            flags |= PageFaultFlags::READ;
        }
        if code.contains(PageFaultErrorCode::USER_MODE) {
            flags |= PageFaultFlags::USER;
        }
        if code.contains(PageFaultErrorCode::INSTRUCTION_FETCH) {
            flags |= PageFaultFlags::EXECUTE;
        }
        Ok(flags)
    }
}
