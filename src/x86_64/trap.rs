use x86::{controlregs::cr2, irq::*};
use x86_64::structures::idt::PageFaultErrorCode;

use super::{gdt, TrapFrame};
use crate::trap::PageFaultFlags;

core::arch::global_asm!(
    include_str!("trap.S"),
    trapframe_size = const core::mem::size_of::<TrapFrame>(),
    UDATA = const gdt::UDATA.0,
    UCODE64 = const gdt::UCODE64.0,
    SYSCALL_VECTOR = const LEGACY_SYSCALL_VECTOR,
);

pub(super) const LEGACY_SYSCALL_VECTOR: u8 = 0x80;
pub(super) const IRQ_VECTOR_START: u8 = 0x20;
pub(super) const IRQ_VECTOR_END: u8 = 0xff;

fn handle_page_fault(tf: &mut TrapFrame) {
    let access_flags = err_code_to_flags(tf.error_code)
        .unwrap_or_else(|e| panic!("Invalid #PF error code: {:#x}", e));
    let vaddr = va!(unsafe { cr2() });
    if handle_trap!(PAGE_FAULT, vaddr, access_flags) {
        return;
    }
    #[cfg(feature = "uspace")]
    if tf.fixup_exception() {
        return;
    }
    core::hint::cold_path();
    panic!(
        "Unhandled #PF @ {:#x}, fault_vaddr={:#x}, error_code={:#x} ({:?}):\n{:#x?}\n{}",
        tf.rip,
        vaddr,
        tf.error_code,
        access_flags,
        tf,
        tf.backtrace()
    );
}

fn handle_breakpoint(tf: &mut TrapFrame) {
    debug!("#BP @ {:#x} ", tf.rip);
    if core::hint::likely(handle_trap!(BREAK_HANDLER, tf)) {
        return;
    }
}

#[unsafe(no_mangle)]
fn x86_trap_handler(tf: &mut TrapFrame) {
    match tf.vector as u8 {
        PAGE_FAULT_VECTOR => handle_page_fault(tf),
        BREAKPOINT_VECTOR => handle_breakpoint(tf),
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
}

fn vec_to_str(vec: u64) -> &'static str {
    if vec < 32 {
        EXCEPTIONS[vec as usize].mnemonic
    } else {
        "Unknown"
    }
}

pub(super) fn err_code_to_flags(err_code: u64) -> Result<PageFaultFlags, u64> {
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
