//! Trap handling.

use core::fmt::Debug;

use memory_addr::VirtAddr;

pub use crate::TrapFrame;
pub use linkme::distributed_slice as def_trap_handler;
pub use linkme::distributed_slice as register_trap_handler;
pub use page_table_entry::MappingFlags as PageFaultFlags;

/// A slice of IRQ handler functions.
#[def_trap_handler]
pub static IRQ: [fn(usize) -> bool];

/// A slice of page fault handler functions.
#[def_trap_handler]
pub static PAGE_FAULT: [fn(VirtAddr, PageFaultFlags) -> bool];

#[allow(unused_macros)]
macro_rules! handle_trap {
    ($trap:ident, $($args:tt)*) => {{
        let mut iter = $crate::trap::$trap.iter();
        if let Some(func) = iter.next() {
            if iter.next().is_some() {
                warn!("Multiple handlers for trap {} are not currently supported", stringify!($trap));
            }
            func($($args)*)
        } else {
            warn!("No registered handler for trap {}", stringify!($trap));
            false
        }
    }}
}


#[derive(Debug, Clone, Copy)]
pub enum ExceptionSource {
    CurrentSpEl0 = 0,
    CurrentSpElx = 1,
    LowerAarch64 = 2,
    LowerAarch32 = 3,
}

pub const fn excp_mask(kind: u8, source: ExceptionSource) -> u16 {
    1 << ((source as u8) * 4 + kind)
}

// 用例
pub const TASK_EXIT_0_1: u16 = excp_mask(0, ExceptionSource::CurrentSpElx);
pub const TASK_EXIT_1_1: u16 = excp_mask(1, ExceptionSource::CurrentSpElx);
pub const TASK_EXIT_0_2: u16 = excp_mask(0, ExceptionSource::LowerAarch64);
pub const TASK_EXIT_1_2: u16 = excp_mask(1, ExceptionSource::LowerAarch64);
// 0x10, 0x20, 0x100, 0x200

#[cfg(feature = "uspace")]
#[derive(Debug, Clone, Copy)]
pub enum ReturnReason {
    Unknown,
    Interrupt,
    Syscall,
    PageFault(VirtAddr, PageFaultFlags),
    Exception(crate::uspace::ExceptionInfo),
}

impl ReturnReason {
    /// 从 task_in() 返回的 bitmask 解码
    pub fn from_mask(mask: u16) -> Self {
        match mask {
            TASK_EXIT_0_1 => ReturnReason::Syscall,    // TASK_EXIT 0 1
            TASK_EXIT_1_1 => ReturnReason::Interrupt,  // TASK_EXIT 1 1
            TASK_EXIT_0_2 => ReturnReason::Syscall,
            TASK_EXIT_1_2 => ReturnReason::Interrupt,
            _ => ReturnReason::Unknown,
        }
    }
    
}

#[cfg(feature = "uspace")]
pub enum ExceptionKind {
    Other,
    Breakpoint,
    IllegalInstruction,
    Misaligned,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ExceptionTableEntry {
    from: usize,
    to: usize,
}

impl TrapFrame {
    pub(crate) fn fixup_exception(&mut self) -> bool {
        let entries = unsafe {
            core::slice::from_raw_parts(
                _ex_table_start as *const ExceptionTableEntry,
                (_ex_table_end as usize - _ex_table_start as usize)
                    / core::mem::size_of::<ExceptionTableEntry>(),
            )
        };
        match entries.binary_search_by(|e| e.from.cmp(&self.ip())) {
            Ok(entry) => {
                self.set_ip(entries[entry].to);
                true
            }
            Err(_) => false,
        }
    }
}

pub(crate) fn init_exception_table() {
    // Sort exception table
    let ex_table = unsafe {
        core::slice::from_raw_parts_mut(
            _ex_table_start as *mut ExceptionTableEntry,
            (_ex_table_end as usize - _ex_table_start as usize) / size_of::<ExceptionTableEntry>(),
        )
    };
    ex_table.sort_unstable();
}

unsafe extern "C" {
    fn _ex_table_start();
    fn _ex_table_end();
}
