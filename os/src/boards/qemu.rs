//! QEMU riscv-64 virt machine

/// clock frequency
pub const CLOCK_FREQ: usize = 12520000;
//pub const MEMORY_END: usize = 0x801000000;

/// The base address of control registers in VIRT_TEST/RTC/Virtio_Block device
pub const MMIO: &[(usize, usize)] = &[
    (0x0010_0000, 0x00_2000), // VIRT_TEST/RTC  in virt machine
    (0x1000_1000, 0x00_1000), // Virtio Block in virt machine
];

//pub type BlockDeviceImpl = crate::drivers::block::VirtIOBlock;

//ref:: https://github.com/andre-richter/qemu-exit
use core::arch::asm;

const EXIT_SUCCESS: u32 = 0x5555; // Equals `exit(0)`. qemu successful exit

const EXIT_FAILURE_FLAG: u32 = 0x3333;
const EXIT_FAILURE: u32 = exit_code_encode(1); // Equals `exit(1)`. qemu failed exit
const EXIT_RESET: u32 = 0x7777; // qemu reset

pub trait QEMUExit {
    /// Exit with specified return code.
    ///
    /// Note: For `X86`, code is binary-OR'ed with `0x1` inside QEMU.
    fn exit(&self, code: u32) -> !;

    /// Exit QEMU using `EXIT_SUCCESS`, aka `0`, if possible.
    ///
    /// Note: Not possible for `X86`.
    fn exit_success(&self) -> !;

    /// Exit QEMU using `EXIT_FAILURE`, aka `1`.
    fn exit_failure(&self) -> !;
}

/// RISCV64 configuration
pub struct RISCV64 {
    /// Address of the sifive_test mapped device.
    addr: u64,
}

/// Encode the exit code using EXIT_FAILURE_FLAG.
const fn exit_code_encode(code: u32) -> u32 {
    (code << 16) | EXIT_FAILURE_FLAG
}

impl RISCV64 {
    /// Create an instance.
    pub const fn new(addr: u64) -> Self {
        RISCV64 { addr }
    }
}

#[cfg(target_arch = "riscv64")]
impl QEMUExit for RISCV64 {
    /// Exit qemu with specified exit code.
    fn exit(&self, code: u32) -> ! {
        // If code is not a special value, we need to encode it with EXIT_FAILURE_FLAG.
        let code_new = match code {
            EXIT_SUCCESS | EXIT_FAILURE | EXIT_RESET => code,
            _ => exit_code_encode(code),
        };

        unsafe {
            asm!(
                "sw {0}, 0({1})",
                in(reg)code_new, in(reg)self.addr
            );

            // For the case that the QEMU exit attempt did not work, transition into an infinite
            // loop. Calling `panic!()` here is unfeasible, since there is a good chance
            // this function here is the last expression in the `panic!()` handler
            // itself. This prevents a possible infinite loop.
            loop {
                asm!("wfi", options(nomem, nostack));
            }
        }
    }

    fn exit_success(&self) -> ! {
        self.exit(EXIT_SUCCESS);
    }

    fn exit_failure(&self) -> ! {
        self.exit(EXIT_FAILURE);
    }
}

const VIRT_TEST: u64 = 0x100000;

pub const QEMU_EXIT_HANDLE: RISCV64 = RISCV64::new(VIRT_TEST);
