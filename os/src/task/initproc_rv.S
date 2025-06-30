    .section .data
    .globl initproc_rv_start
    .globl initproc_rv_end
    .align 12
initproc_rv_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/initproc"
initproc_rv_end:
    .align 12

    .section .data
    .globl test_rv_start
    .globl test_rv_end
    .align 12
test_rv_start:
    .incbin "../run-all-test.sh"
test_rv_end:
    .align 12

    .section .data
    .globl busybox_rv_start
    .globl busybox_rv_end
    .align 12
busybox_rv_start:
    .incbin "../busybox"
busybox_rv_end:
    .align 12