    .section .data
    .globl initproc_rv_start
    .globl initproc_rv_end
initproc_rv_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/initproc"
initproc_rv_end: