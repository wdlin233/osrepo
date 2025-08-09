    .section .data
    .globl initproc_start
    .globl initproc_end
initproc_start:
    .incbin "../user/target/riscv64gc-unknown-none-elf/release/initproc"
initproc_end: