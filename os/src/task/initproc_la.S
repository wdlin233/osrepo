    .section .data
    .globl initproc_rv_start
    .globl initproc_rv_end
initproc_rv_start:
    .incbin "../user_la/target/loongarch64-unknown-none/release/initproc"
initproc_rv_end: