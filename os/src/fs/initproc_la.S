    .section .data
    .globl initproc_start
    .globl initproc_end
initproc_start:
    .incbin "../user_la/target/loongarch64-unknown-none/release/initproc"
initproc_end: