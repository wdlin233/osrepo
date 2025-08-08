    .section .text.sigreturn
    .align 12
    .globl sigreturn
sigreturn:
    li a7,139
    ecall