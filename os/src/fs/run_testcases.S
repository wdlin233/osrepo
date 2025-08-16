    .section .data
    .globl script_start
    .globl script_end
script_start:
    .incbin "run_testcases_musl.sh"
script_end: