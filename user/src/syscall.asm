    .section .text
    .globl do_syscall
    .align 4
do_syscall:
    #syscall(id: usize, args0: usize,args1:usize,args2:usize,)
    # move $t0,$a0
    # move $t1,$a1
    # move $t2,$a2
    # move $t3,$a3
    # move $t4,$a4
    # move $a7, $t0
    # move $a0, $t1
    # move $a1, $t2
    # move $a2, $t3
    # move $a3, $t4
    move $a7, $a0      # syscall id
    move $a0, $a1      # arg0
    move $a1, $a2      # arg1
    move $a2, $a3      # arg2
    move $a3, $a4      # arg3
    move $a4, $a5      # arg4
    move $a5, $a6      # arg5
    syscall 0
    jr $ra