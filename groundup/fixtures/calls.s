# Test fixture: a linked RV64 executable, plus a stripped copy.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o calls.tmp.o calls.s
#   ld.lld -e _start -o calls calls.tmp.o
#   llvm-objcopy --strip-all calls calls_stripped
#
# Call graph: _start -> alpha -> beta, _start -> beta. The stripped copy
# exercises recursive-descent discovery: the only seed is e_entry, and all
# three functions must be found by following calls.

    .text

    .globl _start
    .type _start, @function
_start:
    addi    a0, zero, 5
    jal     ra, alpha
    jal     ra, beta
    addi    a7, zero, 93        # exit(a0)
    ecall
    .size _start, .-_start

    .type alpha, @function
alpha:
    addi    a0, a0, 1
    addi    sp, sp, -16
    sd      ra, 8(sp)
    jal     ra, beta            # nested call: discovery must recurse
    ld      ra, 8(sp)
    addi    sp, sp, 16
    jalr    zero, 0(ra)
    .size alpha, .-alpha

    .type beta, @function
beta:
    slli    a0, a0, 2
    jalr    zero, 0(ra)
    .size beta, .-beta
