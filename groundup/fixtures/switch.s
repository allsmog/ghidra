# Test fixture for jump-table resolution (value-set analysis).
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o switch.tmp.o switch.s
#   ld.lld -e dispatch -o switch switch.tmp.o
#   llvm-objcopy --strip-all switch switch_stripped
#
# dispatch(a0): a switch over a0 in {0,1,2} via a PC-relative jump table in
# .rodata. The case blocks are reachable ONLY through the table, so naive
# recursive descent dead-ends at the indirect jump and never finds them.
# Resolving the table is what lets discovery reach (and size) the function.

    .text

    .globl dispatch
    .type dispatch, @function
dispatch:
    addi    t1, zero, 3
    bgeu    a0, t1, .Ldefault       # if (a0 >= 3) goto default
1:  auipc   t0, %pcrel_hi(.Ltable)  # t0 = &table  (hi part)
    addi    t0, t0, %pcrel_lo(1b)   #            (lo part)
    slli    t1, a0, 3               # t1 = a0 * 8
    add     t0, t0, t1              # t0 = &table[a0]
    ld      t0, 0(t0)               # t0 = table[a0]
    jalr    zero, 0(t0)             # goto *t0  (indirect; resolves to cases)
.Lcase0:
    addi    a0, zero, 10
    jalr    zero, 0(ra)
.Lcase1:
    addi    a0, zero, 20
    jalr    zero, 0(ra)
.Lcase2:
    addi    a0, zero, 30
    jalr    zero, 0(ra)
.Ldefault:
    addi    a0, zero, -1
    jalr    zero, 0(ra)
    .size dispatch, .-dispatch

    .section .rodata
    .p2align 3
.Ltable:
    .quad   .Lcase0
    .quad   .Lcase1
    .quad   .Lcase2
