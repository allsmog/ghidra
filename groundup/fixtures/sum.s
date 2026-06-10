# Test fixture: RV64IM, assembled with:
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o sum.o sum.s
#
# Symbols are deliberately local (no .globl) so the assembler resolves all
# branch/jump fixups at assembly time and the object needs no relocations.

    .text

    .type sum_to_n, @function
sum_to_n:                       # a0 = n  ->  a0 = 1 + 2 + ... + n
    addi    t0, zero, 0         # acc = 0
    addi    t1, zero, 1         # i = 1
.Lloop:
    blt     a0, t1, .Ldone      # while (i <= n)
    add     t0, t0, t1          #   acc += i
    addi    t1, t1, 1           #   i++
    jal     zero, .Lloop
.Ldone:
    addi    a0, t0, 0           # return acc
    jalr    zero, 0(ra)
    .size sum_to_n, .-sum_to_n

    .type entry, @function
entry:
    addi    sp, sp, -16
    sd      ra, 8(sp)
    addi    a0, zero, 10
    jal     ra, sum_to_n        # a0 = sum_to_n(10) = 55
    addi    t2, zero, 3
    mul     a0, a0, t2          # a0 *= 3
    ld      ra, 8(sp)
    addi    sp, sp, 16
    jalr    zero, 0(ra)
    .size entry, .-entry

# A function unrelated to the others: it calls nothing and nothing calls
# it. Used to prove that renames elsewhere do not invalidate its listing.
    .type leaf, @function
leaf:
    addi    a0, a0, 7
    jalr    zero, 0(ra)
    .size leaf, .-leaf
