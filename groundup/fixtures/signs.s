# Test fixture for signedness recovery from comparison operators.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o signs.o signs.s
#
# umax(a0, a1): unsigned max, using an unsigned compare (bltu). Both
# arguments are therefore unsigned; recovery should report
# `unsigned long umax(unsigned long a0, unsigned long a1)`.

    .text

    .globl umax
    .type umax, @function
umax:
    bltu    a0, a1, .Lless      # if (a0 <u a1) goto less   [unsigned]
    jalr    zero, 0(ra)         # return a0
.Lless:
    addi    a0, a1, 0           # a0 = a1
    jalr    zero, 0(ra)
    .size umax, .-umax
