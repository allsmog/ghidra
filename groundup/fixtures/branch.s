# Test fixture for control-flow structuring: an if/else.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o branch.o branch.s
#
# maxfn(a0, a1) returns the larger of the two. Decompiles to an if/else.

    .text

    .globl maxfn
    .type maxfn, @function
maxfn:
    blt     a0, a1, .Lless      # if (a0 < a1) goto less
    jalr    zero, 0(ra)         # return a0
.Lless:
    addi    a0, a1, 0           # a0 = a1
    jalr    zero, 0(ra)         # return a0
    .size maxfn, .-maxfn
