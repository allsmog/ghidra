# Test fixture for SSA-based constant propagation, folding, and DCE.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o consts.o consts.s
#
# compute() builds the constant 42 through a chain of operations whose
# intermediates are all dead once propagation finishes:
#   a0=3; a1=4; a0=a0+a1 (7); a0=a0<<2 (28); a0=a0+14 (42)

    .text

    .globl compute
    .type compute, @function
compute:
    addi    a0, zero, 3
    addi    a1, zero, 4
    add     a0, a0, a1          # 7
    slli    a0, a0, 2           # 28
    addi    a0, a0, 14          # 42
    jalr    zero, 0(ra)
    .size compute, .-compute
