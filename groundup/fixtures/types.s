# Test fixture for type and width recovery.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o types.o types.s
#
# byte_sum(a0=ptr, a1=n): sums n unsigned bytes starting at *a0.
# Exercises:
#   - a0 used as a pointer (load through it)              -> pointer type
#   - the load is byte-sized and unsigned (lbu)           -> unsigned char
#   - a1/i compared unsigned and counts                   -> width from use
#   - the running sum accumulates bytes                   -> integer

    .text

    .globl byte_sum
    .type byte_sum, @function
byte_sum:
    addi    t0, zero, 0         # sum = 0
    addi    t1, zero, 0         # i = 0
.Lloop:
    bgeu    t1, a1, .Ldone      # while (i < n)  [unsigned]
    add     t2, a0, t1          #   p = ptr + i
    lbu     t3, 0(t2)           #   b = *(unsigned char*)p
    add     t0, t0, t3          #   sum += b
    addi    t1, t1, 1           #   i++
    jal     zero, .Lloop
.Ldone:
    addi    a0, t0, 0           # return sum
    jalr    zero, 0(ra)
    .size byte_sum, .-byte_sum
