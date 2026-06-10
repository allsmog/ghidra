# Test fixture for array/element layout recovery.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o array.o array.s
#
# word_sum(a0=ptr, a1=n): sums n 64-bit words: sum += ptr[i].
# The address of element i is ptr + i*8, the canonical array-index shape:
# a scaled index (i << 3) added to a base pointer, then dereferenced at the
# element width. Recovery should render this as ptr[i], not *(ptr + (i<<3)).

    .text

    .globl word_sum
    .type word_sum, @function
word_sum:
    addi    t0, zero, 0         # sum = 0
    addi    t1, zero, 0         # i = 0
.Lloop:
    bgeu    t1, a1, .Ldone      # while (i < n)
    slli    t2, t1, 3           #   off = i * 8
    add     t3, a0, t2          #   p = ptr + off
    ld      t4, 0(t3)           #   w = ptr[i]
    add     t0, t0, t4          #   sum += w
    addi    t1, t1, 1           #   i++
    jal     zero, .Lloop
.Ldone:
    addi    a0, t0, 0           # return sum
    jalr    zero, 0(ra)
    .size word_sum, .-word_sum
