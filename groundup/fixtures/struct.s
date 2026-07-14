# Test fixture for struct field layout recovery.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o struct.o struct.s
#
# pair_sum(a0=ptr): reads two 64-bit fields of a struct and writes a third.
#   struct { long a; long b; long sum; };  // offsets 0, 8, 16
#   ptr->sum = ptr->a + ptr->b;  return ptr->sum;
#
# A pointer dereferenced at several distinct constant offsets is a struct;
# each offset is a field. Recovery should render field_0 / field_8 / field_10.

    .text

    .globl pair_sum
    .type pair_sum, @function
pair_sum:
    ld      t0, 0(a0)           # t0 = ptr->a       (offset 0)
    ld      t1, 8(a0)           # t1 = ptr->b       (offset 8)
    add     t2, t0, t1          # t2 = a + b
    sd      t2, 16(a0)          # ptr->sum = t2     (offset 16)
    ld      a0, 16(a0)          # return ptr->sum
    jalr    zero, 0(ra)
    .size pair_sum, .-pair_sum
