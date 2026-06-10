# Test fixture for stack-variable and signature recovery.
#
#   llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o locals.o locals.s
#
# stash(a0) spills a computed value to a stack slot and reloads it, so the
# store/load survive optimization (no memory forwarding). Stack recovery
# should name the slot a local and infer the signature `long stash(long a0)`.

    .text

    .globl stash
    .type stash, @function
stash:
    addi    sp, sp, -16
    addi    a0, a0, 10          # a0 = arg + 10
    sd      a0, 8(sp)           # local = a0
    ld      a1, 8(sp)           # a1 = local
    slli    a0, a1, 1           # a0 = local * 2
    addi    sp, sp, 16
    jalr    zero, 0(ra)
    .size stash, .-stash
