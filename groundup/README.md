# groundup

A ground-up prototype of a modern binary-analysis kernel — the answer to
"if we built Ghidra from scratch today, what would the foundation look
like?" See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and how it
draws on Ghidra, rev.ng, and rust-analyzer.

This is a working vertical slice, not a product: it loads a RISC-V ELF,
decodes RV64IM, lifts to an architecture-neutral IR with basic-block CFGs,
and serves everything through an incremental, dependency-tracked query
kernel with a diffable text project model.

## Layout

| Crate | Role | Design pillar |
|---|---|---|
| `gu-elf` | ELF64 loader | Memory-safe, zero-dependency, panic-free parsing of hostile input |
| `gu-ir` | Register-transfer IR | Small RE-native IR (P-code spirit), not a compiler IR |
| `gu-rv64` | RV64IM decoder + lifter | Stand-in for spec-generated lifters; tested against llvm-mc encodings |
| `gu-ssa` | SSA construction + analyses | Constant propagation, folding, DCE; the foundation a decompiler stands on |
| `gu-decompile` | Structured pseudo-C | Expression propagation, `if`/`while` structuring, stack/signature/type recovery |
| `gu-kernel` | Query engine + model | Incremental recomputation; user model is diffable text |
| `gu-cli` | `gu` binary | Just a client of the kernel — like every future frontend |

## Try it

```sh
cargo test                                   # full suite
cargo run -p gu-cli -- info   fixtures/sum.o
cargo run -p gu-cli -- disasm fixtures/sum.o
cargo run -p gu-cli -- lift   fixtures/sum.o sum_to_n
cargo run -p gu-cli -- ssa    fixtures/sum.o sum_to_n     # phi nodes at the loop head
cargo run -p gu-cli -- opt    fixtures/consts.o compute   # folds to `return 42`
cargo run -p gu-cli -- decompile fixtures/sum.o sum_to_n  # recovers a `while` loop
cargo run -p gu-cli -- decompile fixtures/branch.o maxfn  # recovers an `if`/`else`
cargo run -p gu-cli -- decompile fixtures/locals.o stash  # recovers a stack local
cargo run -p gu-cli -- decompile fixtures/types.o byte_sum # recovers pointer & byte types
cargo run -p gu-cli -- decompile fixtures/array.o word_sum # recovers array indexing (a0[i])
cargo run -p gu-cli -- decompile fixtures/struct.o pair_sum # recovers struct fields (a0->field_8)
cargo run -p gu-cli -- decompile fixtures/switch_stripped fn_11138 # recovers a switch
cargo run -p gu-cli -- demo   fixtures/sum.o # incremental recomputation demo

# Stripped linked executable: no symbols, functions found by recursive
# descent from the entry point.
cargo run -p gu-cli -- info   fixtures/calls_stripped
cargo run -p gu-cli -- disasm fixtures/calls_stripped fn_11120

# Jump table resolved from .rodata: the indirect jump is annotated with
# its switch cases (value-set analysis over the dispatch pattern).
cargo run -p gu-cli -- disasm fixtures/switch_stripped fn_11138
```

`decompile` is the end of the pipeline. The eight raw RV64 instructions of
`sum_to_n` become a function with a recovered signature and a structured
loop:

```c
long sum_to_n(long a0) {
    t0 = 0;
    t1 = 1;
    while (a0 >= t1) {
        t0 = (t0 + t1);
        t1 = (t1 + 1);
    }
    return t0;
}
```

`stash` (in `locals.o`) shows stack-variable recovery: a spilled value that
survives optimization becomes a declared local, not a memory dereference,
and the stack-pointer bookkeeping is hidden:

```c
long stash(long a0) {
    long local_8;
    local_8 = (a0 + 0xa);
    a1 = local_8;
    return (a1 << 1);
}
```

Call arguments are recovered interprocedurally. In the stripped `calls`
binary, an arity fixpoint over the call graph lets `alpha` forward a
computed argument to `beta`, so both take `a0`:

```c
long fn_11134(long a0) {        // alpha
    long local_8;
    local_8 = ra;
    fn_11150((a0 + 1));         // calls beta with a0 + 1
    return a0;
}
```

Types and widths are recovered from how values are used. In `byte_sum`,
`a0` is added to an index and dereferenced as a byte, so it comes back a
`unsigned char *`, and the loaded value is an `unsigned char`:

```c
long byte_sum(unsigned char *a0, long a1) {
    long t0;
    long t1;
    unsigned char t3;
    t0 = 0;
    t1 = 0;
    while (t1 < a1) {
        t3 = a0[t1];
        t0 = (t0 + t3);
        t1 = (t1 + 1);
    }
    return t0;
}
```

When a pointer is indexed by a scaled variable (`base + i*stride` with
`stride` the element size), the dereference is rendered as array access. In
`word_sum`, `ptr + i*8` over 8-byte words becomes `a0[t1]`:

```c
long word_sum(long *a0, long a1) {
    ...
    while (t1 < a1) {
        t4 = a0[t1];
        t0 = (t0 + t4);
        t1 = (t1 + 1);
    }
    return t0;
}
```

A pointer dereferenced at several distinct constant offsets is a struct;
each offset becomes a field, and stores become field assignments. In
`pair_sum`, `a0` is touched at offsets 0, 8, and 16:

```c
long pair_sum(long *a0) {
    long t0;
    long t1;
    t0 = a0->field_0;
    t1 = a0->field_8;
    a0->field_10 = (t0 + t1);
    a0 = a0->field_10;
    return a0;
}
```

An indirect jump through a resolved jump table structures as a `switch`.
The `dispatch` function's `auipc`/`ld`/`jalr` table dispatch — with the
case blocks reachable only through the table — becomes:

```c
long fn_11138(long a0) {
    if (a0 >= 3) {
        return -1;
    } else {
        switch (a0) {
        case 0:
            return 0xa;
        case 1:
            return 0x14;
        case 2:
            return 0x1e;
        }
    }
}
```

The `demo` command shows the incremental engine: it warms the cache, renames
a function, and shows in the query log that only listings displaying that
name re-render — decoding, lifting, and unrelated listings are reused.

## Regenerating the fixtures

```sh
cd fixtures
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o sum.o sum.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o consts.o consts.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o branch.o branch.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o locals.o locals.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o types.o types.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o array.o array.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o struct.o struct.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o signs.o signs.s
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o calls.tmp.o calls.s
ld.lld -e _start -o calls calls.tmp.o && rm calls.tmp.o
llvm-objcopy --strip-all calls calls_stripped
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o switch.tmp.o switch.s
ld.lld -e dispatch -o switch switch.tmp.o && rm switch.tmp.o
llvm-objcopy --strip-all switch switch_stripped
```
