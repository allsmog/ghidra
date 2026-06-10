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
| `gu-kernel` | Query engine + model | Incremental recomputation; user model is diffable text |
| `gu-cli` | `gu` binary | Just a client of the kernel — like every future frontend |

## Try it

```sh
cargo test                                   # full suite
cargo run -p gu-cli -- info   fixtures/sum.o
cargo run -p gu-cli -- disasm fixtures/sum.o
cargo run -p gu-cli -- lift   fixtures/sum.o sum_to_n
cargo run -p gu-cli -- demo   fixtures/sum.o # incremental recomputation demo
```

The `demo` command is the point of the exercise: it warms the cache, renames
a function, and shows in the query log that listings re-render while
decoding and lifting are reused.

## Regenerating the fixture

```sh
llvm-mc -triple=riscv64 -mattr=+m -filetype=obj -o fixtures/sum.o fixtures/sum.s
```
