# Architecture

This document records the design this prototype implements a slice of: a
ground-up rebuild of a Ghidra-class binary analysis platform, informed by
what Ghidra got right, what rev.ng demonstrated, and what modern tooling
(rust-analyzer's query architecture in particular) has proven out.

## Design pillars

### 1. A headless kernel; every frontend is a client

Ghidra is a Swing application with analysis embedded in it — headless mode
and the debugger were retrofits. Here the dependency arrow points the other
way: `gu-kernel` knows nothing about presentation, and `gu-cli` contains no
analysis. The target is a kernel serving a versioned API (local or remote),
with GUI, CLI, CI, scripts, and LLM agents as peer clients. rev.ng ships
this shape today (client/server with a GraphQL API and a VSCode-based UI).

### 2. Incremental, dependency-tracked computation

Interactive reverse engineering is a dialogue: the analyst renames, retypes,
and re-asks. A batch "auto-analysis" phase with ad-hoc cache invalidation
fights that dialogue. The kernel instead models every derived artifact as a
query with recorded input dependencies and revision stamps — change an
input, and only dependent queries recompute. `gu kernel`'s query log makes
this visible: a rename re-renders listings but never re-decodes bytes.

The implementation here is the minimal honest version: fixed dependency
sets per query kind, coarse inputs (`Binary`, `Names`), no early cutoff, no
parallelism. The production version is a salsa-style engine with dynamic
dependency tracking and fine-grained inputs (per-function bytes, per-symbol
names) so invalidation stays proportional to the edit.

### 3. Memory-safe parsing of hostile input

Loaders and disassemblers chew on attacker-controlled bytes; in C/C++ tools
this is where the CVEs live. `gu-elf` is the statement of intent:
`#![forbid(unsafe_code)]`, zero dependencies, every read bounds-checked,
errors instead of panics, and tests that feed it garbage (including a
corrupt section count that would otherwise drive a huge allocation).

### 4. An RE-native IR, not a compiler IR

rev.ng bets on LLVM IR and gets LLVM's optimizers for free, but compiler
IRs assume well-formed compiler output, churn with toolchain releases, and
carry semantics tuned for codegen rather than analysis of adversarial code.
`gu-ir` follows Ghidra's P-code instead: a small register-transfer language
with explicit loads/stores, owned by this project, stable by construction.
SSA construction, value tracking, and decompilation are passes *on top* of
this IR, not properties of it.

### 5. Declarative architecture specs (the Sleigh idea)

Ghidra's single best idea is that processor support is data, not code:
declarative specs compiled into lifters, which is why it supports dozens of
architectures rev.ng (capped at what QEMU emulates) cannot. The hand-written
`gu-rv64` decoder is a placeholder standing where spec-generated lifters
belong. What we keep from QEMU instead is the *oracle* role: decoders should
be differentially tested against an emulator and against llvm-mc encodings
(the unit tests already do the latter).

### 6. A diffable, mergeable project model

The user-knowledge layer — names, types, comments, overrides — is the
analyst's source code, and it should behave like source code: text,
diffable, mergeable, scriptable. rev.ng's YAML model proved this works.
`Model::to_text`/`from_text` is the v0 of that contract; Ghidra's
server-mediated check-in/check-out becomes git-style collaboration plus
(eventually) real-time co-editing.

## What the slice covers vs. the roadmap

Implemented end-to-end: ELF64 loading → RV64IM decode → CFG construction →
IR lifting → annotated listings, all served through the incremental kernel,
fully tested (`cargo test`), zero clippy warnings, zero dependencies.

Roadmap, roughly in order:

1. **Salsa-style query engine** — dynamic dependency capture, fine-grained
   input keys, early cutoff, parallel queries.
2. **Linked-binary support** — program headers, dynamic symbols, PLT/GOT,
   then PE and Mach-O loaders under the same safety rules.
3. **Function discovery beyond symbols** — recursive descent from entry
   points and call targets; prologue heuristics as a fallback.
4. **SSA + analyses on gu-ir** — SSA construction, constant propagation,
   value-set analysis; the road to a decompiler.
5. **Spec-driven lifters** — a Sleigh-like DSL (or Sleigh import) replacing
   hand-written decoders; differential testing against QEMU/Unicorn.
6. **API server** — the kernel behind a versioned protocol (JSON-RPC or
   GraphQL), Python client first.
7. **Type system + data layout analysis** — struct recovery in the spirit
   of rev.ng's DLA; DWARF/PDB import.
8. **UI client** — listing/graph/decompiler views over the API.

## Influences

- **Ghidra**: P-code, Sleigh, the transactional program database, Apache
  licensing. What we change: UI-embedded analysis, batch-oriented
  invalidation, JVM-embedded scripting.
- **rev.ng** (https://rev.ng): the model-as-text, incremental pipelines,
  client/server with thin UI. What we change: LLVM IR as the core
  representation, QEMU-derived lifting (license + architecture ceiling).
- **rust-analyzer / salsa**: demand-driven, memoized, invalidation-correct
  computation as the engine of interactivity.
