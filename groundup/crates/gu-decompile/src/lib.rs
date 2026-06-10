//! A structured pseudo-C decompiler over optimized SSA.
//!
//! Three stages turn `gu_ssa::SsaProgram` into readable code:
//!
//! 1. **Expression propagation + out-of-SSA** ([`hir`]): single-use pure
//!    definitions are folded into their use sites to rebuild expression
//!    trees, and SSA register versions are coalesced back to one variable
//!    per machine register (phi nodes become implicit).
//! 2. **Control-flow structuring** ([`structure`]): the CFG is recovered
//!    into `if`/`while` regions using dominators and post-dominators, with
//!    `goto` as a guaranteed-correct fallback for shapes it can't match.
//! 3. **Emission** ([`emit`]): the structured tree is printed as C-like
//!    pseudocode.
//!
//! The output is a readable approximation, not a recompilable translation —
//! the honest state of a decompiler that does not yet model types, the full
//! ABI, or memory aliasing.

#![forbid(unsafe_code)]

mod cfg;
mod emit;
mod hir;
mod structure;
mod vars;

use gu_ssa::SsaProgram;

pub use hir::{HExpr, HStmt};
pub use vars::Signature;

/// Decompiles an (ideally already optimized) SSA program to pseudo-C text.
/// `name_of` resolves a call target address to a function name, if known.
pub fn decompile(prog: &SsaProgram, name_of: &dyn Fn(u64) -> Option<String>) -> String {
    let sig = vars::signature(prog);
    if prog.blocks.is_empty() {
        return emit::emit(&prog.name, prog.entry, &sig, &[], &[]);
    }
    let stack = vars::stack_offsets(prog);
    let locals: Vec<String> =
        vars::used_slots(prog, &stack).into_iter().map(vars::local_name).collect();

    let analysis = cfg::Analysis::new(prog);
    let bodies = hir::lower_blocks(prog, &stack, name_of);
    let structured = structure::structure(prog, &analysis, &bodies);
    emit::emit(&prog.name, prog.entry, &sig, &locals, &structured)
}
