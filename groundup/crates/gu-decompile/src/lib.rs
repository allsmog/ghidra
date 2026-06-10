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
mod types;
mod vars;

use gu_ssa::SsaProgram;

pub use hir::{HExpr, HStmt};
pub use vars::{arg_count, Signature};

/// Decompiles an (ideally already optimized) SSA program to pseudo-C text.
/// `name_of` resolves a call target address to a function name, if known.
/// Decompiles an (ideally already optimized) SSA program to pseudo-C text.
///
/// - `name_of` resolves a call target address to a function name.
/// - `arity_of` resolves a call target to its parameter count, so call sites
///   render the right number of arguments and the function's own signature
///   accounts for arguments forwarded to callees. The kernel supplies this
///   from an interprocedural arity fixpoint; pass `|_| 0` for none.
/// - `switch_of` resolves the address of an indirect jump to its jump-table
///   cases and switch-index variable, so the jump structures as a `switch`.
///   Pass `|_| None` for none.
pub fn decompile(
    prog: &SsaProgram,
    name_of: &dyn Fn(u64) -> Option<String>,
    arity_of: &dyn Fn(u64) -> usize,
    switch_of: &dyn Fn(u64) -> Option<(Vec<u64>, Option<String>)>,
) -> String {
    let sig = vars::signature(prog, arity_of);
    let stack = vars::stack_offsets(prog);
    let types = types::recover(prog, &stack);

    // Parameters typed from their incoming value; return type from the
    // returned value.
    let params: Vec<(String, String)> =
        sig.params.iter().map(|p| (types.param_ctype(p), p.clone())).collect();
    let ret = if sig.returns_value { types.return_ctype() } else { "void".to_string() };

    if prog.blocks.is_empty() {
        return emit::emit(&prog.name, prog.entry, &ret, &params, &[], &[]);
    }

    let analysis = cfg::Analysis::new(prog);
    let bodies = hir::lower_blocks(prog, &stack, name_of, arity_of, switch_of);
    let mut structured = structure::structure(prog, &analysis, &bodies);

    // Recognize struct fields / array indexing / pointer deref now that
    // types are known.
    let ptr_info = hir::PtrInfo { pointee_size: &|name| types.pointee_size(name) };
    hir::simplify_accesses(&mut structured, &ptr_info);
    // Drop assignments left dead by structuring (e.g. a jump table's load
    // once its indirect jump became a switch).
    hir::remove_dead_assignments(&mut structured);

    // Local declarations: stack slots, then register variables that appear
    // in the body and are neither parameters nor stack slots.
    let param_names: std::collections::HashSet<&str> =
        sig.params.iter().map(String::as_str).collect();
    let mut decls: Vec<(String, String)> = vars::used_slots(prog, &stack)
        .into_iter()
        .map(|off| (types.slot_ctype(off), vars::local_name(off)))
        .collect();
    let mut seen: std::collections::HashSet<String> =
        decls.iter().map(|(_, n)| n.clone()).collect();
    for name in emit::referenced_vars(&structured) {
        if !param_names.contains(name.as_str()) && seen.insert(name.clone()) {
            decls.push((types.reg_ctype(&name), name));
        }
    }

    emit::emit(&prog.name, prog.entry, &ret, &params, &decls, &structured)
}
