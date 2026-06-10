//! Variable and signature recovery — the first slice of type recovery.
//!
//! Two analyses over SSA:
//!
//! - **Stack-frame analysis** ([`stack_offsets`]): a restricted value-set
//!   analysis that tracks every value of the form `incoming_sp + k`. Any
//!   load or store through such a value is a stack slot, which the
//!   decompiler then names `local_<k>` and declares, instead of printing a
//!   raw memory dereference. (This is also the kernel of a general VSA.)
//! - **Signature recovery** ([`signature`]): parameters are the argument
//!   registers read live-in (before any definition); the return type is
//!   `long` if the function returns and produces a value in `a0`, else
//!   `void`.

use gu_rv64::Rv64Namer;
use gu_ir::RegNamer;
use gu_ssa::{Key, SsaExpr, SsaProgram, SsaStmt, SsaVal};
use std::collections::{BTreeMap, BTreeSet, HashMap};

const SP: u16 = 2; // x2 / stack pointer
const ARG_REGS: std::ops::RangeInclusive<u16> = 10..=17; // a0..a7

/// Offsets, relative to the incoming stack pointer, of every SSA value that
/// holds a stack address. Keyed by the value's definition.
pub type StackMap = HashMap<Key, i64>;

/// Computes the stack-offset map by propagating `incoming_sp + k` through
/// additions and copies to a fixpoint. SSA gives each value one definition,
/// so the propagation is monotone and terminates.
pub fn stack_offsets(prog: &SsaProgram) -> StackMap {
    let mut off: StackMap = HashMap::new();
    // The incoming stack pointer is the base: sp version 0, offset 0.
    off.insert(Key::Reg(SP, 0), 0);

    let val_off = |off: &StackMap, v: &SsaVal| -> Option<i64> {
        match v {
            SsaVal::Reg(SP, 0) => Some(0),
            _ => v.key().and_then(|k| off.get(&k).copied()),
        }
    };

    let mut changed = true;
    while changed {
        changed = false;
        for block in &prog.blocks {
            for (_, stmt) in &block.stmts {
                let SsaStmt::Assign { dst, expr } = stmt else { continue };
                let Some(k) = dst.key() else { continue };
                if off.contains_key(&k) {
                    continue;
                }
                let new = match expr {
                    SsaExpr::Val(v) => val_off(&off, v),
                    SsaExpr::Bin(gu_ir::BinOp::Add, a, b) => match (val_off(&off, a), b) {
                        (Some(base), SsaVal::Imm(c)) => Some(base + c),
                        _ => match (a, val_off(&off, b)) {
                            (SsaVal::Imm(c), Some(base)) => Some(base + c),
                            _ => None,
                        },
                    },
                    SsaExpr::Bin(gu_ir::BinOp::Sub, a, b) => match (val_off(&off, a), b) {
                        (Some(base), SsaVal::Imm(c)) => Some(base - c),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(n) = new {
                    off.insert(k, n);
                    changed = true;
                }
            }
        }
    }
    off
}

/// The stack offset of a load/store address value, if it is a stack slot.
pub fn slot_of(off: &StackMap, addr: SsaVal) -> Option<i64> {
    match addr {
        SsaVal::Reg(SP, 0) => Some(0),
        _ => addr.key().and_then(|k| off.get(&k).copied()),
    }
}

/// The C-ish name for a stack slot at `offset` (relative to incoming sp).
/// Locals live below the entry sp, so offsets are negative; name by
/// magnitude for readability.
pub fn local_name(offset: i64) -> String {
    if offset < 0 {
        format!("local_{:x}", -offset)
    } else {
        format!("arg_{offset:x}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Parameter register names, in ABI order.
    pub params: Vec<String>,
    pub returns_value: bool,
}

impl Signature {
    pub fn return_type(&self) -> &'static str {
        if self.returns_value {
            "long"
        } else {
            "void"
        }
    }
}

/// Recovers a function signature from SSA register usage.
pub fn signature(prog: &SsaProgram) -> Signature {
    // Parameters are argument registers read live-in (version 0). Crucially
    // this scan excludes a return's `live_out`: the conservative ABI model
    // lists a1 there even when the function doesn't take or return it, and
    // counting that would invent phantom parameters.
    let mut live_in_args: BTreeSet<u16> = BTreeSet::new();
    for block in &prog.blocks {
        for (_, stmt) in &block.stmts {
            visit_reads_excluding_return(stmt, &mut |v| {
                if let SsaVal::Reg(r, 0) = v {
                    if ARG_REGS.contains(r) {
                        live_in_args.insert(*r);
                    }
                }
            });
        }
    }

    // With the parameter set known, decide whether any return yields a value.
    let returns_value = prog.blocks.iter().flat_map(|b| &b.stmts).any(|(_, stmt)| {
        matches!(stmt, SsaStmt::Return { live_out }
            if live_out.first().is_some_and(|v| produces_value(*v, &live_in_args)))
    });

    let params = live_in_args
        .iter()
        .map(|&r| Rv64Namer.reg_name(r).to_string())
        .collect::<Vec<_>>();

    Signature { params, returns_value }
}

/// Whether a return's first live-out value is a real result the caller would
/// read, as opposed to an untouched pass-through of incoming state.
fn produces_value(v: SsaVal, params: &BTreeSet<u16>) -> bool {
    match v {
        SsaVal::Imm(_) | SsaVal::Tmp(_) => true,
        // A defined value (version != 0), or an unmodified argument returned.
        SsaVal::Reg(r, ver) => ver != 0 || params.contains(&r),
    }
}

/// Visits the register/temp reads of a statement, but treats `Return`'s
/// live-out as not-a-read (it is the function's result, not an input).
fn visit_reads_excluding_return(stmt: &SsaStmt, f: &mut dyn FnMut(&SsaVal)) {
    if matches!(stmt, SsaStmt::Return { .. }) {
        return;
    }
    super_visit_uses(stmt, f);
}

/// Visits the SSA-value *uses* (reads) of a statement — shared with
/// `hir`'s use scan but kept local to avoid a cross-module dependency.
fn super_visit_uses(stmt: &SsaStmt, f: &mut dyn FnMut(&SsaVal)) {
    let expr = |e: &SsaExpr, f: &mut dyn FnMut(&SsaVal)| match e {
        SsaExpr::Val(v) => f(v),
        SsaExpr::Bin(_, a, b) => {
            f(a);
            f(b);
        }
        SsaExpr::Un(_, v) => f(v),
        SsaExpr::Load { addr, .. } => f(addr),
    };
    match stmt {
        SsaStmt::Assign { expr: e, .. } => expr(e, f),
        SsaStmt::Store { addr, val, .. } => {
            f(addr);
            f(val);
        }
        SsaStmt::CondJump { lhs, rhs, .. } => {
            f(lhs);
            f(rhs);
        }
        SsaStmt::CallIndirect { addr, .. } => f(addr),
        SsaStmt::JumpIndirect { addr } => f(addr),
        SsaStmt::Return { live_out } => live_out.iter().for_each(f),
        _ => {}
    }
}

/// Collects the set of stack-slot offsets actually accessed by loads and
/// stores, so the emitter can declare exactly those locals (sorted).
pub fn used_slots(prog: &SsaProgram, off: &StackMap) -> Vec<i64> {
    let mut slots: BTreeMap<i64, ()> = BTreeMap::new();
    for block in &prog.blocks {
        for (_, stmt) in &block.stmts {
            match stmt {
                SsaStmt::Assign { expr: SsaExpr::Load { addr, .. }, .. } => {
                    if let Some(o) = slot_of(off, *addr) {
                        slots.insert(o, ());
                    }
                }
                SsaStmt::Store { addr, .. } => {
                    if let Some(o) = slot_of(off, *addr) {
                        slots.insert(o, ());
                    }
                }
                _ => {}
            }
        }
    }
    slots.into_keys().collect()
}
