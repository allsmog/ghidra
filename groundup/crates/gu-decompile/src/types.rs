//! Type and width recovery — the second half of data-layout analysis.
//!
//! Every value starts untyped (rendered `long`). Types are then inferred
//! from how values flow through the SSA and refined to a fixpoint:
//!
//! - a value produced by a load takes the load's width and signedness;
//! - a value used as a load/store address is a pointer to the accessed type;
//! - pointer-ness propagates backwards through the base of pointer
//!   arithmetic (`ptr + index`);
//! - copies and phi nodes unify their operands' types.
//!
//! Conflicting evidence falls back to `long`, so the result is always a
//! sound (if sometimes imprecise) C rendering.

use gu_rv64::Rv64Namer;
use gu_ir::{BinOp, RegNamer};
use gu_ssa::{Key, SsaExpr, SsaProgram, SsaStmt, SsaVal};
use std::collections::HashMap;

use crate::vars::{slot_of, StackMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ty {
    /// No evidence yet — renders as the default `long`.
    Unknown,
    Int { bits: u8, signed: bool },
    Ptr(Box<Ty>),
    /// Contradictory evidence — also renders as `long`.
    Conflict,
}

impl Ty {
    fn int(bits: u8, signed: bool) -> Ty {
        Ty::Int { bits, signed }
    }

    /// Lattice join: `Unknown` is the identity; equal types agree; anything
    /// else (including pointer-vs-int) conflicts.
    fn join(&self, other: &Ty) -> Ty {
        match (self, other) {
            (Ty::Unknown, t) | (t, Ty::Unknown) => t.clone(),
            (a, b) if a == b => a.clone(),
            (Ty::Ptr(a), Ty::Ptr(b)) => Ty::Ptr(Box::new(a.join(b))),
            _ => Ty::Conflict,
        }
    }

    /// C spelling; `Unknown`/`Conflict` and 64-bit signed all render `long`.
    pub fn c_name(&self) -> String {
        match self {
            Ty::Unknown | Ty::Conflict => "long".to_string(),
            Ty::Ptr(inner) => format!("{} *", inner.c_name()),
            Ty::Int { bits, signed } => {
                let base = match bits {
                    8 => "char",
                    16 => "short",
                    32 => "int",
                    _ => "long",
                };
                if *signed {
                    if *bits == 8 {
                        "signed char".to_string() // explicit: `char` signedness is impl-defined
                    } else {
                        base.to_string()
                    }
                } else {
                    format!("unsigned {base}")
                }
            }
        }
    }
}

/// Recovered types for a function's variables.
pub struct Types {
    /// By machine-register name, joined over all SSA versions. Used for
    /// local variables.
    reg: HashMap<String, Ty>,
    /// By machine-register name, from the *incoming* (version 0) value only.
    /// Used for parameters, so a register reused for an unrelated purpose
    /// later in the function does not pollute its parameter type.
    param: HashMap<String, Ty>,
    /// By stack-slot offset.
    slot: HashMap<i64, Ty>,
    /// The type of the returned value.
    ret: Ty,
}

impl Types {
    pub fn reg_ctype(&self, name: &str) -> String {
        self.reg.get(name).map_or_else(|| "long".to_string(), Ty::c_name)
    }

    pub fn param_ctype(&self, name: &str) -> String {
        self.param.get(name).map_or_else(|| "long".to_string(), Ty::c_name)
    }

    pub fn slot_ctype(&self, offset: i64) -> String {
        self.slot.get(&offset).map_or_else(|| "long".to_string(), Ty::c_name)
    }

    pub fn return_ctype(&self) -> String {
        self.ret.c_name()
    }
}

/// The inferred type of each SSA value.
type TyMap = HashMap<Key, Ty>;

/// Joins `t` into the recorded type of `v`, returning whether it changed.
fn refine(ty: &mut TyMap, v: SsaVal, t: Ty) -> bool {
    let Some(k) = v.key() else { return false };
    let cur = ty.get(&k).cloned().unwrap_or(Ty::Unknown);
    let joined = cur.join(&t);
    if joined != cur {
        ty.insert(k, joined);
        true
    } else {
        false
    }
}

/// Infers value types over the SSA and projects them onto variables.
pub fn recover(prog: &SsaProgram, stack: &StackMap) -> Types {
    let mut ty: TyMap = HashMap::new();

    let mut changed = true;
    while changed {
        changed = false;
        for block in &prog.blocks {
            // phi: unify destination with each argument's register version.
            for phi in &block.phis {
                let dst = SsaVal::Reg(phi.reg, phi.dst);
                let dst_ty = ty.get(&Key::Reg(phi.reg, phi.dst)).cloned().unwrap_or(Ty::Unknown);
                for (_, ver) in &phi.args {
                    let arg = SsaVal::Reg(phi.reg, *ver);
                    let arg_ty =
                        ty.get(&Key::Reg(phi.reg, *ver)).cloned().unwrap_or(Ty::Unknown);
                    changed |= refine(&mut ty, dst, arg_ty);
                    changed |= refine(&mut ty, arg, dst_ty.clone());
                }
            }
            for (_, stmt) in &block.stmts {
                changed |= infer_stmt(stmt, &mut ty);
            }
        }
    }

    project(prog, stack, &ty)
}

/// Applies the per-statement inference rules, reporting whether the type map
/// changed.
fn infer_stmt(stmt: &SsaStmt, ty: &mut TyMap) -> bool {
    let mut changed = false;
    match stmt {
        SsaStmt::Assign { dst, expr } => {
            match expr {
                SsaExpr::Load { addr, size, signed } => {
                    changed |= refine(ty, *dst, Ty::int(size * 8, *signed));
                    changed |= refine(ty, *addr, Ty::Ptr(Box::new(Ty::int(size * 8, *signed))));
                }
                SsaExpr::Val(src) => {
                    let st = src.key().and_then(|k| ty.get(&k).cloned()).unwrap_or(Ty::Unknown);
                    let dt = dst.key().and_then(|k| ty.get(&k).cloned()).unwrap_or(Ty::Unknown);
                    changed |= refine(ty, *dst, st);
                    changed |= refine(ty, *src, dt);
                }
                SsaExpr::Bin(op @ (BinOp::Add | BinOp::Sub), a, b) => {
                    // If the result is a pointer, the base operand is too.
                    let dt = dst.key().and_then(|k| ty.get(&k).cloned()).unwrap_or(Ty::Unknown);
                    if let Ty::Ptr(_) = dt {
                        if let Some(base) = pointer_base(*a, *b, ty) {
                            changed |= refine(ty, base, dt);
                        }
                    }
                    let _ = op;
                }
                _ => {}
            }
        }
        SsaStmt::Store { addr, size, .. } => {
            changed |= refine(ty, *addr, Ty::Ptr(Box::new(Ty::int(size * 8, true))));
        }
        _ => {}
    }
    changed
}

/// Chooses which operand of an address-producing add is the pointer base:
/// prefer a non-immediate operand that isn't already a concrete integer,
/// favoring the first such operand (matching `base + index` codegen).
fn pointer_base(a: SsaVal, b: SsaVal, ty: &HashMap<Key, Ty>) -> Option<SsaVal> {
    let is_concrete_int = |v: SsaVal| {
        matches!(v.key().and_then(|k| ty.get(&k)), Some(Ty::Int { .. }))
    };
    for v in [a, b] {
        if !matches!(v, SsaVal::Imm(_)) && !is_concrete_int(v) {
            return Some(v);
        }
    }
    None
}

/// Projects SSA value types onto variables: register types join over all
/// versions; stack-slot types come from the access widths.
fn project(prog: &SsaProgram, stack: &StackMap, ty: &HashMap<Key, Ty>) -> Types {
    let mut reg: HashMap<String, Ty> = HashMap::new();
    let mut param: HashMap<String, Ty> = HashMap::new();
    for (key, t) in ty {
        if let Key::Reg(r, ver) = key {
            let name = Rv64Namer.reg_name(*r).to_string();
            let entry = reg.entry(name.clone()).or_insert(Ty::Unknown);
            *entry = entry.join(t);
            if *ver == 0 {
                let p = param.entry(name).or_insert(Ty::Unknown);
                *p = p.join(t);
            }
        }
    }

    // Return type: join of every returned value's type.
    let mut ret = Ty::Unknown;
    for block in &prog.blocks {
        for (_, stmt) in &block.stmts {
            if let SsaStmt::Return { live_out } = stmt {
                if let Some(v) = live_out.first() {
                    let vt = v.key().and_then(|k| ty.get(&k).cloned()).unwrap_or(Ty::Unknown);
                    ret = ret.join(&vt);
                }
            }
        }
    }

    let mut slot: HashMap<i64, Ty> = HashMap::new();
    let mut note_slot = |addr: SsaVal, t: Ty| {
        if let Some(off) = slot_of(stack, addr) {
            let e = slot.entry(off).or_insert(Ty::Unknown);
            *e = e.join(&t);
        }
    };
    for block in &prog.blocks {
        for (_, stmt) in &block.stmts {
            match stmt {
                SsaStmt::Assign { expr: SsaExpr::Load { addr, size, signed }, .. } => {
                    note_slot(*addr, Ty::int(size * 8, *signed));
                }
                SsaStmt::Store { addr, val, size } => {
                    // Prefer the stored value's own type when known.
                    let vt = val
                        .key()
                        .and_then(|k| ty.get(&k).cloned())
                        .unwrap_or_else(|| Ty::int(size * 8, true));
                    note_slot(*addr, vt);
                }
                _ => {}
            }
        }
    }

    Types { reg, param, slot, ret }
}
