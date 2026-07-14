//! SSA construction and SSA-based analyses over `gu-ir`.
//!
//! Takes a [`gu_ir::LiftedFn`] (basic blocks of register-transfer IR) and
//! produces [`SsaProgram`]: the same control-flow graph with every register
//! definition given a unique version and phi nodes placed where versions
//! merge. SSA is the form on which value tracking, constant propagation,
//! and ultimately decompilation are cheap and correct — each use refers to
//! exactly one definition.
//!
//! Pipeline: dominators ([`dom`]) -> phi placement + renaming ([`build`])
//! -> optional optimization ([`opt`]).

#![forbid(unsafe_code)]

mod build;
pub mod dom;
mod opt;

pub use build::build;
pub use opt::optimize;

use gu_ir::{BinOp, CmpOp, RegNamer, UnOp};
use std::fmt::Write as _;

/// An SSA operand. Registers carry a version; temporaries are already
/// single-assignment from the lifter, so they keep their identity;
/// immediates are constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsaVal {
    /// `Reg(register, version)`. Version 0 is the function's live-in value
    /// of that register (an argument or caller-provided state).
    Reg(u16, u32),
    Tmp(u32),
    Imm(i64),
}

impl SsaVal {
    /// The definition key this value introduces or refers to, if it is a
    /// register or temporary (immediates are not keys).
    pub fn key(self) -> Option<Key> {
        match self {
            SsaVal::Reg(r, v) => Some(Key::Reg(r, v)),
            SsaVal::Tmp(t) => Some(Key::Tmp(t)),
            SsaVal::Imm(_) => None,
        }
    }
}

/// A definition site identity, used as a map key by analyses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Reg(u16, u32),
    Tmp(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaExpr {
    Val(SsaVal),
    Bin(BinOp, SsaVal, SsaVal),
    Un(UnOp, SsaVal),
    Load { addr: SsaVal, size: u8, signed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaStmt {
    Assign { dst: SsaVal, expr: SsaExpr },
    Store { addr: SsaVal, val: SsaVal, size: u8 },
    Jump { target: u64 },
    CondJump { op: CmpOp, lhs: SsaVal, rhs: SsaVal, target: u64 },
    /// A call. `args` are the argument registers (a0-a7) read at the call
    /// site — modeling that the call consumes them, so the code producing
    /// them stays live. `defs` are the caller-saved registers it redefines
    /// with fresh versions — modeling "the call produces unknown values
    /// here" so nothing propagates stale state across it.
    Call { target: u64, args: Vec<SsaVal>, defs: Vec<SsaVal> },
    CallIndirect { addr: SsaVal, args: Vec<SsaVal>, defs: Vec<SsaVal> },
    JumpIndirect { addr: SsaVal },
    /// `live_out` are the ABI return-value registers (a0, a1) at this point,
    /// modeling that the caller reads them — so their definitions are live.
    Return { live_out: Vec<SsaVal> },
    SysCall { args: Vec<SsaVal>, defs: Vec<SsaVal> },
    Break,
    Nop,
}

/// `reg_dst = phi(pred -> value, ...)` at a control-flow merge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phi {
    pub reg: u16,
    pub dst: u32,
    /// One argument per predecessor: `(predecessor block start, version)`.
    pub args: Vec<(u64, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaBlock {
    pub start: u64,
    pub preds: Vec<u64>,
    pub phis: Vec<Phi>,
    pub stmts: Vec<(u64, SsaStmt)>,
    pub succs: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsaProgram {
    pub name: String,
    pub entry: u64,
    pub blocks: Vec<SsaBlock>,
}

// ---- rendering ----

fn fmt_val(v: SsaVal, names: &dyn RegNamer) -> String {
    match v {
        SsaVal::Reg(r, ver) => format!("{}_{ver}", names.reg_name(r)),
        SsaVal::Tmp(t) => format!("t{t}"),
        SsaVal::Imm(i) => {
            if (-9..=9).contains(&i) {
                format!("{i}")
            } else {
                format!("{i:#x}")
            }
        }
    }
}

fn fmt_expr(e: &SsaExpr, names: &dyn RegNamer) -> String {
    match e {
        SsaExpr::Val(v) => fmt_val(*v, names),
        SsaExpr::Bin(op, a, b) => {
            format!("{} {} {}", fmt_val(*a, names), bin_sym(*op), fmt_val(*b, names))
        }
        SsaExpr::Un(UnOp::Sext32, v) => format!("sext32({})", fmt_val(*v, names)),
        SsaExpr::Un(UnOp::Zext32, v) => format!("zext32({})", fmt_val(*v, names)),
        SsaExpr::Load { addr, size, signed } => {
            let s = if *signed { "s" } else { "u" };
            format!("load.{s}{}[{}]", size * 8, fmt_val(*addr, names))
        }
    }
}

fn fmt_defs(defs: &[SsaVal], names: &dyn RegNamer) -> String {
    if defs.is_empty() {
        String::new()
    } else {
        let list: Vec<String> = defs.iter().map(|d| fmt_val(*d, names)).collect();
        format!("  ; clobbers {}", list.join(", "))
    }
}

fn fmt_stmt(s: &SsaStmt, names: &dyn RegNamer) -> String {
    match s {
        SsaStmt::Assign { dst, expr } => {
            format!("{} = {}", fmt_val(*dst, names), fmt_expr(expr, names))
        }
        SsaStmt::Store { addr, val, size } => {
            format!("store.{}[{}] = {}", size * 8, fmt_val(*addr, names), fmt_val(*val, names))
        }
        SsaStmt::Jump { target } => format!("goto {target:#x}"),
        SsaStmt::CondJump { op, lhs, rhs, target } => format!(
            "if ({} {} {}) goto {target:#x}",
            fmt_val(*lhs, names),
            cmp_sym(*op),
            fmt_val(*rhs, names)
        ),
        SsaStmt::Call { target, defs, .. } => {
            format!("call {target:#x}{}", fmt_defs(defs, names))
        }
        SsaStmt::CallIndirect { addr, defs, .. } => {
            format!("call [{}]{}", fmt_val(*addr, names), fmt_defs(defs, names))
        }
        SsaStmt::JumpIndirect { addr } => format!("goto [{}]", fmt_val(*addr, names)),
        SsaStmt::Return { live_out } => {
            if live_out.is_empty() {
                "return".to_string()
            } else {
                let v: Vec<String> = live_out.iter().map(|v| fmt_val(*v, names)).collect();
                format!("return {}", v.join(", "))
            }
        }
        SsaStmt::SysCall { defs, .. } => format!("syscall{}", fmt_defs(defs, names)),
        SsaStmt::Break => "breakpoint".to_string(),
        SsaStmt::Nop => "nop".to_string(),
    }
}

fn bin_sym(op: BinOp) -> &'static str {
    use BinOp::*;
    match op {
        Add => "+", Sub => "-", And => "&", Or => "|", Xor => "^",
        Shl => "<<", Shr => ">>", Sar => ">>s",
        SltS => "<s", SltU => "<u",
        Mul => "*", MulHS => "*hs", MulHU => "*hu", MulHSU => "*hsu",
        DivS => "/s", DivU => "/u", RemS => "%s", RemU => "%u",
    }
}

fn cmp_sym(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==", CmpOp::Ne => "!=",
        CmpOp::LtS => "<s", CmpOp::GeS => ">=s",
        CmpOp::LtU => "<u", CmpOp::GeU => ">=u",
    }
}

impl SsaProgram {
    pub fn render(&self, names: &dyn RegNamer) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "fn {} @ {:#x} (ssa):", self.name, self.entry);
        for block in &self.blocks {
            let _ = writeln!(out, "  block_{:x}:", block.start);
            for phi in &block.phis {
                let args: Vec<String> = phi
                    .args
                    .iter()
                    .map(|(pred, ver)| format!("block_{pred:x}: {}_{ver}", names.reg_name(phi.reg)))
                    .collect();
                let _ = writeln!(
                    out,
                    "    {}_{} = phi({})",
                    names.reg_name(phi.reg),
                    phi.dst,
                    args.join(", ")
                );
            }
            for (addr, stmt) in &block.stmts {
                let _ = writeln!(out, "    {addr:#06x}  {}", fmt_stmt(stmt, names));
            }
            if !block.succs.is_empty() {
                let t: Vec<String> =
                    block.succs.iter().map(|s| format!("block_{s:x}")).collect();
                let _ = writeln!(out, "    -> {}", t.join(", "));
            }
        }
        out
    }

    /// Total statement + phi count, for measuring optimization effect.
    pub fn node_count(&self) -> usize {
        self.blocks.iter().map(|b| b.phis.len() + b.stmts.len()).sum()
    }
}

/// Caller-saved registers clobbered across a call (RV64 calling
/// convention): ra, t0-t2, a0-a7, t3-t6.
pub(crate) const CALL_CLOBBERS: &[u16] =
    &[1, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31];

/// ABI return-value registers: a0, a1.
pub(crate) const RET_REGS: &[u16] = &[10, 11];

/// ABI argument registers: a0-a7, in order. A call reads these; how many
/// are real arguments is decided later by interprocedural arity analysis.
pub(crate) const ARG_REGS: &[u16] = &[10, 11, 12, 13, 14, 15, 16, 17];
