//! High-level IR: expression trees and statements, built from SSA by
//! expression propagation and out-of-SSA variable naming.

use gu_ir::{BinOp, CmpOp, RegNamer, UnOp};
use gu_rv64::Rv64Namer;
use gu_ssa::{Key, SsaBlock, SsaExpr, SsaProgram, SsaStmt, SsaVal};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HExpr {
    Const(i64),
    Var(String),
    Bin(BinOp, Box<HExpr>, Box<HExpr>),
    Cmp(CmpOp, Box<HExpr>, Box<HExpr>),
    Un(UnOp, Box<HExpr>),
    Load { addr: Box<HExpr>, size: u8, signed: bool },
}

impl HExpr {
    /// Smart binary constructor that folds algebraic identities (`x + 0`,
    /// `x * 1`, `x & -1`, ...) so register moves and no-op arithmetic don't
    /// clutter the output.
    pub fn bin(op: BinOp, a: HExpr, b: HExpr) -> HExpr {
        use BinOp::*;
        let is = |e: &HExpr, k: i64| matches!(e, HExpr::Const(c) if *c == k);
        // Reassociate `(x ± c1) + c2` into `x + (c1 ± c2)` so chained address
        // arithmetic (e.g. `sp - 16 + 8`) collapses to a single offset.
        if op == Add {
            if let (HExpr::Bin(inner @ (Add | Sub), x, c1), HExpr::Const(c2)) = (&a, &b) {
                if let HExpr::Const(c1) = **c1 {
                    let combined = match inner {
                        Sub => c2.wrapping_sub(c1),
                        _ => c1.wrapping_add(*c2),
                    };
                    return HExpr::bin(Add, (**x).clone(), HExpr::Const(combined));
                }
            }
        }
        match op {
            Add | Sub | Or | Xor | Shl | Shr | Sar if is(&b, 0) => a,
            Add | Or if is(&a, 0) => b,
            Mul if is(&b, 1) => a,
            Mul if is(&a, 1) => b,
            Mul | And if is(&b, 0) => HExpr::Const(0),
            And if is(&b, -1) => a,
            // Normalize `x + (negative)` to a subtraction for readability.
            Add => match b {
                HExpr::Const(c) if c < 0 => {
                    HExpr::Bin(Sub, Box::new(a), Box::new(HExpr::Const(-c)))
                }
                _ => HExpr::Bin(Add, Box::new(a), Box::new(b)),
            },
            _ => HExpr::Bin(op, Box::new(a), Box::new(b)),
        }
    }

    /// Logical negation of a comparison, used to turn a loop's exit test
    /// into its continuation condition.
    pub fn negated(&self) -> HExpr {
        match self {
            HExpr::Cmp(op, a, b) => {
                let flipped = match op {
                    CmpOp::Eq => CmpOp::Ne,
                    CmpOp::Ne => CmpOp::Eq,
                    CmpOp::LtS => CmpOp::GeS,
                    CmpOp::GeS => CmpOp::LtS,
                    CmpOp::LtU => CmpOp::GeU,
                    CmpOp::GeU => CmpOp::LtU,
                };
                HExpr::Cmp(flipped, a.clone(), b.clone())
            }
            // Non-comparison conditions are rare here; wrap in `0 ==`.
            other => HExpr::Cmp(
                CmpOp::Eq,
                Box::new(other.clone()),
                Box::new(HExpr::Const(0)),
            ),
        }
    }
}

/// A high-level statement. Control flow (`if`/`while`/`goto`) is added later
/// by the structurer; these are the per-block "body" statements plus the
/// terminator data the structurer consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HStmt {
    Assign(String, HExpr),
    Store { addr: HExpr, val: HExpr, size: u8 },
    Call { name: String, args: Vec<HExpr> },
    CallIndirect { target: HExpr, args: Vec<HExpr> },
    SysCall,
    // --- inserted by the structurer ---
    If { cond: HExpr, then_body: Vec<HStmt>, else_body: Vec<HStmt> },
    While { cond: HExpr, body: Vec<HStmt> },
    Return(Option<HExpr>),
    IndirectJump(HExpr),
    Goto(u64),
    Label(u64),
    Break,
    Continue,
}

/// The terminator that ends a block, separated from its body so the
/// structurer can decide how to render control flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    /// Conditional branch: `if (cond) goto taken;` else fall through.
    Cond { cond: HExpr, taken: u64 },
    Jump(u64),
    Return(Option<HExpr>),
    Indirect(HExpr),
    /// Falls through to the single successor (no explicit terminator).
    Fall(u64),
    /// No successors and no return value (e.g. a syscall-exit tail).
    Sink,
}

/// A block lowered to high-level form.
pub struct LowBlock {
    pub body: Vec<HStmt>,
    pub term: Term,
}

/// Where a definition is used. Inlining is only safe when the single use is
/// an ordinary statement in the *same* block — a use inside a phi argument
/// means the value flows across a control-flow edge and must stay a real
/// assignment (the phi is implicit once SSA versions are coalesced).
#[derive(Default)]
struct UseInfo {
    count: u32,
    /// `(block_start, is_phi_arg)` of the unique use, when `count == 1`.
    single: Option<(u64, bool)>,
}

struct Uses(HashMap<Key, UseInfo>);

impl Uses {
    fn record(&mut self, k: Key, block: u64, is_phi: bool) {
        let e = self.0.entry(k).or_default();
        e.count += 1;
        e.single = if e.count == 1 { Some((block, is_phi)) } else { None };
    }

    /// May the definition of `k` (in `def_block`) be inlined into its use?
    fn inlinable(&self, k: Key, def_block: u64) -> bool {
        matches!(self.0.get(&k), Some(UseInfo { count: 1, single: Some((b, false)) }) if *b == def_block)
    }
}

/// Lowers every block: expression propagation within the block, out-of-SSA
/// naming, stack-slot rewriting, and terminator extraction.
pub fn lower_blocks(
    prog: &SsaProgram,
    stack: &crate::vars::StackMap,
    name_of: &dyn Fn(u64) -> Option<String>,
    arity_of: &dyn Fn(u64) -> usize,
) -> HashMap<u64, LowBlock> {
    let uses = global_uses(prog);
    prog.blocks
        .iter()
        .map(|b| (b.start, lower_block(b, &uses, stack, name_of, arity_of)))
        .collect()
}

/// Records every use of each SSA definition across the function, tagging
/// uses that occur inside phi arguments.
fn global_uses(prog: &SsaProgram) -> Uses {
    let mut uses = Uses(HashMap::new());
    for block in &prog.blocks {
        for phi in &block.phis {
            for (_, ver) in &phi.args {
                uses.record(Key::Reg(phi.reg, *ver), block.start, true);
            }
        }
        for (_, stmt) in &block.stmts {
            let mut bump = |v: &SsaVal| {
                if let Some(k) = v.key() {
                    uses.record(k, block.start, false);
                }
            };
            visit_stmt_uses(stmt, &mut bump);
            // Call argument registers are reads too; counting them keeps
            // single-use inlining decisions correct.
            if let Some(args) = call_args(stmt) {
                args.iter().for_each(&mut bump);
            }
        }
    }
    uses
}

fn visit_expr_uses(e: &SsaExpr, f: &mut dyn FnMut(&SsaVal)) {
    match e {
        SsaExpr::Val(v) => f(v),
        SsaExpr::Bin(_, a, b) => {
            f(a);
            f(b);
        }
        SsaExpr::Un(_, v) => f(v),
        SsaExpr::Load { addr, .. } => f(addr),
    }
}

/// The argument-register reads of a call statement, if any.
fn call_args(stmt: &SsaStmt) -> Option<&[SsaVal]> {
    match stmt {
        SsaStmt::Call { args, .. }
        | SsaStmt::CallIndirect { args, .. }
        | SsaStmt::SysCall { args, .. } => Some(args),
        _ => None,
    }
}

fn visit_stmt_uses(stmt: &SsaStmt, f: &mut dyn FnMut(&SsaVal)) {
    match stmt {
        SsaStmt::Assign { expr, .. } => visit_expr_uses(expr, f),
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

/// The variable name for an SSA value: machine-register name (versions
/// coalesced) for registers, `tmpN` for surviving temporaries.
fn var_name(v: SsaVal) -> Option<String> {
    match v {
        SsaVal::Reg(r, _) => Some(Rv64Namer.reg_name(r).to_string()),
        SsaVal::Tmp(t) => Some(format!("tmp{t}")),
        SsaVal::Imm(_) => None,
    }
}

struct Lowerer<'a> {
    /// Inlinable definitions in this block: key -> its expression. A key is
    /// present only if it is pure and used exactly once in the function.
    inlinable: HashMap<Key, HExpr>,
    stack: &'a crate::vars::StackMap,
}

impl Lowerer<'_> {
    fn val(&self, v: SsaVal) -> HExpr {
        match v {
            SsaVal::Imm(i) => HExpr::Const(i),
            _ => {
                if let Some(k) = v.key() {
                    if let Some(expr) = self.inlinable.get(&k) {
                        return expr.clone();
                    }
                }
                HExpr::Var(var_name(v).expect("non-immediate has a name"))
            }
        }
    }

    fn expr(&self, e: &SsaExpr) -> HExpr {
        match e {
            SsaExpr::Val(v) => self.val(*v),
            SsaExpr::Bin(op, a, b) => HExpr::bin(*op, self.val(*a), self.val(*b)),
            SsaExpr::Un(op, v) => HExpr::Un(*op, Box::new(self.val(*v))),
            SsaExpr::Load { addr, size, signed } => {
                // A load from a recovered stack slot reads the local directly.
                if let Some(off) = crate::vars::slot_of(self.stack, *addr) {
                    return HExpr::Var(crate::vars::local_name(off));
                }
                HExpr::Load {
                    addr: Box::new(self.val(*addr)),
                    size: *size,
                    signed: *signed,
                }
            }
        }
    }

    fn is_pure(e: &SsaExpr) -> bool {
        // Loads are not inlined across statements: a store between the load
        // and its use could change the value.
        !matches!(e, SsaExpr::Load { .. })
    }
}

fn lower_block(
    block: &SsaBlock,
    uses: &Uses,
    stack: &crate::vars::StackMap,
    name_of: &dyn Fn(u64) -> Option<String>,
    arity_of: &dyn Fn(u64) -> usize,
) -> LowBlock {
    let mut low = Lowerer { inlinable: HashMap::new(), stack };
    let mut body = Vec::new();
    let stmts = &block.stmts;
    let n = stmts.len();

    // The last statement may be a control-flow terminator; body is the rest.
    let term_idx = stmts
        .iter()
        .position(|(_, s)| is_terminator(s))
        .unwrap_or(n);

    for (i, (_, stmt)) in stmts.iter().enumerate() {
        if i == term_idx {
            break;
        }
        match stmt {
            SsaStmt::Assign { dst, expr } => {
                // Stack-pointer bookkeeping (prologue/epilogue) is frame
                // management, not program logic — don't emit it.
                if matches!(dst, SsaVal::Reg(2, _)) {
                    continue;
                }
                let he = low.expr(expr);
                let key = dst.key();
                let inlinable = key.is_some_and(|k| uses.inlinable(k, block.start));
                if inlinable && Lowerer::is_pure(expr) {
                    // Fold into the (single, later, same-block) use instead
                    // of emitting an assignment.
                    low.inlinable.insert(key.unwrap(), he);
                } else if let Some(name) = dst.and_then_name() {
                    body.push(HStmt::Assign(name, he));
                }
            }
            SsaStmt::Store { addr, val, size } => {
                // A store to a recovered stack slot writes the local.
                if let Some(off) = crate::vars::slot_of(stack, *addr) {
                    body.push(HStmt::Assign(crate::vars::local_name(off), low.val(*val)));
                } else {
                    body.push(HStmt::Store {
                        addr: low.val(*addr),
                        val: low.val(*val),
                        size: *size,
                    });
                }
            }
            SsaStmt::Call { target, args, .. } => {
                let name = name_of(*target).unwrap_or_else(|| format!("fn_{target:x}"));
                let n = arity_of(*target).min(args.len());
                let args = args[..n].iter().map(|v| low.val(*v)).collect();
                body.push(HStmt::Call { name, args });
            }
            SsaStmt::CallIndirect { addr, args, .. } => {
                // Arity of an indirect callee is unknown; show no arguments.
                body.push(HStmt::CallIndirect { target: low.val(*addr), args: Vec::new() });
                let _ = args;
            }
            SsaStmt::SysCall { .. } => body.push(HStmt::SysCall),
            _ => {}
        }
    }

    let term = match stmts.get(term_idx).map(|(_, s)| s) {
        Some(SsaStmt::CondJump { op, lhs, rhs, target }) => Term::Cond {
            cond: HExpr::Cmp(*op, Box::new(low.val(*lhs)), Box::new(low.val(*rhs))),
            taken: *target,
        },
        Some(SsaStmt::Jump { target }) => Term::Jump(*target),
        Some(SsaStmt::Return { live_out }) => {
            Term::Return(live_out.first().map(|v| low.val(*v)))
        }
        Some(SsaStmt::JumpIndirect { addr }) => Term::Indirect(low.val(*addr)),
        _ => match block.succs.first() {
            Some(&s) => Term::Fall(s),
            None => Term::Sink,
        },
    };

    LowBlock { body, term }
}

fn is_terminator(s: &SsaStmt) -> bool {
    matches!(
        s,
        SsaStmt::CondJump { .. }
            | SsaStmt::Jump { .. }
            | SsaStmt::Return { .. }
            | SsaStmt::JumpIndirect { .. }
    )
}

trait NameOf {
    fn and_then_name(&self) -> Option<String>;
}

impl NameOf for SsaVal {
    fn and_then_name(&self) -> Option<String> {
        var_name(*self)
    }
}
