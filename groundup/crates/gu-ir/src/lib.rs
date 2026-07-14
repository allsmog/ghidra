//! Architecture-neutral register-transfer IR, in the spirit of Ghidra's
//! P-code: a small set of explicit operations over registers, temporaries,
//! and constants. Lifters in arch crates translate decoded instructions
//! into sequences of [`Stmt`]s; analyses then only ever deal with this IR.
//!
//! This is deliberately *not* LLVM IR (compiler IRs assume well-formed
//! compiler output and churn with toolchain releases) and not yet SSA —
//! SSA construction is a planned analysis pass on top, see ARCHITECTURE.md.

#![forbid(unsafe_code)]

use std::fmt::Write as _;

/// An operand: a machine register, an IR temporary, or an immediate.
/// Registers are identified by an arch-specific index; the arch crate
/// supplies a [`RegNamer`] for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Reg(u16),
    Tmp(u32),
    Imm(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    SltS,
    SltU,
    Mul,
    MulHS,
    MulHU,
    MulHSU,
    DivS,
    DivU,
    RemS,
    RemU,
}

impl BinOp {
    fn symbol(self) -> &'static str {
        match self {
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Xor => "^",
            BinOp::Shl => "<<",
            BinOp::Shr => ">>",
            BinOp::Sar => ">>s",
            BinOp::SltS => "<s",
            BinOp::SltU => "<u",
            BinOp::Mul => "*",
            BinOp::MulHS => "*hs",
            BinOp::MulHU => "*hu",
            BinOp::MulHSU => "*hsu",
            BinOp::DivS => "/s",
            BinOp::DivU => "/u",
            BinOp::RemS => "%s",
            BinOp::RemU => "%u",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    /// Sign-extend the low 32 bits to 64.
    Sext32,
    /// Zero-extend the low 32 bits to 64.
    Zext32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    LtS,
    GeS,
    LtU,
    GeU,
}

impl CmpOp {
    fn symbol(self) -> &'static str {
        match self {
            CmpOp::Eq => "==",
            CmpOp::Ne => "!=",
            CmpOp::LtS => "<s",
            CmpOp::GeS => ">=s",
            CmpOp::LtU => "<u",
            CmpOp::GeU => ">=u",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Val(Value),
    Bin(BinOp, Value, Value),
    Un(UnOp, Value),
    Load { addr: Value, size: u8, signed: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stmt {
    Assign { dst: Value, expr: Expr },
    Store { addr: Value, val: Value, size: u8 },
    Jump { target: u64 },
    CondJump { op: CmpOp, lhs: Value, rhs: Value, target: u64 },
    /// Direct call; the lifter has already modeled the link-register write.
    Call { target: u64 },
    CallIndirect { addr: Value },
    JumpIndirect { addr: Value },
    Return,
    SysCall,
    Break,
    Nop,
}

/// Supplied by arch crates so the IR printer can show `a0` instead of `r10`.
pub trait RegNamer {
    fn reg_name(&self, reg: u16) -> &'static str;
}

pub fn fmt_value(v: Value, names: &dyn RegNamer) -> String {
    match v {
        Value::Reg(r) => names.reg_name(r).to_string(),
        Value::Tmp(t) => format!("t{t}"),
        Value::Imm(i) => {
            if (-9..=9).contains(&i) {
                format!("{i}")
            } else {
                format!("{i:#x}")
            }
        }
    }
}

pub fn fmt_expr(e: &Expr, names: &dyn RegNamer) -> String {
    match e {
        Expr::Val(v) => fmt_value(*v, names),
        Expr::Bin(op, a, b) => {
            format!("{} {} {}", fmt_value(*a, names), op.symbol(), fmt_value(*b, names))
        }
        Expr::Un(UnOp::Sext32, v) => format!("sext32({})", fmt_value(*v, names)),
        Expr::Un(UnOp::Zext32, v) => format!("zext32({})", fmt_value(*v, names)),
        Expr::Load { addr, size, signed } => {
            let sign = if *signed { "s" } else { "u" };
            format!("load.{sign}{}[{}]", size * 8, fmt_value(*addr, names))
        }
    }
}

pub fn fmt_stmt(s: &Stmt, names: &dyn RegNamer) -> String {
    match s {
        Stmt::Assign { dst, expr } => {
            format!("{} = {}", fmt_value(*dst, names), fmt_expr(expr, names))
        }
        Stmt::Store { addr, val, size } => {
            format!(
                "store.{}[{}] = {}",
                size * 8,
                fmt_value(*addr, names),
                fmt_value(*val, names)
            )
        }
        Stmt::Jump { target } => format!("goto {target:#x}"),
        Stmt::CondJump { op, lhs, rhs, target } => format!(
            "if ({} {} {}) goto {target:#x}",
            fmt_value(*lhs, names),
            op.symbol(),
            fmt_value(*rhs, names)
        ),
        Stmt::Call { target } => format!("call {target:#x}"),
        Stmt::CallIndirect { addr } => format!("call [{}]", fmt_value(*addr, names)),
        Stmt::JumpIndirect { addr } => format!("goto [{}]", fmt_value(*addr, names)),
        Stmt::Return => "return".to_string(),
        Stmt::SysCall => "syscall".to_string(),
        Stmt::Break => "breakpoint".to_string(),
        Stmt::Nop => "nop".to_string(),
    }
}

/// A basic block: straight-line IR plus the addresses of successor blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub start: u64,
    /// Statements paired with the address of the instruction they came from.
    pub stmts: Vec<(u64, Stmt)>,
    pub succs: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedFn {
    pub name: String,
    pub entry: u64,
    pub blocks: Vec<Block>,
}

impl LiftedFn {
    pub fn render(&self, names: &dyn RegNamer) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "fn {} @ {:#x}:", self.name, self.entry);
        for block in &self.blocks {
            let _ = writeln!(out, "  block_{:x}:", block.start);
            for (addr, stmt) in &block.stmts {
                let _ = writeln!(out, "    {addr:#06x}  {}", fmt_stmt(stmt, names));
            }
            if !block.succs.is_empty() {
                let targets: Vec<String> =
                    block.succs.iter().map(|s| format!("block_{s:x}")).collect();
                let _ = writeln!(out, "    -> {}", targets.join(", "));
            }
        }
        out
    }
}
