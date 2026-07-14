//! High-level IR: expression trees and statements, built from SSA by
//! expression propagation and out-of-SSA variable naming.

use gu_ir::{BinOp, CmpOp, RegNamer, UnOp};
use gu_rv64::Rv64Namer;
use gu_ssa::{Key, SsaBlock, SsaExpr, SsaProgram, SsaStmt, SsaVal};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HExpr {
    Const(i64),
    Var(String),
    Bin(BinOp, Box<HExpr>, Box<HExpr>),
    Cmp(CmpOp, Box<HExpr>, Box<HExpr>),
    Un(UnOp, Box<HExpr>),
    Load { addr: Box<HExpr>, size: u8, signed: bool },
    /// `base[index]` — a load recognized as array indexing.
    Index(Box<HExpr>, Box<HExpr>),
    /// `*base` — a load through a typed pointer at offset zero.
    Deref(Box<HExpr>),
    /// `base->field_<off>` — a load through a pointer at a constant offset
    /// into a recovered struct.
    Field(Box<HExpr>, i64),
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
    /// A resolved jump table: `switch (value) { case i: <body> ... }`, where
    /// each case body is the structured region of a target block.
    Switch { value: String, cases: Vec<(usize, Vec<HStmt>)> },
    /// `place = val;` where `place` is a recovered lvalue (field/index/deref).
    SetPlace { place: HExpr, val: HExpr },
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
    /// A resolved jump table: the switch index variable and the case target
    /// block addresses, in table order.
    Switch { value: String, cases: Vec<u64> },
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
    switch_of: &dyn Fn(u64) -> Option<(Vec<u64>, Option<String>)>,
) -> HashMap<u64, LowBlock> {
    let uses = global_uses(prog);
    prog.blocks
        .iter()
        .map(|b| (b.start, lower_block(b, &uses, stack, name_of, arity_of, switch_of)))
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
    switch_of: &dyn Fn(u64) -> Option<(Vec<u64>, Option<String>)>,
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

    let term = match stmts.get(term_idx) {
        Some((_, SsaStmt::CondJump { op, lhs, rhs, target })) => Term::Cond {
            cond: HExpr::Cmp(*op, Box::new(low.val(*lhs)), Box::new(low.val(*rhs))),
            taken: *target,
        },
        Some((_, SsaStmt::Jump { target })) => Term::Jump(*target),
        Some((_, SsaStmt::Return { live_out })) => {
            Term::Return(live_out.first().map(|v| low.val(*v)))
        }
        Some((addr, SsaStmt::JumpIndirect { addr: target })) => match switch_of(*addr) {
            // A resolved jump table: structure it as a switch.
            Some((cases, index)) if !cases.is_empty() => Term::Switch {
                value: index.unwrap_or_else(|| "/* index */".to_string()),
                cases,
            },
            _ => Term::Indirect(low.val(*target)),
        },
        _ => match block.succs.first() {
            Some(&s) => Term::Fall(s),
            None => Term::Sink,
        },
    };

    LowBlock { body, term }
}

/// Removes assignments to variables that are never read anywhere in the
/// function. Iterated to a fixpoint, since removing one dead assignment can
/// make the values it read dead in turn. Expressions here have no side
/// effects, so a write whose result is unused is safe to drop — this clears
/// out, e.g., the table-load left behind once an indirect jump becomes a
/// `switch`.
pub fn remove_dead_assignments(stmts: &mut Vec<HStmt>) {
    loop {
        let mut reads = HashSet::new();
        collect_reads(stmts, &mut reads);
        if !drop_dead(stmts, &reads) {
            break;
        }
    }
}

/// Variable names that appear as reads (operands), excluding plain
/// assignment targets.
fn collect_reads(stmts: &[HStmt], reads: &mut HashSet<String>) {
    for stmt in stmts {
        match stmt {
            // The LHS name of a plain assignment is a write, not a read.
            HStmt::Assign(_, e) | HStmt::Return(Some(e)) | HStmt::IndirectJump(e) => {
                collect_expr_vars(e, reads)
            }
            HStmt::Store { addr, val, .. } => {
                collect_expr_vars(addr, reads);
                collect_expr_vars(val, reads);
            }
            HStmt::SetPlace { place, val } => {
                collect_expr_vars(place, reads);
                collect_expr_vars(val, reads);
            }
            HStmt::Call { args, .. } => args.iter().for_each(|e| collect_expr_vars(e, reads)),
            HStmt::CallIndirect { target, args } => {
                collect_expr_vars(target, reads);
                args.iter().for_each(|e| collect_expr_vars(e, reads));
            }
            HStmt::Switch { value, cases } => {
                reads.insert(value.clone());
                for (_, body) in cases {
                    collect_reads(body, reads);
                }
            }
            HStmt::If { cond, then_body, else_body } => {
                collect_expr_vars(cond, reads);
                collect_reads(then_body, reads);
                collect_reads(else_body, reads);
            }
            HStmt::While { cond, body } => {
                collect_expr_vars(cond, reads);
                collect_reads(body, reads);
            }
            _ => {}
        }
    }
}

fn collect_expr_vars(e: &HExpr, out: &mut HashSet<String>) {
    match e {
        HExpr::Var(n) => {
            out.insert(n.clone());
        }
        HExpr::Bin(_, a, b) | HExpr::Cmp(_, a, b) | HExpr::Index(a, b) => {
            collect_expr_vars(a, out);
            collect_expr_vars(b, out);
        }
        HExpr::Un(_, v) | HExpr::Deref(v) | HExpr::Field(v, _) => collect_expr_vars(v, out),
        HExpr::Load { addr, .. } => collect_expr_vars(addr, out),
        HExpr::Const(_) => {}
    }
}

/// Drops dead assignments in place; returns whether any were removed.
fn drop_dead(stmts: &mut Vec<HStmt>, reads: &HashSet<String>) -> bool {
    let before = count_stmts(stmts);
    stmts.retain(|s| !matches!(s, HStmt::Assign(name, _) if !reads.contains(name)));
    for stmt in stmts.iter_mut() {
        match stmt {
            HStmt::If { then_body, else_body, .. } => {
                drop_dead(then_body, reads);
                drop_dead(else_body, reads);
            }
            HStmt::While { body, .. } => {
                drop_dead(body, reads);
            }
            HStmt::Switch { cases, .. } => {
                for (_, body) in cases.iter_mut() {
                    drop_dead(body, reads);
                }
            }
            _ => {}
        }
    }
    count_stmts(stmts) != before
}

fn count_stmts(stmts: &[HStmt]) -> usize {
    stmts
        .iter()
        .map(|s| match s {
            HStmt::If { then_body, else_body, .. } => {
                1 + count_stmts(then_body) + count_stmts(else_body)
            }
            HStmt::While { body, .. } => 1 + count_stmts(body),
            HStmt::Switch { cases, .. } => {
                1 + cases.iter().map(|(_, b)| count_stmts(b)).sum::<usize>()
            }
            _ => 1,
        })
        .sum()
}

/// Information the access-recovery pass needs about pointer variables.
pub struct PtrInfo<'a> {
    /// Pointee size in bytes of a pointer variable, if it is a pointer.
    pub pointee_size: &'a dyn Fn(&str) -> Option<u8>,
}

/// Rewrites memory dereferences into struct fields, array indexing, or
/// pointer derefs, using recovered pointer types.
///
/// - `*(T*)(base + const)` where `base` is dereferenced at several distinct
///   offsets  ->  `base->field_<off>` (struct)
/// - `*(T*)(base + index*size)` with `size` the pointee size -> `base[index]`
/// - `*(T*)(base)` where `base` is a plain pointer           -> `*base`
pub fn simplify_accesses(stmts: &mut [HStmt], info: &PtrInfo) {
    // Phase 1: which pointers are accessed at a non-zero constant offset?
    // Those are structs; collect their bases.
    let mut struct_bases: HashSet<String> = HashSet::new();
    collect_struct_bases(stmts, info, &mut struct_bases);
    // Phase 2: rewrite loads and stores into the recovered lvalues.
    rewrite_stmts(stmts, info, &struct_bases);
}

/// The constant offset of `addr` from a pointer base `(base_name, offset)`:
/// `base` itself is offset 0, `base + k` is offset `k`.
fn const_offset(addr: &HExpr) -> Option<(&str, i64)> {
    match addr {
        HExpr::Var(name) => Some((name, 0)),
        HExpr::Bin(BinOp::Add, base, off) => match (base.as_ref(), off.as_ref()) {
            (HExpr::Var(name), HExpr::Const(k)) => Some((name, *k)),
            _ => None,
        },
        _ => None,
    }
}

/// Records a struct base if `addr` is a non-zero constant offset into a
/// pointer.
fn note_struct_base(addr: &HExpr, info: &PtrInfo, out: &mut HashSet<String>) {
    if let Some((name, off)) = const_offset(addr) {
        if off != 0 && (info.pointee_size)(name).is_some() {
            out.insert(name.to_string());
        }
    }
}

fn walk_expr_for_structs(e: &HExpr, info: &PtrInfo, out: &mut HashSet<String>) {
    match e {
        HExpr::Load { addr, .. } => {
            note_struct_base(addr, info, out);
            walk_expr_for_structs(addr, info, out);
        }
        HExpr::Bin(_, a, b) | HExpr::Cmp(_, a, b) | HExpr::Index(a, b) => {
            walk_expr_for_structs(a, info, out);
            walk_expr_for_structs(b, info, out);
        }
        HExpr::Un(_, v) | HExpr::Deref(v) | HExpr::Field(v, _) => {
            walk_expr_for_structs(v, info, out)
        }
        HExpr::Var(_) | HExpr::Const(_) => {}
    }
}

fn collect_struct_bases(stmts: &[HStmt], info: &PtrInfo, out: &mut HashSet<String>) {
    for stmt in stmts {
        for_each_expr(stmt, &mut |e| walk_expr_for_structs(e, info, out));
        if let HStmt::Store { addr, .. } = stmt {
            note_struct_base(addr, info, out);
        }
        match stmt {
            HStmt::If { then_body, else_body, .. } => {
                collect_struct_bases(then_body, info, out);
                collect_struct_bases(else_body, info, out);
            }
            HStmt::While { body, .. } => collect_struct_bases(body, info, out),
            HStmt::Switch { cases, .. } => {
                for (_, body) in cases {
                    collect_struct_bases(body, info, out);
                }
            }
            _ => {}
        }
    }
}

/// Applies `f` to each top-level expression of a statement (not recursing
/// into nested statement bodies).
fn for_each_expr(stmt: &HStmt, f: &mut dyn FnMut(&HExpr)) {
    match stmt {
        HStmt::Assign(_, e) | HStmt::Return(Some(e)) | HStmt::IndirectJump(e) => f(e),
        HStmt::Store { addr, val, .. } => {
            f(addr);
            f(val);
        }
        HStmt::SetPlace { place, val } => {
            f(place);
            f(val);
        }
        HStmt::Call { args, .. } => args.iter().for_each(f),
        HStmt::CallIndirect { target, args } => {
            f(target);
            args.iter().for_each(f);
        }
        HStmt::If { cond, .. } | HStmt::While { cond, .. } => f(cond),
        _ => {}
    }
}

/// The index expression of `index * stride`, if `e` scales by `stride`.
fn scaled_index(e: &HExpr, stride: u8) -> Option<HExpr> {
    match e {
        HExpr::Bin(BinOp::Shl, idx, shift) => match **shift {
            HExpr::Const(k) if (1i64 << k) == stride as i64 => Some((**idx).clone()),
            _ => None,
        },
        HExpr::Bin(BinOp::Mul, idx, factor) => match **factor {
            HExpr::Const(s) if s == stride as i64 => Some((**idx).clone()),
            _ => None,
        },
        _ if stride == 1 => Some(e.clone()),
        _ => None,
    }
}

/// Builds the lvalue an address denotes: a struct field, an array element,
/// or a plain deref. `size` is the access width.
fn as_place(
    addr: &HExpr,
    size: u8,
    info: &PtrInfo,
    structs: &HashSet<String>,
) -> Option<HExpr> {
    // Struct field: a constant offset into a known struct base.
    if let Some((name, off)) = const_offset(addr) {
        if structs.contains(name) {
            return Some(HExpr::Field(Box::new(HExpr::Var(name.to_string())), off));
        }
    }
    let is_ptr = |e: &HExpr| matches!(e, HExpr::Var(n) if (info.pointee_size)(n) == Some(size));
    match addr {
        // base + index*size  ->  base[index]
        HExpr::Bin(BinOp::Add, base, offset) if is_ptr(base) => {
            scaled_index(offset, size).map(|idx| HExpr::Index(base.clone(), Box::new(idx)))
        }
        // bare pointer  ->  *base
        base if is_ptr(base) => Some(HExpr::Deref(Box::new(base.clone()))),
        _ => None,
    }
}

fn rewrite_stmts(stmts: &mut [HStmt], info: &PtrInfo, structs: &HashSet<String>) {
    for stmt in stmts.iter_mut() {
        // Convert a recognized store into a place-assignment.
        if let HStmt::Store { addr, val, size } = stmt {
            if let Some(place) = as_place(addr, *size, info, structs) {
                let mut val = std::mem::replace(val, HExpr::Const(0));
                rewrite_expr(&mut val, info, structs);
                *stmt = HStmt::SetPlace { place, val };
                continue;
            }
        }
        match stmt {
            HStmt::Assign(_, e) | HStmt::Return(Some(e)) | HStmt::IndirectJump(e) => {
                rewrite_expr(e, info, structs)
            }
            HStmt::SetPlace { place, val } => {
                rewrite_expr(place, info, structs);
                rewrite_expr(val, info, structs);
            }
            HStmt::Store { addr, val, .. } => {
                rewrite_expr(addr, info, structs);
                rewrite_expr(val, info, structs);
            }
            HStmt::Call { args, .. } => {
                args.iter_mut().for_each(|a| rewrite_expr(a, info, structs))
            }
            HStmt::CallIndirect { target, args } => {
                rewrite_expr(target, info, structs);
                args.iter_mut().for_each(|a| rewrite_expr(a, info, structs));
            }
            HStmt::If { cond, then_body, else_body } => {
                rewrite_expr(cond, info, structs);
                rewrite_stmts(then_body, info, structs);
                rewrite_stmts(else_body, info, structs);
            }
            HStmt::While { cond, body } => {
                rewrite_expr(cond, info, structs);
                rewrite_stmts(body, info, structs);
            }
            HStmt::Switch { cases, .. } => {
                for (_, body) in cases.iter_mut() {
                    rewrite_stmts(body, info, structs);
                }
            }
            _ => {}
        }
    }
}

fn rewrite_expr(e: &mut HExpr, info: &PtrInfo, structs: &HashSet<String>) {
    match e {
        HExpr::Bin(_, a, b) | HExpr::Cmp(_, a, b) | HExpr::Index(a, b) => {
            rewrite_expr(a, info, structs);
            rewrite_expr(b, info, structs);
        }
        HExpr::Un(_, v) | HExpr::Deref(v) | HExpr::Field(v, _) => rewrite_expr(v, info, structs),
        HExpr::Load { addr, .. } => rewrite_expr(addr, info, structs),
        HExpr::Var(_) | HExpr::Const(_) => {}
    }
    if let HExpr::Load { addr, size, .. } = e {
        if let Some(place) = as_place(addr, *size, info, structs) {
            *e = place;
        }
    }
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
