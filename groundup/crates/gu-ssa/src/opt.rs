//! SSA-based optimization: constant propagation, constant folding, and
//! dead-code elimination. This is where SSA pays off — because every use
//! refers to exactly one definition, a simple fixpoint over the value
//! lattice is sound, and dead definitions fall out by reachability.

use crate::{Key, Phi, SsaBlock, SsaExpr, SsaProgram, SsaStmt, SsaVal};
use gu_ir::{BinOp, UnOp};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lat {
    Top,
    Const(i64),
    Bottom,
}

impl Lat {
    fn meet(self, other: Lat) -> Lat {
        match (self, other) {
            (Lat::Top, x) | (x, Lat::Top) => x,
            (Lat::Const(a), Lat::Const(b)) if a == b => Lat::Const(a),
            (Lat::Const(_), Lat::Const(_)) => Lat::Bottom,
            _ => Lat::Bottom,
        }
    }
}

/// Optimizes a function's SSA form, returning the rewritten program. Safe
/// to run on any `SsaProgram`; on already-optimal code it is a no-op.
pub fn optimize(prog: &SsaProgram) -> SsaProgram {
    let values = constant_values(prog);
    let folded = rewrite_with_constants(prog, &values);
    eliminate_dead_code(&folded)
}

// ---- constant propagation ----

fn eval_bin(op: BinOp, a: i64, b: i64) -> Option<i64> {
    let sh = (b & 63) as u32;
    Some(match op {
        BinOp::Add => a.wrapping_add(b),
        BinOp::Sub => a.wrapping_sub(b),
        BinOp::And => a & b,
        BinOp::Or => a | b,
        BinOp::Xor => a ^ b,
        BinOp::Shl => ((a as u64) << sh) as i64,
        BinOp::Shr => ((a as u64) >> sh) as i64,
        BinOp::Sar => a >> sh,
        BinOp::Mul => a.wrapping_mul(b),
        BinOp::SltS => (a < b) as i64,
        BinOp::SltU => ((a as u64) < (b as u64)) as i64,
        BinOp::DivS if b != 0 => a.wrapping_div(b),
        BinOp::DivU if b != 0 => ((a as u64) / (b as u64)) as i64,
        BinOp::RemS if b != 0 => a.wrapping_rem(b),
        BinOp::RemU if b != 0 => ((a as u64) % (b as u64)) as i64,
        // High-multiply and divide-by-zero: not folded.
        _ => return None,
    })
}

fn eval_un(op: UnOp, x: i64) -> i64 {
    match op {
        UnOp::Sext32 => (x as i32) as i64,
        UnOp::Zext32 => (x as u32) as i64,
    }
}

fn lookup(v: SsaVal, vals: &HashMap<Key, Lat>) -> Lat {
    match v {
        SsaVal::Imm(i) => Lat::Const(i),
        // A key with no recorded definition is a live-in or call result:
        // unknown.
        other => other.key().map(|k| vals.get(&k).copied().unwrap_or(Lat::Bottom)).unwrap(),
    }
}

fn eval_expr(e: &SsaExpr, vals: &HashMap<Key, Lat>) -> Lat {
    match e {
        SsaExpr::Val(v) => lookup(*v, vals),
        SsaExpr::Bin(op, a, b) => match (lookup(*a, vals), lookup(*b, vals)) {
            (Lat::Const(x), Lat::Const(y)) => {
                eval_bin(*op, x, y).map_or(Lat::Bottom, Lat::Const)
            }
            (Lat::Top, _) | (_, Lat::Top) => Lat::Top,
            _ => Lat::Bottom,
        },
        SsaExpr::Un(op, v) => match lookup(*v, vals) {
            Lat::Const(x) => Lat::Const(eval_un(*op, x)),
            other => other,
        },
        // Memory reads are never known constants.
        SsaExpr::Load { .. } => Lat::Bottom,
    }
}

/// Iterates the value lattice to a fixpoint. Assignment and phi
/// destinations start at Top and descend; call clobbers are Bottom.
fn constant_values(prog: &SsaProgram) -> HashMap<Key, Lat> {
    let mut vals: HashMap<Key, Lat> = HashMap::new();
    for block in &prog.blocks {
        for phi in &block.phis {
            vals.insert(Key::Reg(phi.reg, phi.dst), Lat::Top);
        }
        for (_, stmt) in &block.stmts {
            match stmt {
                SsaStmt::Assign { dst, .. } => {
                    if let Some(k) = dst.key() {
                        vals.insert(k, Lat::Top);
                    }
                }
                SsaStmt::Call { defs, .. }
                | SsaStmt::CallIndirect { defs, .. }
                | SsaStmt::SysCall { defs, .. } => {
                    for d in defs {
                        if let Some(k) = d.key() {
                            vals.insert(k, Lat::Bottom);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in &prog.blocks {
            for phi in &block.phis {
                let new = phi
                    .args
                    .iter()
                    .map(|(_, ver)| {
                        vals.get(&Key::Reg(phi.reg, *ver)).copied().unwrap_or(Lat::Bottom)
                    })
                    .fold(Lat::Top, Lat::meet);
                let key = Key::Reg(phi.reg, phi.dst);
                if vals.get(&key) != Some(&new) {
                    vals.insert(key, new);
                    changed = true;
                }
            }
            for (_, stmt) in &block.stmts {
                if let SsaStmt::Assign { dst, expr } = stmt {
                    if let Some(k) = dst.key() {
                        let new = eval_expr(expr, &vals);
                        if vals.get(&k) != Some(&new) {
                            vals.insert(k, new);
                            changed = true;
                        }
                    }
                }
            }
        }
    }
    vals
}

// ---- rewrite uses with discovered constants ----

fn subst(v: SsaVal, vals: &HashMap<Key, Lat>) -> SsaVal {
    match v.key().and_then(|k| vals.get(&k)) {
        Some(Lat::Const(c)) => SsaVal::Imm(*c),
        _ => v,
    }
}

fn subst_expr(e: &SsaExpr, vals: &HashMap<Key, Lat>) -> SsaExpr {
    match e {
        SsaExpr::Val(v) => SsaExpr::Val(subst(*v, vals)),
        SsaExpr::Bin(op, a, b) => SsaExpr::Bin(*op, subst(*a, vals), subst(*b, vals)),
        SsaExpr::Un(op, v) => SsaExpr::Un(*op, subst(*v, vals)),
        SsaExpr::Load { addr, size, signed } => {
            SsaExpr::Load { addr: subst(*addr, vals), size: *size, signed: *signed }
        }
    }
}

fn rewrite_with_constants(prog: &SsaProgram, vals: &HashMap<Key, Lat>) -> SsaProgram {
    let blocks = prog
        .blocks
        .iter()
        .map(|block| {
            let stmts = block
                .stmts
                .iter()
                .map(|(addr, stmt)| (*addr, rewrite_stmt(stmt, vals)))
                .collect();
            SsaBlock { stmts, ..block.clone() }
        })
        .collect();
    SsaProgram { blocks, ..prog.clone() }
}

fn rewrite_stmt(stmt: &SsaStmt, vals: &HashMap<Key, Lat>) -> SsaStmt {
    match stmt {
        SsaStmt::Assign { dst, expr } => {
            // If the definition is itself a known constant, collapse the
            // whole right-hand side to that immediate.
            let expr = match dst.key().and_then(|k| vals.get(&k)) {
                Some(Lat::Const(c)) => SsaExpr::Val(SsaVal::Imm(*c)),
                _ => subst_expr(expr, vals),
            };
            SsaStmt::Assign { dst: *dst, expr }
        }
        SsaStmt::Store { addr, val, size } => {
            SsaStmt::Store { addr: subst(*addr, vals), val: subst(*val, vals), size: *size }
        }
        SsaStmt::CondJump { op, lhs, rhs, target } => SsaStmt::CondJump {
            op: *op,
            lhs: subst(*lhs, vals),
            rhs: subst(*rhs, vals),
            target: *target,
        },
        SsaStmt::Call { target, args, defs } => SsaStmt::Call {
            target: *target,
            args: args.iter().map(|v| subst(*v, vals)).collect(),
            defs: defs.clone(),
        },
        SsaStmt::CallIndirect { addr, args, defs } => SsaStmt::CallIndirect {
            addr: subst(*addr, vals),
            args: args.iter().map(|v| subst(*v, vals)).collect(),
            defs: defs.clone(),
        },
        SsaStmt::SysCall { args, defs } => SsaStmt::SysCall {
            args: args.iter().map(|v| subst(*v, vals)).collect(),
            defs: defs.clone(),
        },
        SsaStmt::JumpIndirect { addr } => SsaStmt::JumpIndirect { addr: subst(*addr, vals) },
        SsaStmt::Return { live_out } => {
            SsaStmt::Return { live_out: live_out.iter().map(|v| subst(*v, vals)).collect() }
        }
        other => other.clone(),
    }
}

// ---- dead-code elimination ----

fn expr_uses(e: &SsaExpr, out: &mut Vec<Key>) {
    let mut push = |v: SsaVal| out.extend(v.key());
    match e {
        SsaExpr::Val(v) => push(*v),
        SsaExpr::Bin(_, a, b) => {
            push(*a);
            push(*b);
        }
        SsaExpr::Un(_, v) => push(*v),
        SsaExpr::Load { addr, .. } => push(*addr),
    }
}

/// Statements with observable effects are always live; their operands seed
/// the liveness worklist. Returns the seed uses, or `None` for a pure
/// assignment (whose liveness depends on whether its result is used).
fn effect_uses(stmt: &SsaStmt) -> Option<Vec<Key>> {
    let mut uses = Vec::new();
    let mut push = |v: SsaVal| uses.extend(v.key());
    match stmt {
        // Pure: an assignment is live only if its definition is used.
        SsaStmt::Assign { .. } | SsaStmt::Nop => return None,
        SsaStmt::Store { addr, val, .. } => {
            push(*addr);
            push(*val);
        }
        SsaStmt::CondJump { lhs, rhs, .. } => {
            push(*lhs);
            push(*rhs);
        }
        SsaStmt::JumpIndirect { addr } => push(*addr),
        SsaStmt::Return { live_out } => live_out.iter().for_each(|v| push(*v)),
        // A call reads its argument registers and (if indirect) its target.
        // Seeding all of them keeps argument-producing code live; how many
        // are real arguments is decided later by arity analysis.
        SsaStmt::Call { args, .. } | SsaStmt::SysCall { args, .. } => {
            args.iter().for_each(|v| push(*v))
        }
        SsaStmt::CallIndirect { addr, args, .. } => {
            push(*addr);
            args.iter().for_each(|v| push(*v));
        }
        // Jumps and breaks have no SSA operands.
        _ => {}
    }
    Some(uses)
}

fn eliminate_dead_code(prog: &SsaProgram) -> SsaProgram {
    // Map each definition key to the expression that produced it, so we can
    // pull in the uses of a def once it becomes live.
    let mut def_expr: HashMap<Key, SsaExpr> = HashMap::new();
    let mut phi_uses: HashMap<Key, Vec<Key>> = HashMap::new();
    for block in &prog.blocks {
        for phi in &block.phis {
            let uses = phi
                .args
                .iter()
                .map(|(_, ver)| Key::Reg(phi.reg, *ver))
                .collect();
            phi_uses.insert(Key::Reg(phi.reg, phi.dst), uses);
        }
        for (_, stmt) in &block.stmts {
            if let SsaStmt::Assign { dst, expr } = stmt {
                if let Some(k) = dst.key() {
                    def_expr.insert(k, expr.clone());
                }
            }
        }
    }

    // Seed liveness from effectful statements, then close over definitions.
    let mut live: HashSet<Key> = HashSet::new();
    let mut work: Vec<Key> = Vec::new();
    for block in &prog.blocks {
        for (_, stmt) in &block.stmts {
            if let Some(uses) = effect_uses(stmt) {
                work.extend(uses);
            }
        }
    }
    while let Some(k) = work.pop() {
        if !live.insert(k) {
            continue;
        }
        if let Some(expr) = def_expr.get(&k) {
            let mut uses = Vec::new();
            expr_uses(expr, &mut uses);
            work.extend(uses);
        }
        if let Some(uses) = phi_uses.get(&k) {
            work.extend(uses.iter().copied());
        }
    }

    // Drop pure assignments and phis whose definitions are not live.
    let blocks = prog
        .blocks
        .iter()
        .map(|block| {
            let phis: Vec<Phi> = block
                .phis
                .iter()
                .filter(|p| live.contains(&Key::Reg(p.reg, p.dst)))
                .cloned()
                .collect();
            let stmts = block
                .stmts
                .iter()
                .filter(|(_, stmt)| match stmt {
                    SsaStmt::Assign { dst, .. } => {
                        dst.key().is_none_or(|k| live.contains(&k))
                    }
                    SsaStmt::Nop => false,
                    _ => true,
                })
                .cloned()
                .collect();
            SsaBlock { phis, stmts, ..block.clone() }
        })
        .collect();
    SsaProgram { blocks, ..prog.clone() }
}
