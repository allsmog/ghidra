//! SSA construction: phi placement at iterated dominance frontiers, then
//! dominator-tree renaming (the classic Cytron et al. algorithm).

use crate::dom::Cfg;
use crate::{
    Phi, SsaBlock, SsaExpr, SsaProgram, SsaStmt, SsaVal, ARG_REGS, CALL_CLOBBERS, RET_REGS,
};
use gu_ir::{Expr, LiftedFn, Stmt, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Builds SSA form for a lifted function.
///
/// Only blocks reachable from the entry are emitted; our lifter never
/// produces unreachable blocks, but discovery-fed CFGs could, and dropping
/// them keeps the SSA invariants intact.
pub fn build(func: &LiftedFn) -> SsaProgram {
    if func.blocks.is_empty() {
        return SsaProgram { name: func.name.clone(), entry: func.entry, blocks: Vec::new() };
    }

    let idx: BTreeMap<u64, usize> =
        func.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let entry = idx[&func.entry];
    let n = func.blocks.len();

    let succs: Vec<Vec<usize>> = func
        .blocks
        .iter()
        .map(|b| b.succs.iter().filter_map(|s| idx.get(s).copied()).collect())
        .collect();
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (b, ss) in succs.iter().enumerate() {
        for &s in ss {
            preds[s].push(b);
        }
    }

    let cfg = Cfg { nblocks: n, entry, preds: preds.clone(), succs: succs.clone() };
    let doms = cfg.dominators();
    let df = cfg.dominance_frontiers(&doms);
    let reachable: BTreeSet<usize> = doms.rpo.iter().copied().collect();

    // Def sites per register: any block that assigns the register or calls
    // (calls clobber the caller-saved set).
    let mut def_sites: HashMap<u16, BTreeSet<usize>> = HashMap::new();
    for (b, block) in func.blocks.iter().enumerate() {
        if !reachable.contains(&b) {
            continue;
        }
        for (_, stmt) in &block.stmts {
            if let Stmt::Assign { dst: Value::Reg(r), .. } = stmt {
                def_sites.entry(*r).or_default().insert(b);
            }
            if is_call(stmt) {
                for &r in CALL_CLOBBERS {
                    def_sites.entry(r).or_default().insert(b);
                }
            }
        }
    }

    // Phi placement: iterated dominance frontier of each register's def
    // sites. Phis are keyed by (block, reg) so each block gets at most one
    // phi per register.
    let mut phi_regs: Vec<BTreeSet<u16>> = vec![BTreeSet::new(); n];
    for (&reg, sites) in &def_sites {
        let mut worklist: Vec<usize> = sites.iter().copied().collect();
        let mut placed: BTreeSet<usize> = BTreeSet::new();
        while let Some(x) = worklist.pop() {
            for &y in &df[x] {
                if phi_regs[y].insert(reg) && placed.insert(y) && !sites.contains(&y) {
                    worklist.push(y);
                }
            }
        }
    }

    // Pre-create SSA blocks with empty phis (args filled during renaming).
    let mut ssa_blocks: Vec<SsaBlock> = func
        .blocks
        .iter()
        .enumerate()
        .map(|(b, block)| SsaBlock {
            start: block.start,
            preds: preds[b].iter().map(|&p| func.blocks[p].start).collect(),
            phis: phi_regs[b]
                .iter()
                .map(|&reg| Phi { reg, dst: 0, args: Vec::new() })
                .collect(),
            stmts: Vec::new(),
            succs: block.succs.clone(),
        })
        .collect();

    let mut renamer = Renamer {
        func,
        succs: &succs,
        children: &doms.children,
        counter: HashMap::new(),
        stacks: HashMap::new(),
    };
    renamer.rename(entry, &mut ssa_blocks);

    // Emit reachable blocks only, preserving address order.
    let blocks = ssa_blocks
        .into_iter()
        .enumerate()
        .filter(|(b, _)| reachable.contains(b))
        .map(|(_, blk)| blk)
        .collect();

    SsaProgram { name: func.name.clone(), entry: func.entry, blocks }
}

fn is_call(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Call { .. } | Stmt::CallIndirect { .. } | Stmt::SysCall)
}

struct Renamer<'a> {
    func: &'a LiftedFn,
    succs: &'a [Vec<usize>],
    children: &'a [Vec<usize>],
    counter: HashMap<u16, u32>,
    stacks: HashMap<u16, Vec<u32>>,
}

impl Renamer<'_> {
    fn cur(&self, reg: u16) -> u32 {
        self.stacks.get(&reg).and_then(|s| s.last()).copied().unwrap_or(0)
    }

    fn fresh(&mut self, reg: u16) -> u32 {
        let c = self.counter.entry(reg).or_insert(0);
        *c += 1;
        let v = *c;
        self.stacks.entry(reg).or_default().push(v);
        v
    }

    fn val(&self, v: Value) -> SsaVal {
        match v {
            Value::Reg(r) => SsaVal::Reg(r, self.cur(r)),
            Value::Tmp(t) => SsaVal::Tmp(t),
            Value::Imm(i) => SsaVal::Imm(i),
        }
    }

    fn expr(&self, e: &Expr) -> SsaExpr {
        match e {
            Expr::Val(v) => SsaExpr::Val(self.val(*v)),
            Expr::Bin(op, a, b) => SsaExpr::Bin(*op, self.val(*a), self.val(*b)),
            Expr::Un(op, v) => SsaExpr::Un(*op, self.val(*v)),
            Expr::Load { addr, size, signed } => {
                SsaExpr::Load { addr: self.val(*addr), size: *size, signed: *signed }
            }
        }
    }

    /// Argument registers read at a call, captured at their current
    /// versions *before* the call's clobber defs bump them.
    fn call_args(&self) -> Vec<SsaVal> {
        ARG_REGS.iter().map(|&r| SsaVal::Reg(r, self.cur(r))).collect()
    }

    fn call_defs(&mut self, pushed: &mut Vec<u16>) -> Vec<SsaVal> {
        CALL_CLOBBERS
            .iter()
            .map(|&r| {
                let v = self.fresh(r);
                pushed.push(r);
                SsaVal::Reg(r, v)
            })
            .collect()
    }

    fn rename(&mut self, b: usize, ssa: &mut [SsaBlock]) {
        let mut pushed: Vec<u16> = Vec::new();

        // 1. Give phi destinations fresh versions.
        for phi in &mut ssa[b].phis {
            phi.dst = self.fresh(phi.reg);
            pushed.push(phi.reg);
        }

        // 2. Translate statements, renaming uses before defs.
        let mut out = Vec::with_capacity(self.func.blocks[b].stmts.len());
        for (addr, stmt) in &self.func.blocks[b].stmts {
            let s = match stmt {
                Stmt::Assign { dst, expr } => {
                    let expr = self.expr(expr); // uses: current versions
                    let dst = match dst {
                        Value::Reg(r) => SsaVal::Reg(*r, {
                            let v = self.fresh(*r);
                            pushed.push(*r);
                            v
                        }),
                        other => self.val(*other),
                    };
                    SsaStmt::Assign { dst, expr }
                }
                Stmt::Store { addr, val, size } => {
                    SsaStmt::Store { addr: self.val(*addr), val: self.val(*val), size: *size }
                }
                Stmt::Jump { target } => SsaStmt::Jump { target: *target },
                Stmt::CondJump { op, lhs, rhs, target } => SsaStmt::CondJump {
                    op: *op,
                    lhs: self.val(*lhs),
                    rhs: self.val(*rhs),
                    target: *target,
                },
                Stmt::Call { target } => {
                    let args = self.call_args(); // read args before clobbering
                    SsaStmt::Call { target: *target, args, defs: self.call_defs(&mut pushed) }
                }
                Stmt::CallIndirect { addr } => {
                    let addr = self.val(*addr); // use before clobber defs
                    let args = self.call_args();
                    SsaStmt::CallIndirect { addr, args, defs: self.call_defs(&mut pushed) }
                }
                Stmt::JumpIndirect { addr } => SsaStmt::JumpIndirect { addr: self.val(*addr) },
                Stmt::Return => SsaStmt::Return {
                    live_out: RET_REGS.iter().map(|&r| SsaVal::Reg(r, self.cur(r))).collect(),
                },
                Stmt::SysCall => {
                    let args = self.call_args();
                    SsaStmt::SysCall { args, defs: self.call_defs(&mut pushed) }
                }
                Stmt::Break => SsaStmt::Break,
                Stmt::Nop => SsaStmt::Nop,
            };
            out.push((*addr, s));
        }
        ssa[b].stmts = out;

        // 3. Fill this block's slot in each successor's phi arguments.
        for &s in &self.succs[b] {
            let pred_start = self.func.blocks[b].start;
            for phi in &mut ssa[s].phis {
                let ver = self.cur(phi.reg);
                phi.args.push((pred_start, ver));
            }
        }

        // 4. Recurse over dominator-tree children.
        for &c in &self.children[b] {
            self.rename(c, ssa);
        }

        // 5. Pop the versions this block introduced.
        for r in pushed {
            self.stacks.get_mut(&r).expect("pushed register has a stack").pop();
        }
    }
}
