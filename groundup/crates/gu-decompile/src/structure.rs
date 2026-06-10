//! Control-flow structuring: recovers `if`/`while` regions from the CFG.
//!
//! This is a recursive region structurer for reducible CFGs. It walks the
//! graph from the entry, emitting:
//!
//! - **while loops** at loop headers (detected via natural loops), using the
//!   header's branch as the loop condition;
//! - **if / if-else** at conditional blocks, with the immediate
//!   post-dominator as the reconvergence point;
//! - **sequences** otherwise.
//!
//! Any edge it cannot structure inline (a jump to an already-emitted block,
//! or a shape it doesn't recognize) becomes a `break`, `continue`, or
//! labeled `goto` — so the output is always a faithful representation of the
//! control flow, never a wrong one. Every block is prefixed with a `Label`;
//! the emitter prints only the labels that are actually targeted.

use crate::cfg::Analysis;
use crate::hir::{HExpr, HStmt, LowBlock, Term};
use gu_ssa::SsaProgram;
use std::collections::{HashMap, HashSet};

struct Structurer<'a> {
    a: &'a Analysis,
    bodies: &'a HashMap<u64, LowBlock>,
    visited: HashSet<usize>,
}

/// Loop context for the region currently being structured: the enclosing
/// loop's header and exit, so back/exit edges become continue/break.
#[derive(Clone, Copy)]
struct LoopCtx {
    header: usize,
    exit: Option<usize>,
}

pub fn structure(
    prog: &SsaProgram,
    a: &Analysis,
    bodies: &HashMap<u64, LowBlock>,
) -> Vec<HStmt> {
    if prog.blocks.is_empty() {
        return Vec::new();
    }
    let mut s = Structurer { a, bodies, visited: HashSet::new() };
    s.seq(a.entry, None, None)
}

impl Structurer<'_> {
    fn block(&self, idx: usize) -> &LowBlock {
        &self.bodies[&self.a.start[idx]]
    }

    /// The successor of `c` other than `other`, if `c` has a second one.
    /// For a conditional block this is the fall-through (not-taken) edge.
    fn other_succ(&self, c: usize, other: usize) -> Option<usize> {
        self.a.succs[c].iter().copied().find(|&s| s != other)
    }

    /// Structures the region from `start`, stopping at `stop` (exclusive).
    fn seq(&mut self, start: usize, stop: Option<usize>, ctx: Option<LoopCtx>) -> Vec<HStmt> {
        let mut out = Vec::new();
        let mut cur = Some(start);

        while let Some(c) = cur {
            if Some(c) == stop {
                break;
            }
            if self.visited.contains(&c) {
                out.push(self.edge_stmt(c, ctx)); // continue / break / goto
                break;
            }
            if self.a.is_loop_header(c) {
                let (stmts, after) = self.emit_loop(c, ctx);
                out.extend(stmts);
                cur = after;
                continue;
            }

            self.visited.insert(c);
            out.push(HStmt::Label(self.a.start[c]));
            out.extend(self.block(c).body.clone());

            match self.block(c).term.clone() {
                Term::Return(v) => {
                    out.push(HStmt::Return(v));
                    cur = None;
                }
                Term::Indirect(e) => {
                    out.push(HStmt::IndirectJump(e));
                    cur = None;
                }
                Term::Switch { value, cases } => {
                    out.push(self.emit_switch(value, &cases, ctx));
                    // Every case body ends in its own terminator (the cases
                    // here return), so control does not fall out of the switch.
                    cur = None;
                }
                Term::Sink => cur = None,
                Term::Jump(t) | Term::Fall(t) => cur = self.a.index.get(&t).copied(),
                Term::Cond { cond, taken } => {
                    out.push(self.emit_if(c, cond, taken, stop, ctx, &mut cur));
                }
            }
        }
        out
    }

    /// Structures a resolved jump table: each table entry becomes a `case`
    /// whose body is the structured region of the target block. Distinct
    /// targets sharing a block (a target listed for several indices) collapse
    /// into one case body listing all its indices.
    fn emit_switch(&mut self, value: String, cases: &[u64], ctx: Option<LoopCtx>) -> HStmt {
        let mut bodies: Vec<(usize, Vec<HStmt>)> = Vec::new();
        for (i, &target) in cases.iter().enumerate() {
            let Some(idx) = self.a.index.get(&target).copied() else { continue };
            if self.visited.contains(&idx) {
                // A target shared with an earlier case: just a fallthrough
                // label, rendered as an extra case index with an empty body.
                bodies.push((i, vec![HStmt::Goto(target)]));
                continue;
            }
            let body = self.seq(idx, None, ctx);
            bodies.push((i, body));
        }
        HStmt::Switch { value, cases: bodies }
    }

    fn emit_if(
        &mut self,
        c: usize,
        cond: HExpr,
        taken: u64,
        stop: Option<usize>,
        ctx: Option<LoopCtx>,
        cur: &mut Option<usize>,
    ) -> HStmt {
        let then_idx = self.a.index[&taken];
        let else_idx = self.other_succ(c, then_idx);
        // Reconvergence point; fall back to the region's stop if there is no
        // real post-dominator.
        let merge = self.a.ipostdom(c).or(stop);

        // if-then with empty else: the taken edge jumps straight to the
        // merge, so the real body is the fall-through. Invert the condition.
        let (cond, then_idx, else_idx) = match else_idx {
            Some(e) if Some(then_idx) == merge => (cond.negated(), e, Some(then_idx)),
            _ => (cond, then_idx, else_idx),
        };

        let then_body = self.seq(then_idx, merge, ctx);
        let else_body = match else_idx {
            Some(e) if Some(e) != merge && !self.visited.contains(&e) => self.seq(e, merge, ctx),
            _ => Vec::new(),
        };
        *cur = merge;
        HStmt::If { cond, then_body, else_body }
    }

    /// Emits a loop at header `h`; returns the loop statements and the block
    /// to continue from (the loop exit, if any).
    fn emit_loop(&mut self, h: usize, _outer: Option<LoopCtx>) -> (Vec<HStmt>, Option<usize>) {
        self.visited.insert(h);
        let header = self.block(h);
        let header_body = header.body.clone();

        if let Term::Cond { cond, taken } = header.term.clone() {
            let taken_idx = self.a.index[&taken];
            let fall_idx = self.other_succ(h, taken_idx);
            let loop_nodes = self.a.loop_body(h);

            // The successor inside the loop is the body; the other is the exit.
            let (body_succ, exit_succ, exit_is_taken) = if loop_nodes.contains(&taken_idx) {
                (Some(taken_idx), fall_idx, false)
            } else {
                (fall_idx, Some(taken_idx), true)
            };

            // Loop while we do NOT take the exit edge.
            let loop_cond = if exit_is_taken { cond.negated() } else { cond };
            let ctx = LoopCtx { header: h, exit: exit_succ };

            if header_body.is_empty() {
                let body = body_succ.map(|b| self.seq(b, Some(h), Some(ctx))).unwrap_or_default();
                return (vec![HStmt::While { cond: loop_cond, body }], exit_succ);
            }
            // Header has its own statements: `while (1)` with an early break
            // so they run before the test each iteration.
            let mut body = header_body;
            body.push(HStmt::If {
                cond: loop_cond.negated(),
                then_body: vec![HStmt::Break],
                else_body: Vec::new(),
            });
            if let Some(b) = body_succ {
                body.extend(self.seq(b, Some(h), Some(ctx)));
            }
            return (vec![HStmt::While { cond: HExpr::Const(1), body }], exit_succ);
        }

        // Unconditional header (infinite or irreducible loop): `while (1)`,
        // relying on inner breaks/gotos to carry control out.
        let ctx = LoopCtx { header: h, exit: None };
        let mut body = header_body;
        if let Term::Jump(t) | Term::Fall(t) = self.block(h).term.clone() {
            if let Some(s) = self.a.index.get(&t).copied() {
                if s != h {
                    body.extend(self.seq(s, Some(h), Some(ctx)));
                }
            }
        }
        (vec![HStmt::While { cond: HExpr::Const(1), body }], None)
    }

    /// Turns an edge into already-emitted code into continue / break / goto.
    fn edge_stmt(&mut self, target: usize, ctx: Option<LoopCtx>) -> HStmt {
        if let Some(c) = ctx {
            if target == c.header {
                return HStmt::Continue;
            }
            if c.exit == Some(target) {
                return HStmt::Break;
            }
        }
        HStmt::Goto(self.a.start[target])
    }
}
