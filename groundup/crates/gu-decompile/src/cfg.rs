//! Control-flow analysis the structurer needs: dominators, post-dominators,
//! and natural loops, all derived from an [`SsaProgram`].
//!
//! Dominators come from `gu_ssa::dom`. Post-dominators are just dominators
//! on the reversed CFG with a synthetic exit node that all sink blocks
//! (returns and indirect jumps) feed into.

use gu_ssa::dom::{Cfg, Doms};
use gu_ssa::SsaProgram;
use std::collections::{BTreeMap, BTreeSet};

pub struct Analysis {
    /// Block index by start address, and the reverse.
    pub index: BTreeMap<u64, usize>,
    pub start: Vec<u64>,
    pub succs: Vec<Vec<usize>>,
    pub entry: usize,
    /// Immediate post-dominator per block; `None` means the synthetic exit
    /// (i.e. no real block post-dominates it — the paths only reconverge at
    /// function exit).
    ipostdom: Vec<Option<usize>>,
    /// For each loop header, the set of blocks in its natural loop.
    loops: BTreeMap<usize, BTreeSet<usize>>,
}

impl Analysis {
    pub fn new(prog: &SsaProgram) -> Analysis {
        let n = prog.blocks.len();
        let index: BTreeMap<u64, usize> =
            prog.blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
        let start: Vec<u64> = prog.blocks.iter().map(|b| b.start).collect();
        let entry = index[&prog.entry];

        let succs: Vec<Vec<usize>> = prog
            .blocks
            .iter()
            .map(|b| b.succs.iter().filter_map(|s| index.get(s).copied()).collect())
            .collect();
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (b, ss) in succs.iter().enumerate() {
            for &s in ss {
                preds[s].push(b);
            }
        }

        let cfg = Cfg { nblocks: n, entry, preds, succs: succs.clone() };
        let doms = cfg.dominators();
        let ipostdom = post_dominators(n, &succs);
        let loops = natural_loops(n, &succs, &doms);

        Analysis { index, start, succs, entry, ipostdom, loops }
    }

    pub fn is_loop_header(&self, b: usize) -> bool {
        self.loops.contains_key(&b)
    }

    pub fn loop_body(&self, header: usize) -> &BTreeSet<usize> {
        &self.loops[&header]
    }

    /// Immediate post-dominator, or `None` for the synthetic exit.
    pub fn ipostdom(&self, b: usize) -> Option<usize> {
        self.ipostdom[b]
    }
}

/// Post-dominators via dominators on the reversed graph. Node `n` is a
/// synthetic exit; every sink (no successors) is treated as connected to it.
fn post_dominators(n: usize, succs: &[Vec<usize>]) -> Vec<Option<usize>> {
    if n == 0 {
        return Vec::new();
    }
    let exit = n;
    let rn = n + 1;
    let mut rsuccs: Vec<Vec<usize>> = vec![Vec::new(); rn];
    let mut rpreds: Vec<Vec<usize>> = vec![Vec::new(); rn];
    // Reverse every real edge.
    for (u, ss) in succs.iter().enumerate() {
        for &v in ss {
            rsuccs[v].push(u);
            rpreds[u].push(v);
        }
    }
    // Connect the synthetic exit to every sink, in both directions.
    for (u, ss) in succs.iter().enumerate() {
        if ss.is_empty() {
            rsuccs[exit].push(u);
            rpreds[u].push(exit);
        }
    }

    let rcfg = Cfg { nblocks: rn, entry: exit, preds: rpreds, succs: rsuccs };
    let rdoms = rcfg.dominators();
    // ipostdom(b) = idom of b in the reversed graph; map the synthetic exit
    // back to None.
    (0..n)
        .map(|b| match rdoms.idom[b] {
            Some(d) if d == exit => None,
            other => other,
        })
        .collect()
}

/// Natural loops: for each back edge `latch -> header` (header dominates
/// latch), the loop body is the header plus everything that reaches the
/// latch without passing through the header.
fn natural_loops(
    n: usize,
    succs: &[Vec<usize>],
    doms: &Doms,
) -> BTreeMap<usize, BTreeSet<usize>> {
    let dominates = |a: usize, b: usize| -> bool {
        let mut cur = Some(b);
        while let Some(c) = cur {
            if c == a {
                return true;
            }
            match doms.idom[c] {
                Some(p) if p != c => cur = Some(p),
                _ => return false,
            }
        }
        false
    };

    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (u, ss) in succs.iter().enumerate() {
        for &v in ss {
            preds[v].push(u);
        }
    }

    let mut loops: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (latch, ss) in succs.iter().enumerate() {
        for &header in ss {
            if !dominates(header, latch) {
                continue; // not a back edge
            }
            let body = loops.entry(header).or_default();
            body.insert(header);
            // Walk predecessors back from the latch, stopping at the header.
            let mut stack = vec![latch];
            while let Some(b) = stack.pop() {
                if body.insert(b) {
                    stack.extend(preds[b].iter().copied());
                }
            }
            body.insert(latch);
        }
    }
    loops
}
