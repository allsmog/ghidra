//! Dominator tree and dominance frontiers, used for SSA phi placement.
//!
//! Dominators use the iterative algorithm of Cooper, Harvey, and Kennedy
//! ("A Simple, Fast Dominance Algorithm"), which is straightforward and
//! fast for the small CFGs we build. Dominance frontiers then follow the
//! Cytron et al. construction.

/// CFG topology by block index. Built once and shared by the analyses.
pub struct Cfg {
    pub nblocks: usize,
    pub entry: usize,
    pub preds: Vec<Vec<usize>>,
    pub succs: Vec<Vec<usize>>,
}

pub struct Doms {
    /// Immediate dominator of each block; `None` for the entry and for any
    /// block unreachable from the entry.
    pub idom: Vec<Option<usize>>,
    /// Blocks reachable from the entry, in reverse postorder.
    pub rpo: Vec<usize>,
    /// Children in the dominator tree.
    pub children: Vec<Vec<usize>>,
}

impl Cfg {
    /// Postorder over reachable blocks, plus each block's postorder index
    /// (`usize::MAX` for unreachable blocks).
    fn postorder(&self) -> (Vec<usize>, Vec<usize>) {
        let mut order = Vec::new();
        let mut state = vec![0u8; self.nblocks]; // 0 = new, 1 = on stack
        // Iterative DFS so deep CFGs cannot overflow the stack.
        let mut stack = vec![(self.entry, 0usize)];
        state[self.entry] = 1;
        while let Some(&mut (node, ref mut i)) = stack.last_mut() {
            if *i < self.succs[node].len() {
                let s = self.succs[node][*i];
                *i += 1;
                if state[s] == 0 {
                    state[s] = 1;
                    stack.push((s, 0));
                }
            } else {
                order.push(node);
                stack.pop();
            }
        }
        let mut index = vec![usize::MAX; self.nblocks];
        for (i, &b) in order.iter().enumerate() {
            index[b] = i;
        }
        (order, index)
    }

    pub fn dominators(&self) -> Doms {
        let (post, post_idx) = self.postorder();
        let reachable = |b: usize| post_idx[b] != usize::MAX;
        let mut idom = vec![None; self.nblocks];
        idom[self.entry] = Some(self.entry);

        // Higher postorder index = closer to the entry, so to walk two
        // fingers up to their common dominator we always advance the one
        // with the smaller index.
        let intersect = |mut a: usize, mut b: usize, idom: &[Option<usize>]| -> usize {
            while a != b {
                while post_idx[a] < post_idx[b] {
                    a = idom[a].expect("processed node has an idom");
                }
                while post_idx[b] < post_idx[a] {
                    b = idom[b].expect("processed node has an idom");
                }
            }
            a
        };

        let rpo: Vec<usize> = post.iter().rev().copied().collect();
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == self.entry {
                    continue;
                }
                let mut new_idom: Option<usize> = None;
                for &p in &self.preds[b] {
                    if !reachable(p) || idom[p].is_none() {
                        continue;
                    }
                    new_idom = Some(match new_idom {
                        None => p,
                        Some(cur) => intersect(p, cur, &idom),
                    });
                }
                if let Some(ni) = new_idom {
                    if idom[b] != Some(ni) {
                        idom[b] = Some(ni);
                        changed = true;
                    }
                }
            }
        }

        // The entry dominates itself, but it has no immediate dominator.
        let mut children = vec![Vec::new(); self.nblocks];
        let mut idom_out = idom.clone();
        idom_out[self.entry] = None;
        for &b in &rpo {
            if b != self.entry {
                if let Some(d) = idom[b] {
                    children[d].push(b);
                }
            }
        }

        Doms { idom: idom_out, rpo, children }
    }

    /// Dominance frontier of each block (Cytron et al.).
    pub fn dominance_frontiers(&self, doms: &Doms) -> Vec<Vec<usize>> {
        let mut df: Vec<Vec<usize>> = vec![Vec::new(); self.nblocks];
        for b in 0..self.nblocks {
            if self.preds[b].len() < 2 {
                continue;
            }
            let Some(idom_b) = doms.idom[b].or({
                // entry has idom None but never has >= 2 meaningful preds here
                if b == self.entry { Some(self.entry) } else { None }
            }) else {
                continue;
            };
            for &p in &self.preds[b] {
                let mut runner = p;
                while runner != idom_b {
                    if !df[runner].contains(&b) {
                        df[runner].push(b);
                    }
                    match doms.idom[runner] {
                        Some(next) => runner = next,
                        None => break,
                    }
                }
            }
        }
        df
    }
}
