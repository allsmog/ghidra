//! Recursive-descent function discovery for linked binaries.
//!
//! Symbol tables are a courtesy; stripped binaries don't extend it. So
//! discovery seeds from whatever is reliable — function symbols when
//! present, always the entry point — and chases direct call targets to a
//! fixpoint. Two phases:
//!
//! 1. **Entry collection.** Explore the instruction stream from every seed,
//!    following branches and fallthrough, collecting `jal ra` targets as
//!    new function entries. Exploration may overrun into a neighboring
//!    function (e.g. after a non-returning `ecall`); that is harmless here
//!    because this phase only collects the global entry set.
//! 2. **Extent measurement.** Re-explore each function, stopping at any
//!    other known entry, so a function's extent never swallows its
//!    neighbor.
//!
//! Indirect calls/jumps end paths (value tracking is future work), and
//! exploration is capped defensively — the input is untrusted.

use crate::FuncInfo;
use gu_elf::Elf;
use gu_rv64::{decode, Insn, Mnemonic};
use std::collections::{BTreeMap, BTreeSet};

/// Safety cap on instructions explored per function.
const MAX_INSNS_PER_FN: usize = 65_536;

fn fetch(elf: &Elf, addr: u64) -> Option<Insn> {
    elf.exec_segment_at(addr)?;
    let bytes = elf.bytes_at_vaddr(addr, 4).ok()?;
    Some(decode(addr, u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])))
}

struct Walk {
    visited: BTreeSet<u64>,
    callees: BTreeSet<u64>,
}

/// Explores the instruction stream from `entry`, following intra-function
/// control flow. Paths end at returns, indirect jumps, undecodable bytes,
/// unmapped addresses, and (when `stop_at` is given) other function entries.
fn explore(
    elf: &Elf,
    entry: u64,
    stop_at: Option<&BTreeSet<u64>>,
    jumps: &BTreeMap<u64, Vec<u64>>,
) -> Walk {
    let mut walk = Walk { visited: BTreeSet::new(), callees: BTreeSet::new() };
    let mut work = vec![entry];

    while let Some(addr) = work.pop() {
        if walk.visited.len() >= MAX_INSNS_PER_FN || walk.visited.contains(&addr) {
            continue;
        }
        if addr != entry {
            if let Some(stops) = stop_at {
                if stops.contains(&addr) {
                    continue;
                }
            }
        }
        let Some(insn) = fetch(elf, addr) else {
            continue;
        };
        if insn.mn == Mnemonic::Unknown {
            continue;
        }
        walk.visited.insert(addr);

        let next = addr + 4;
        match insn.mn {
            Mnemonic::Jal => {
                let target = insn.branch_target().expect("jal always has a target");
                if insn.rd == 1 {
                    walk.callees.insert(target);
                    work.push(next);
                } else {
                    // Plain jump: in-function edge. (A jump to another
                    // function's entry is a tail call; phase 2's stop set
                    // keeps it out of this function's extent.)
                    work.push(target);
                }
            }
            Mnemonic::Beq
            | Mnemonic::Bne
            | Mnemonic::Blt
            | Mnemonic::Bge
            | Mnemonic::Bltu
            | Mnemonic::Bgeu => {
                if let Some(t) = insn.branch_target() {
                    work.push(t);
                }
                work.push(next);
            }
            Mnemonic::Jalr => {
                if insn.rd == 1 {
                    work.push(next); // indirect call returns here
                } else if let Some(targets) = jumps.get(&addr) {
                    // Resolved jump table: the case blocks are in-function
                    // edges. This is what makes them reachable at all.
                    work.extend(targets.iter().copied());
                }
                // Otherwise rd == 0: return or unresolved indirect jump —
                // the path ends here.
            }
            _ => work.push(next),
        }
    }
    walk
}

/// Resolves jump tables for every function, keyed by the address of the
/// indirect jump. Each function is decoded linearly from its entry up to the
/// next entry, which is enough to recognize the dispatch pattern.
fn resolve_jump_tables(elf: &Elf, entries: &BTreeSet<u64>) -> BTreeMap<u64, Vec<u64>> {
    let ordered: Vec<u64> = entries.iter().copied().collect();
    let mut jumps = BTreeMap::new();
    for (i, &entry) in ordered.iter().enumerate() {
        let end = ordered.get(i + 1).copied().unwrap_or(u64::MAX);
        let mut insns = Vec::new();
        let mut addr = entry;
        while addr < end && insns.len() < MAX_INSNS_PER_FN {
            match fetch(elf, addr) {
                Some(insn) if insn.mn != Mnemonic::Unknown => insns.push(insn),
                _ => break,
            }
            addr += 4;
        }
        for (jump_addr, targets) in crate::jumptable::resolve(elf, &insns) {
            jumps.insert(jump_addr, targets);
        }
    }
    jumps
}

/// Discovers functions in a linked binary: named symbols plus everything
/// reachable through direct calls, with measured extents.
pub fn discover(elf: &Elf) -> Vec<FuncInfo> {
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    for sym in elf.function_symbols() {
        names.insert(sym.value, sym.name.clone());
    }

    let mut entries: BTreeSet<u64> = names.keys().copied().collect();
    if elf.exec_segment_at(elf.header.entry).is_some() {
        entries.insert(elf.header.entry);
    }

    let no_jumps = BTreeMap::new();

    // Phase 1: chase call targets to a fixpoint.
    let mut queue: Vec<u64> = entries.iter().copied().collect();
    while let Some(entry) = queue.pop() {
        for callee in explore(elf, entry, None, &no_jumps).callees {
            if elf.exec_segment_at(callee).is_some() && entries.insert(callee) {
                queue.push(callee);
            }
        }
    }

    // Phase 1.5: resolve jump tables now that the entry set bounds each
    // function's instruction span, so case blocks become reachable below.
    let jumps = resolve_jump_tables(elf, &entries);

    // Phase 2: measure each function, clipped at every other entry.
    entries
        .iter()
        .map(|&entry| {
            let walk = explore(elf, entry, Some(&entries), &jumps);
            let size = walk.visited.last().map(|&last| last + 4 - entry).unwrap_or(0);
            let name = names
                .get(&entry)
                .cloned()
                .unwrap_or_else(|| format!("fn_{entry:x}"));
            FuncInfo { entry, name, size }
        })
        .collect()
}
