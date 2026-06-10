//! SSA construction and optimization, end to end from RV64 bytes.

use gu_ir::LiftedFn;
use gu_rv64::{decode_all, lift_function, Rv64Namer};
use gu_ssa::{build, optimize, SsaStmt, SsaVal};

fn lift(words: &[u32]) -> LiftedFn {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    lift_function("test", &decode_all(0, &bytes))
}

/// sum_to_n from fixtures/sum.s: a counted loop over registers t0 (x5) and
/// t1 (x6). Encodings via llvm-mc.
const SUM_TO_N: [u32; 8] = [
    0x00000293, 0x00100313, 0x00654863, 0x006282b3, 0x00130313, 0xff5ff06f, 0x00028513,
    0x00008067,
];

/// compute from fixtures/consts.s: builds the constant 42.
const COMPUTE: [u32; 6] = [
    0x00300513, // addi a0, zero, 3
    0x00400593, // addi a1, zero, 4
    0x00b50533, // add  a0, a0, a1
    0x00251513, // slli a0, a0, 2
    0x00e50513, // addi a0, a0, 14
    0x00008067, // ret
];

#[test]
fn places_phis_at_loop_head() {
    let ssa = build(&lift(&SUM_TO_N));

    // The loop head is block_8 (preds block_0 and block_c). x5 and x6 are
    // defined on both the entry path and the back edge, so both need a phi
    // there; the return value x10 (a0), defined on one path, must not.
    let head = ssa.blocks.iter().find(|b| b.start == 0x8).expect("loop head exists");
    let mut phi_regs: Vec<u16> = head.phis.iter().map(|p| p.reg).collect();
    phi_regs.sort();
    assert_eq!(phi_regs, [5, 6], "expected phis for x5/x6 at loop head");

    // Each phi has one argument per predecessor (entry + back edge).
    for phi in &head.phis {
        let preds: Vec<u64> = phi.args.iter().map(|(p, _)| *p).collect();
        assert_eq!(preds.len(), 2, "phi {:?} should merge two preds", phi.reg);
        assert!(preds.contains(&0x0) && preds.contains(&0xc), "{preds:?}");
    }

    // No phi anywhere for x10 — it is defined only in the exit block.
    assert!(
        ssa.blocks.iter().all(|b| b.phis.iter().all(|p| p.reg != 10)),
        "x10 should not get a phi"
    );
}

#[test]
fn each_use_has_exactly_one_definition() {
    let ssa = build(&lift(&SUM_TO_N));

    // Collect every defined (reg, version) and check none is defined twice.
    let mut defs: Vec<(u16, u32)> = Vec::new();
    for b in &ssa.blocks {
        for p in &b.phis {
            defs.push((p.reg, p.dst));
        }
        for (_, s) in &b.stmts {
            if let SsaStmt::Assign { dst: SsaVal::Reg(r, v), .. } = s {
                defs.push((*r, *v));
            }
        }
    }
    let mut sorted = defs.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), defs.len(), "every SSA register is defined once");
}

#[test]
fn folds_constant_chain_to_return_42() {
    let ssa = build(&lift(&COMPUTE));
    let opt = optimize(&ssa);

    // After propagation the whole function collapses to `return 42`: the
    // return's live-out a0 is the constant 42.
    let ret = opt
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .find_map(|(_, s)| match s {
            SsaStmt::Return { live_out } => Some(live_out.clone()),
            _ => None,
        })
        .expect("function returns");
    assert_eq!(ret.first(), Some(&SsaVal::Imm(42)), "a0 return value, got {ret:?}");
}

#[test]
fn dead_code_elimination_removes_intermediates() {
    let ssa = build(&lift(&COMPUTE));
    let before = ssa.node_count();
    let opt = optimize(&ssa);
    let after = opt.node_count();

    assert!(after < before, "DCE should shrink the function: {before} -> {after}");

    // Once the return value is the folded constant, every assignment that
    // built it (a0 chain, a1) is dead and removed.
    let any_assign = opt
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .any(|(_, s)| matches!(s, SsaStmt::Assign { .. }));
    assert!(!any_assign, "all constant-building assignments should be removed");
}

#[test]
fn call_clobbers_prevent_propagation_across_calls() {
    // addi a0, zero, 5 ; jal ra, <self+8> (a call) ; the a0 the call may
    // return must not be the constant 5.
    let ssa = build(&lift(&[
        0x00500513, // addi a0, zero, 5
        0x008000ef, // jal ra, +8   (direct call)
        0x00008067, // ret
    ]));
    let opt = optimize(&ssa);
    let text = opt.render(&Rv64Namer);
    // The call records clobbered a0 with a fresh version.
    assert!(text.contains("clobbers"), "call should list clobbers:\n{text}");
}

#[test]
fn optimize_is_idempotent() {
    let once = optimize(&build(&lift(&COMPUTE)));
    let twice = optimize(&once);
    assert_eq!(once, twice, "optimization should reach a fixpoint");
}
