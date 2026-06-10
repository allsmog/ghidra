//! End-to-end decompilation from RV64 bytes to structured pseudo-C.

use gu_rv64::{decode_all, lift_function};
use gu_ssa::{build, optimize};

/// Decompiles a sequence of RV64 words, with no call-name resolution.
fn decompile(words: &[u32]) -> String {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let lifted = lift_function("f", &decode_all(0, &bytes));
    let ssa = optimize(&build(&lifted));
    gu_decompile::decompile(&ssa, &|_| None, &|_| 0)
}

const SUM_TO_N: [u32; 8] = [
    0x00000293, 0x00100313, 0x00654863, 0x006282b3, 0x00130313, 0xff5ff06f, 0x00028513,
    0x00008067,
];

const COMPUTE: [u32; 6] =
    [0x00300513, 0x00400593, 0x00b50533, 0x00251513, 0x00e50513, 0x00008067];

const MAXFN: [u32; 4] = [
    0x00b54463, // blt a0, a1, +8
    0x00008067, // ret  (return a0)
    0x00058513, // mv a0, a1
    0x00008067, // ret  (return a0=a1)
];

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn loop_becomes_a_while() {
    let c = decompile(&SUM_TO_N);
    let n = norm(&c);
    // A real while loop with both loop-variable updates in the body.
    assert!(n.contains("while (a0 >= t1)"), "got:\n{c}");
    assert!(n.contains("t0 = (t0 + t1)"), "loop body missing accumulate:\n{c}");
    assert!(n.contains("t1 = (t1 + 1)"), "loop body missing increment:\n{c}");
    assert!(n.contains("return t0"), "got:\n{c}");
    // The loop body must not be empty (regression: phi-only defs were once
    // inlined away).
    assert!(!n.contains("while (a0 >= t1) { }"), "empty loop body:\n{c}");
}

#[test]
fn constant_function_returns_folded_value() {
    let c = decompile(&COMPUTE);
    assert!(norm(&c).contains("return 0x2a"), "got:\n{c}");
    // Everything else folded away: no intermediate assignments.
    assert!(!c.contains(" = "), "expected no assignments:\n{c}");
}

#[test]
fn conditional_becomes_if_else() {
    let c = decompile(&MAXFN);
    let n = norm(&c);
    assert!(n.contains("if (a0 < a1)"), "got:\n{c}");
    assert!(n.contains("return a1"), "got:\n{c}");
    assert!(n.contains("return a0"), "got:\n{c}");
    // No `+ 0` clutter from register moves.
    assert!(!c.contains("+ 0)"), "unsimplified move:\n{c}");
}

#[test]
fn output_is_balanced_and_nonempty() {
    for prog in [&SUM_TO_N[..], &COMPUTE[..], &MAXFN[..]] {
        let c = decompile(prog);
        let opens = c.matches('{').count();
        let closes = c.matches('}').count();
        assert_eq!(opens, closes, "unbalanced braces:\n{c}");
        assert!(c.contains("return"), "no return emitted:\n{c}");
    }
}

const STASH: [u32; 7] = [
    0xff010113, // addi sp, sp, -16
    0x00a50513, // addi a0, a0, 10
    0x00a13423, // sd a0, 8(sp)
    0x00813583, // ld a1, 8(sp)
    0x00159513, // slli a0, a1, 1
    0x01010113, // addi sp, sp, 16
    0x00008067, // ret
];

#[test]
fn recovers_signature() {
    // One argument read, returns a value.
    assert!(decompile(&SUM_TO_N).contains("long f(long a0)"), "{}", decompile(&SUM_TO_N));
    // Two arguments.
    assert!(decompile(&MAXFN).contains("long f(long a0, long a1)"), "{}", decompile(&MAXFN));
    // No arguments, but returns a constant -> long, not void.
    let c = decompile(&COMPUTE);
    assert!(c.contains("long f(void)"), "{c}");
    // A phantom a1 (from the conservative return ABI model) must not appear.
    assert!(!c.contains("a1"), "phantom parameter leaked:\n{c}");
}

#[test]
fn recovers_stack_local() {
    let c = decompile(&STASH);
    // The spill slot becomes a declared local, not a memory dereference.
    assert!(c.contains("long local_8;"), "missing local declaration:\n{c}");
    assert!(c.contains("local_8 = (a0 + 0xa)"), "store not lowered to local:\n{c}");
    assert!(!c.contains("*(int"), "raw memory access remains:\n{c}");
    // Stack-pointer bookkeeping is hidden.
    assert!(!c.contains("sp ="), "sp adjustment leaked:\n{c}");
    assert!(c.contains("long f(long a0)"), "{c}");
}

#[test]
fn empty_function_does_not_panic() {
    let lifted = lift_function("empty", &[]);
    let ssa = optimize(&build(&lifted));
    let _ = gu_decompile::decompile(&ssa, &|_| None, &|_| 0);
}
