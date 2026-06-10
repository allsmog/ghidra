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

/// byte_sum(ptr, n): sums n unsigned bytes from *ptr. Exercises pointer and
/// width recovery.
const BYTE_SUM: [u32; 10] = [
    0x00000293, // addi t0, zero, 0
    0x00000313, // addi t1, zero, 0
    0x00b37c63, // bgeu t1, a1, +24
    0x006503b3, // add t2, a0, t1
    0x0003ce03, // lbu t3, 0(t2)
    0x01c282b3, // add t0, t0, t3
    0x00130313, // addi t1, t1, 1
    0xfedff06f, // j -24
    0x00028513, // mv a0, t0
    0x00008067, // ret
];

#[test]
fn recovers_pointer_and_width_types() {
    let c = decompile(&BYTE_SUM);
    // a0 is added to an index and dereferenced as a byte -> unsigned char *.
    assert!(c.contains("unsigned char *a0"), "pointer not recovered:\n{c}");
    // The byte load result is typed unsigned char.
    assert!(c.contains("unsigned char t3"), "byte width not recovered:\n{c}");
    // Local variables are now declared (the output is C-shaped).
    assert!(c.contains("long t0;"), "locals not declared:\n{c}");
    // The index/count register stays a plain integer.
    assert!(c.contains("long a1") || c.contains("(long a1"), "{c}");
}

/// word_sum(ptr, n): sums n 64-bit words via ptr[i] (base + i*8).
const WORD_SUM: [u32; 11] = [
    0x00000293, // addi t0, zero, 0
    0x00000313, // addi t1, zero, 0
    0x00b37e63, // bgeu t1, a1, +28
    0x00331393, // slli t2, t1, 3
    0x00750e33, // add t3, a0, t2
    0x000e3e83, // ld t4, 0(t3)
    0x01d282b3, // add t0, t0, t4
    0x00130313, // addi t1, t1, 1
    0xfe9ff06f, // j -28
    0x00028513, // mv a0, t0
    0x00008067, // ret
];

#[test]
fn scaled_index_becomes_array_access() {
    // base + i*8 with an 8-byte element renders as base[i].
    let c = decompile(&WORD_SUM);
    assert!(c.contains("a0[t1]"), "array index not recovered:\n{c}");
    assert!(!c.contains("<< 3"), "scaled offset still raw:\n{c}");
    assert!(!c.contains("*(int64_t*)"), "raw deref remains:\n{c}");
    assert!(c.contains("long *a0"), "pointer type lost:\n{c}");
}

#[test]
fn byte_array_index_uses_unit_stride() {
    // base + i (stride 1) on a byte pointer also renders as base[i].
    let c = decompile(&BYTE_SUM);
    assert!(c.contains("a0[t1]"), "byte array index not recovered:\n{c}");
}

/// pair_sum(ptr): reads ptr->a (off 0), ptr->b (off 8), writes ptr->sum
/// (off 16), returns it. A pointer dereferenced at several constant offsets.
const PAIR_SUM: [u32; 6] = [
    0x00053283, // ld t0, 0(a0)
    0x00853303, // ld t1, 8(a0)
    0x006283b3, // add t2, t0, t1
    0x00753823, // sd t2, 16(a0)
    0x01053503, // ld a0, 16(a0)
    0x00008067, // ret
];

#[test]
fn constant_offsets_become_struct_fields() {
    let c = decompile(&PAIR_SUM);
    // Each distinct constant offset is a named field.
    assert!(c.contains("a0->field_0"), "field at offset 0 missing:\n{c}");
    assert!(c.contains("a0->field_8"), "field at offset 8 missing:\n{c}");
    assert!(c.contains("a0->field_10"), "field at offset 16 missing:\n{c}");
    // The store is rendered as a field assignment, not a raw deref.
    assert!(c.contains("a0->field_10 = "), "struct store not recovered:\n{c}");
    assert!(!c.contains("*(int64_t*)"), "raw deref remains:\n{c}");
}

#[test]
fn scalar_pointer_is_not_treated_as_struct() {
    // word_sum only ever indexes a0 (no constant offset), so it must use
    // array syntax, never field syntax.
    let c = decompile(&WORD_SUM);
    assert!(!c.contains("->field"), "array pointer mistaken for struct:\n{c}");
    assert!(c.contains("a0[t1]"), "{c}");
}

#[test]
fn pointer_reuse_does_not_pollute_parameter_type() {
    // sum_to_n returns via a0 (reused as the result holder) but takes a0 as a
    // plain integer; the reuse must not make the parameter a pointer.
    let c = decompile(&SUM_TO_N);
    assert!(c.contains("long f(long a0)"), "parameter type polluted:\n{c}");
}

#[test]
fn empty_function_does_not_panic() {
    let lifted = lift_function("empty", &[]);
    let ssa = optimize(&build(&lifted));
    let _ = gu_decompile::decompile(&ssa, &|_| None, &|_| 0);
}
