//! Function discovery on linked executables, with and without symbols.

use gu_kernel::Kernel;

const CALLS: &[u8] = include_bytes!("../../../fixtures/calls");
const CALLS_STRIPPED: &[u8] = include_bytes!("../../../fixtures/calls_stripped");

#[test]
fn linked_binary_keeps_symbol_names() {
    let mut k = Kernel::new(CALLS.to_vec());
    let funcs = k.functions().unwrap();
    let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["_start", "alpha", "beta"]);
    assert!(funcs.iter().all(|f| f.size > 0), "extents must be measured: {funcs:?}");

    // Extents must tile without swallowing neighbors: _start may not
    // extend into alpha even though execution falls past its ecall.
    assert_eq!(funcs[0].entry + funcs[0].size, funcs[1].entry, "{funcs:?}");
    assert_eq!(funcs[1].entry + funcs[1].size, funcs[2].entry, "{funcs:?}");
}

#[test]
fn stripped_binary_discovers_functions_from_entry() {
    let mut k = Kernel::new(CALLS_STRIPPED.to_vec());
    let funcs = k.functions().unwrap();

    // No symbols at all: everything below comes from recursive descent.
    assert_eq!(funcs.len(), 3, "{funcs:?}");
    assert_eq!(funcs[0].entry, 0x11120, "seeded from e_entry");
    let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["fn_11120", "fn_11134", "fn_11150"]);

    // The whole pipeline runs on discovered functions: the entry function
    // calls both others, annotated with synthetic names.
    let listing = k.listing(0x11120).unwrap();
    assert!(listing.contains("# call fn_11134"), "got:\n{listing}");
    assert!(listing.contains("# call fn_11150"), "got:\n{listing}");

    // And lifting sees a real call graph.
    let lifted = k.lifted(0x11134).unwrap();
    let text = lifted.render(&gu_rv64::Rv64Namer);
    assert!(text.contains("call 0x11150"), "got:\n{text}");
}

#[test]
fn interprocedural_arity_threads_arguments_through_the_call_graph() {
    let mut k = Kernel::new(CALLS_STRIPPED.to_vec());

    // beta is a leaf taking one argument.
    let beta = k.decompile(0x11150).unwrap();
    assert!(beta.contains("(long a0)"), "beta should take a0:\n{beta}");

    // alpha forwards a computed argument to beta, so alpha takes a0 too and
    // the call site shows the forwarded expression.
    let alpha = k.decompile(0x11134).unwrap();
    assert!(alpha.contains("fn_11134(long a0)"), "alpha should take a0:\n{alpha}");
    assert!(alpha.contains("fn_11150((a0 + 1))"), "argument not forwarded:\n{alpha}");

    // _start passes a constant to alpha and takes no arguments itself.
    let start = k.decompile(0x11120).unwrap();
    assert!(start.contains("fn_11120(void)"), "_start takes no args:\n{start}");
    assert!(start.contains("fn_11134(5)"), "constant arg not passed:\n{start}");
}

const SWITCH: &[u8] = include_bytes!("../../../fixtures/switch_stripped");

#[test]
fn jump_table_targets_are_annotated_in_the_listing() {
    let mut k = Kernel::new(SWITCH.to_vec());
    let funcs = k.functions().unwrap();
    let dispatch = funcs[0].entry;

    let listing = k.listing(dispatch).unwrap();
    // The indirect jump is annotated with the resolved case addresses read
    // from the .rodata table.
    assert!(
        listing.contains("# switch -> 0x11158, 0x11160, 0x11168"),
        "jump table not resolved:\n{listing}"
    );
}

#[test]
fn jump_table_decompiles_to_a_switch() {
    let mut k = Kernel::new(SWITCH.to_vec());
    let dispatch = k.functions().unwrap()[0].entry;
    let c = k.decompile(dispatch).unwrap();

    // The indirect jump structures as a switch over the recovered index, and
    // each case returns its constant.
    assert!(c.contains("switch (a0)"), "no switch recovered:\n{c}");
    assert!(c.contains("case 0:") && c.contains("return 0xa"), "case 0 wrong:\n{c}");
    assert!(c.contains("case 1:") && c.contains("return 0x14"), "case 1 wrong:\n{c}");
    assert!(c.contains("case 2:") && c.contains("return 0x1e"), "case 2 wrong:\n{c}");
    // The bounds check is the default path.
    assert!(c.contains("if (a0 >= 3)"), "bounds check lost:\n{c}");
    // The dead table-load was cleaned up.
    assert!(!c.contains("0x10120"), "dead table load remains:\n{c}");
    assert!(!c.contains("goto *"), "indirect jump not structured:\n{c}");
}

#[test]
fn renames_work_on_discovered_functions() {
    let mut k = Kernel::new(CALLS_STRIPPED.to_vec());
    k.functions().unwrap();
    k.listing(0x11120).unwrap();
    k.take_log();

    k.set_function_name(0x11150, "shift_left_2");
    let listing = k.listing(0x11120).unwrap();
    assert!(listing.contains("# call shift_left_2"), "got:\n{listing}");

    // Fine-grained invalidation holds for discovered functions too: the
    // renamed callee's own decode is untouched.
    let log = k.take_log();
    assert!(
        log.contains(&"cached   insns(0x11120)".to_string()),
        "decode must be reused, got: {log:?}"
    );
}
