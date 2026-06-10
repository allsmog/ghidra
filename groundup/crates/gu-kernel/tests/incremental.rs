//! End-to-end test of the vertical slice: ELF -> decode -> lift -> listing,
//! plus the property the kernel exists for: changing the model recomputes
//! only model-dependent queries.

use gu_kernel::{Kernel, Model};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/sum.o");

fn kernel() -> Kernel {
    Kernel::new(FIXTURE.to_vec())
}

#[test]
fn end_to_end_pipeline() {
    let mut k = kernel();

    let funcs = k.functions().unwrap();
    let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["sum_to_n", "entry"]);

    // sum_to_n: 8 instructions, loop CFG with 4 blocks.
    let lifted = k.lifted(funcs[0].entry).unwrap();
    assert_eq!(lifted.blocks.len(), 4);

    // entry's listing annotates the call to sum_to_n by name.
    let listing = k.listing(funcs[1].entry).unwrap();
    assert!(listing.contains("# call sum_to_n"), "got:\n{listing}");
}

#[test]
fn rename_invalidates_listings_but_not_decode() {
    let mut k = kernel();
    let funcs = k.functions().unwrap();
    let (sum, entry) = (funcs[0].entry, funcs[1].entry);

    k.listing(sum).unwrap();
    k.listing(entry).unwrap();
    k.lifted(sum).unwrap();
    k.take_log();

    // Warm cache: everything should be a hit.
    k.listing(sum).unwrap();
    k.listing(entry).unwrap();
    let log = k.take_log();
    assert!(
        log.iter().all(|l| l.starts_with("cached")),
        "expected all hits, got: {log:?}"
    );

    // Rename sum_to_n. Listings must recompute; decode/lift must not.
    k.set_function_name(sum, "sum");
    let listing = k.listing(entry).unwrap();
    assert!(listing.contains("# call sum"), "got:\n{listing}");

    let log = k.take_log();
    assert!(
        log.contains(&format!("computed listing({entry:#x})")),
        "listing should recompute, got: {log:?}"
    );
    assert!(
        log.contains(&format!("cached   insns({entry:#x})")),
        "decode must be reused, got: {log:?}"
    );

    // The lifted IR is untouched by renames.
    k.lifted(sum).unwrap();
    let log = k.take_log();
    assert!(
        log.contains(&format!("cached   lifted({sum:#x})")),
        "lift must be reused, got: {log:?}"
    );
}

#[test]
fn model_round_trips_as_text() {
    let mut k = kernel();
    let funcs = k.functions().unwrap();
    k.set_function_name(funcs[0].entry, "sum");
    k.set_function_name(funcs[1].entry, "main");

    let text = k.model().to_text();
    assert!(text.contains("name 0x0 sum"), "got:\n{text}");
    assert_eq!(Model::from_text(&text), *k.model());
}
