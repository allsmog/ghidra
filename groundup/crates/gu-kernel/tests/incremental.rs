//! End-to-end test of the vertical slice: ELF -> decode -> lift -> listing,
//! plus the properties the query engine exists for: fine-grained
//! invalidation and early cutoff.

use gu_kernel::{Kernel, Model};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/sum.o");

/// Returns a kernel plus the entries of (sum_to_n, entry, leaf).
fn kernel() -> (Kernel, u64, u64, u64) {
    let mut k = Kernel::new(FIXTURE.to_vec());
    let funcs = k.functions().unwrap();
    let names: Vec<&str> = funcs.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["sum_to_n", "entry", "leaf"]);
    (k, funcs[0].entry, funcs[1].entry, funcs[2].entry)
}

#[test]
fn end_to_end_pipeline() {
    let (mut k, sum, entry, _) = kernel();

    // sum_to_n: 8 instructions, loop CFG with 4 blocks.
    let lifted = k.lifted(sum).unwrap();
    assert_eq!(lifted.blocks.len(), 4);

    // entry's listing annotates the call to sum_to_n by name.
    let listing = k.listing(entry).unwrap();
    assert!(listing.contains("# call sum_to_n"), "got:\n{listing}");
}

#[test]
fn warm_cache_is_all_hits() {
    let (mut k, sum, entry, leaf) = kernel();
    for f in [sum, entry, leaf] {
        k.listing(f).unwrap();
        k.lifted(f).unwrap();
    }
    k.take_log();

    for f in [sum, entry, leaf] {
        k.listing(f).unwrap();
        k.lifted(f).unwrap();
    }
    let log = k.take_log();
    assert!(
        log.iter().all(|l| l.starts_with("cached")),
        "expected all hits, got: {log:?}"
    );
}

#[test]
fn rename_invalidates_only_dependent_listings() {
    let (mut k, sum, entry, leaf) = kernel();
    for f in [sum, entry, leaf] {
        k.listing(f).unwrap();
    }
    k.lifted(sum).unwrap();
    k.take_log();

    // Rename sum_to_n. entry's listing displays that name (call site), so
    // it must recompute; leaf's listing never reads it, so it must not.
    k.set_function_name(sum, "sum");
    let listing = k.listing(entry).unwrap();
    assert!(listing.contains("# call sum"), "got:\n{listing}");
    k.listing(leaf).unwrap();
    k.listing(sum).unwrap();

    let log = k.take_log();
    assert!(
        log.contains(&format!("computed listing({entry:#x})")),
        "entry's listing should recompute, got: {log:?}"
    );
    assert!(
        log.contains(&format!("computed listing({sum:#x})")),
        "sum's own listing should recompute, got: {log:?}"
    );
    assert!(
        log.contains(&format!("cached   listing({leaf:#x})")),
        "leaf's listing must be reused, got: {log:?}"
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
fn writing_the_same_value_is_a_noop() {
    let (mut k, sum, entry, _) = kernel();
    k.set_function_name(sum, "sum");
    k.listing(entry).unwrap();
    k.take_log();

    // Same name again: no revision bump, so even validation is skipped.
    k.set_function_name(sum, "sum");
    k.listing(entry).unwrap();
    let log = k.take_log();
    assert_eq!(log, [format!("cached   listing({entry:#x})")]);
}

#[test]
fn early_cutoff_when_recomputed_value_is_equal() {
    let (mut k, sum, entry, _) = kernel();
    k.listing(entry).unwrap();
    k.take_log();

    // Add a model override identical to the symbol name. The display_name
    // query must re-execute (its input changed) but produce an equal value,
    // so the listings that show the name must stay cached.
    k.set_function_name(sum, "sum_to_n");
    k.listing(entry).unwrap();
    let log = k.take_log();
    assert!(
        log.contains(&format!("computed display_name({sum:#x}) (value unchanged)")),
        "expected early-cutoff marker on display_name, got: {log:?}"
    );
    assert!(
        log.contains(&format!("cached   listing({entry:#x})")),
        "listing must be cut off, got: {log:?}"
    );
}

#[test]
fn model_round_trips_as_text() {
    let (mut k, sum, entry, _) = kernel();
    k.set_function_name(sum, "sum");
    k.set_function_name(entry, "main");

    let text = k.model().to_text();
    assert!(text.contains("name 0x0 sum"), "got:\n{text}");
    assert_eq!(Model::from_text(&text), *k.model());
}

#[test]
fn load_model_invalidates_per_changed_name() {
    let (mut k, sum, entry, leaf) = kernel();
    for f in [sum, entry, leaf] {
        k.listing(f).unwrap();
    }
    k.take_log();

    // A model that only renames leaf must leave the other listings cached.
    let mut m = k.model().clone();
    m.set_name(leaf, "tiny");
    k.load_model(m);

    let leaf_listing = k.listing(leaf).unwrap();
    assert!(leaf_listing.contains("tiny @"), "got:\n{leaf_listing}");
    k.listing(sum).unwrap();
    k.listing(entry).unwrap();

    let log = k.take_log();
    assert!(
        log.contains(&format!("computed listing({leaf:#x})")),
        "leaf's listing should recompute, got: {log:?}"
    );
    assert!(
        log.contains(&format!("cached   listing({sum:#x})")),
        "sum's listing must be reused, got: {log:?}"
    );
    assert!(
        log.contains(&format!("cached   listing({entry:#x})")),
        "entry's listing must be reused, got: {log:?}"
    );
}
