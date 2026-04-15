# Sprint 23: Dead Strip (`-dead_strip`)

## Prerequisites
Sprint 9 — atomization; Sprint 19 — `-dead_strip` CLI flag.

## Goals
Implement `-dead_strip`: remove atoms that are unreachable from the GC roots. Populates the side table that Sprint 19's `-why_live` diagnostic reads.

## Deliverables

### 1. GC roots
Live set seeded from:
- The entry-point symbol's atom (executable only).
- Every exported symbol's atom (governed by `-exported_symbols_list` / defaults).
- Every atom with `NoDeadStrip` flag (from `N_NO_DEAD_STRIP` or `.no_dead_strip`).
- Every atom referenced by a `LC_RPATH` / `LC_LOAD_DYLIB` side-channel (usually none, but keep the hook).
- `_dyld_stub_binder` — always referenced by `__stub_helper`.
- Compact-unwind and eh_frame atoms are **not** roots; they are transitively live via their `parent_of` link to a function atom (Sprint 9).
- Personality functions referenced by any live unwind FDE.

### 2. Mark-live traversal
Worklist algorithm over the atom reference graph:

```rust
pub fn mark_live(layout: &mut Layout, roots: &[AtomId]) {
    let mut worklist: Vec<AtomId> = roots.to_vec();
    while let Some(atom_id) = worklist.pop() {
        if layout.atoms[atom_id].live { continue; }
        layout.atoms[atom_id].live = true;
        record_why_live(atom_id, cause);  // for -why_live diagnostic
        for referent in atom_references(&layout.atoms[atom_id]) {
            worklist.push(referent);
        }
    }
}
```

`atom_references` pulls from the reloc list of the atom, yielding the atom-id each reloc points to.

### 3. Transitive rules
- A live function makes its `__compact_unwind` record live via the `parent_of` link from Sprint 9.
- A live function makes its `__eh_frame` FDE live (FDE references function via SUBTRACTOR pair — the FDE's life is parasitic on the function's).
- A live personality function is reached via the unwind records that reference it.
- LSDA blobs are live iff their owning function is.

### 4. Dead atoms purged
After mark-live, walk the atom list; atoms with `live = false` are removed from the output. Output sections shrink accordingly; Sprint 10's layout pass re-runs to compact addresses.

### 5. `-why_live` side table
Every time an atom is marked live, record its cause: "GC root (entry point)", "reachable from <other atom>", "reachable via unwind parent", etc. Stored as a `HashMap<AtomId, LiveCause>`. Sprint 19's `-why_live` walks back from a named symbol through this map to a root.

### 6. Interactions with ICF (Sprint 24)
Dead-strip runs before ICF. ICF folds only live atoms. Dead atoms never get folded.

### 7. Stripped-symbol enumeration
The `-map` output (Sprint 19) lists dead-stripped symbols. Populate this list from the purged atoms.

### 8. Default behavior
`-dead_strip` is opt-in. Without it, no GC runs, no `-why_live` data is produced (the diagnostic explains this).

## Testing Strategy
- Fixture: two functions, one called by `_main`, one unreferenced. With `-dead_strip`: output's `__text` shrinks, `nm -n` lists only the called function.
- `-why_live _main` on the fixture: "root".
- `-why_live _called_fn`: "reachable from _main; _main is root".
- `-why_live _unreferenced_fn`: "not live (dead-stripped)".
- `N_NO_DEAD_STRIP` fixture: that symbol survives even without a reference.
- Weak def reference: weak-coalesced winner survives, losers dead-stripped.
- Differential: output's `__text` length matches `ld -dead_strip` on 10+ fixtures.

## Definition of Done
- Live set matches `ld -dead_strip` on a corpus of 15+ fixtures.
- `-why_live` produces coherent chains.
- Compact-unwind and eh_frame entries correctly follow their parent functions.
- fortsh builds under `-dead_strip` (Sprint 29 retest).
