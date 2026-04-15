# Sprint 7: Symbol Model & Table

## Prerequisites
Sprints 2, 4, 5, 6 — object, archive, dylib, TBD readers in place.

## Goals
A uniform symbol table that fuses definitions from every input kind. Establishes the invariants Sprint 8's resolution pass will preserve.

## Deliverables

### 1. `Symbol` sum type
`afs-ld/src/symbol.rs`:

```rust
pub enum Symbol {
    Undefined   { name: Istr, origin: InputId,        weak_ref: bool },
    Defined     { name: Istr, origin: InputId, atom:  AtomId, value: u64,
                  weak: bool, private_extern: bool, no_dead_strip: bool },
    Common      { name: Istr, origin: InputId, size: u64, align_pow2: u8 },
    DylibImport { name: Istr, dylib: DylibId, ordinal: u16, weak_import: bool },
    LazyArchive { name: Istr, archive: ArchiveId, member: MemberId },
    LazyObject  { name: Istr, origin: InputId },        // --start-lib / --end-lib
    Alias       { name: Istr, aliased: Istr },          // N_INDR
}
```

`Istr` = interned string handle. Interning happens once when a name first enters the table; all comparisons are handle-equality.

### 2. `SymbolTable`
```rust
pub struct SymbolTable {
    names: StringInterner,
    by_name: HashMap<Istr, SymbolId>,
    symbols: Vec<Symbol>,
    // replacement log for diagnostics + -why_live
    transitions: Vec<Transition>,
}

pub struct Transition { pub at: SymbolId, pub from: SymbolKindTag, pub to: SymbolKindTag, pub cause: Cause }
```

`HashMap` is fine for Sprint 7; Sprint 28 may swap in a custom open-addressing table.

### 3. Insertion semantics
`SymbolTable::insert(sym: Symbol)` runs the resolution rules inline:

| Existing \ New       | Undefined | Defined | Common | DylibImport | LazyArchive | LazyObject |
|----------------------|-----------|---------|--------|-------------|-------------|------------|
| *vacant*             | insert    | insert  | insert | insert      | insert      | insert     |
| Undefined            | keep      | replace | replace| replace     | replace     | replace    |
| Defined (strong)     | keep      | **error if both strong and same kind** | keep | keep | keep | keep |
| Defined (weak)       | keep      | replace if new strong | keep | keep | keep | keep |
| Common               | keep      | replace (common → Defined) | pick larger size / stricter align | keep | keep | keep |
| DylibImport          | keep      | replace (definition shadows import) | keep | keep | keep | keep |
| LazyArchive          | **fetch** | replace | replace | replace | keep first | replace |
| LazyObject           | **fetch** | replace | replace | replace | replace | keep |

"Fetch" means: load the member/object, enqueue its symbols, mark this entry's transition.

### 4. Weak coalescing rules
- `weak_def` + `weak_def` → first wins.
- `weak_def` + strong → strong wins.
- Strong + strong → hard error, diagnostic cites both input paths.
- `weak_ref` without a definition is not an error; the reference resolves to address 0 (handled in relocation pass).

### 5. Aliases (N_INDR)
Flattened on insertion: an `Alias(name → aliased)` is resolved by looking up `aliased`. If `aliased` is itself an alias, walk until a non-alias is found; cycle detection with a depth cap.

### 6. Transition log
Every `insert` records the old/new kind + input path + (for lazy fetches) the reason the fetch happened. The `-why_live` diagnostic introduced in Sprint 19 reads this log.

### 7. Tombstoned symbols
Common → Defined promotion preserves the common size and alignment (so the BSS slot is large enough). Dead-stripping (Sprint 23) can tombstone a Defined without removing it from the table.

## Testing Strategy
- Unit tests for every cell in the resolution matrix. Each combination has a named test.
- Synthetic inputs: two `.o`s both defining `_foo` strong → error; one strong + one weak → strong wins; two weak → first wins; common + strong → common replaced.
- Alias-chain cycles detected with a diagnostic, not a stack overflow.
- Interner stress test: 100K unique names, membership queries are O(1) average.

## Definition of Done
- Every matrix cell has a passing test.
- Weak coalescing matches `ld` on a corpus of 20+ scenarios (differential test: both linkers produce the same `nm` output).
- Alias flattening correct and cycle-safe.
- Transition log surfaces replacement causes for `-why_live`.
