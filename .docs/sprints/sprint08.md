# Sprint 8: Name Resolution Pass

## Prerequisites
Sprint 7 — `SymbolTable` with insertion semantics.

## Goals
Drive the symbol table to a fixed point: every undefined reference either resolves to a Defined (from an object), Common (promoted in BSS), DylibImport (from a dylib/TBD), or raises a clear, actionable diagnostic. `-force_load` / `-all_load` / `-undefined <treatment>` all handled.

## Deliverables

### 1. Resolution algorithm
`afs-ld/src/resolve.rs`:

```rust
pub fn resolve(inputs: &mut Inputs, table: &mut SymbolTable, opts: &LinkOptions)
    -> Result<(), Vec<ResolveError>>
{
    seed_table_with_objects_and_dylib_imports(inputs, table, opts);
    if opts.all_load    { force_load_everything(inputs, table); }
    for forced in &opts.force_load { force_load_one(inputs, table, forced); }
    fixed_point_pull_from_archives(inputs, table);
    classify_unresolved(table, opts);
}
```

### 2. Seed phase
Walk every explicit `.o` first, then every `.dylib` / `.tbd`: add Defined / Common from objects, DylibImport from dylibs. Archives are added as LazyArchive entries only — their members are not parsed until pulled.

### 3. Fixed-point pull
```
while let Some(name) = table.undefined_pending.pop() {
    for archive in &inputs.archives_in_command_line_order {
        if let Some(member) = archive.fetch(name) {
            ingest_member(member, table);
            break;
        }
    }
}
```

Order matters: armfortas's driver currently passes `<objs> <runtime.a> -lSystem`, and resolution must match `ld`'s left-to-right behavior. Ingesting a member can create new undefined pending names; loop terminates when no member was fetched this round.

### 4. `-force_load` and `-all_load`
- `-force_load <archive>`: pull every member of that archive before fixed-point.
- `-all_load`: pull every member of every archive.
- Both happen before the fixed-point loop so their transitively-pulled symbols feed into the same fixed point.

### 5. `-undefined <treatment>`
After the fixed point, any still-Undefined entry is classified by the `-undefined` setting:
- `error` (default): hard error, cite every input that references the name (collected via the transition log).
- `warning`: warn but emit, writing the symbol as address 0 (bind to nothing).
- `suppress`: silent, address 0.
- `dynamic_lookup`: flat-namespace DylibImport with ordinal `BIND_SPECIAL_DYLIB_FLAT_LOOKUP=-2`.

### 6. Weak references
`weak_ref` to a missing symbol is always valid regardless of `-undefined`; it resolves to address 0 at bind time and the runtime tests for null.

### 7. Diagnostics
Undefined errors must cite every referrer input, not just one. Output format:

```
afs-ld: error: undefined symbol: _afs_print
      referenced by program.o(text section + 0x34)
      referenced by runtime.o(text section + 0x120)
      (also via 2 relocations in libarmfortas_rt.a(io.o))
Hint: did you mean _afs_print_real? (Levenshtein distance 5)
```

Did-you-mean uses a basic Levenshtein-3 search over defined symbols.

### 8. Diagnostics for duplicate strong
```
afs-ld: error: duplicate symbol _foo
  defined in: a.o (text + 0x0)
  also in:    b.o (text + 0x0)
```

No suggestion — two strong defs is a real ambiguity.

## Testing Strategy
- Resolution matrix revisited from Sprint 7, but with real archives and dylibs.
- Order sensitivity: `a.o b.a` vs `b.a a.o` — first resolves when `a.o` references a symbol in `b.a`; second does not (matches `ld`'s classic behavior).
- `-force_load` pulls in a member whose symbols would otherwise go unreferenced.
- `-all_load` across a multi-member archive.
- Weak-import from a dylib that at runtime will be missing.
- Did-you-mean fires on a close misspell, stays silent when the closest match is > 3 edits away.

## Definition of Done
- Fixed-point loop terminates on all corpus inputs.
- Diagnostics match the format above, include every referrer, include did-you-mean suggestions.
- Differential test against `ld` for order-dependent resolution on 10+ scenarios.
- `-force_load` / `-all_load` / `-undefined=*` all pass dedicated tests.
