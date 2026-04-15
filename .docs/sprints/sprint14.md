# Sprint 14: LC_SYMTAB / LC_DYSYMTAB / String Table

## Prerequisites
Sprints 10–13 — layout, relocs, GOT/stubs/TLV all emitted.

## Goals
Build the final symbol table, string table, and `LC_DYSYMTAB` partitioning expected by dyld. Byte-level matches with `ld`'s layout on simple inputs.

## Deliverables

### 1. Symbol table partitioning
dyld requires symbols in this order inside `LC_SYMTAB`:

1. **Locals** (ilocalsym..ilocalsym+nlocalsym): private Defined + `N_PEXT` private-external symbols, debug stabs (we have none from afs-as today), `N_STAB` entries.
2. **External defined** (iextdefsym..iextdefsym+nextdefsym): `N_EXT` Defined symbols sorted by name for dyld lookups.
3. **Undefined** (iundefsym..iundefsym+nundefsym): dylib imports, sorted by name.

`LC_DYSYMTAB` records each partition's start and count.

### 2. Symbol entry construction
Per output symbol, emit an `nlist_64`:

```
strx:    offset into the string table
n_type:  N_SECT | N_EXT for external Defined;
         N_SECT | N_PEXT for private Defined;
         N_UNDF | N_EXT for undefined / dylib import;
         N_ABS for absolute
n_sect:  1-based index into the section-table-in-header order; 0 for UNDF/ABS
n_desc:  for UNDF: high 16 bits = library ordinal (1-based) or special (0..-3)
         N_WEAK_REF | N_WEAK_DEF | N_NO_DEAD_STRIP as appropriate
n_value: Defined's VM address; UNDF = 0
```

Two-level namespace: every dylib-imported symbol gets the ordinal of its DylibFile in `n_desc`'s high 16 bits. Flat lookup = 0; special ordinals per `<mach-o/nlist.h>`.

### 3. String table
- Starts with a null byte at offset 0 (dyld-required).
- All symbol names follow, each null-terminated.
- Suffix-dedup like afs-as: sort names by reverse-lexicographic suffix order and reuse trailing bytes where possible. Cheap space win and preserves the style contract with afs-as.
- 8-byte pad at end.

### 4. Indirect symbol table
Already populated by Sprint 12 via GOT/stubs/lazy-pointers. Lives in `__LINKEDIT`, pointed at by `LC_DYSYMTAB.indirectsymoff / nindirectsyms`. Each entry is a u32:
- Symbol-table index for symbols in `__stubs`, `__la_symbol_ptr`, `__got`.
- Special sentinel `INDIRECT_SYMBOL_LOCAL=0x80000000` for entries pointing at local symbols (not exported).
- Special sentinel `INDIRECT_SYMBOL_ABS=0x40000000` for absolute symbols.

### 5. Local-symbol stripping (`-x`)
`ld` supports `-x` to strip local symbols from the output. We record the flag (Sprint 19 wires CLI) and at emission time drop locals from the symbol table. Relocs (if any were external-only) and debug info are unaffected. If `-x` is not set, emit all locals.

### 6. Relocations in the output
For `MH_EXECUTE` and `MH_DYLIB`, dyld-era outputs don't emit per-section relocations — `LC_DYLD_INFO` (or chained fixups) does that job. afs-ld writes zero `nreloc`/`reloff` on output sections. (For `MH_OBJECT`, which we're not emitting, it would matter.)

### 7. File-offset sequencing in __LINKEDIT
`__LINKEDIT` data layout order ld uses (we match for differential ease):
1. Chained fixups blob (if present) or dyld-info opcode streams.
2. Function starts blob.
3. Data-in-code blob.
4. Symbol table (`nsyms * 16` bytes).
5. Indirect symbol table.
6. String table.
7. Code signature.

Each block aligned to 8 bytes; `__LINKEDIT` itself page-aligned. `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, `LC_DYLD_INFO_ONLY`, `LC_CODE_SIGNATURE` all point into this region with file offsets.

## Testing Strategy
- Build a fixture with one local, one external Defined, one undefined dylib import. Verify `LC_SYMTAB` / `LC_DYSYMTAB` partitions match `ld`'s output exactly.
- String-table dedup: two symbols `_afs_array_sum` and `_array_sum` share suffix bytes.
- Two-level namespace ordinals assigned in load-command order; mismatches produce hard errors when the dylib isn't listed.
- Differential: symbol-table byte-level match for every staging fixture.

## Definition of Done
- `nm -v` output identical (modulo address offsets allowed by differential harness) between afs-ld and `ld` on all staging fixtures.
- `LC_DYSYMTAB` partition boundaries exact.
- Indirect symbol table entries point to the correct nlist indices for stubs, lazy pointers, and GOT.
- String-table byte length within 5% of `ld`'s (suffix-dedup parity).
