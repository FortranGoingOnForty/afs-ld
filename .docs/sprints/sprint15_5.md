# Sprint 15.5: Chained Fixups (LC_DYLD_CHAINED_FIXUPS)

## Prerequisites
Sprint 15 — classic dyld-info format working.

## Goals
Emit the modern `LC_DYLD_CHAINED_FIXUPS` format, introduced in macOS 12 and mandatory on arm64e. `LC_DYLD_EXPORTS_TRIE` pairs with it for the export side. Coexists with Sprint 15 under `-fixup_chains` / `-no_fixup_chains`; chained becomes default once Sprint 27's parity gate clears.

## Deliverables

### 1. Chained-fixups header
`__LINKEDIT` blob pointed at by `LC_DYLD_CHAINED_FIXUPS`:

```
struct dyld_chained_fixups_header {
    uint32 fixups_version;     // 0
    uint32 starts_offset;      // offset of dyld_chained_starts_in_image
    uint32 imports_offset;     // offset of imports table
    uint32 symbols_offset;     // offset of symbol strings
    uint32 imports_count;
    uint32 imports_format;     // DYLD_CHAINED_IMPORT (1), _ADDEND (2), or _ADDEND64 (3)
    uint32 symbols_format;     // 0 = uncompressed
}
```

### 2. Per-segment fixup starts
```
struct dyld_chained_starts_in_image {
    uint32 seg_count;
    uint32 seg_info_offset[seg_count];   // 0 = no fixups in this segment
}

struct dyld_chained_starts_in_segment {
    uint32 size;
    uint16 page_size;               // 0x4000 on arm64 Apple Silicon
    uint16 pointer_format;          // DYLD_CHAINED_PTR_64 (2) or _64_OFFSET (6)
    uint64 segment_offset;
    uint32 max_valid_pointer;       // 0 for 64-bit
    uint16 page_count;
    uint16 page_start[page_count];   // offset of first chain within each page (0xFFFF = no chain)
}
```

### 3. Pointer formats
arm64 uses `DYLD_CHAINED_PTR_64` (plain 64-bit) or `DYLD_CHAINED_PTR_64_OFFSET` (offsets from image base). arm64e uses `DYLD_CHAINED_PTR_ARM64E` (with auth bits); skip arm64e for now. Each chained pointer is a 64-bit word with fields:

```
bind:  31-bit ordinal | 1-bit bind | 8-bit next | 1-bit auth=0
rebase: 36-bit target | 19-bit high | 1-bit bind=0 | 8-bit next | 1-bit auth=0
```

The `next` field is the distance in 4-byte units from this fixup to the next one within the page (0 = end of chain). Rebuilding chains after layout is the bulk of this sprint.

### 4. Imports table
One entry per imported symbol. `DYLD_CHAINED_IMPORT` format:
```
uint32 lib_ordinal : 8;        // dylib ordinal
uint32 weak_import : 1;
uint32 name_offset : 23;       // into the symbol strings blob
```

`_ADDEND` (32-bit) and `_ADDEND64` (64-bit) formats add an explicit addend — we pick the smallest that fits our inputs (ADDEND64 only if any addend exceeds i32 range).

### 5. Chain construction
Walk every output fixup (rebase or bind), grouped by segment and page. Within a page, chain them in ascending file offset; the `next` field of each points at the next. Pages with no fixups set `page_start = 0xFFFF`. Validate that no chain ever crosses a page boundary.

### 6. Exports trie → LC_DYLD_EXPORTS_TRIE
The export trie is unchanged from Sprint 15's format. In chained-fixups mode the trie lives under `LC_DYLD_EXPORTS_TRIE` instead of inside `LC_DYLD_INFO_ONLY`.

### 7. CLI flag wiring
`-fixup_chains` forces chained, `-no_fixup_chains` forces classic. Default policy:
- If `-platform_version macos` minimum ≥ 12.0: chained.
- Otherwise: classic.

Sprint 19's CLI sprint consumes these flags; this sprint just implements both paths.

### 8. Removing `__stub_helper` under chained
Chained fixups don't use lazy binding — `__stub_helper` is unnecessary, `__la_symbol_ptr` becomes an ordinary bind slot in `__DATA` or `__AUTH_DATA`. Under chained mode the writer skips emitting `__stub_helper` and wires `BRANCH26` through a different stub that loads directly from the bind slot.

Modified ARM64 stub for chained:
```
ADRP x16, _symbol@PAGE
LDR  x16, [x16, _symbol@PAGEOFF]
BR   x16
```

Where `_symbol@PAGE/PAGEOFF` resolves to the bind slot in `__DATA`. Dyld has already bound it by the time the stub runs.

## Testing Strategy
- Parity vs `ld -fixup_chains` on staging fixtures: byte-identical chain layout and imports table.
- Parity vs `ld -no_fixup_chains`: retains Sprint 15 byte-identical output.
- Page-boundary test: a fixup at the last 4 bytes of a page followed by one at byte 0 of the next page — each in its own chain, both reachable.
- Default-policy test: `-platform_version macos 11.0` → classic, `-platform_version macos 12.0` → chained.
- Runtime test: binaries linked both ways load and execute correctly on an M-series Mac.

## Definition of Done
- Both `-fixup_chains` and `-no_fixup_chains` produce runnable binaries.
- Chain layout byte-identical to `ld` on 10+ staging fixtures.
- Default format switches on `-platform_version`.
- `__stub_helper` correctly omitted in chained mode.
