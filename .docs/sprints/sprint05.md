# Sprint 5: Dylibs (MH_DYLIB Binary)

## Prerequisites
Sprints 1–3 — Mach-O reading complete.

## Goals
Parse binary dylibs (`MH_DYLIB`). Extract exported symbols via the export trie or `LC_DYLD_CHAINED_FIXUPS` exports, resolve re-exports through umbrella frameworks, and expose a linkable `DylibFile` surface.

## Deliverables

### 1. DylibFile model
`afs-ld/src/macho/dylib.rs`:

```rust
pub struct DylibFile {
    pub path: PathBuf,
    pub install_name: String,
    pub current_version: u32,         // X.Y.Z packed
    pub compat_version: u32,
    pub is_umbrella: bool,
    pub load_kind: DylibLoadKind,     // Normal, Weak, Reexport, Upward
    pub ordinal: u16,                 // two-level namespace ordinal
    pub reexports: Vec<PathBuf>,      // LC_REEXPORT_DYLIB paths
    pub exports: ExportTrie,          // resolved during loading
}

pub enum DylibLoadKind { Normal, Weak, Reexport, Upward }
```

### 2. Load command decoding
- `LC_ID_DYLIB` (for the dylib itself): install_name, timestamp, current_version, compat_version.
- `LC_LOAD_DYLIB`: normal dependency.
- `LC_LOAD_WEAK_DYLIB`: weak dep (imports allowed to be null at runtime).
- `LC_REEXPORT_DYLIB`: dependency whose exports we rebroadcast (umbrella-framework case).
- `LC_LOAD_UPWARD_DYLIB`: cyclic dependency escape hatch.

### 3. Export trie decoder
Export trie lives in `__LINKEDIT` pointed at by either `LC_DYLD_INFO_ONLY.export_off/export_size` (classic) or `LC_DYLD_CHAINED_FIXUPS.exports_trie_offset` (modern). Trie format:

- Each node: ULEB128 terminal-size, optional terminal payload (flags ULEB + address ULEB, plus re-export or resolver data), then child count, then `(edge_string, child_offset_ULEB)` pairs.
- Terminal flags: `EXPORT_SYMBOL_FLAGS_KIND_REGULAR`/`_THREAD_LOCAL`/`_ABSOLUTE`, `EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION`, `EXPORT_SYMBOL_FLAGS_REEXPORT`, `EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER`.

```rust
pub struct ExportTrie { /* walk-only view */ }
impl ExportTrie {
    pub fn lookup(&self, name: &str) -> Option<ExportEntry>;
    pub fn iter(&self) -> impl Iterator<Item = (String, ExportEntry)>;
}

pub struct ExportEntry {
    pub flags: u32,
    pub address: u64,
    pub reexport: Option<(u16 /*ordinal*/, String /*imported_name*/)>,
    pub resolver: Option<u64>,
}
```

Walking is recursive; we guard against malformed trees with a depth cap and visited-offset set.

### 4. Two-level namespace ordinals
Each dylib loaded by path gets an ordinal (1..=N) assigned in load-command order; `BIND_SPECIAL_DYLIB_SELF=0`, `BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE=-1`, `BIND_SPECIAL_DYLIB_FLAT_LOOKUP=-2`, `BIND_SPECIAL_DYLIB_WEAK_LOOKUP=-3`. When an imported symbol is bound in Sprint 15, we use this ordinal.

### 5. Re-export resolution
Loading a dylib recursively loads its `LC_REEXPORT_DYLIB` chain. Names looked up in the umbrella are delegated down the chain. For CoreFoundation / Foundation style umbrella frameworks (not strictly required for armfortas today but landed now to avoid retrofit).

### 6. SDK path resolution
`-syslibroot <SDK>` + `-l<name>` needs to locate `${SDK}/usr/lib/lib<name>.{dylib,tbd}`. This sprint establishes the search order; the rest lands in Sprint 19's CLI work.

## Testing Strategy
- Fixtures: tiny hand-built `.dylib` via the system toolchain (one exported symbol, one re-export). Parsed and exports match `nm -g`.
- Differential: load `CoreFoundation.tbd` in Sprint 6, not here; this sprint uses real binary `.dylib`s from `/usr/lib/` (where present on older macOS) or synthetic ones.
- Malformed trie: cycle, out-of-bounds child offset, ULEB128 overrun — diagnostics, no panics.

## Definition of Done
- Export trie walker handles real `.dylib` files correctly.
- `DylibFile` constructed with correct install_name, versions, ordinal.
- Re-exports chained through umbrella fixtures.
- `dyld_info -export <dylib>` output matches our export dumper.
