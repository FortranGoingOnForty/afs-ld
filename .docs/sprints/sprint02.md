# Sprint 2: Sections, Symbols, String Tables

## Prerequisites
Sprint 1 — header + load commands parsed.

## Goals
Decode section payloads, the symbol table (nlist_64), and the string table. Expose the full section/symbol/string model that later sprints build on.

Closeout note: `tests/reader_malformed_stress.rs` now also covers malformed
symbol/string-table variants derived from real corpus objects so the reader's
symbol and string surfaces are exercised under targeted bad-input cases, not
just hand-written unit fixtures. `tests/reader_tool_parity.rs` now also checks
symbol classification against `nm -a` and raw relocation tables against
`otool -r` across the afs-as corpus.

## Deliverables

### 1. Section attributes and kinds
`afs-ld/src/section.rs` — `SectionKind` mirrors afs-as's but richer on the reader side (we receive inputs with flags already set):

```rust
pub enum SectionKind {
    Text, CStringLiterals, Literal4, Literal8, Literal16,
    ConstData, Data, ZeroFill, GbZeroFill,
    ThreadLocalRegular, ThreadLocalZerofill,
    ThreadLocalVariables, ThreadLocalInitPointers,
    CompactUnwind, EhFrame, Coalesced,
    Regular, Unknown,
}

pub fn kind_from_flags(flags: u32) -> SectionKind; // S_* attribute bits
```

Respect all `S_ATTR_*` flags and section-type nibble (`flags & 0xff`).

### 2. Section content slicing
`InputSection` struct: segment, name, kind, addr, size, align (log2), flags, raw `data: &[u8]` borrowed from the mmap'd input, plus the raw relocation entries as `&[u8]` (decoded in Sprint 3). For `S_ZEROFILL` / `S_THREAD_LOCAL_ZEROFILL`, `data` is empty; size is virtual.

### 3. nlist_64 and symbol flags
`afs-ld/src/symbol.rs`:

```rust
pub const N_STAB: u8 = 0xe0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0e; // mask
pub const N_EXT:  u8 = 0x01;

pub const N_UNDF: u8 = 0x0;
pub const N_ABS:  u8 = 0x2;
pub const N_SECT: u8 = 0xe;
pub const N_INDR: u8 = 0xa;

pub const N_NO_DEAD_STRIP: u16 = 0x0020;
pub const N_WEAK_REF:      u16 = 0x0040;
pub const N_WEAK_DEF:      u16 = 0x0080;
pub const N_ARM_THUMB_DEF: u16 = 0x0008;
pub const N_SYMBOL_RESOLVER: u16 = 0x0100;

pub struct RawNlist {
    pub strx: u32,
    pub n_type: u8, pub n_sect: u8, pub n_desc: u16,
    pub n_value: u64,
}

pub struct InputSymbol<'a> {
    pub name: &'a str,
    pub kind: SymKind,                // Undef, Abs, SectLocal, SectExt, PExt, Indirect
    pub weak_ref: bool, pub weak_def: bool,
    pub no_dead_strip: bool, pub private_extern: bool,
    pub sect_idx: u8, pub value: u64,
    pub common_align_pow2: Option<u8>, // from n_desc bits 8..15 when UNDF + value != 0
}
```

Common symbols detected the way afs-as emits them: `N_UNDF | N_EXT` with nonzero `n_value` encoding the size and `n_desc >> 8` encoding alignment.

### 4. Indirect (N_INDR) pass-through
Alias symbols: record the aliased name from the string table via `n_value` used as a strx into the string table. Resolution lives in Sprint 7; this sprint just surfaces the data.

### 5. String table reader
`StringTable` wraps the raw bytes of `__LINKEDIT` string table, exposes `name_at(strx: u32) -> &str`, validates null termination, gracefully handles the suffix-dedup trick afs-as uses (`"_foo\0"` can overlap with a later `"_bar_foo\0"` by pointing mid-string).

### 6. DYSYMTAB partitioning
Decode the partition `(ilocalsym, nlocalsym)`, `(iextdefsym, nextdefsym)`, `(iundefsym, nundefsym)`. Record `toc`, `modtab`, `extrefsym`, `indirectsymoff/nindirectsyms`, `extreloff`, `locreloff` offsets for later phases (most are for dylibs).

### 7. Input file model
`afs-ld/src/input.rs`:

```rust
pub struct ObjectFile {
    pub path: PathBuf,
    pub header: MachHeader64,
    pub commands: Vec<LoadCommand>,
    pub sections: Vec<InputSection>,
    pub symbols: Vec<InputSymbol>,
    pub strings: StringTable,
    pub dysymtab: DysymtabView,
}
```

## Testing Strategy
- Round-trip: parse every section/symbol/string from the afs-as corpus; re-emit; match bytes.
- Diffing against `nm -a` and `otool -r` for symbols and relocation offsets (relocation bodies come in Sprint 3).
- Edge cases: empty `__bss`, tentative common with 16-byte alignment, weak-def with `N_NO_DEAD_STRIP`, indirect symbol chains.
- Fuzz: malformed nlist entries (strx out of bounds, n_sect out of range, invalid n_type bits) produce sourced diagnostics, never panics.

## Definition of Done
- Every symbol attribute afs-as can emit is recognized and round-trips.
- Common symbols surface with correct size and alignment.
- String table reader handles suffix-dedup overlaps correctly.
- Corpus-wide symbol and section parity against `nm -a` / `otool -v`.
