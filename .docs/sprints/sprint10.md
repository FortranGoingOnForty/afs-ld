# Sprint 10: Output Segment & Section Layout (dylib-aware)

## Prerequisites
Sprints 7–9 — resolved table and atomized inputs.

## Goals
One layout engine, two modes: `MH_EXECUTE` and `MH_DYLIB`. Assign VM addresses, file offsets, and segment membership to every atom. End state: the writer can emit a valid-but-empty Mach-O for both modes that `otool -lV` accepts.

## Deliverables

### 1. Output segment & section model
`afs-ld/src/section.rs`:

```rust
pub struct OutputSegment {
    pub name: String,           // "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT", "__PAGEZERO"
    pub sections: Vec<OutputSectionId>,
    pub vm_addr: u64, pub vm_size: u64,
    pub file_off: u64, pub file_size: u64,
    pub init_prot: Prot, pub max_prot: Prot,
}

pub struct OutputSection {
    pub segment: String, pub name: String,    // e.g. ("__TEXT", "__text")
    pub kind: SectionKind,
    pub align_pow2: u8, pub flags: u32,
    pub atoms: Vec<AtomId>,
    pub addr: u64, pub size: u64, pub file_off: u64,
}
```

### 2. Segment plan
Two plans, keyed by `OutputKind::Executable | Dylib`:

**Executable**:
- `__PAGEZERO`: VM `[0, 0x1_0000_0000)`, prot `---`. No file backing.
- `__TEXT`: prot `r-x`. Contains `__text`, `__stubs`, `__stub_helper`, `__cstring`, `__const`, `__literal16`, `__unwind_info`, `__eh_frame`.
- `__DATA_CONST`: prot `r--` (rebased to `r--` by dyld after fixups). Contains `__got`, `__const` data.
- `__DATA`: prot `rw-`. Contains `__data`, `__bss`, `__la_symbol_ptr`, `__thread_ptrs`, `__thread_vars`, `__thread_data`, `__thread_bss`.
- `__LINKEDIT`: prot `r--`. Symbol table, string table, dyld-info opcodes (or chained fixups), function starts, data-in-code, code signature.

**Dylib**:
- No `__PAGEZERO`. `__TEXT` starts at VM `0`.
- Everything else the same.

### 3. Section placement order within segments
Matches ld's defaults so differential testing converges:
- `__TEXT`: `__text`, `__stubs`, `__stub_helper`, `__cstring`, `__const`, `__literal16`, `__unwind_info`, `__eh_frame`.
- `__DATA_CONST`: `__got`, `__const`.
- `__DATA`: `__la_symbol_ptr`, `__data`, `__thread_vars`, `__thread_ptrs`, `__thread_data`, `__thread_bss`, `__bss`.
- `__LINKEDIT`: fixup stream, function starts, data-in-code, symbol table, string table, code signature (in that order — matches ld's observed layout).

Missing sections are simply absent; empty sections are dropped entirely.

### 4. Atom placement
Each atom maps to one output section by its `OutputSectionKey`. Within a section, atoms ordered by:
1. Input-file command-line order.
2. Within an input, atom original offset.
3. Tiebreaker: symbol name (for determinism).

ICF (Sprint 24) and `-order_file` (later polish) will override this later; for now, deterministic default.

### 5. Address assignment
Pass 1: accumulate sizes per section, respecting atom alignment. Pass 2: assign section `addr` by accumulating `vm_addr + padding-to-section-alignment`. Pass 3: file offsets — `__TEXT` starts at file 0 (header lives there); other segments at next 4 KiB boundary. Zerofill sections have `size > 0` but contribute 0 to file size.

Page alignment is 16 KiB on arm64 (Apple Silicon always). Section alignment comes from atoms.

### 6. MH_EXECUTE vs MH_DYLIB writer dispatch
`afs-ld/src/macho/writer.rs`:

```rust
pub enum OutputKind { Executable, Dylib }

pub fn write(layout: &Layout, kind: OutputKind, opts: &LinkOptions, out: &mut Vec<u8>)
    -> Result<(), WriteError>;
```

Dispatches to the right load-command set:
- Executable: `LC_MAIN` with entry offset, optional `LC_UUID`, `LC_SOURCE_VERSION`.
- Dylib: `LC_ID_DYLIB` with install-name, current-version, compat-version; no `LC_MAIN`.
- Both: `LC_SEGMENT_64` per segment, `LC_BUILD_VERSION`, `LC_SYMTAB`, `LC_DYSYMTAB`, `LC_DYLD_INFO_ONLY` or `LC_DYLD_CHAINED_FIXUPS`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, one `LC_LOAD_DYLIB` per dylib dependency, `LC_RPATH` entries, `LC_CODE_SIGNATURE`.

### 7. Minimum-viable empty output
End-of-sprint gate: both `OutputKind::Executable` (empty `_main`) and `OutputKind::Dylib` (no exports) emit a file that:
- `otool -lV` accepts without complaint.
- `file` identifies as `Mach-O 64-bit executable arm64` / `Mach-O 64-bit dynamically linked shared library arm64`.
- Does not yet need to run or load — just parse.

## Testing Strategy
- Snapshot tests: produce the minimal empty executable and dylib; compare load-command layout against a golden captured from `ld`.
- Differential: for empty inputs, our load-command order and segment protections must match `ld`'s.
- Golden section-ordering tests for the standard ld section order.

## Definition of Done
- Empty executable output passes `otool -lV`.
- Empty dylib output passes `otool -lV`.
- Section placement order matches `ld` on a corpus of staged fixtures.
- Address assignment deterministic across 100 invocations of the same input.
