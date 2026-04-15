# Sprint 12: GOT, Stubs, Lazy Pointers

## Prerequisites
Sprints 5, 10, 11 — dylibs loaded, layout pass, core reloc application.

## Goals
Synthesize `__got`, `__stubs`, `__stub_helper`, `__la_symbol_ptr`. Wire `GOT_LOAD_*` / `POINTER_TO_GOT` relocations to GOT slots. Rewire `BRANCH26` to a dylib import through a stub. Classic lazy-binding model; chained fixups land in Sprint 15.5.

## Deliverables

### 1. GOT synthetic section
`afs-ld/src/synth/got.rs`:

```rust
pub struct GotSection {
    entries: Vec<GotEntry>,
    index: HashMap<SymbolId, usize>,
}

pub struct GotEntry { pub symbol: SymbolId, pub weak_import: bool }
```

- Lives in `__DATA_CONST,__got`, section flags `S_NON_LAZY_SYMBOL_POINTERS` (type = 6). `reserved1` in the section header = the starting indirect-symbol-table index.
- 8 bytes per entry, aligned 8.
- GOT entry for a Defined symbol holds that symbol's address directly (no dyld bind).
- GOT entry for a DylibImport is zeroed in the file; dyld binds it at load time via the non-lazy bind stream (Sprint 15).

### 2. Stubs synthetic section
`afs-ld/src/synth/stubs.rs`:

ARM64 stub is 12 bytes:
```
ADRP x16, la_symbol_ptr@PAGE
LDR  x16, [x16, la_symbol_ptr@PAGEOFF]
BR   x16
```

- Lives in `__TEXT,__stubs`, section flags `S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS` (type = 8). `reserved1` = starting indirect-sym index, `reserved2` = 12 (stub size).
- One stub per dylib-imported function whose address is branched to (`BRANCH26` target).

### 3. Lazy symbol pointers
`__DATA,__la_symbol_ptr`, section flags `S_LAZY_SYMBOL_POINTERS` (type = 7). Each 8-byte entry is initialized to point at the corresponding `__stub_helper` entry; at first call, the stub-helper resolves the symbol and patches the lazy pointer.

### 4. Stub helper
`__TEXT,__stub_helper`:

Header (24 bytes on arm64):
```
ADRP x17, __dyld_private@PAGE
ADD  x17, x17, __dyld_private@PAGEOFF
STP  x16, x17, [sp, #-16]!
ADRP x16, dyld_stub_binder@GOTPAGE
LDR  x16, [x16, dyld_stub_binder@GOTPAGEOFF]
BR   x16
```

Per-symbol entry (12 bytes):
```
LDR  w16, =<lazy_bind_offset>
B    <header_addr>
```

Where `<lazy_bind_offset>` is the offset of this symbol's opcode sequence within the `__LINKEDIT` lazy-bind stream (Sprint 15 wires this).

Needs `___dyld_private` (local anchor) and `_dyld_stub_binder` (dylib import from `libSystem`).

### 5. Binding strategy
- `_dyld_stub_binder` is imported from `libSystem`. Gets a GOT entry; no stub (we take its address directly).
- `___dyld_private` is a 0-filled 8-byte slot in `__DATA,__data`. Not exported. Dyld uses it as scratch during binding.

### 6. Reloc rewiring
Relocation application pass (Sprint 11 + this):

- `GOT_LOAD_PAGE21` / `GOT_LOAD_PAGEOFF12` → target = GOT slot address.
- `POINTER_TO_GOT` → target = GOT slot address (used for 32-bit pointer-to-GOT references).
- `BRANCH26` to a dylib import → target = stub address.
- `BRANCH26` to a Defined → target unchanged (direct call).
- `BRANCH26` to an Undefined resolved via `-undefined dynamic_lookup` → target = stub address.

### 7. Indirect symbol table
`__LINKEDIT` indirect-symbol table = list of u32 symbol-table indices, used by dyld to map each stub / lazy pointer / GOT slot entry back to its symbol. Populated here, pointed at by `LC_DYSYMTAB.indirectsymoff`.

### 8. Weak-import dylib functions
`weak_import` symbols get stubs whose lazy binding opcode sequence includes the `BIND_SYMBOL_FLAGS_WEAK_IMPORT` flag. At runtime, if the symbol is missing, dyld patches the lazy pointer to 0 instead of erroring. The call site must test for null before branching — that's user code's responsibility.

## Testing Strategy
- Hello-world staging fixture: a `.o` that calls `_printf` + references `_errno`. Produces `__stubs`, `__la_symbol_ptr`, `__stub_helper`, `__got` in the expected order and sizes.
- Differential: stub/lazy-pointer/GOT layout byte-identical to `ld` on the staging fixture.
- Reloc-rewire test: `BRANCH26` to a dylib-imported function lands in the stub, not in the dylib directly.
- Disassembly test: `otool -v -t` on `__stubs` matches the expected three-instruction sequence for every entry.

## Definition of Done
- GOT, stubs, lazy pointers, stub helper all emitted with correct flags and `reserved*` fields.
- Indirect symbol table populated correctly (Sprint 14 consumes it).
- BRANCH26-to-dylib correctly rewired to stubs.
- Differential pass on the staging hello-world fixture.
