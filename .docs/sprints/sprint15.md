# Sprint 15: Classic LC_DYLD_INFO Opcodes

## Prerequisites
Sprints 12, 14 — GOT/stubs/lazy-pointers in place, symbol table shaped.

## Goals
Generate the four ULEB128 opcode streams and the export trie that dyld reads via `LC_DYLD_INFO_ONLY`. This is the classic format (macOS 11–13 default) and the `-no_fixup_chains` path on newer macOS. Chained fixups land in Sprint 15.5.

## Deliverables

### 1. The five streams

`LC_DYLD_INFO_ONLY` load command points at five blobs in `__LINKEDIT`:
- **rebase_off / rebase_size**: rebase opcodes — fix up absolute pointers for ASLR slide.
- **bind_off / bind_size**: bind opcodes — non-lazy imports from dylibs.
- **weak_bind_off / weak_bind_size**: weak-bind opcodes — C++-style weak symbol coalescing at runtime.
- **lazy_bind_off / lazy_bind_size**: lazy-bind opcodes — one block per stub_helper entry.
- **export_off / export_size**: export trie — what this image exports to other images.

### 2. Opcode encoder
`afs-ld/src/synth/dyld_info.rs`:

```rust
pub struct OpcodeStream { buf: Vec<u8> }

impl OpcodeStream {
    pub fn uleb(&mut self, v: u64);
    pub fn sleb(&mut self, v: i64);
    pub fn string(&mut self, s: &str);   // null-terminated
    pub fn byte(&mut self, op_and_imm: u8);
    pub fn done(&mut self);              // terminating REBASE_OPCODE_DONE / BIND_OPCODE_DONE
}
```

Opcode byte = (opcode_nibble << 4) | imm_nibble.

### 3. Rebase stream
For every absolute pointer in output `__DATA` / `__DATA_CONST` (an `Unsigned` reloc or a GOT entry resolved to a local address), emit rebase opcodes:

```
REBASE_OPCODE_SET_TYPE_IMM(REBASE_TYPE_POINTER)
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(seg_idx, offset_within_seg)
REBASE_OPCODE_DO_REBASE_ULEB_TIMES(count) or _IMM(count)
```

Batching: consecutive rebases collapse into single `_ULEB_TIMES`; strided rebases use `_ULEB_TIMES_SKIPPING_ULEB`. Matching ld's batching is what keeps the differential harness happy.

### 4. Non-lazy bind stream
For every GOT entry pointing at a dylib import:

```
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM(ordinal) or _ULEB(ordinal)
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM(flags) + <name>\0
BIND_OPCODE_SET_TYPE_IMM(BIND_TYPE_POINTER)
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(seg_idx, offset)
BIND_OPCODE_DO_BIND
```

Flags: `BIND_SYMBOL_FLAGS_WEAK_IMPORT`, `BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION`.

### 5. Weak bind stream
For symbols that participate in weak coalescing across the program (weak defs that can be overridden by other images). For armfortas today this is empty; fortsh may or may not need it. Emit a terminator-only stream by default.

### 6. Lazy bind stream
One block per stub_helper entry (one dylib-imported callable per stub). Each block:
```
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB(seg_idx_of_la_symbol_ptr, offset_of_this_slot)
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM/ULEB(ordinal)
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM(flags) + <name>\0
BIND_OPCODE_DO_BIND
BIND_OPCODE_DONE
```

The stub_helper entry pushes the byte offset of its block; `dyld_stub_binder` reads from that offset, interprets the block, patches the lazy pointer.

### 7. Export trie
Rooted at `__LINKEDIT[export_off]`. Built from the output's external Defined symbols (including re-exports from dylibs we re-export). Tree construction:

- Collect `(name, ExportEntry)` pairs.
- Build a prefix trie.
- Emit depth-first: each node = ULEB terminal-size, optional terminal payload (flags + address ULEB), child-count, (edge_string, child_offset) pairs.
- Child offsets are fixed up in a second pass once sizes are known.

Terminal payload formats:
- Regular: `flags ULEB | address_from_file_start ULEB`.
- Re-export: `flags ULEB | dylib_ordinal ULEB | imported_name\0`.
- Stub-and-resolver: `flags ULEB | stub_addr ULEB | resolver_addr ULEB`.

### 8. Stream-size determinism
Every stream must be deterministic across invocations given identical inputs. Sort keys everywhere, no hashmap iteration order.

## Testing Strategy
- Differential: for every staging fixture, afs-ld and `ld` produce byte-identical opcode streams after normalizing any tolerated differences.
- Unit tests for ULEB128 encoding at boundary values (0, 127, 128, 16383, 16384, big).
- Export-trie walker (Sprint 5's `DylibFile::exports` reader) round-trips our emitted tries: emit a trie, parse it back, every name resolves.

## Definition of Done
- All five streams emitted correctly.
- Export trie round-trips through our own reader.
- Differential byte-level parity with `ld` on 10+ staging fixtures.
- Opcode emission is deterministic.
