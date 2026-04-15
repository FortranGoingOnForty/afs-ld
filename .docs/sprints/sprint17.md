# Sprint 17: Unwind Info

## Prerequisites
Sprints 9, 10, 11 — atoms, output layout, reloc application.

## Goals
Synthesize `__TEXT,__unwind_info` from per-function `__compact_unwind` records that afs-as already emits. Pass `__TEXT,__eh_frame` through as the DWARF fallback path. Without this sprint, `_Unwind_Backtrace`, C++ exceptions, and some system panics produce garbage or abort.

## Deliverables

### 1. Input: afs-as `__compact_unwind`

afs-as emits one 32-byte record per function:
```
uint64 function_start;    // reloc to function atom
uint32 code_len;
uint32 encoding;          // ARM64 compact-unwind encoding (UNWIND_ARM64_MODE_*)
uint64 personality;       // reloc to personality function or 0
uint64 lsda;              // reloc to LSDA or 0
```

ARM64 encoding nibbles (`UNWIND_ARM64_MODE_MASK = 0x0F000000`):
- `UNWIND_ARM64_MODE_FRAMELESS = 0x02000000` (+ stack size in 16-byte units)
- `UNWIND_ARM64_MODE_DWARF = 0x03000000` (falls back to __eh_frame)
- `UNWIND_ARM64_MODE_FRAME = 0x04000000` (+ saved-register bitfield for x19-x28, d8-d15)

### 2. `__TEXT,__unwind_info` layout

Complex, but structured. Header:
```
uint32 version;                   // UNWIND_SECTION_VERSION = 1
uint32 common_encodings_offset;
uint32 common_encodings_count;
uint32 personalities_offset;
uint32 personalities_count;
uint32 indices_offset;            // first-level index
uint32 indices_count;
```

Then three variable-length arrays:

1. **Common encodings**: up to 127 most-frequent 32-bit encodings. Lookups in per-page tables reference them by index instead of repeating the 32-bit value.
2. **Personalities**: array of 32-bit offsets from mach header to each personality function (usually `___gxx_personality_v0` or `___objc_personality_v0`).
3. **First-level indices**: `(function_offset, second_level_page_offset, lsda_index_offset)` triples, one per page worth of functions. Last entry is a sentinel with function_offset = text section end.

Then **second-level pages** — one per first-level index — each starting with a kind tag:
- `UNWIND_SECOND_LEVEL_REGULAR = 2`: array of `(function_offset, encoding)` pairs. Larger, uncompressed.
- `UNWIND_SECOND_LEVEL_COMPRESSED = 3`: delta-encoded `(function_delta, encoding_index)` pairs in 32 bits each; encoding_index ≤ 127 indexes common encodings, ≥ 128 indexes a page-local encodings array.

Plus an **LSDA table**: sorted `(function_offset, lsda_offset)` pairs for functions that have LSDAs.

### 3. Construction algorithm

1. Gather input `__compact_unwind` records; remap function_start to output VM.
2. Sort by function_start.
3. Tally encoding frequencies; pick top 127 as common encodings.
4. Walk the sorted list, packing up to `pageSize/4 - header` records per compressed page (ld uses 4 KB pages here, ~1020 entries max).
5. Records with DWARF encoding: defer to `__eh_frame` — we still emit them but dyld's unwinder will follow the encoding to DWARF.
6. Write the three top arrays, the per-page second-level tables, and the LSDA index.

### 4. `__eh_frame` pass-through

afs-as emits DWARF CIEs and FDEs in `__TEXT,__eh_frame`. We don't re-encode — we concatenate per-input `__eh_frame` contents, adjust personality function references (LC_SUBTRACTOR pairs), and emit. CIE deduplication is a nice-to-have (Sprint 30); for this sprint we pass through without deduping.

### 5. Coordination with dead-strip

If Sprint 23 removes a function, its compact-unwind and eh_frame records must go too. Compact-unwind atoms are already `parent_of` linked to function atoms from Sprint 9; Sprint 23 walks that link. Eh_frame FDEs similarly reference their function via a SUBTRACTOR pair — when the function atom dies, strip the FDE.

### 6. Correctness validation

After writing, we can re-read our own `__unwind_info` (write a tiny walker) and verify:
- Every function in `__text` is represented (either in compact form or with DWARF encoding).
- Every personality/LSDA reference resolves to a valid VM address.
- First-level index is strictly ascending.
- Second-level compressed encoding_index < common_count + 255.

## Testing Strategy

- Fixture from afs-as emitting a function with prologue (`stp x29, x30, [sp, #-16]!`) → compact-unwind FRAME encoding. Parity byte-level with `ld`.
- Function with no prologue (leaf) → FRAMELESS encoding with size 0.
- Function that falls back to DWARF → DWARF encoding, associated FDE survives in `__eh_frame`.
- C++ fixture compiled by clang (C interop via iso_c_binding is in-scope for armfortas) — personality + LSDA survive; `try/throw/catch` still works when executed.
- Backtrace test: program calls `backtrace()` from execinfo.h; output lists the right function names.

## Definition of Done

- `__unwind_info` byte-identical to `ld` on staging fixtures with prologues, leaves, and DWARF fallbacks.
- `__eh_frame` passthrough preserves all FDEs with correct personality/LSDA references.
- Backtraces produce real symbolic names on a binary linked by afs-ld.
- C++ exceptions (via clang input) unwind correctly when linked by afs-ld.
