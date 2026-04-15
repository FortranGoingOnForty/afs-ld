# Sprint 13: TLV Relocations

## Prerequisites
Sprint 12 — GOT-like synthesis patterns established.

## Goals
Support thread-local variables: the full chain from afs-as's `__thread_vars` / `__thread_data` / `__thread_bss` through `__DATA,__thread_ptrs` into the ARM64 TLV runtime call. `TLVP_LOAD_PAGE21` and `TLVP_LOAD_PAGEOFF12` relocations applied correctly.

## Deliverables

### 1. TLV descriptor layout
Apple's TLV model: each TLV gets a 3-word descriptor in `__DATA,__thread_vars` (section type `S_THREAD_LOCAL_VARIABLES`, 0x13):

```
u64 thunk_addr;   // pointer to tlv_get_addr (libSystem) — rebased/bound at load
u64 key;          // pthread_key_t, set to 0 initially
u64 offset;       // offset of the variable's initial data within __thread_data
```

afs-as emits the descriptor template (thunk_addr = 0, key = 0, offset = section-relative to `__thread_data` or `__thread_bss`). afs-ld:

- Patches `thunk_addr` to reference `_tlv_bootstrap` (from libSystem) via `__DATA,__thread_ptrs`.
- Leaves `key = 0` (runtime initializes on first access).
- Adjusts `offset` to be the final VM offset into the laid-out `__thread_data` / `__thread_bss` section.

### 2. `__DATA,__thread_ptrs` synth
Section type `S_THREAD_LOCAL_VARIABLE_POINTERS` (0x16). Contains non-lazy pointers to the TLV thunk function (`_tlv_bootstrap` from libSystem). One 8-byte entry per imported TLV thunk. Equivalent to the GOT for TLVs.

### 3. TLVP reloc application
`TLVP_LOAD_PAGE21` and `TLVP_LOAD_PAGEOFF12` resolve to a `__thread_ptrs` entry (not a `__thread_vars` descriptor directly). The thread-local access sequence afs-as emits:

```
ADRP  x0, _tlv@TLVPPAGE
LDR   x0, [x0, _tlv@TLVPPAGEOFF]   ; x0 = &thread_ptrs[_tlv]
LDR   x1, [x0]                       ; x1 = &tlv_descriptor (actually thunk ptr!)
BLR   x1                              ; returns address of TLV body in x0
```

Wait — re-check Apple's TLV ABI. The correct sequence: `__thread_ptrs` entry is a pointer to the TLV descriptor (the 3-word thing in `__thread_vars`). The sequence loads `[desc+0]` = thunk, `[desc+8]` = key, and calls the thunk with the descriptor address in `x0`. The thunk reads the key, calls `pthread_getspecific` if needed, and returns the body address. Verify against reference in `.refs/ld64/` before coding.

### 4. Coordinate with afs-as section layout
afs-as emits:
- `__DATA,__thread_data` (S_THREAD_LOCAL_REGULAR, 0x11): TLV initializers.
- `__DATA,__thread_bss` (S_THREAD_LOCAL_ZEROFILL, 0x12): zero-initialized TLVs.
- `__DATA,__thread_vars` (S_THREAD_LOCAL_VARIABLES, 0x13): descriptors.

afs-ld preserves these three sections and adds `__DATA,__thread_ptrs` (S_THREAD_LOCAL_VARIABLE_POINTERS, 0x16).

### 5. `_tlv_bootstrap` import
Auto-injected as an undefined symbol (if any TLV descriptor needs it), resolves from `libSystem`. Its GOT-equivalent entry lives in `__DATA,__thread_ptrs`, not `__DATA_CONST,__got` (TLV has its own indirection).

### 6. Zero TLVs early-out
If no input section has `S_THREAD_LOCAL_*` contents and no reloc has a TLVP kind, emit no TLV sections at all.

## Testing Strategy
- Fixture: a `.f90` with `THREADPRIVATE` → `.o` with `__thread_vars`, `__thread_data`, `__thread_bss` and TLVP relocs. Link with afs-ld and with `ld`. Diff the resulting TLV descriptors, `__thread_ptrs`, and reloc-patched bytes.
- Runtime test: link a tiny C program that reads a TLV via the Apple TLV ABI sequence, run it, check output.
- Zero-TLV fixture: no TLV sections leak into the output.

## Definition of Done
- `TLVP_LOAD_*` relocs apply correctly.
- `__thread_ptrs` emitted with correct type flag and entries.
- `_tlv_bootstrap` imported only when needed.
- Runtime test loads and reads a TLV correctly under afs-ld.
