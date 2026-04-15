# Sprint 11: Core Relocation Application (ARM64)

## Prerequisites
Sprints 3, 9, 10 — relocs parsed, atoms sized, addresses assigned.

## Goals
Patch atom bytes according to every basic ARM64 reloc kind. This sprint covers `BRANCH26`, `PAGE21`, `PAGEOFF12`, `UNSIGNED`, `SUBTRACTOR`, and the folded `ADDEND`. GOT/stubs land in Sprint 12, TLV in Sprint 13.

## Deliverables

### 1. Reloc application pass
`afs-ld/src/reloc/arm64.rs`:

```rust
pub fn apply(layout: &Layout, atom: &Atom, bytes: &mut [u8]) -> Result<(), RelocError>;
```

For each reloc in the atom:
1. Resolve `Referent` to a final address (atom.addr + referent.atom.offset + addend, or dylib import → 0 for now, handled fully in Sprint 12).
2. Compute the reloc value per kind.
3. Patch `bytes` at `reloc.offset`.

### 2. Reloc math (reference)

| Kind | Formula | Encoding |
|---|---|---|
| `Unsigned` (length=2) | `S + A` | little-endian u32 write |
| `Unsigned` (length=3) | `S + A` | little-endian u64 write |
| `Subtractor` | `S_min - S_sub + A` | u32 or u64 depending on length |
| `Branch26` | `(S + A - P) >> 2` | 26-bit sign-check, OR into bottom 26 bits of the instruction |
| `Page21` | `(page(S+A) - page(P)) >> 12` | ADRP immhi:immlo encoding, 21-bit sign-check |
| `PageOff12` | `(S + A) & 0xFFF` | ADD imm12 or LDR imm12 (scaled per LDR size!) |

Where `S` = symbol/section address, `A` = addend, `P` = address of the relocated instruction, `page(x) = x & ~0xFFF`.

### 3. PAGEOFF12 scaling detail
For `LDR` immediate-offset forms the 12-bit immediate is scaled by the load size (1 for `LDRB`, 2 for `LDRH`, 4 for `LDR W`, 8 for `LDR X`). afs-as sets the instruction bits correctly; our job is to right-shift the 12-bit offset by the load size's log2 before OR'ing into the instruction. The `size` nibble of the LDR encoding tells us the shift.

For `ADD` immediate-offset the 12-bit immediate is unscaled — write as-is.

Disambiguate by disassembling the instruction: opcode bits `[31:24]` distinguish ADD vs LDR (B/H/W/X).

### 4. Range checks
- `Branch26`: `(S + A - P)` must fit in signed 28 bits (26 bits × 4-byte scale). If not, emit a hard error citing the caller atom and the out-of-range target. Thunks land in Sprint 26.
- `Page21`: `(page(S+A) - page(P))` must fit in signed 33 bits (21 bits × 4 KiB scale). In practice, always satisfiable on macOS.
- `PageOff12`: always fits by construction.
- `Unsigned`: wraps silently.

### 5. Subtractor + Unsigned pair
A `RelocKind::Subtractor` entry carries both the minuend and subtrahend. Formula: `target = minuend.addr + minuend_addend - (subtrahend.addr + subtrahend_addend)`. Write as u32 or u64 depending on length. afs-as uses this for `.quad _a - _b` and for CIE offset diff in `__eh_frame`.

### 6. PC vs atom address
`P` is the address of the relocated 4-byte instruction, `atom.addr + reloc.offset`. `P` for an `Unsigned` reloc still evaluates even when `pcrel=false`; the formula just doesn't use it. A wrong `P` is the most common reloc bug — unit test every kind against a hand-computed value.

### 7. Error reporting
Every failed reloc cites the originating input + atom + offset + kind + referent. No panics.

### 8. Defer: GOT and TLVP
`GOT_LOAD_PAGE21`, `GOT_LOAD_PAGEOFF12`, `POINTER_TO_GOT`, `TLVP_LOAD_*` — Sprint 12 and Sprint 13 allocate the synthetic sections and wire them. This sprint emits a clear "not yet implemented" error if encountered.

## Testing Strategy
- Unit test each kind with hand-computed encodings cross-checked against ARM ARM and `otool -tv` disassembly.
- Differential: identical inputs through `ld` and afs-ld produce the same patched bytes (within allowed-diff categories from Sprint 0's harness).
- Corner cases: max-negative branch, wrap-around UNSIGNED addend, SUBTRACTOR across sections, SUBTRACTOR within same section.
- Regression fixture: a tiny `.o` that exercises every kind covered in this sprint.

## Definition of Done
- All covered reloc kinds apply correctly against a corpus of fixtures.
- Out-of-range BRANCH26 emits an actionable error.
- Differential pass: 10+ fixtures link to byte-identical `__text` under afs-ld and `ld`.
- GOT/TLVP kinds emit "not yet implemented" errors with a pointer to Sprints 12/13.
