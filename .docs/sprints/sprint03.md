# Sprint 3: Relocations (Read-Side)

## Prerequisites
Sprints 1–2 — header/load commands and section/symbol parsing in place.

## Goals
Decode every ARM64 relocation type afs-as emits. Normalize paired relocations (ADDEND + primary, SUBTRACTOR + UNSIGNED) into a linker-friendly form. End state: the linker's reloc model captures every arithmetic and semantic constraint needed by Sprint 11.

## Deliverables

### 1. Relocation constants and raw form
`afs-ld/src/macho/constants.rs` additions:

```rust
pub const ARM64_RELOC_UNSIGNED:             u8 = 0;
pub const ARM64_RELOC_SUBTRACTOR:           u8 = 1;
pub const ARM64_RELOC_BRANCH26:             u8 = 2;
pub const ARM64_RELOC_PAGE21:               u8 = 3;
pub const ARM64_RELOC_PAGEOFF12:            u8 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21:      u8 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12:   u8 = 6;
pub const ARM64_RELOC_POINTER_TO_GOT:       u8 = 7;
pub const ARM64_RELOC_TLVP_LOAD_PAGE21:     u8 = 8;
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12:  u8 = 9;
pub const ARM64_RELOC_ADDEND:               u8 = 10;
```

Raw `relocation_info`: 8 bytes. `r_address: i32`, `r_info: u32` packed as `[r_symbolnum:24][r_pcrel:1][r_length:2][r_extern:1][r_type:4]`.

### 2. Parsed relocation form
`afs-ld/src/reloc/mod.rs`:

```rust
pub struct Reloc {
    pub offset: u32,            // byte offset into input section
    pub kind: RelocKind,
    pub length: RelocLength,    // Byte=0, Half=1, Word=2, Quad=3
    pub pcrel: bool,
    pub referent: Referent,
    pub addend: i64,            // folded from ARM64_RELOC_ADDEND prefix or inline
}

pub enum RelocKind {
    Unsigned, Branch26,
    Page21, PageOff12,
    GotLoadPage21, GotLoadPageOff12, PointerToGot,
    TlvpLoadPage21, TlvpLoadPageOff12,
    Subtractor,     // minuend in `referent`; paired with a following Unsigned subtrahend
}

pub enum Referent {
    Symbol(SymRef),        // r_extern = 1
    Section(SectRef),      // r_extern = 0
}
```

### 3. Paired reloc fusion
Two pairings afs-as emits:

1. **ARM64_RELOC_ADDEND**: a prefix reloc whose `r_symbolnum` field is actually a 24-bit signed addend. The next reloc in the list is the primary (UNSIGNED, PAGE21, PAGEOFF12, BRANCH26, or GOT/TLVP variant). Parser fuses: `addend_reloc.symnum → primary.addend`, primary kept.

2. **ARM64_RELOC_SUBTRACTOR + ARM64_RELOC_UNSIGNED**: difference expression. Emitted as a pair where SUBTRACTOR names the subtrahend symbol and UNSIGNED names the minuend. Parser fuses into a single `RelocKind::Subtractor { minuend, subtrahend }` record on the minuend-carrying entry.

After fusion no ADDEND or SUBTRACTOR relocs should leak out of the reader.

### 4. Integrity checks
- `r_address + (length_bytes)` within section bounds.
- `r_extern = 1` → `r_symbolnum < nsyms`.
- `r_extern = 0` → `r_symbolnum` is a 1-based section index in range.
- `r_pcrel` matches the reloc kind (PC-relative: BRANCH26, PAGE21 variants, PAGEOFF12 that looks at ADRP page, TLVP variants; not PC-relative: UNSIGNED, PAGEOFF12 for immediates, POINTER_TO_GOT is PC-relative).
- `r_length` matches kind (all ARM64 reloc kinds are length = 2 except UNSIGNED which is length = 2 or 3 and SUBTRACTOR which matches UNSIGNED).

### 5. Round-trip serializer (for golden tests)
`afs-ld/src/reloc/mod.rs::write_relocs(sect: &InputSection, relocs: &[Reloc]) -> Vec<u8>` reassembles into Mach-O wire form, including the ADDEND prefix when necessary. Used to prove the reader lost nothing.

## Testing Strategy
- Round-trip every reloc in the afs-as corpus. Byte equality after ADDEND/SUBTRACTOR fusion + re-emission.
- Synthetic fixtures for each reloc kind (smallest possible `.s` input through afs-as):
  - `bl _extern` → BRANCH26 external.
  - `adrp x0, _g@PAGE; add x0, x0, _g@PAGEOFF` → PAGE21 + PAGEOFF12.
  - `adrp x0, _g@GOTPAGE; ldr x0, [x0, _g@GOTPAGEOFF]` → GOT_LOAD_PAGE21 + GOT_LOAD_PAGEOFF12.
  - `.quad _g + 0x1000` → ADDEND + UNSIGNED pair.
  - `.quad _a - _b` → SUBTRACTOR + UNSIGNED pair.
  - `adrp x0, _tlv@TLVPPAGE; ldr x0, [x0, _tlv@TLVPPAGEOFF]` → TLVP_LOAD_* pair.
- Malformed-input: reloc pointing past section end, unpaired SUBTRACTOR, unpaired ADDEND. Each produces a specific diagnostic citing input path and offset.

## Definition of Done
- Every ARM64 reloc afs-as emits is represented in `RelocKind` post-fusion.
- Paired relocs never leak as separate entries into downstream code.
- Corpus-wide round-trip byte equality.
- Integrity checks trigger diagnostics on malformed fixtures.
