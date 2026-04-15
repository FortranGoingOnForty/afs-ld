# Sprint 9: Subsections-via-Symbols Atomization

## Prerequisites
Sprints 2, 7, 8 — sections, symbols, resolved table.

## Goals
Split each input section into **atoms** at symbol boundaries when `MH_SUBSECTIONS_VIA_SYMBOLS` is set (afs-as always sets this). Atoms are the unit of dead-stripping (Sprint 23), ICF (Sprint 24), and output layout (Sprint 10). Every Defined symbol owns exactly one atom.

## Deliverables

### 1. Atom model
`afs-ld/src/atom.rs`:

```rust
pub struct Atom {
    pub id: AtomId,
    pub owner: SymbolId,           // the primary symbol defining this atom
    pub alt_entries: Vec<SymbolId>, // .alt_entry chains
    pub section: OutputSectionKey,  // which output section it will land in
    pub input_origin: InputId,
    pub input_section: SectIdx,
    pub offset: u32,                // offset within input section
    pub size: u32,
    pub align_pow2: u8,
    pub data: DataRef,              // borrowed from input mmap, or ZeroFill
    pub relocs: Vec<RelocIdx>,      // relocs originating inside this atom
    pub flags: AtomFlags,           // NoDeadStrip, WeakDef, ThreadLocal, ...
}
```

### 2. Atomization algorithm
For each input section:
1. Collect every Defined symbol whose section is this section, sorted by value.
2. If `MH_SUBSECTIONS_VIA_SYMBOLS` is set: split the section at each symbol's offset. Each slice becomes an atom owned by the symbol at its head.
3. If a symbol is `.alt_entry`, fold it into the previous atom's `alt_entries`, don't split.
4. If the flag is not set: one atom per section (Apple-style consolidated section).

Atoms for text preserve instruction alignment; atoms for zerofill carry size only.

### 3. Literal atoms (C strings, 16-byte literals)
`__TEXT,__cstring` and `__TEXT,__literal16` are special. Every null-terminated string / every 16-byte block is an atom candidate for de-duplication (Sprint 24 ICF). For now, store each literal as its own atom with a content-hash annotation.

### 4. Unwind + compact-unwind atoms
`__TEXT,__compact_unwind` contains 32-byte records, each referring (via a reloc) to a function atom. One unwind atom per function; tracked as `parent_of: AtomId` so unwind atoms get stripped alongside dead functions.

### 5. Reloc → atom remapping
Every reloc has an input offset into its source section. After atomization, recompute as `(atom, offset_within_atom)`. When a reloc crosses atom boundaries it can only point at a whole symbol (subsections-via-symbols invariant); confirm this and diagnose if not.

### 6. Reloc references to atoms
`Reloc::referent` gains:
```rust
pub enum Referent {
    SymbolExternal(SymbolId),       // undefined or dylib import
    SymbolLocal(AtomId, i64),       // same-tu reference, addend in bytes
    AbsoluteSection(AtomId, i64),   // rare, section-relative
}
```

The "local" case is what the atomization unlocks: a reloc from function `_a` to function `_b` in the same `.o` becomes a reference to `_b`'s atom, not to an offset within a monolithic text section.

### 7. `.no_dead_strip` propagation
Symbol flag propagates to its atom. Unwind atoms inherit `NoDeadStrip` from their parent function. Entry point symbol is marked `NoDeadStrip`.

## Testing Strategy
- Fixture: a `.s` with several functions where one branches to another. After atomization, reloc's referent must be the callee atom, not a byte-offset.
- `.alt_entry` folding: `_foo` and `.alt_entry _bar` in the same input produce one atom whose `alt_entries = [_bar]`.
- Boundary-crossing reloc (synthesized maliciously): parser diagnoses.
- Differential: `ld -dead_strip` behavior on a corpus of ~20 atomization fixtures compared to what Sprint 23 will produce.

## Definition of Done
- Every `.o` in the afs-as corpus atomizes without diagnostics.
- `.alt_entry` correctly folded.
- Relocs re-targeted to atoms; no raw section-relative references leak into Sprint 10.
- Unwind atoms track their parent function atom.
