# Sprint 25: LOH Relaxation

## Prerequisites
Sprints 1, 11 — LOH hints preserved, reloc application in place.

## Goals
Apply Linker Optimization Hints that afs-as emits. LOHs describe safe peephole opportunities — replace ADRP+ADD with a single ADR when the target is in ±1 MB, or nop-out an unnecessary LDR. Until this sprint, LOHs are preserved as-is and no relaxation happens.

## Deliverables

### 1. LOH kinds afs-as emits

From the existing `.loh` directives:
- `AdrpAdd`: ADRP + ADD (compute address). If target is in ±1 MB, replace with ADR + nop.
- `AdrpLdr`: ADRP + LDR (load through page/pageoff). If target is in ±1 MB and aligned, can become ADR + LDR (using the LDR's literal form).
- `AdrpLdrGot`: ADRP + LDR from GOT. If the GOT entry's content is a local symbol with known address, can skip the GOT load entirely (ADR + nop).
- `AdrpLdrGotLdr`: ADRP + LDR (GOT) + LDR (final). Similar combo: if GOT can be skipped, fold into a direct LDR.

### 2. LOH data format

`LC_LINKER_OPTIMIZATION_HINT` points to a ULEB128 stream:
```
uleb128 kind
uleb128 argcount
uleb128 arg1  // file offset
uleb128 arg2
...
```

Kind constants: `LOH_ARM64_ADRP_ADRP=1`, `LOH_ARM64_ADRP_LDR=2`, `LOH_ARM64_ADRP_ADD_LDR=3`, `LOH_ARM64_ADRP_LDR_GOT_LDR=4`, `LOH_ARM64_ADRP_ADD_STR=5`, `LOH_ARM64_ADRP_LDR_GOT_STR=6`, `LOH_ARM64_ADRP_ADD=7`, `LOH_ARM64_ADRP_LDR_GOT=8`.

afs-as emits kinds 3, 7, 8 (and 4 for load-from-pointer-in-GOT).

### 3. Relaxation pass

Runs **after** reloc application (Sprint 11) and **before** LOH re-serialization. For each LOH:

1. Parse the referenced instructions.
2. Compute if the symbolic target fits the tighter encoding.
3. If yes: rewrite the instruction bytes; mark the LOH as "applied" so it can be either dropped or left in the output (ld's convention varies; we match).
4. If no: leave untouched.

Safety: every relaxation is reversible (the original instructions still achieve the goal), and no relaxation narrows a correctly-wider encoding to an incorrect one. Extensive testing required.

### 4. Safe conservatism

A LOH is only applied when the target fits **strictly** within the narrower range. Off-by-one guard: recompute both original and relaxed forms, assert the relaxed form computes the same address.

### 5. Cross-LOH interaction

A single instruction can participate in multiple LOHs (one as a member of an ADRP+ADD, another as a member of an ADRP+ADD+LDR). Apply LOHs in a deterministic order — longest first — and skip any LOH whose instructions have already been rewritten.

### 6. Output LOH preservation

ld emits `LC_LINKER_OPTIMIZATION_HINT` in the output even for executables (for the benefit of post-processing tools). We match: emit a new LOH blob with the final state (applied LOHs marked or omitted).

### 7. `-no_loh` flag

For debugging: `-no_loh` skips relaxation. Helpful when comparing output against a known-bad state.

## Testing Strategy

- Synthetic fixture with a function whose `__data` target is 1 MB away → AdrpAdd LOH applies; disassembly shows ADR + nop.
- Fixture with a target 10 MB away → LOH does not apply; ADRP + ADD preserved.
- Differential: afs-ld output byte-matches `ld` output for both fixtures.
- Runtime test: the relaxed code still dereferences the right address.
- Random-fuzz: 100 fixtures with various target distances; every relaxation verified against recomputed ground truth.

## Definition of Done

- LOH relaxation applied correctly on fixtures that fit.
- LOH skipped correctly on fixtures that don't.
- Byte-parity with `ld` on a representative corpus.
- `-no_loh` flag produces a cleanly un-relaxed output.
