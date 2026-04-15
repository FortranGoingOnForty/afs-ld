# Sprint 24: ICF (`-icf=safe`)

## Prerequisites
Sprints 9, 23 — atoms, dead-strip done.

## Goals
Identical Code Folding: merge atoms whose content, relocations, and attributes are identical, so one copy survives. Safe mode only — respects address-taken symbols so function-pointer equality is preserved.

## Deliverables

### 1. Safety rules

Atom is **foldable** iff:
- It lives in `__TEXT,__text`, `__TEXT,__cstring`, `__TEXT,__literal16`, `__TEXT,__const`, or `__DATA_CONST,__const`.
- It has no `NoDeadStrip` flag.
- It has no `AddressTaken` annotation (see below).
- It is not the primary symbol of its atom under `-exported_symbols_list`.

### 2. Address-taken detection

During reloc application (Sprint 11 + this sprint's prep pass), mark any atom referenced via `Unsigned` or `PointerToGot` or any `GOT_LOAD_*` as `AddressTaken`. Function pointers, vtable slots, RTTI entries, anything comparable via `==` — all take the address, so they must not be folded.

Only `Branch26` references are considered "fold-safe" on their own; direct calls don't create address equality.

### 3. Segregation algorithm

Two-phase refinement (lld/MachO style):

1. **Initial hash**: for each foldable atom, compute a 64-bit hash over (size, flags, content bytes, reloc list normalized to (kind, addend, target class)).
2. **Bucket**: group atoms by hash. Single-element buckets are unique and not foldable.
3. **Refine**: within each bucket, check pairwise equality of content + relocs. Use equivalence classes — two atoms equivalent iff every referenced atom is equivalent (fixed-point refinement, à la Hopcroft's DFA minimization).
4. **Repeat step 3 until no class splits**. Converges in log(N) iterations in practice.
5. **Fold**: within each final equivalence class, pick a winner by input command-line order (stable, deterministic); rewrite every other atom's `owner_symbol` redirect to the winner; erase the loser atoms.

### 4. Reloc patching

After folding, some relocations now point at folded-away atoms. Rewrite every such reloc to target the winner. Layout recomputed; sizes shrink.

### 5. `-icf=none` path

Default off. `-icf=safe` enables. `-icf=all` (unsafe, doesn't respect AddressTaken) is not implemented — emits a diagnostic.

### 6. Interaction with `-map` and `-why_live`

- `-map` reports folded symbols with their winner: `_foo folded to _bar`.
- `-why_live` of a folded symbol reports the winner's live-chain.

### 7. Determinism

Winner selection by command-line order is stable across invocations. Hash function is seeded with a fixed seed — same inputs, same winners, same output bytes.

## Testing Strategy

- Fixture: two functions with byte-identical code and relocs. `-icf=safe` folds them into one; `nm` shows only one entry, both symbol aliases point at the same address.
- Address-taken fixture: two identical functions, one has its address stored in a table. Fold does not happen for the address-taken one; both survive.
- String dedup: `__cstring` atoms with identical content folded.
- Large-scale: 50+ near-identical functions, fold correctness verified by running each alias.
- Differential: folded output's `__text` size matches `ld -icf=safe` within 1%.

## Definition of Done

- `-icf=safe` reduces text size on a constructed fixture.
- Address-taken functions never folded.
- All aliases point to the folded winner at runtime.
- fortsh builds with `-icf=safe` and behaves identically to its `-icf=none` counterpart.
