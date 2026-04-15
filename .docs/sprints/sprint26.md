# Sprint 26: Thunks for Out-of-Range Branches

## Prerequisites
Sprint 11 — BRANCH26 reloc application; Sprint 10 — layout pass.

## Goals
When a `BRANCH26` target is more than ±128 MiB from the caller, insert a branch island that can reach any 32-bit-aligned address via an ADRP + BR sequence. Required for very large executables; fortsh is not that large today, but a statically-linked Fortran program with full-intrinsic binding could be.

## Deliverables

### 1. Detection pass

After layout (Sprint 10) assigns addresses, walk every BRANCH26 reloc. Compute `distance = (target - P) >> 2`. If `|distance| > 0x0200_0000` (that's 2^25 = 33,554,432 × 4 bytes = 128 MiB), flag the reloc as needing a thunk.

### 2. Thunk synthesis

One thunk atom per (output segment, distant target). A thunk is 12 bytes:

```
ADRP x16, <target>@PAGE
ADD  x16, x16, <target>@PAGEOFF
BR   x16
```

Or, if the target is a Defined with a known value at link time:

```
ADRP x16, #<computed_page>
ADD  x16, x16, #<pageoff>
BR   x16
```

The ADRP+ADD form reaches anywhere in the process's 4 GiB virtual range (actually ±4 GiB, plenty).

### 3. Placement

Thunks land in `__TEXT,__thunks`, a new synthetic section placed between `__text` and `__stubs`. Placement must be within ±128 MiB of every call site that uses it — for very large binaries, multiple thunk islands may be needed.

Algorithm:
1. Run layout once.
2. Detect overflow sites.
3. Insert thunks near the caller cluster.
4. Re-run layout (sizes changed).
5. Re-check overflow — repeat until stable.

Termination: adding a thunk can only make addresses shift by up to 12 bytes per thunk; overflow is a global property that converges rapidly.

### 4. Thunk sharing

Multiple callers to the same out-of-range target share one thunk. Keyed by `(output_section, target_atom_id)`.

### 5. Reloc rewrite

Each thunked BRANCH26 reloc gets rewritten to point at the thunk atom instead of the original target. Thunk atom's BR then reaches the real target via ADRP+ADD.

### 6. Interaction with `-dead_strip` and ICF

- Thunks are dead-stripped if no live caller remains.
- Thunks are never ICF candidates (they have unique target addresses).
- A dead-stripped target invalidates its thunk(s); easy since we generate thunks after dead-strip.

### 7. `-thunks <none|safe|normal>`

- `-thunks=none`: overflow is a hard error (default for small programs to catch bugs).
- `-thunks=safe` (default on large programs): thunks inserted when needed.
- `-thunks=all`: thunks inserted for every BRANCH26 (for testing).

Sprint 19 CLI wires these; this sprint implements the behavior.

### 8. Regression: small programs don't grow

Default is `-thunks=safe`. Programs that don't need thunks emit no `__thunks` section and are byte-identical to the pre-sprint output.

## Testing Strategy

- Synthetic: compile a source that produces >128 MiB of code (requires artificially padding `.o` files, or using a large constant array in `__text`). Verify thunks inserted.
- Every thunk target reachable from its caller cluster.
- Runtime: the large binary's entry point actually runs and calls through thunks without crashing.
- `-thunks=none` + overflow: produces a clear error citing the caller and target.
- Small-program regression: fortsh output size unchanged vs pre-Sprint-26 (no thunks inserted).

## Definition of Done

- Thunks correctly inserted for out-of-range BRANCH26 on large fixtures.
- Layout fixed-point converges rapidly.
- Small programs unchanged.
- `-thunks` CLI matrix all wired.
