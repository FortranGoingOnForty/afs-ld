# Sprint 18: HELLO WORLD MILESTONE (Executable)

## Prerequisites
Sprints 0–17 — full read, resolve, atomize, layout, reloc-apply, dyld-info, function-starts, unwind pipeline.

## Goals
Produce a runnable arm64 PIE executable. afs-ld takes `hello.o + libarmfortas_rt.a + libSystem.tbd + -e _main` and emits a binary that, when executed on an M-series Mac, prints "Hello, World!". Not a demo — an exit criterion for everything that came before.

## Deliverables

### 1. Staging fixture
`tests/corpus/hello/` contains:
- `hello.f90`: trivial Fortran program with `print *, "Hello, World!"`.
- `hello.o`: assembled by afs-as from armfortas's `hello.s` output.
- Expected output on run: `Hello, World!\n` (Fortran print adds a leading blank on some paths — match what armfortas currently produces).

### 2. End-to-end link
Invocation:
```
afs-ld hello.o libarmfortas_rt.a \
  -lSystem -syslibroot "$(xcrun --show-sdk-path)" \
  -e _main -no_uuid -platform_version macos 11.0 14.0 \
  -o hello
```

Expected:
- Output file passes `file hello` → `Mach-O 64-bit executable arm64`.
- `otool -lV hello` accepts without errors and shows `LC_MAIN`, expected segments, dylibs.
- `codesign -dv hello` reports no signature (Sprint 22 adds ad-hoc signing — binaries still run unsigned on Apple Silicon **from** Xcode or a trusted source, but `./hello` from a Terminal prompt requires signing. Document this caveat.).
- `./hello` (after the Sprint 22 signature) prints the expected string and exits 0.

### 3. Differential gate
`tests/hello_world.rs`:
```rust
let ours = link_with_afs_ld(&inputs, &args);
let theirs = link_with_system_ld(&inputs, &args);
let diff = diff_macho(&ours, &theirs);
assert!(diff.critical.is_empty(), "critical diffs: {:#?}", diff.critical);
```

Allowed tolerated diffs:
- UUID bytes (we emit zero with `-no_uuid`, ld may or may not — both should honor `-no_uuid`).
- String table ordering within a partition as long as every symbol resolves to the same address.
- LC_DYLD_INFO vs LC_DYLD_CHAINED_FIXUPS if defaults disagree — gate with the same `-fixup_chains` / `-no_fixup_chains` flag.

### 4. Load-command `otool -lV` parity
Run `otool -lV` on both outputs; diff should be empty after normalizing absolute file offsets (ld and afs-ld may interleave `__LINKEDIT` regions slightly differently — document and justify any remaining diffs).

### 5. Execution gate (requires Sprint 22's ad-hoc signing, but staged here)
Two cases:
- Unsigned path: `./hello` fails with "killed: 9" (correct Apple Silicon behavior); `codesign -s - hello && ./hello` works.
- Once Sprint 22 lands, afs-ld's own output is signed ad-hoc and `./hello` works directly.

This sprint declares success as soon as `codesign -s - hello && ./hello` prints the expected string.

### 6. Audit
Brutal audit after Sprint 18. Same rules as armfortas audits:
- No "placeholder" or "stub" explanations that hide wrong output.
- Test every claim. Wrong output from a linker is critical.
- If the binary runs but produces extra or missing newlines, investigate — don't rationalize.

## Testing Strategy
- `tests/hello_world.rs` runs the differential gate.
- `tests/hello_world_run.rs` executes the binary (gated on CI-locally-on-Mac) and asserts stdout.
- Regression fixtures: any hello-world variant that once broke gets its own test.

## Definition of Done
- `tests/hello_world.rs` passes — zero critical diffs vs `ld`.
- Binary runs and produces correct output (after `codesign -s - hello` pre-Sprint-22).
- `otool -lV` diff empty after documented normalizations.
- Audit passes.
