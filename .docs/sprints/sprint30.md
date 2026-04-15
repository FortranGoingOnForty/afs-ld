# Sprint 30: Diagnostics & Polish

## Prerequisites
Sprints 19 (`-map`, `-why_live`), 29 (fortsh audit informs diagnostic quality).

## Goals
Raise every diagnostic surface to afs-as's caret-under-line standard. Polish `--help`, `--version`, `-t`, error recovery in binary parsers. Ship-quality UX for linker errors.

## Deliverables

### 1. Binary-input diagnostics

Every parser error cites the input file, the byte offset, and a caret pointing at the offending region in a hex dump:

```
afs-ld: error: in input.o at byte 0x1a4: LC_SEGMENT_64 claims nsects=3 but cmdsize fits only 2 section headers

  0x1a0: 00 01 00 00 48 02 00 00 03 00 00 00 00 00 00 00
                                 ^^
  cmdsize=0x248 accommodates 2 × 80-byte section_64 entries; nsects=3 needs 240+72=312 bytes.
```

Implemented in `src/diag.rs` with helpers for "byte offset → nearest load command, section, atom, symbol" so every error can contextualize itself.

### 2. Source-level backmapping

When diagnosing a reloc error, point at the originating `.s` line if the object's symbol table includes debug info (afs-as emits no debug info today; this is a forward-compatible hook). Otherwise, map to the offending atom's symbol name and input file.

### 3. Did-you-mean everywhere

- Undefined symbol (Sprint 8).
- Unknown flag (Sprint 19).
- Missing library (`-lFoo` → did you mean `-lfoo`?).
- Mistyped architecture (`-arch arm86` → did you mean `arm64`?).

Levenshtein-3, capped at the 10 closest matches.

### 4. Colorized output

ANSI color codes on TTY stderr. Flagged off under `NO_COLOR` env var and under `--color=never`. Matches afs-as's approach in `afs-as/src/diag*.rs`.

### 5. Verbose and trace modes

- `-v`: version + target + active flag summary.
- `-t` / `--trace`: every input file logged as it's loaded.
- `-verbose_deprecation`: warnings for deprecated flags (we accept them for `ld` compatibility but note they're deprecated).

### 6. `--help` format

Mirrors `ld`'s. Sections: inputs, outputs, symbols, diagnostics, platform. Each flag has a one-line description and (where applicable) a default value. Fits on 80 columns, readable.

### 7. `--version` format

```
afs-ld <version>
Bespoke ARM64 Mach-O linker for armfortas
Target: arm64-apple-macos
Commit: <git hash>
```

### 8. Deterministic stderr

Error output is the same for the same input across runs. No wall clock, no pid, no thread-id. Supports scripted diffing in CI.

### 9. Error-code conventions

Exit codes:
- 0: success.
- 1: link failure (undefined symbol, ambiguous resolution, etc.).
- 2: CLI misuse (bad flag, missing required arg).
- 64–78: BSD `<sysexits.h>` codes where they fit (EX_USAGE=64, EX_DATAERR=65, EX_NOINPUT=66, EX_UNAVAILABLE=69, EX_SOFTWARE=70).

### 10. Regression: no diagnostic regresses below afs-as quality

Every diagnostic in afs-ld should be at least as useful as the closest afs-as analog. Cross-checked in an audit.

## Testing Strategy

- Snapshot tests for every major error category: undefined symbol, duplicate symbol, missing library, bad flag, malformed input. Compare against a stored expected-output; diff the text (modulo terminal width and colors).
- `--help` and `--version` snapshot tests.
- TTY detection test via a pty harness (or a manual verification step).

## Definition of Done

- Every error category has a snapshot test that matches a stored golden.
- Did-you-mean fires on the five categories listed.
- `--help` fits 80 cols and is scannable.
- Color on TTY, off under `NO_COLOR` / `--color=never`.
- Exit codes follow the convention.
