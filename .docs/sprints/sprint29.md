# Sprint 29: fortsh Link Audit

## Prerequisites
Sprints 18–28 — every functional sprint, parity gate, performance tuning.

## Goals
End-to-end link of fortsh under afs-ld. fortsh is ~57 KLoC Fortran 2018, 55 modules, heavy `iso_c_binding`, allocatable strings, derived types. Linking it is the first real-world stress test of everything before this sprint. Fix what breaks. No excuses.

## Deliverables

### 1. fortsh build pipeline under afs-ld

```
cd fortsh
AFS_LD=1 armfortas --std=f2018 -O2 <all sources> -o fortsh
```

Expected:
- Build succeeds.
- `./fortsh --version` prints the expected version string.
- Interactive mode starts and reads a line.
- `./fortsh -c "echo hello"` prints "hello".

### 2. Failure taxonomy

Anticipated categories (adjust during sprint based on what actually breaks):

- **Symbol resolution**: missing runtime symbols, weak-coalesce wrong winner, common-size mismatches.
- **Relocation math**: PAGE21/PAGEOFF12 miscomputation on specific offsets, SUBTRACTOR pair issues in eh_frame.
- **TLV**: thread-local I/O state failing at runtime.
- **Unwind**: backtrace on crash produces garbage.
- **Dead-strip**: functions stripped that were live (or live that should have been stripped).
- **Chained fixups**: a chain crossing a page boundary or containing a bad `next` offset.
- **Code signature**: kernel-kill on exec.

Each class has a known file/function starting point for triage from earlier sprints.

### 3. Audit process

Same rules as armfortas audits (`armfortas/CLAUDE.md`):

- **Assume nothing works until proven otherwise.** Every subsystem gets exercised by some fortsh code path.
- **Stubs and placeholders are synonyms for broken.** If fortsh passes a case only because of a hand-patched workaround, the sprint isn't done.
- **Wrong output is worse than crashes.** A fortsh that "runs" but produces wrong answers is a critical failure.
- **Don't soften findings.** "Major" = wrong answers. "Critical" = silent corruption.
- **Fix now unless it genuinely requires a later sprint.**

Every bug becomes a regression test in `tests/parity_corpus/fortsh_*/`.

### 4. Runtime behavior matrix

Curated list of fortsh scenarios run under the afs-ld-linked binary:

- Interactive `echo`, `cat`, `ls` (builtins).
- Pipe: `echo hello | cat`.
- Redirect: `echo hello > /tmp/f`.
- Variables: `x=1; echo $x`.
- Scripts: `./fortsh script.fsh`.
- Error paths: `nonexistent_command` returns non-zero.
- `iso_c_binding` calls into libc from Fortran.
- Allocatable string assignment: `s = s // "more"`.
- Derived-type shell_state_t access.

Every item green, or the sprint isn't done.

### 5. Differential vs system-ld-linked fortsh

Same fortsh source, linked by both. Runtime behavior **must** match for every scenario in §4. Binary size within 5%. Load-command shape equivalent. Output byte-by-byte for the parts our Sprint 27 rules cover.

### 6. Perf check

Link time for fortsh under afs-ld is within Sprint 28's 2× budget.

### 7. Audit report

`.docs/audits/sprint29_fortsh.md` (or wherever the project convention puts audit reports, parallel to armfortas's audit structure): a brutally honest writeup of what worked, what broke, what was fixed, what remains. No soft-pedaling.

## Testing Strategy

- Full fortsh test suite executed under both linker paths.
- Each scenario in §4 scripted as a parity test.
- Perf budget asserted.
- Memory usage at link time within reason (< 1 GiB on fortsh).

## Definition of Done

- fortsh links under afs-ld.
- Every scenario in §4 passes.
- All fortsh integration tests pass.
- Differential with ld-linked fortsh matches on every runtime scenario.
- Audit report filed; no open critical items.
