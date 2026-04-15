# Sprint 31: Final Audit

## Prerequisites
Every prior sprint.

## Goals
The last line of defense before afs-ld is declared the armfortas default linker permanently (i.e., Sprint 20's env-var fallback is removed). Brutally honest audit of every subsystem. Regressions caught, gaps documented, decisions defended.

## Deliverables

### 1. Parity corpus green

Sprint 27's `tests/parity_corpus/` fully green, plus every fortsh-derived scenario added in Sprint 29. No tolerated-diff entries added since Sprint 27 without audit-committee (i.e., user) sign-off.

### 2. Determinism sweep

Link every corpus scenario 10 times under parallelism. All 10 outputs byte-identical. Record the hash.

### 3. Spec conformance survey

Walk the Mach-O, Apple Mach-O ABI, and arm64 AAPCS64 specs section by section. For each feature used by armfortas or fortsh, confirm afs-ld implements it correctly. Checklist:

- Header & magic.
- Load command set.
- Segment/section flags.
- Every relocation type in `<mach-o/arm64/reloc.h>`.
- Symbol types in `<mach-o/nlist.h>`.
- `LC_DYLD_INFO_ONLY` opcode set.
- `LC_DYLD_CHAINED_FIXUPS` format.
- Export trie terminal formats.
- `__unwind_info` layout.
- Compact unwind encoding.
- Code signature SuperBlob.

For each, cite the afs-ld file/function that implements it. Gaps documented in `.docs/audits/sprint31_final.md`.

### 4. CLI parity survey

Every `ld` flag that armfortas or fortsh passes must be supported. Cross-check against:
- `armfortas/src/driver/mod.rs` linker-invocation call sites.
- `fortsh` CMake / build-system linker flags (consult the project).
- The set listed in Sprint 19.

Any flag in the "passes but no-op" category audited for silent misbehavior.

### 5. Binary size audit

Compare total output size (afs-ld vs `ld`) on:
- hello-world.
- libarmfortas_rt-linked Fortran program.
- fortsh.

Within 5% of `ld` on each. Larger than 5% triggers an investigation into where the bloat lives.

### 6. Performance audit

Sprint 28's benchmarks run one more time. fortsh link within 2× of `ld`. No regression since Sprint 28.

### 7. Diagnostic quality audit

Manual pass over every error and warning message. Each evaluated on:
- Does it name the input?
- Does it cite a location (file, offset, symbol)?
- Does it tell the user how to fix it?

Low-quality diagnostics fixed on the spot.

### 8. Dead code and `unwrap`/`panic` sweep

Cargo-geiger-style (but hand-rolled, since we forbid external deps):
- Every `.unwrap()` / `.expect()` reviewed. Panics only in truly-impossible cases.
- Every `todo!()` or `unimplemented!()` either implemented or explicitly deferred with a pointer to a future sprint.
- Dead code removed.

### 9. CLAUDE.md, README, overview.md refresh

Sync documentation with the final state of the crate. Note any scope changes from the original plan. If any sprint was rescoped or split, update the sprint index.

### 10. Submodule pin

Parent armfortas pinned to a specific afs-ld commit. Tag the afs-ld repo `v0.1.0`.

### 11. Default-swap removal

After the audit passes, Sprint 20's `AFS_LD=1` default flip becomes permanent. The env-var fallback stays for one more sprint as a safety net (configurable via `AFS_LD=0` to fall back to system `ld`), then removed entirely.

## Testing Strategy

- Every prior test suite run; all green.
- Determinism sweep (§2).
- Perf sweep (§6).
- Manual binary-size diff (§5).
- Manual CLI parity checklist (§4).

## Definition of Done

- Audit report `.docs/audits/sprint31_final.md` written.
- All tests green.
- No open critical items.
- afs-ld is the armfortas default linker.
- Tagged `v0.1.0`.
