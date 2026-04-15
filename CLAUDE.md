# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Context

`afs-ld` is a **git submodule** of [ARMFORTAS](https://github.com/FortranGoingOnForty/armfortas), a bespoke ARM64 Fortran compiler. It is the standalone ARM64 Mach-O linker: it reads Mach-O relocatable objects (MH_OBJECT) produced by `afs-as`, static archives, binary dylibs, and TAPI TBD text stubs, and emits linked Mach-O executables (MH_EXECUTE) and shared libraries (MH_DYLIB). It knows nothing about Fortran — the boundary with the compiler is the CLI (an `ld`-compatible flag surface).

The parent `armfortas/CLAUDE.md` describes the broader compiler philosophy (bespoke, no LLVM, no parser generators, no compiler-infrastructure crates) and applies here too. **Rust standard library only** — no `clap`, no `serde`, no `byteorder`, no `object`, no `goblin`, no `memmap2`, no YAML crate. Hand-roll parsers, serializers, and the tiny subset of YAML we need for TBD files.

## Build, Test, Lint

```bash
cargo build -p afs-ld                          # build linker crate
cargo test  -p afs-ld                          # run all afs-ld tests
cargo clippy -p afs-ld --all-targets -- -D warnings

cargo test --lib -p afs-ld                     # unit tests only (in src/)
cargo test --test <name> -p afs-ld             # one integration test file
cargo test --test parity_matrix                # vs Apple `ld` across the corpus
cargo test --test hello_world                  # executable end-to-end
cargo test --test hello_library                # dylib end-to-end
cargo test -p afs-ld -- <substring>            # filter by test name
```

Integration tests shell out to Apple `ld`, `otool`, `nm`, `codesign`, and `xcrun`. They require **macOS on Apple Silicon** and a working Xcode command-line toolchain. Do not stub these out — the differential against the system linker is the entire point of the parity matrix.

## Architecture

Pipeline, end to end:

```
args → inputs → resolve → atomize → layout → apply relocs → synth sections → write → sign
 │        │        │         │        │            │              │            │       │
args.rs  input.rs resolve.rs atom.rs layout.rs  reloc/arm64.rs  synth/*.rs  macho/   synth/
                 symbol.rs                                                   writer    code_sig
```

### Module responsibilities

- **`src/args.rs`** — CLI parser. Hand-rolled, no `clap`. Recognizes the `ld`-compatible flag surface (Sprint 19 ships the full set).
- **`src/macho/`** — Mach-O 64 read/write. `constants.rs` holds the numeric literals (`LC_*`, `MH_*`, `S_*`, `N_*`, `ARM64_RELOC_*`) — duplicated from afs-as rather than cross-crate coupled, keeping each submodule independent. `reader.rs` parses MH_OBJECT; `writer.rs` emits MH_EXECUTE and MH_DYLIB; `dylib.rs` parses binary MH_DYLIB; `tbd.rs` parses TAPI TBD v4 text stubs (minimal YAML subset, not a general parser).
- **`src/archive.rs`** — BSD + SysV + GNU-thin static archives. Lazy member fetch.
- **`src/input.rs`** — `InputFile` enum unifying objects, archives, dylibs, TBDs.
- **`src/symbol.rs`** / **`src/resolve.rs`** — `Symbol` sum type and the name resolution pass. Archive-driven fixed-point loop; weak/common/alias coalescing; diagnostics with did-you-mean.
- **`src/atom.rs`** — subsections-via-symbols atomization. Atoms are the unit of dead-stripping, ICF, and output layout.
- **`src/section.rs`** / **`src/layout.rs`** — output segment plan and VM/file-offset assignment. `MH_EXECUTE` and `MH_DYLIB` are both first-class.
- **`src/reloc/`** — ARM64 reloc application (`arm64.rs`) and LOH relaxation (`loh.rs`). Handles BRANCH26, PAGE21/PAGEOFF12, GOT_LOAD_*, POINTER_TO_GOT, TLVP_LOAD_*, UNSIGNED, SUBTRACTOR, ADDEND.
- **`src/synth/`** — synthetic sections: `got`, `stubs`, `tlv`, `symtab`, `dyld_info` (classic), `chained` (LC_DYLD_CHAINED_FIXUPS), `unwind`, `eh_frame`, `func_starts`, `data_in_code`, `code_sig` (ad-hoc SHA-256).
- **`src/gc.rs`** / **`src/icf.rs`** — `-dead_strip` and `-icf=safe` passes.
- **`src/map.rs`** / **`src/why_live.rs`** — `-map` link map and `-why_live` dead-strip reasoning.
- **`src/driver.rs`** — orchestrator: args → inputs → resolve → atomize → layout → apply relocs → synth → write → sign.
- **`src/diag.rs`** — diagnostics. Path + byte offset + caret, matching `afs-as/src/diag*.rs` style. Deterministic output: no wall clock, no pid, no thread-id.

## Coding Conventions

- **Rust std only.** Any external dependency needs an explicit debate and a CLAUDE.md update.
- **`unsafe` only where genuinely required.** Keep blocks small and commented. The one known case is `libc::mmap` for large input files (Sprint 28).
- **Exhaustive pattern matching** on `Section`, `Symbol`, `Relocation`, `InputFile`, `Fixup`, `LoadCommand` — no catch-all `_` arms outside tests.
- **Determinism**: no timestamps in output, sorted iteration order, stable hashing, parallelism preserves byte-identical output.
- **Commit discipline**: terse imperative messages, no co-authors, per-file / per-chunk commits, never monoliths. No sprint-number references in commit messages.
- **No "stubs pass silently"**: placeholder code that returns wrong answers is worse than code that panics. Tests must catch the stub, not paper over it.
- **Diagnostics always cite input + offset + caret.** `src/diag.rs` is the one place that constructs these; every error path goes through it.

## Test Architecture

Tests are **layered**, not a single golden path. Each layer catches a different class of regression:

| Test file | What it proves |
|---|---|
| `src/**/#[cfg(test)]` | Parser / encoder / resolution unit tests (`cargo test --lib`) |
| `tests/common/harness.rs` | Differential harness: spawn afs-ld + system ld on the same inputs, diff outputs |
| `tests/reader_*.rs` | Round-trip Mach-O object reads across the afs-as corpus |
| `tests/reloc_*.rs` | Golden-file relocation application |
| `tests/resolve_*.rs` | Symbol resolution matrices (strong vs weak vs common vs dylib vs archive) |
| `tests/hello_world.rs` | End-to-end: afs-as → afs-ld → runnable PIE executable |
| `tests/hello_library.rs` | End-to-end: afs-as → afs-ld → `dlopen`able dylib |
| `tests/parity_matrix.rs` | Full corpus byte-level differential vs Apple `ld` (CI gate) |
| `tests/armfortas_integration.rs` | Parent's integration suite run under `AFS_LD=1` |

Corpus fixtures live in `tests/corpus/`. Every new relocation kind, section kind, or CLI flag lands a corpus entry in the same sprint that implements it.

## Audit discipline

After each sprint, a brutally honest audit:

- Assume nothing works until proven otherwise. Test every claim.
- "Placeholder" and "stub" are synonyms for "broken." Wrong answers silently produced are worse than crashes.
- Check against the Mach-O ABI spec, not just "does it link." Wrong output corrupts the loader's bind/rebase state.
- Don't soften findings. "Major" means "produces wrong binaries." "Critical" means "silent corruption that dyld will accept."
- No deferred items unless they genuinely require a later sprint. Fix it now if it can be fixed now.
- The audit is not a formality. It's the last line of defense before bad linker output gets merged and ships bad binaries downstream.

## Key references

- `.refs/llvm/lld/MachO/` — primary architectural reference.
- `.refs/ld64/src/` — Apple authoritative. `src/ld/` and `src/mach_o/` cover the whole linker.
- `.refs/mold/src/` — performance techniques (parallel parsing, string merging, allocator tricks). Mostly ELF-oriented but the performance patterns apply.
- Apple `<mach-o/loader.h>`, `<mach-o/nlist.h>`, `<mach-o/reloc.h>`, `<mach-o/arm64/reloc.h>` — mirrored numerically in `src/macho/constants.rs`.
- `dyld` open source — bind/rebase/lazy-bind opcode semantics and chained-fixups format.
- ARM Architecture Reference Manual (ARMv8-A) — encoding of relocated instructions.

## Sprint roadmap

`.docs/sprints/index.md` — 32 sprints across 10 phases. Each sprint has an individual markdown file with prerequisites, deliverables, testing strategy, and definition of done.
