# afs-ld

**Bespoke ARM64 Mach-O linker for Apple Silicon, written in Rust, stdlib only.**

> This is the original Mach-O design roadmap, not a complete inventory of the
> current multi-format crate. The shipped Mach-O writer emits classic
> `LC_DYLD_INFO_ONLY`; it does not emit `LC_DYLD_CHAINED_FIXUPS`.
> `-fixup_chains` is reserved and fails before output publication until the
> chained-fixup sprint is implemented and validated.

## Why

armfortas already owns the compiler (`armfortas`) and the assembler (`afs-as`). Every binary the toolchain produces today is still shaped by Apple's `ld` — which puts the same class of opaque, untouchable bugs back in our path that motivated abandoning LLVM in the first place. `afs-ld` closes the loop. We own every byte from `.f90` source to the final Mach-O executable on disk.

This is **not** a toy or educational linker. The target is production parity with Apple `ld` for:

- Everything armfortas produces today: arm64 PIE executables statically linking `libarmfortas_rt.a` and dynamically linking `libSystem`.
- The fortsh milestone: ~57 KLoC Fortran 2018, 55 modules, `iso_c_binding`, allocatable strings, derived types.
- Deterministic output: `-no_uuid` parity, reproducible byte layout across invocations.
- All ARM64 Mach-O relocation types, static archives (`.a`), binary dylibs, and TAPI TBD v4 text stubs (libSystem ships as `.tbd` on modern SDKs).
- Classic `LC_DYLD_INFO_ONLY` output today, with modern
  `LC_DYLD_CHAINED_FIXUPS` retained as explicit future scope.
- Dylib output (`-dylib`) as a first-class feature, not an afterthought.
- Ad-hoc code signing — macOS 11+ will not execute an unsigned arm64 binary, even if every other byte is perfect.

## Non-goals (current)

- ELF, COFF, PE, or any non-Mach-O format.
- x86_64, arm64_32, armv7, or any architecture other than arm64.
- Bitcode/LTO. armfortas emits assembly, not bitcode; lto is not part of the armfortas pipeline.
- ObjC / Swift metadata merging. No armfortas code emits it. Hooks exist for later.
- Cross-compilation. We target the host Mac; no `-sdk_version` time-travel.

These are non-goals **now**; afs-ld is built to grow into them without architectural retrofit.

## What afs-as hands us

afs-as emits `MH_OBJECT` only (hand-rolled, no external Mach-O crate). Its output defines the contract afs-ld reads:

- Load commands: `LC_SEGMENT_64`, `LC_BUILD_VERSION` (PLATFORM_MACOS), optional `LC_LINKER_OPTIMIZATION_HINT`, `LC_SYMTAB`, `LC_DYSYMTAB`.
- Section kinds: `__TEXT,__text`, `__TEXT,__cstring`, `__TEXT,__literal16`, `__TEXT,__const`, `__TEXT,__compact_unwind`, `__TEXT,__eh_frame`, `__DATA,__data`, `__DATA,__bss`, `__DATA,__thread_data`, `__DATA,__thread_bss`, `__DATA,__thread_vars`.
- Symbol flags: `N_UNDF`/`N_SECT`/`N_ABS` with `N_EXT`, `N_PEXT`, `N_WEAK_REF`, `N_WEAK_DEF`, `N_NO_DEAD_STRIP`. Common symbols live in `N_UNDF` with `n_desc`-encoded alignment.
- Relocation types: `ARM64_RELOC_UNSIGNED`, `SUBTRACTOR`, `BRANCH26`, `PAGE21`, `PAGEOFF12`, `GOT_LOAD_PAGE21`, `GOT_LOAD_PAGEOFF12`, `POINTER_TO_GOT`, `TLVP_LOAD_PAGE21`, `TLVP_LOAD_PAGEOFF12`, `ADDEND` (paired prefix).
- Flags: `MH_SUBSECTIONS_VIA_SYMBOLS` always set — atomization model is in play.
- LOH hints: `AdrpAdd`, `AdrpLdr`, `AdrpLdrGot`, `AdrpLdrGotLdr` — afs-ld preserves them from Sprint 0 and relaxes them in Sprint 25.

afs-as exposes no Mach-O reader. afs-ld ships its own.

## Current driver contract

`armfortas/src/driver/mod.rs:497-565` shells out to `ld`:

```
ld <obj1> <obj2> ... <libarmfortas_rt.a> \
   -lSystem -no_uuid -syslibroot <SDK> -e _main -o <output>
```

Inputs are `.o` from afs-as plus `libarmfortas_rt.a` from the `runtime/` crate. Output is an arm64 PIE executable with entry `_main` (a synthetic wrapper at `src/driver/mod.rs:371-392` calling `_afs_program_init` → user PROGRAM → `_afs_program_finalize`). afs-ld drops into this contract unchanged; the driver swap (Sprint 20) is initially gated behind `AFS_LD=1`.

## Reference material

Already in parent `.refs/`:

- `.refs/llvm/lld/MachO/` (~21 KLoC C++) — primary architectural reference. Most relevant files: `Driver.cpp` (pipeline), `InputFiles.cpp` (object/archive/dylib parsing), `SymbolTable.cpp` (resolution), `SyntheticSections.cpp` (GOT/stubs/binding), `Arch/ARM64.cpp` (reloc math), `Writer.cpp` (layout).
- `.refs/llvm/lld/docs/MachO/index.rst` — design notes comparing lld and ld64.

Cloned in Sprint 0:

- `.refs/ld64/` — Apple's open-source `ld64` (GitHub mirror of last publicly released tarball). Authoritative for byte-level parity edge cases when our diff harness disagrees with Apple's `ld`.
- `.refs/mold/` — Rui Ueyama's `mold` including its Darwin port. Leaner second opinion and a source of performance ideas.

Spec-level:

- Apple `<mach-o/loader.h>`, `<mach-o/nlist.h>`, `<mach-o/reloc.h>`, `<mach-o/arm64/reloc.h>` — mirrored numerically in our `macho/constants.rs`.
- `dyld` open source — bind/rebase/lazy-bind opcode semantics and chained-fixups format.
- ARM Architecture Reference Manual (ARMv8-A) — encoding of relocated instructions (ADRP, ADD, LDR, B/BL).

## Repo layout

afs-ld is a Cargo workspace member of `armfortas` and a Git submodule at `armfortas/afs-ld` pointing at `git@github.com:FortranGoingOnForty/afs-ld.git`, mirroring how `afs-as` is organized.

```
afs-ld/
├── Cargo.toml                 # no deps outside std
├── CLAUDE.md                  # mirrors afs-as/CLAUDE.md, tailored to linker
├── README.md
├── .docs/
│   ├── overview.md            # this file
│   └── sprints/               # 32 sprint files
├── src/
│   ├── lib.rs                 # re-export Linker, LinkOptions, OutputKind
│   ├── main.rs                # afs-ld binary
│   ├── args.rs                # CLI parsing (hand-rolled, no clap)
│   ├── macho/
│   │   ├── mod.rs
│   │   ├── constants.rs       # LC_*, MH_*, S_*, N_*, ARM64_RELOC_*
│   │   ├── reader.rs          # parse MH_OBJECT
│   │   ├── writer.rs          # emit MH_EXECUTE or MH_DYLIB
│   │   ├── dylib.rs           # parse MH_DYLIB
│   │   └── tbd.rs             # parse TAPI TBD v4
│   ├── archive.rs             # ar/ranlib archive reader
│   ├── input.rs               # InputFile enum, lazy member fetch
│   ├── symbol.rs              # Symbol kinds, SymbolTable
│   ├── resolve.rs             # name resolution pass
│   ├── atom.rs                # subsections-via-symbols atom model
│   ├── section.rs             # InputSection, OutputSection, OutputSegment
│   ├── layout.rs              # VM addr + file offset assignment
│   ├── reloc/
│   │   ├── mod.rs
│   │   ├── arm64.rs           # ARM64_RELOC_* application
│   │   └── loh.rs             # LOH preservation / relaxation
│   ├── synth/                 # synthetic sections
│   │   ├── mod.rs
│   │   ├── got.rs
│   │   ├── stubs.rs
│   │   ├── tlv.rs
│   │   ├── symtab.rs
│   │   ├── dyld_info.rs       # classic rebase/bind/lazy/weak + export trie
│   │   ├── unwind.rs
│   │   ├── eh_frame.rs
│   │   ├── func_starts.rs
│   │   ├── data_in_code.rs
│   │   └── code_sig.rs        # ad-hoc SHA-256 code signature
│   ├── map.rs                 # -map text link map
│   ├── why_live.rs            # -why_live dead-strip reasons
│   ├── gc.rs                  # -dead_strip
│   ├── icf.rs                 # -icf=safe
│   ├── driver.rs              # orchestrator
│   └── diag.rs                # diagnostics, path/line/col parity with afs-as
└── tests/
    ├── common/harness.rs      # spawn afs-ld, diff output vs system ld
    ├── reader_*.rs            # round-trip object reads
    ├── reloc_*.rs             # golden-file reloc application
    ├── resolve_*.rs           # symbol resolution matrices
    ├── hello_world.rs         # first end-to-end executable link
    ├── hello_library.rs       # first end-to-end dylib link
    ├── armfortas_integration.rs
    └── corpus/                # hand-curated .o / .a / .dylib / .tbd fixtures
```

## Architecture pipeline

```
args → inputs → resolve → atomize → layout → apply relocs → synth sections → write → sign
```

1. **args**: hand-rolled parser for the `ld`-compatible CLI surface. No clap.
2. **inputs**: demultiplex `.o`, `.a`, `.dylib`, `.tbd`; lazy archive-member fetching.
3. **resolve**: symbol-table fixed-point loop; weak/common/alias coalescing; archive-driven pulls.
4. **atomize**: split input sections at symbol boundaries per `MH_SUBSECTIONS_VIA_SYMBOLS`.
5. **layout**: assign VM addrs (`__PAGEZERO`/`__TEXT`/`__DATA_CONST`/`__DATA`/`__LINKEDIT` for executables; no `__PAGEZERO` for dylibs) and file offsets.
6. **apply relocs**: ARM64_RELOC_* patching; GOT/stubs/lazy-pointer emission; LOH honoring.
7. **synth sections**: `__LINKEDIT` payload — symbol table, string table, classic `LC_DYLD_INFO_ONLY`, function starts, data-in-code, compact unwind, eh_frame passthrough. Chained fixups remain a planned alternative.
8. **write**: Mach-O header + load commands + segment data; `-no_uuid` deterministic.
9. **sign**: ad-hoc SHA-256 page hashes in `LC_CODE_SIGNATURE` so the binary runs on bare arm64.

## Coding conventions

- **Rust std only.** No `clap`, no `serde`, no `byteorder`, no `object`, no `goblin`. Hand-roll parsers, serializers, and the tiny YAML subset we need for TBD.
- **`unsafe` only where genuinely required.** Keep blocks small and commented.
- **Exhaustive pattern matching** on `Section`, `Symbol`, `Relocation`, `InputFile`, `Fixup` — no catch-all `_` arms outside tests.
- **Diagnostics**: path, offset, caret under source — mirror `afs-as/src/diag*.rs`.
- **Determinism**: no timestamps in output, sorted iteration, stable hashing.
- **Commit discipline**: terse imperative, no co-authors, per-file/per-chunk commits, never monoliths. Matches armfortas and afs-as house rules.
- **No borrowed constants across crates.** afs-ld duplicates `MH_*`, `LC_*`, `S_*`, `N_*`, `ARM64_RELOC_*` in `macho/constants.rs` rather than depending on afs-as at a type level. Each submodule stays independent.

## Testing strategy

- **Unit**: every parser and encoder has a round-trip test — parse a fixture, re-emit, compare bytes.
- **Corpus**: `tests/corpus/` collects `.o`, `.a`, `.dylib`, `.tbd` fixtures. Every new relocation type or section kind lands a corpus entry in the same sprint that implements it.
- **Differential** (from Sprint 1): `tests/common/harness.rs` links the same inputs through `ld` and `afs-ld`, diffs load commands, symbol tables, classic bind/rebase streams, and disassembly. Chained-stream comparison belongs to the still-planned chained producer. Tolerated-diff allowlists must never hide semantic output differences.
- **End-to-end** (from Sprint 18): hello-world executable must run; (Sprint 18.5) hello-library dylib must `dlopen`. (Sprint 21) the full armfortas integration suite must pass.
- **fortsh link** (Sprint 29): explicit milestone. A fortsh binary linked by afs-ld must behave identically to one linked by system `ld`.
- **Audits**: post-Sprint 18 (hello), 18.5 (dylib), 22 (first signed & running on bare arm64), 27 (parity gate), 29 (fortsh), 31 (final). Brutal honesty rules from armfortas/CLAUDE.md apply.

## Sprint roadmap (summary)

See `.docs/sprints/index.md` for the full list. Ten phases, 32 sprints:

- **Phase 0 — Scaffolding**: Sprint 0.
- **Phase 1 — Mach-O reading**: Sprints 1–3 (header/load commands, sections/symbols, relocations).
- **Phase 2 — Archives & dylibs**: Sprints 4–6 (`ar`, binary dylib, TBD).
- **Phase 3 — Symbol resolution**: Sprints 7–9 (model, resolution pass, atomization).
- **Phase 4 — Output construction**: Sprints 10–14 (layout, reloc application, GOT/stubs, TLV, symtab/strtab). MH_EXECUTE and MH_DYLIB both first-class.
- **Phase 5 — Dyld metadata**: Sprint 15 (classic `LC_DYLD_INFO`, shipped), Sprint 15.5 (chained fixups, still planned), Sprint 16 (function starts/data-in-code), Sprint 17 (unwind info).
- **Phase 6 — End-to-end**: Sprint 18 (hello-world executable), 18.5 (hello-library dylib).
- **Phase 7 — CLI & driver**: Sprints 19 (CLI + `-map`/`-why_live` diagnostics), 20 (driver swap).
- **Phase 8 — Runtime compatibility**: Sprints 21 (runtime archive + integration tests), 22 (ad-hoc code signature).
- **Phase 9 — Advanced**: Sprints 23 (`-dead_strip`), 24 (`-icf=safe`), 25 (LOH relaxation), 26 (thunks).
- **Phase 10 — Hardening**: Sprints 27 (differential gate), 28 (performance), 29 (fortsh link audit), 30 (polish), 31 (final audit).

## Scope decisions (confirmed)

- Dylib output is in scope from Phase 4; the writer is dylib-aware from Sprint 10. Dylib milestone at Sprint 18.5.
- Classic `LC_DYLD_INFO_ONLY` is shipped. Chained fixups remain in scope but
  cannot become a default until Sprint 15.5 has a writer-side producer,
  structural/runtime parity evidence, and an explicit policy change.
- `.refs/` gains ld64 and mold alongside lld. lld is the architectural reference, ld64 is authoritative for Apple-parity edge cases, mold informs performance.
- `-map` and `-why_live` land in Sprint 19 with the core CLI. They are the debugging surface during driver adoption, not a polish item.
