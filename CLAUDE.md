# CLAUDE.md

Guidance to Claude Code when working in this repository. The parent
`armfortas/CLAUDE.md` governs the compiler and applies here too; this file
adds linker-specific discipline on top.

## Repository Context

`afs-ld` is a **git submodule** of [ARMFORTAS](https://github.com/FortranGoingOnForty/armfortas),
the bespoke ARM64 Fortran compiler. It is the standalone ARM64 Mach-O
linker: reads `MH_OBJECT` from `afs-as`, static archives (`.a`), binary
dylibs, and TAPI TBD text stubs; emits `MH_EXECUTE` and `MH_DYLIB`.

It knows nothing about Fortran. The boundary with the compiler is the
CLI — an `ld`-compatible flag surface.

**Rust standard library only.** No `clap`, `serde`, `byteorder`, `object`,
`goblin`, `memmap2`, `yaml-rust`. Hand-roll parsers, serializers, and
the tiny YAML subset TBD files need. Adding a dependency requires a
discussion, a CLAUDE.md update, and a justification.

## Build, Test, Lint

```bash
cargo build -p afs-ld                          # build linker crate
cargo test  -p afs-ld                          # full suite
cargo clippy -p afs-ld --all-targets -- -D warnings

cargo test --lib -p afs-ld                     # unit tests only
cargo test --test <name> -p afs-ld             # one integration test file
cargo test --test parity_matrix                # vs Apple `ld` across the corpus (Sprint 27)
cargo test --test hello_world                  # executable end-to-end (Sprint 18)
cargo test --test hello_library                # dylib end-to-end (Sprint 18.5)
cargo test --test reader_corpus_round_trip     # afs-as corpus → byte-identity
cargo test --test archive_runtime              # libarmfortas_rt.a reality check
cargo test --test dylib_integration            # clang-built dylib → DylibFile
cargo test -p afs-ld -- <substring>            # filter by test name
```

Integration tests shell out to `xcrun as`, `xcrun clang`, `ld`, `otool`,
`nm`, `codesign`. They require **macOS on Apple Silicon** and a working
Xcode command-line toolchain. Do not stub or skip them — the
differential against the system tools is the entire point of the suite.
If `xcrun` is missing, tests emit `skipping: ...` and return cleanly.
Never rewrite a test to always pass.

The `--dump*` CLI modes exist for manual inspection:

```bash
afs-ld --dump         input.o        # Mach-O header, load commands, sections, symbols, relocs
afs-ld --dump-archive libfoo.a       # flavor, members, symbol index
afs-ld --dump-dylib   libfoo.dylib   # install_name, dependencies, rpaths, export trie
```

Every time a new decoder lands, extend the relevant `--dump*` output.

## Target

- **Architecture**: arm64 Mach-O (primary; the rules below) plus
  x86_64 ELF static linking (x16 arc, src/elf.rs — rungs 1-2 landed
  2026-07-05: freestanding + full static libc.a/crt via archive
  selection, GOT, TLS local-exec, IFUNC/IPLT, init arrays, symbol
  versioning; parent repo .docs/sprints/x16-afs-ld-elf.md).
- **OS**: macOS. Mach-O file format, Apple AAPCS64 calling convention.
- **Goal**: parity with Apple `ld` for the binaries armfortas produces and
  the fortsh milestone. Not a toy. Not a subset. The full Mach-O/dyld
  contract for our use cases.

## Design Philosophy

- **Bespoke.** We write every decoder, encoder, and layout pass. No
  `object`, no `goblin`, no `mach-object`. When something breaks, we
  read our code.
- **Byte-level round-trip is the invariant.** For every wire structure
  (header, load commands, sections, symbols, strings, relocations,
  archive members, export-trie nodes), `parse(write(x)) == x` and
  `write(parse(bytes)) == bytes` on every corpus fixture. If a
  structure can't round-trip, it's not done.
- **Total control.** `ld` has bugs we can't fix, behaviors we can't
  observe, and refactors we can't predict. Owning the linker closes the
  loop on every binary armfortas produces.
- **No hidden state.** Every transformation between raw wire form and
  linker-side form is explicit. Raw bits are preserved until the
  writer phase reshapes them; `Raw { cmd, cmdsize, data }` is a
  legitimate forever-variant for load commands we don't decode yet.

## Architecture

Pipeline, end-to-end:

```
args → inputs → resolve → atomize → layout → apply relocs → synth sections → write → sign
 │        │        │         │        │            │              │            │       │
args.rs  input.rs resolve.rs atom.rs layout.rs  reloc/arm64.rs  synth/*.rs  macho/   synth/
                 symbol.rs                                                   writer    code_sig
```

### Module responsibilities

- **`src/args.rs`** — CLI parser. Hand-rolled, streaming argv scan. No `clap`.
- **`src/macho/`** — Mach-O 64 read/write.
  - `constants.rs`: `LC_*`, `MH_*`, `S_*`, `N_*`, `ARM64_RELOC_*`, `EXPORT_SYMBOL_FLAGS_*`, `PLATFORM_*`. Numeric literals mirroring Apple's `<mach-o/loader.h>` / `<nlist.h>` / `<reloc.h>` / `<arm64/reloc.h>`. **Duplicated from afs-as** rather than cross-crate coupled — each submodule owns its copy so they stay independent.
  - `reader.rs`: `MachHeader64`, `LoadCommand` enum, per-command structs (`Segment64`, `Section64Header`, `SymtabCmd`, `DysymtabCmd`, `BuildVersionCmd`, `DylibCmd`, `RpathCmd`, `DyldInfoCmd`, `LinkEditDataCmd`). Every variant has `parse(cmdsize, payload)` and `write(&mut Vec<u8>)` paired as round-trip.
  - `dylib.rs`: `DylibFile::parse` — pulls `LC_ID_DYLIB`, dependency chain, rpaths, and routes export-trie bytes through to `exports.rs`.
  - `exports.rs`: `ExportTrie`, `ExportKind`, cycle-safe walker with `MAX_DEPTH=128`.
  - `writer.rs`: emits `MH_EXECUTE` / `MH_DYLIB` (lands at Sprint 10+).
  - `tbd.rs`: TAPI TBD v4 YAML-subset parser (Sprint 6).
- **`src/archive.rs`** — BSD + SysV + GNU-thin static archives. Lazy member fetch via `fetch_object_defining(name)`.
- **`src/input.rs`** — `ObjectFile` aggregate: header + load commands + sections + symbols + strings + dysymtab. Sprint 4 adds archive fetching; Sprint 7 introduces `InputFile` enum.
- **`src/symbol.rs`** — `RawNlist` (wire form, round-trip) + `InputSymbol` accessors (kind, ext, weak_ref/def, common size/alignment, library ordinal, indirect strx).
- **`src/string_table.rs`** — owned `StringTable` with suffix-dedup-aware `strx → &str` lookup.
- **`src/section.rs`** — `SectionKind` taxonomy (code / data / zerofill / TLS / literals / stubs / GOT / compact-unwind / eh_frame) derived from `(segname, sectname, flags)`; `InputSection` with data + raw-reloc slices.
- **`src/reloc/`** — ARM64 relocs.
  - `mod.rs`: `RawRelocation` (bit-packed), `Reloc` (fused; ADDEND / SUBTRACTOR prefixes folded into primaries), `parse_relocs` / `write_relocs` (reversible), `validate_relocs` (bounds, referent range, kind-vs-length-vs-pcrel).
  - `arm64.rs`: reloc application against final addresses (Sprint 11).
  - `loh.rs`: LOH preservation / relaxation (Sprint 25).
- **`src/leb.rs`** — ULEB128/SLEB128 codec reused by export trie, function-starts deltas, dyld opcode streams, chained fixups.
- **`src/diag.rs`** — diagnostics. Path + byte offset + caret, matching `afs-as/src/diag*.rs` style. Deterministic output: no wall clock, no pid, no thread-id in error text.
- **`src/dump.rs`** — `--dump*` inspection modes. Every time a reader decodes something new, extend the dump.
- **`src/driver.rs`** — orchestrator (Sprint 20).

## Coding Conventions

- **Rust, idiomatic.** Use enums for wire structures and linker models.
  Exhaustive pattern matching everywhere — no catch-all `_` arms
  outside tests. When a new `LoadCommand` variant lands, every
  `match` that inspects `LoadCommand` has to grow a new arm; the
  compiler enforces this and that's the point.
- **`unsafe` only where genuinely required.** The one known case is
  `libc::mmap` for large input files (Sprint 28). Keep blocks small,
  comment the invariant, and never let unsafe leak across module
  boundaries.
- **Byte-level round-trip for every wire structure.** Don't add a
  parser without its writer. Don't add a writer without a test that
  proves `write(parse(x)) == x`. See `src/macho/reader.rs` for the
  template.
- **Raw wire form stays accessible.** A Reloc kind that can't losslessly
  re-emit its ADDEND prefix is broken. A `Name16` stored as `String`
  instead of `[u8; 16]` loses null padding and breaks byte-identity.
  Preserve the wire.
- **Constants duplicated, not imported.** `afs-ld/src/macho/constants.rs`
  mirrors Apple's headers numerically. Do not depend on `afs-as` at a
  type level. Submodule independence matters more than deduplication.
- **Diagnostics cite input + offset + caret.** Every parser error goes
  through `ReadError` / `ArchiveError` variants with explicit
  `at_offset` / `context` / `reason`. No `String::from("something
  broke")` noise.
- **Commit discipline**: terse imperative messages, no co-authors,
  per-file / per-chunk commits, never monoliths. No sprint-number
  references in commit subjects. Commit often — "if I had to
  bisect this sprint, which revision would I want to land on?" is
  the granularity.
- **Tests alongside code.** Every new decoder lands with unit tests in
  the same commit. Every bug fix gets a regression test. Integration
  tests that assemble/link real fixtures at test time always skip
  cleanly when `xcrun` is unavailable — never hard-fail on missing
  toolchain.
- **No "stubs pass silently."** Placeholder code that returns wrong
  answers is worse than code that panics. If a kind is "not yet
  implemented", say so with a hard error and a pointer to the sprint
  that'll finish it. Tests must catch the stub, not paper over it.
- **Don't cut corners without stopping to discuss.** If you find
  yourself about to skip a round-trip test, hardcode a "good enough"
  offset, or silently accept a malformed input, stop and talk it
  through. We are not building a toy linker.
- **Avoid rushing through sprints to get to an audit.** The hard work
  of each sprint is the point of the sprint. The audit is the
  downstream check, not the goal.
- **Always opt for the robust solution.** If you find yourself saying
  "the simple solution is X", stop and ask whether a production linker
  uses the simple solution or digs deeper. The simple one might be
  right — but we have to be sure this is not a toy.
- **When unsure, consult `.refs/`.** `.refs/llvm/lld/MachO/` is the
  primary architectural reference; `.refs/ld64/src/` is Apple's
  authoritative implementation for parity edge cases; `.refs/mold/src/`
  informs performance choices. Read before inventing.
- **Run long test jobs judiciously.** Think about the grep/filter before
  you launch — `cargo test -p afs-ld -- reader_` beats
  `cargo test --workspace` when you only touched the reader. The
  corpus round-trip is fast (~1s); the parity matrix (Sprint 27) won't
  be.

## Test Architecture

Layered, not a single golden path. Each layer catches a different class
of regression:

| Test file                            | What it proves |
|--------------------------------------|----------------|
| `src/**/#[cfg(test)]`                | Unit tests per decoder / encoder / accessor |
| `tests/common/harness.rs`            | Differential harness — afs-ld vs system `ld`, tolerated-diff classifier |
| `tests/reader_corpus_round_trip.rs`  | Full afs-as corpus → byte-identity for header + LC region, symtab, strtab, relocs |
| `tests/archive_runtime.rs`           | Real `libarmfortas_rt.a` parses; symbol index resolves |
| `tests/dylib_integration.rs`         | `xcrun clang` dylib → `DylibFile`, install_name + exports + libSystem dep |
| `tests/reader_empty.rs`              | CLI contract: empty argv → `afs-ld: error: no input files`, exit 2 |
| `tests/diff_harness_sanity.rs`       | Harness zero-diffs on identical inputs |
| `tests/diff_harness_finds_critical.rs` | Harness catches intentional byte differences |
| `tests/hello_world.rs`               | Executable end-to-end (Sprint 18) |
| `tests/hello_library.rs`             | Dylib end-to-end (Sprint 18.5) |
| `tests/parity_matrix.rs`             | Corpus byte-level differential vs Apple `ld` (Sprint 27) |
| `tests/armfortas_integration.rs`     | Parent's integration suite under `AFS_LD=1` (Sprint 21) |

Corpus fixtures live in `tests/corpus/`. Every new relocation kind,
section kind, or CLI flag lands a corpus entry in the same sprint.

## Audit Discipline

After each sprint, a brutally honest audit:

- Assume nothing works until proven otherwise. Test every claim.
  Re-run the whole test suite, not just the freshly-written tests.
- "Placeholder" and "stub" are synonyms for "broken." Wrong answers
  silently produced are worse than crashes.
- Check against the Mach-O ABI spec, not just "does it link." Wrong
  output corrupts dyld's bind/rebase state at runtime; the kernel or
  loader will tell you, hours later, in ways that are hard to
  bisect.
- Don't soften findings. **Major** means "produces wrong binaries."
  **Critical** means "silent corruption that dyld will accept."
- No deferred items unless they genuinely require a later sprint.
  Fix it now if it can be fixed now. A deferred item accumulates
  debt with compound interest.
- The audit is not a formality. It is the last line of defense
  before bad linker output gets merged and ships bad binaries
  downstream.

## Completeness Philosophy

Every Mach-O feature modern dyld consumes is in scope. When implementing
a decoder or encoder:

- Implement it fully, not just the subset armfortas or fortsh happens to
  exercise. Every `ARM64_RELOC_*` kind, every `EXPORT_SYMBOL_FLAGS_*`
  terminal form, every `LC_*_DYLIB` variant.
- Don't defer features with "fortsh doesn't use this." Other Mach-O
  binaries do, and the parity gate (Sprint 27) will surface what we
  missed.
- The Mach-O spec + `dyld` source are the spec. `ld` behavior is a
  useful reference, not gospel. Where `ld` and the documented format
  disagree, match `ld`'s actual output and document the deviation in
  the diff-tolerance allowlist.
- Don't modify tests that reveal real bugs to suit incorrect afs-ld
  behavior. Fix afs-ld.

## Key Technical Decisions

- **No LLVM, no `ld64` fork.** We own the stack. `.refs/llvm/lld/MachO/`
  is architectural inspiration; we do not link against it.
- **Both `LC_DYLD_INFO_ONLY` (classic) and `LC_DYLD_CHAINED_FIXUPS`
  (modern).** Classic first (Sprint 15) so hello-world works on
  macOS 11+; chained immediately after (Sprint 15.5) so we match the
  Apple default on macOS 12+. Gate via `-fixup_chains` /
  `-no_fixup_chains`; default depends on `-platform_version`.
- **Dylib output from day one.** The writer is dylib-aware from
  Sprint 10; the hello-library milestone is Sprint 18.5, not
  Sprint 25 as originally scoped.
- **Ad-hoc code signing is mandatory.** macOS 11+ kills unsigned arm64
  binaries at exec time. Sprint 22 ships our own SHA-256 code-signature
  emitter; we do not shell out to `codesign`.
- **Owned bytes over borrowed slices, for now.** `InputSection::data`,
  `StringTable::raw`, and their peers are `Vec<u8>`. Input buffers
  can drop after `ObjectFile::parse` returns. `mmap` + borrowed slices
  arrive in Sprint 28 if profiling justifies the complexity.
- **Ordinals from load-command order.** Two-level-namespace ordinals
  are 1-based positions in `LC_*_DYLIB` appearance order. Do not
  renumber on re-export or umbrella expansion.
- **Per-test unique scratch dirs.** Cargo runs integration tests in
  parallel within one process. Two tests writing to
  `/tmp/afs-ld-corpus-{pid}/` race. Use an `AtomicUsize` counter
  per test or process-id + thread-id composite. See
  `tests/reader_corpus_round_trip.rs::tempdir` for the pattern.

## Practical Gotchas

Lessons carved out of actually building the first few sprints:

- **Never `rm -rf` a directory containing `.docs/` without triple-verification.**
  During Sprint 0 we had a near-miss extracting afs-ld into its own
  repo. Before any destructive operation that touches `.docs/`, keep
  a safety copy outside the operation scope, verify the snapshot has
  the expected file count, and only then proceed. The user has been
  burned; don't burn them again.
- **Submodule work is three-step.** Commit inside afs-ld → push
  origin/trunk → back in armfortas, `git add afs-ld && git commit`
  to bump the pin. Never stop after step one unless explicitly asked.
- **Every new `LoadCommand` variant needs exhaustive-match updates in
  at least three places**: `cmd()`, `cmdsize()`, and
  `src/dump.rs::write_command`. The compiler will tell you — listen.
- **`#[allow(dead_code)]` is a short-lived bridge, not a marker.**
  When a helper is unused because the caller lands in the next commit,
  `#[allow(dead_code)]` is acceptable with a comment naming the caller.
  Remove the allow as soon as the caller lands.
- **Clippy's `manual_is_multiple_of` / `identity_op` /
  `unusual_byte_groupings` lints fire often on bit-field code.** Use
  `.is_multiple_of(8)`, avoid `x | (0 << n)`, and use constants for
  unusual bit masks.
- **Integration tests must skip cleanly on missing toolchain.** If
  `xcrun as` / `xcrun clang` isn't available, `eprintln!("skipping:
  …")` and return. CI on a non-Mac runner must not fail.
- **ASCII helpers for `ar_hdr` must accept empty → 0.** Apple's `ar`
  writes all-space `date/uid/gid/mode` fields on anonymized archives;
  `ascii_decimal` returns `Ok(0)` for an all-whitespace slice.

## Key References

- `.refs/llvm/lld/MachO/` — primary architectural reference.
  - `Driver.cpp` — pipeline shape.
  - `InputFiles.cpp` — object/archive/dylib parsing.
  - `SymbolTable.cpp` — resolution and coalescing rules.
  - `SyntheticSections.cpp` — GOT/stubs/binding opcodes.
  - `Arch/ARM64.cpp` — reloc arithmetic.
  - `Writer.cpp` — layout and emission.
- `.refs/ld64/src/` — Apple authoritative. `src/ld/` + `src/mach_o/`.
- `.refs/mold/src/` — performance techniques (mostly ELF; patterns apply).
- Apple `<mach-o/loader.h>`, `<mach-o/nlist.h>`, `<mach-o/reloc.h>`,
  `<mach-o/arm64/reloc.h>` — mirrored numerically in
  `src/macho/constants.rs`.
- `dyld` open source — bind/rebase/lazy-bind opcode semantics and
  chained-fixups format.
- ARM Architecture Reference Manual (ARMv8-A), section C4 — encoding
  of relocated instructions (ADRP, ADD, LDR, B/BL).

## Sprint Roadmap

`.docs/sprints/index.md` — 32 sprints across 10 phases. Each has an
individual markdown file with prerequisites, deliverables, testing
strategy, and definition of done. Current completion is in each
commit's parent-repo pin bump message.
