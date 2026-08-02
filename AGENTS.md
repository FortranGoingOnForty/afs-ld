# AFS-LD

Tracked local working guide for agents in `afs-ld`. Read it together with
`CLAUDE.md`: this file records the current implementation and repository
workflow, while `CLAUDE.md` carries the longer-lived linker design discipline.
Neither roadmap prose nor an old status paragraph overrides code and tests.

## Repository Context

`afs-ld` is the standalone final linker for the ARMFORTAS toolchain. It sits
beside `afs-as` as a submodule in the `armfortas` workspace and ships two
independent output paths:

- ARM64 Mach-O executables and dylibs for Apple Silicon.
- x86_64 ELF static and dynamically linked executables for Linux and FreeBSD.

The project boundary is intentionally clean:

- `afs-as` emits `MH_OBJECT`.
- The Mach-O path reads `.o`, `.a`, `.dylib`, and `.tbd` inputs.
- The ELF path reads `ET_REL`, archives, linker scripts, and `ET_DYN`
  dependencies.
- armfortas invokes `afs-ld` through the CLI; the subprojects do not share Rust
  format types.

The crate is Rust standard-library only. Mach-O is arm64-only; ELF is
x86_64-only. COFF, PE, LTO, and bitcode are outside the current scope.

## Definition Of Done

The Mach-O finish line is parity with Apple's `ld` for the binaries armfortas
and fortsh need:

- arm64 Mach-O executables and dylibs
- static archive linking
- dylib and TBD ingestion
- dyld metadata that works on real macOS systems
- ad-hoc signing so output executes on Apple Silicon
- deterministic output
- enough correctness to link fortsh without ARM-specific workarounds

The shipped ELF boundary is narrower and explicit: non-PIE `ET_EXEC` output,
both static and dynamically linked, with supported x86_64 relocations and GNU
archive/search semantics. ELF PIE and shared-object output are not implemented.

## Current Reality

This repository produces final binaries, but it is not a drop-in replacement
for every Apple or GNU linker mode. The roadmap in `.docs/overview.md` and
`.docs/sprints/` remains broader than the supported CLI and output matrix.

What is implemented now:

- hand-rolled CLI parsing, response files, ordered input normalization, and dump
  modes
- Mach-O object/archive/dylib/TBD ingestion, symbol resolution, atomization,
  layout, ARM64 relocation application, thunks, safe ICF, and dead stripping
- Mach-O GOT/stub/TLV/unwind/dyld/symbol metadata synthesis, deterministic
  `MH_EXECUTE` and `MH_DYLIB` writing, ad-hoc signing, link maps, and atomic
  output publication
- x86_64 ELF `ET_REL`, archive, linker-script, and `ET_DYN` ingestion
- static and dynamically linked ELF `ET_EXEC` writing with ordered archive
  scans, GOT/PLT, TLS, IFUNC/IPLT, init arrays, garbage collection, unwind
  headers, and symbol versioning
- structural, deterministic, differential, and runtime-oriented test suites for
  both paths, with destination-specific execution when the host permits it
- `--dump`, `--dump-archive`, `--dump-dylib`, and `--dump-tbd`

What is not implemented yet:

- the full Apple `ld` or GNU `ld` option surface
- Mach-O relocatable and bundle output
- ELF PIE, ELF shared-object output, and non-x86_64 ELF targets
- modes that the CLI currently diagnoses as deferred or unsupported

Important practical note:

- `Linker` in `src/lib.rs` owns the Mach-O final-link pipeline.
- `src/main.rs` selects the ELF path before Mach-O argument parsing when an ELF
  emulation or input identifies that target.
- Unsupported output modes must fail before replacing an existing output.

## Strengths

- Both output paths are exercised beyond parser-only tests.
- The project has strong bespoke discipline: no `clap`, `serde`, `object`,
  `goblin`, `byteorder`, or other format-parsing shortcuts.
- Raw wire structures are modeled explicitly and usually paired with
  round-trip-oriented tests.
- The type modeling is strong: opaque ids, interned strings, explicit symbol
  states, explicit atom ownership, explicit relocation referents.
- Real-world fixtures include afs-as corpus objects, `libarmfortas_rt.a`,
  `libSystem.tbd`, native archives/shared libraries, and compiler-produced
  inputs.
- Output publication is isolated behind atomic replacement helpers.
- Dump modes remain useful for inspecting input and output structure.

## Weaknesses And Risk Areas

- Apple/GNU compatibility is intentionally incomplete; confirm each flag and
  output kind in `src/args.rs`, `src/main.rs`, and the tests.
- Some tracked `.docs` material describes intended end state rather than shipped
  behavior.
- Mach-O runtime and differential coverage depends on Apple Silicon hosts;
  Linux-only runs cannot prove destination execution or Apple `ld` parity.
- ELF has a deliberately different target/output matrix from Mach-O; do not
  generalize one path's features to the other.
- Large-link performance and native-linker parity remain continuing audit areas.

## Build And Test

Primary commands:

```bash
cargo build -p afs-ld
cargo test -p afs-ld
cargo clippy -p afs-ld --all-targets -- -D warnings
```

Useful targeted commands:

```bash
cargo test --lib -p afs-ld
cargo test --test reader_corpus_round_trip -p afs-ld
cargo test --test linker_run -p afs-ld
cargo test --test linker_write_integration -p afs-ld
cargo test --test parity_matrix -p afs-ld
cargo test --test elf_link_run -p afs-ld
cargo test --test elf_mode_selection -p afs-ld
cargo test --test documentation_claims -p afs-ld
cargo test -p afs-ld -- <substring>
```

Environment assumptions:

- Rust-only and host-independent tests run on any development host.
- Mach-O differential/runtime tests need macOS on Apple Silicon and Xcode
  command-line tools available through `xcrun`.
- ELF execution/differential tests need a supported x86_64 Linux or FreeBSD host
  and the native assembler/linker/runtime tools used by that test.
- access to the parent workspace, especially `runtime/` and `.refs/`

Integration tests already shell out to system tools in a few places. Do not
replace those with fake fixtures if a real toolchain interaction is the thing
being tested.

## Project Structure

Key source areas today:

```text
afs-ld/
├── AGENTS.md
├── CLAUDE.md
├── README.md
├── src/
│   ├── lib.rs / main.rs / args.rs       # Mach-O orchestration + CLI routing
│   ├── input.rs / resolve.rs / atom.rs  # Mach-O ingestion and graph model
│   ├── layout.rs / output.rs            # layout and atomic publication
│   ├── macho/ / synth/ / reloc/         # Mach-O wire, metadata, relocation
│   ├── elf.rs                           # x86_64 ELF reader/linker/writer
│   └── icf.rs / loh.rs / link_map.rs / why_live.rs
└── tests/
    ├── linker_run.rs / linker_write_integration.rs / parity_*.rs
    ├── elf_*.rs
    ├── reader_*.rs / archive_runtime.rs / dylib_integration.rs
    └── common/
```

Treat modules named only by roadmap prose as design intent until `rg --files`
and tests confirm that they exist.

## Implemented Pipelines

ARM64 Mach-O:

```text
argv -> args -> inputs -> resolve -> atomize -> dead-strip/ICF/thunks
     -> layout -> apply ARM64 relocs -> synth metadata/unwind/linkedit
     -> write Mach-O -> ad-hoc sign -> atomic publish
```

x86_64 ELF:

```text
argv -> ELF mode/input detection -> object/archive/script/shared ingestion
     -> ordered resolution + optional GC -> static/dynamic layout and relocs
     -> synth GOT/PLT/TLS/unwind/dynamic metadata -> write ET_EXEC
     -> atomic publish
```

When planning work, identify the selected format path first. Shared concepts do
not imply shared wire structures or identical supported flags.

## Development Guidance

### 1. Trust code and tests over roadmap prose

Read these in order before substantial work:

1. `CLAUDE.md`
2. `.docs/overview.md`
3. the relevant sprint file in `.docs/sprints/`
4. the actual Rust module you will touch
5. the tests covering that module

If the docs and the code disagree, treat the code plus tests as the truth about
what exists today, then decide whether the docs need to be refreshed.

### 2. Keep the bespoke contract intact

- Stdlib only unless a dependency discussion happens first.
- Do not couple afs-ld to afs-as at a Rust type level.
- Duplicate Mach-O constants locally when needed.
- Do not hide format details behind clever abstractions that erase wire truth.

### 3. Preserve the wire

- Keep raw bytes or raw fields accessible when lossless re-emission matters.
- Prefer explicit parse and write pairs for on-disk structures.
- Avoid converting fixed-size or padded wire data into lossy higher-level forms
  unless the raw representation is still available somewhere.
- If a new decoder lands, pair it with tests that prove it round-trips or at
  least preserves the exact bytes relevant to the current stage.

### 4. Be explicit about incomplete work

- Hard errors are better than silent wrong answers.
- If something is not implemented, say so directly.
- Do not introduce "temporary" behavior that quietly emits malformed Mach-O.
- Do not soften a missing feature into a no-op unless the flag or structure is
  explicitly intended to be ignored.

### 5. Exhaustive matches matter

- Prefer enums for wire forms and linker-side states.
- Avoid catch-all `_` arms in production matches when a new variant should force
  the compiler to help us.
- When adding a new variant, update every relevant match deliberately.

### 6. Keep dump surfaces useful

- `--dump*` modes are an active debugging tool, not a side feature.
- When new reader functionality lands, extend the corresponding dump output.
- If you add a new parsed field but the dump cannot show it, the repo loses one
  of its best inspection surfaces.

### 7. Respect deterministic behavior

- Avoid nondeterministic iteration when output order matters.
- Avoid timestamps, random ids, or unstable hashing in every output path.
- When adding diagnostics, keep them stable and testable.

## Testing Practices

- Every bug fix gets a regression test.
- New parser behavior should land with unit tests close to the module.
- When touching integration behavior, prefer real fixtures over mocked ones.
- For archive work, look first at `tests/archive_runtime.rs`.
- For dylib and TBD work, look first at `tests/dylib_integration.rs`,
  `tests/tbd_integration.rs`, and `tests/tbd_smoke.rs`.
- For reader invariants, `tests/reader_corpus_round_trip.rs` is a key guardrail.
- For resolution and atomization, `tests/resolve_integration.rs` and
  `tests/atom_integration.rs` should move with the code.
- When extending output functionality, extend the differential harness
  rather than building a parallel ad hoc test path.

Run focused tests first, then widen:

- module-local or single integration test while developing
- `cargo test -p afs-ld` before handing work off
- `cargo clippy -p afs-ld --all-targets -- -D warnings` when changing code paths
  broadly enough to justify it

## Documentation Practices

- `CLAUDE.md` is policy and development discipline.
- `.docs/overview.md` is the intended architecture and scope.
- `.docs/sprints/` is the staged roadmap.
- `README.md` is the user-facing summary of the currently shipped target and
  output matrix.

When a change materially shifts reality, update the tracked docs that are now
misleading. This is especially important in this repo because the roadmap is
ambitious and can otherwise create false assumptions for future work.

## References

Use the parent repository's references when you need to confirm Mach-O or linker
behavior instead of inventing from memory:

- `.refs/llvm/lld/MachO/` for architecture and pass structure
- `.refs/ld64/` for Apple-parity edge cases
- `.refs/mold/` for performance ideas and comparative implementation choices

Also use Apple's Mach-O and arm64 relocation headers as the numeric source of
truth for constants mirrored in `src/macho/constants.rs`.

## Working Style For This Repo

- Prefer small, reviewable changes.
- Keep commit messages terse and imperative.
- Do not mention sprint numbers in commit subjects.
- Avoid monolithic "land the whole linker" changes; the sprint plan is granular
  for a reason.
- Before implementing a planned module from the roadmap, make sure the crate
  actually has the prerequisites the sprint assumed.
- If you are about to say "the docs say this exists," stop and confirm with
  `ls`, `rg`, and the tests.

## Practical Shortcuts

- Use `rg --files` and `rg` first; the repo is small enough that this is fast
  and keeps context grounded in the actual tree.
- For current status, start with `src/lib.rs`, `src/main.rs`, `src/args.rs`,
  `tests/common/harness.rs`, and `README.md`.
- For architectural intent, then read `.docs/overview.md` and the relevant
  sprint file.

That order will save a lot of confusion.
