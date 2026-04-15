# AFS-LD

Local working guide for agents in `afs-ld`. Keep this file untracked.
`CLAUDE.md` is the tracked, authoritative policy file; this document adds a
reality-checked snapshot of the current implementation so we do not confuse the
roadmap with shipped code.

## Repository Context

`afs-ld` is the standalone ARM64 Mach-O linker for the ARMFORTAS toolchain. It
sits beside `afs-as` as a submodule in the `armfortas` workspace and is meant
to replace Apple's `ld` for binaries produced by armfortas.

The project boundary is intentionally clean:

- `afs-as` emits `MH_OBJECT`.
- `afs-ld` reads `.o`, `.a`, `.dylib`, and `.tbd`.
- armfortas should eventually hand final linking to `afs-ld` rather than to
  the system linker.

The project is Mach-O only, macOS only, arm64 only, stdlib only.

## Definition Of Done

The real finish line is not "parses some objects" or "links hello world once."
It is parity with Apple's `ld` for the binaries armfortas and fortsh need:

- arm64 Mach-O executables and dylibs
- static archive linking
- dylib and TBD ingestion
- dyld metadata that works on real macOS systems
- ad-hoc signing so output executes on Apple Silicon
- deterministic output
- enough correctness to link fortsh without ARM-specific workarounds

## Current Reality

This repo is ahead of Sprint 0 scaffolding, but it is not yet a full linker.
The roadmap in `.docs/overview.md` and `.docs/sprints/` is broader than the
code that exists today.

What is implemented now:

- hand-rolled CLI parsing for a small flag subset plus dump modes
- Mach-O header/load-command/section/symbol/string-table reading
- relocation parsing, fusion, validation, and round-trip support
- archive parsing and lazy member fetch support
- binary dylib parsing and export-trie walking
- TAPI TBD v4 parsing, including the custom YAML subset parser
- linker-side symbol interning, symbol table modeling, and resolution passes
- subsections-via-symbols atomization
- `--dump`, `--dump-archive`, `--dump-dylib`, and `--dump-tbd`

What is not implemented yet:

- real `Linker::run` output production
- output layout and Mach-O writing
- dyld metadata synthesis
- code signing
- dead-strip / ICF / thunks
- real differential linking against Apple `ld`
- driver integration with armfortas
- the full `ld`-compatible CLI surface described in Sprint 19

Important practical note:

- `src/lib.rs` still returns `LinkError::NotYetImplemented` for real link runs.
- `tests/common/harness.rs::link_both` still panics because full end-to-end
  linker execution has not landed.
- `README.md` still describes the crate as "Sprint 0 scaffolding only," which is
  now too pessimistic for the read-side code but still accurate for the actual
  link-producing path.

As of 2026-04-15 in this checkout, `cargo test -p afs-ld` is green.

## Strengths

- The read-side core is already substantial and well-tested.
- The project has strong bespoke discipline: no `clap`, `serde`, `object`,
  `goblin`, `byteorder`, or other format-parsing shortcuts.
- Raw wire structures are modeled explicitly and usually paired with
  round-trip-oriented tests.
- The type modeling is strong: opaque ids, interned strings, explicit symbol
  states, explicit atom ownership, explicit relocation referents.
- Real-world fixtures are already in play: afs-as corpus objects,
  `libarmfortas_rt.a`, `libSystem.tbd`, and small clang-built dylibs.
- The codebase already separates concerns cleanly enough that writer/layout work
  can land without tearing up the read-side foundation.
- Dump modes make inspection easy and are useful while the full writer does not
  exist yet.

## Weaknesses And Risk Areas

- The actual link-producing pipeline does not exist yet, so the hardest parity
  bugs are still ahead of us.
- Some tracked docs are aspirational. `.docs/overview.md` is the intended end
  state, not a guarantee that every listed module already exists.
- `README.md` is stale in the opposite direction: it understates how much
  read-side work has landed.
- The current diagnostics surface is still minimal. `src/diag.rs` only prints
  `afs-ld: error: ...`; the richer caret diagnostics are planned, not present.
- The CLI surface is intentionally tiny right now. Any work that assumes
  `ld`-compatibility must start by checking `src/args.rs`, not by trusting the
  sprint plan.
- Performance characteristics are mostly unknown because the writer, layout, and
  full-link path are not in place yet.
- The differential harness is only half-built: the diff engine exists, but the
  "run both linkers" machinery is not wired.
- Several future modules named in the roadmap do not exist yet:
  `layout.rs`, `driver.rs`, `map.rs`, `gc.rs`, `icf.rs`, `synth/`,
  `macho/writer.rs`, and the code-signing path are all still planned work.

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
cargo test --test archive_runtime -p afs-ld
cargo test --test dylib_integration -p afs-ld
cargo test --test tbd_integration -p afs-ld
cargo test --test resolve_integration -p afs-ld
cargo test --test atom_integration -p afs-ld
cargo test -p afs-ld -- <substring>
```

Environment assumptions:

- macOS on Apple Silicon
- Xcode command-line tools available through `xcrun`
- access to the parent workspace, especially `runtime/` and `.refs/`

Integration tests already shell out to system tools in a few places. Do not
replace those with fake fixtures if a real toolchain interaction is the thing
being tested.

## Project Structure

Actual source tree today:

```text
afs-ld/
├── CLAUDE.md
├── README.md
├── .docs/
│   ├── overview.md
│   └── sprints/
├── src/
│   ├── archive.rs
│   ├── args.rs
│   ├── atom.rs
│   ├── diag.rs
│   ├── dump.rs
│   ├── input.rs
│   ├── leb.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── resolve.rs
│   ├── section.rs
│   ├── string_table.rs
│   ├── symbol.rs
│   ├── macho/
│   │   ├── constants.rs
│   │   ├── dylib.rs
│   │   ├── exports.rs
│   │   ├── reader.rs
│   │   ├── tbd.rs
│   │   └── tbd_yaml.rs
│   └── reloc/
│       └── mod.rs
└── tests/
    ├── common/harness.rs
    ├── archive_runtime.rs
    ├── atom_integration.rs
    ├── diff_harness_*.rs
    ├── dylib_integration.rs
    ├── reader_*.rs
    ├── resolve_integration.rs
    ├── tbd_*.rs
    └── reader_corpus_round_trip.rs
```

Planned future modules listed in the docs should be treated as design intent,
not as present-tense implementation.

## Implemented Pipeline Vs Planned Pipeline

Implemented today:

```text
argv
  -> args.rs
  -> dump/read paths
  -> archive/object/dylib/TBD ingestion
  -> symbol/section/reloc decoding
  -> resolve.rs
  -> atom.rs
```

Current real-link path:

```text
argv -> args.rs -> Linker::run -> NotYetImplemented
```

Planned end-to-end pipeline from the roadmap:

```text
args -> inputs -> resolve -> atomize -> layout -> apply relocs
     -> synth sections -> write -> sign
```

When you are planning work, always identify which of those stages is real in
this checkout and which stage is still only described in docs.

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
- Avoid timestamps, random ids, or unstable hashing in any future write path.
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
- If you add future write-side functionality, extend the differential harness
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
- `README.md` is user-facing and currently stale relative to the read-side code.

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
