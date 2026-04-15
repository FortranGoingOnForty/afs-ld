# Sprint 0-9 Closeout Checklist

Concrete closeout checklist based on the current codebase audit.

Current conclusion: we are not ready to honestly declare Sprint 10 complete-in-practice yet.
The main blockers are:

- Sprint 0's tolerated-diff categories are still deferred until afs-ld can emit real linked output for Mach-O-to-Mach-O differential checks.

## Sprint 10 Gate

Do not declare "we are on Sprint 10" until all of these are true:

- [x] Sprint 9 reloc referents are remapped to atom-aware forms.
- [x] Sprint 8 resolution orchestration exists as a real callable stage, not just loose helper APIs.
- [x] `cargo test -p afs-ld` is green after the closeout work.
- [x] `cargo clippy -p afs-ld --all-targets -- -D warnings` is green after the closeout work.
- [x] `README.md` and sprint docs no longer materially misstate the current state of the crate.

## Recommended Order

- [x] Close Sprint 9 reloc-to-atom remap first.
- [x] Close Sprint 8 resolution orchestration and option coverage second.
- [x] Close Sprint 6 TBD/SDK search gaps third.
- [x] Close Sprint 4 nested archive support fourth.
- [ ] Finish the deferred Sprint 0 differential-harness tolerance work once afs-ld can emit real output.

## Cross-Sprint Exit Criteria

- [ ] Every closeout chunk lands with tests.
- [ ] Every bug fix or behavioral gap gets a regression test.
- [ ] No newly-discovered roadmap/code mismatch is left undocumented.
- [ ] Any user-facing diagnostic we touch stays deterministic and testable.

## Sprint 0

Status: closed

Validated:

- [x] `afs-ld` exists as its own git submodule in the parent workspace.
- [x] Parent `Cargo.toml` includes `afs-ld` as a workspace member.
- [x] `CLAUDE.md`, `README.md`, crate wiring, and test harness scaffolding exist.
- [x] Reference repos are present under parent `.refs/` (`ld64`, `mold`, `lld`).
- [x] `tests/reader_empty.rs` enforces the empty-invocation CLI contract.
- [x] `tests/diff_harness_sanity.rs` and `tests/diff_harness_finds_critical.rs` exist and pass.
- [x] `cargo clippy -p afs-ld --all-targets -- -D warnings` is currently clean.

Remaining closeout work:

- [x] Explicitly downscope Sprint 0 docs so the current diff harness is described as synthetic until end-to-end linking exists.
- [ ] Add tolerated-diff categories once real Mach-O-to-Mach-O comparisons exist.

## Sprint 1

Status: closed

Validated:

- [x] Mach-O constants are duplicated locally in `src/macho/constants.rs`.
- [x] `MachHeader64` parsing exists and rejects malformed headers.
- [x] Load-command dispatch exists and preserves unknown commands as raw bytes.
- [x] Segment and section-header metadata parsing exists.
- [x] `LC_BUILD_VERSION` and `LC_LINKER_OPTIMIZATION_HINT` decoding exists.
- [x] `--dump` exists through `src/dump.rs` and `src/main.rs`.
- [x] Corpus round-trip tests pass in `tests/reader_corpus_round_trip.rs`.

Remaining closeout work:

- [x] Add an `otool -lV` parity test for dumper output shape across the corpus.
- [x] Add a panic-focused malformed-input stress pass beyond the current unit tests so the "no panics on malformed input" claim is defensible.

## Sprint 2

Status: closed

Validated:

- [x] Section classification exists in `src/section.rs`.
- [x] `InputSection` carries section data and raw relocation bytes.
- [x] `RawNlist` / `InputSymbol` parsing and classification exist in `src/symbol.rs`.
- [x] Common symbols, weak flags, private externs, and indirect aliases are surfaced.
- [x] `StringTable` exists and handles suffix-dedup overlaps.
- [x] `DysymtabCmd` is parsed and exposed through `ObjectFile`.
- [x] `ObjectFile` integrates header, commands, sections, symbols, strings, and dysymtab.

Remaining closeout work:

- [x] Add `nm -a` parity tests for symbol view and classification.
- [x] Add `otool -r` parity checks for relocation-offset surfaces promised by Sprint 2, with section/load-command parity covered by the Sprint 1 `otool -lV` gate.
- [x] Add stronger malformed-symbol / malformed-string-table stress coverage if we want the "never panics" bar to be explicit.

## Sprint 3

Status: closed enough for current closeout

Validated:

- [x] ARM64 relocation constants exist.
- [x] Raw relocation parsing and writing exist.
- [x] Fused `Reloc` form exists.
- [x] `ADDEND` and `SUBTRACTOR + UNSIGNED` pairing is fused in `parse_relocs`.
- [x] Validation logic exists in `validate_relocs`.
- [x] Write-side round-trip support exists.
- [x] Unit coverage is broad and current corpus relocation round-trips pass.

Remaining closeout work:

- [x] No audit-blocking work found for Sprint 3.

## Sprint 4

Status: closed

Validated:

- [x] BSD, SysV, and GNU-thin archive flavors are recognized.
- [x] Archive headers and name decoding are implemented.
- [x] Symbol-index parsing exists for BSD and SysV archives.
- [x] Lazy member fetch exists via `fetch_object_defining`.
- [x] `libarmfortas_rt.a` is exercised by `tests/archive_runtime.rs`.
- [x] Archive dump mode exists via `--dump-archive`.

Remaining closeout work:

- [x] Implement one-level nested archive support (`.a` member inside `.a`) and preserve provenance for diagnostics.
- [x] Formally treat `resolve::force_load_archive` / `force_load_all` as the Sprint 4 completion surface and document that surface instead of adding a parallel archive-only helper.
- [x] Add `ar -t` shape/parity coverage for `--dump-archive`.

## Sprint 5

Status: partially closed

Validated:

- [x] `DylibFile` exists and parses binary `MH_DYLIB`.
- [x] `LC_ID_DYLIB`, dependency dylib commands, ordinals, and rpaths are decoded.
- [x] Export trie decoding exists with cycle/depth protection.
- [x] Real clang-built dylib coverage exists in `tests/dylib_integration.rs`.
- [x] Dylib dump mode exists via `--dump-dylib`.

Remaining closeout work:

- [ ] Prove recursive re-export / umbrella lookup behavior with a focused test, not just dependency collection.
- [ ] Confirm the public dylib surface matches what Sprint 5 intended for re-exported symbols, not only direct exports.

## Sprint 6

Status: closed

Validated:

- [x] The custom YAML subset parser exists in `src/macho/tbd_yaml.rs`.
- [x] TBD schema decoding exists in `src/macho/tbd.rs`.
- [x] `DylibFile::from_tbd` exists and materializes TBDs into the same linker-facing surface.
- [x] Real `libSystem.tbd` smoke/integration coverage exists in `tests/tbd_smoke.rs` and `tests/tbd_integration.rs`.
- [x] TBD dump mode exists via `--dump-tbd`.

Remaining closeout work:

- [x] Implement SDK `-syslibroot` library search helpers for `.tbd` / `.dylib`.
- [x] Implement framework search helpers promised by Sprint 6.
- [x] Make target filtering fail loudly when the requested target is not exported, instead of only materializing matching targets when the caller already knows one exists.
- [x] No further audit-blocking work found for Sprint 6 in the current helper/test surface.

## Sprint 7

Status: closed

Validated:

- [x] `Symbol` sum type exists with the planned major variants.
- [x] `StringInterner`, opaque ids, and `SymbolTable` exist.
- [x] The insertion matrix is heavily unit-tested.
- [x] Weak/strong/common coalescing behavior is covered in unit tests.
- [x] Alias-cycle detection and chain resolution exist.
- [x] Transition logging exists.

Remaining closeout work:

- [ ] Add the differential weak-coalescing / duplicate-behavior coverage against system `ld` that Sprint 7 originally called for.

## Sprint 8

Status: closed

Validated:

- [x] Archive seeding, object seeding, and dylib seeding exist.
- [x] Fixed-point archive fetch draining exists.
- [x] `force_load_archive` and `force_load_all` helpers exist in `src/resolve.rs`.
- [x] Undefined classification exists for `Error`, `Warning`, `Suppress`, and `DynamicLookup`.
- [x] Did-you-mean support exists.
- [x] Duplicate-symbol and undefined-symbol formatting helpers exist.
- [x] Real integration coverage exists for archive pull plus unresolved-symbol reporting.

Remaining closeout work:

- [x] Add a real orchestration entrypoint for resolution (`seed -> optional force load -> drain -> classify`) that can be called as a coherent stage.
- [x] Add option/state plumbing for `all_load`, `force_load`, and undefined treatment so resolution is not just a bag of helper APIs.
- [x] Add an archive order-sensitivity test.
- [x] Add dedicated tests for `force_load_archive` and `force_load_all`.
- [x] Add dedicated tests for `UndefinedTreatment::Warning`, `Suppress`, and `DynamicLookup`.
- [x] Add a dedicated test that unresolved weak refs stay accepted regardless of treatment.
- [x] Tighten diagnostics toward the Sprint 8 format by carrying section/offset provenance and aggregate repeated relocation sites when available.

## Sprint 9

Status: closed

Validated:

- [x] Atom model and atom table exist.
- [x] Section splitting at symbol boundaries exists.
- [x] `.alt_entry` folding exists.
- [x] CString atom splitting exists and is integration-tested.
- [x] Compact-unwind atom splitting and `parent_of` wiring exist.
- [x] Backpatching of `Symbol::Defined { atom }` exists.
- [x] `N_NO_DEAD_STRIP` and weak-def flags are propagated into atom flags.
- [x] Embedded payload addends on symbol-based data relocs are folded into local atom offsets or preserved on external refs.

Remaining closeout work:

- [x] Remap relocations from raw section/symbol referents into atom-aware referents.
- [x] Add atom-local relocation storage or an equivalent per-atom relocation view.
- [x] Ensure same-object references point at target atoms, not raw section offsets.
- [x] Add a focused integration test proving a local branch or data reference resolves to the callee/target atom.
- [x] Add a boundary-crossing reloc diagnostic test.
- [x] Confirm no raw section-relative relocation state leaks into Sprint 10 inputs.
- [x] No further audit-blocking work found for Sprint 9 in the current corpus and targeted local-addend probes.

## Documentation Closeout

- [x] Update `README.md` so it no longer says the crate is only Sprint 0 scaffolding.
- [x] Refresh sprint docs whose deliverables have been implemented under a different surface than originally planned.
- [x] Keep `CLAUDE.md` as the authority for discipline, but make user-facing docs match the actual code.

## Verification Commands

- [x] `cargo test -p afs-ld`
- [x] `cargo clippy -p afs-ld --all-targets -- -D warnings`
- [ ] Focused xcrun-backed checks when touching reader/resolve/atom/TBD/dylib paths:
  - [x] `cargo test -p afs-ld --test reader_corpus_round_trip -- --nocapture`
  - [x] `cargo test -p afs-ld --test resolve_integration -- --nocapture`
  - [x] `cargo test -p afs-ld --test atom_integration -- --nocapture`
  - [x] `cargo test -p afs-ld --test dylib_integration -- --nocapture`
  - [x] `cargo test -p afs-ld --test tbd_integration -- --nocapture`
