# Sprint 29 fortsh Link Audit

Status date: 2026-05-19

## Current result

- `AFS_LD=1` can link the armfortas-built fortsh object set.
- The afs-ld-linked binary starts and prints `fortsh 1.7.0`.
- Code signing validation passes with `codesign -v`.
- `--help` output matches the same armfortas object set linked with Apple `ld`.
- Binary size is now within the Sprint 29 5% budget after dropping final-output `__DWARF` and `__LLVM` payload sections:
  - afs-ld: `14,573,584` bytes
  - Apple `ld`: `14,327,424` bytes
  - delta: about 1.7%

## Fixed during audit

- `afs-ld` previously preserved `__DWARF` and `__LLVM` input sections into final executables. Apple `ld` omits those sections for this fortsh link.
- `src/layout.rs` now filters debug payload and `__LLVM` sections before output layout, while preserving `__TEXT,__compact_unwind`.
- `src/macho/writer.rs` now skips local and global symbols that point only into dropped input sections.
- Linkedit symbol planning no longer builds its `SymbolId -> nlist` lookup through a hash table; the table is now dense over the linker symbol arena.
- TBD-backed dylib seeding now walks flat export lists by reference instead of cloning every `ExportEntry` before interning.
- Linkedit finalization now caches the output symbol string table across relayout convergence passes when the symbol-name order is unchanged.
- The linkedit string-table cache is now reused across the outer unwind/finalize convergence loop, with the same symbol-name-order validation.
- TBD-backed dylib loading now starts with metadata plus a targeted export filter, then materializes any remaining unresolved dylib exports after archive fetches. The filtered TBD path scans symbol flow lists incrementally instead of cloning libSystem's full export arrays.
- Parsed relocation caches are now sorted once and relocation apply uses partitioned per-atom slices instead of scanning each section's full relocation list for every atom.
- Linkedit finalization now skips the pre-relayout full plan rebuild; the first pass computes load-command shape, relayouts, then builds the first real linkedit plan.
- Relocation target resolution now uses a sorted per-input-section atom range index and a borrowed symbol-name index, avoiding repeated linear atom scans and duplicate symbol-name allocation during relocation/thunk passes.
- Linkedit symbol planning now shares cached string-table buffers across convergence passes and makes suffix-dedup lookup O(1) after reverse-suffix sorting.
- Unwind synthesis now reuses the linker-wide parsed relocation cache and indexed atom/symbol lookups instead of reparsing compact-unwind relocations and linearly scanning atoms/symbols for each record.
- Regression coverage:
  - `layout_omits_debug_and_llvm_payload_sections`
  - `linker_run_omits_debug_and_llvm_payload_sections_like_ld`
  - `tests/parity_corpus/fortsh_debug_llvm_payload_exec`
  - `target_matching_fast_path_keeps_only_requested_exports`
  - `cargo test -p afs-ld --test tbd_integration -- --nocapture`
  - `relocated_sections_match_apple_ld_across_fixture_matrix`

## Non-linker blocker found

`fortsh -c ...` aborts with an invalid free when using armfortas-generated objects, regardless of linker:

- afs-ld-linked armfortas objects: aborts.
- Apple-ld-linked armfortas objects: aborts.
- lldb points at `afs_modproc_command_tree_destroy_command_node`.

Reference compiler checks do not reproduce the crash:

- flang-new 22.1.4: `fortsh -c 'echo hello'` prints `hello`, exit 0; `fortsh -c true` exits 0.
- gfortran 15.2.0: `fortsh -c 'echo hello'` prints `hello`, exit 0; `fortsh -c true` exits 0.

This classifies the current `-c` runtime blocker as an armfortas-generated-object
or armfortas runtime/codegen issue, not an afs-ld issue.

## Still open

- Full Sprint 29 runtime matrix is blocked on the armfortas fortsh `-c` invalid-free bug.
- Link-time performance still misses the Sprint 29 2x gate on this machine:
  - Through the armfortas final-link path with release afs-ld: afs-ld `0.16-0.17s`, Apple `ld` `0.06s`.
  - Direct linker invocation on the same object list after the unwind-indexing slice: afs-ld warm runs are about `0.08-0.09s`, Apple `ld` remains about `0.03-0.04s`.
  - Current profile for the fortsh fixture: total is typically about `87-102ms` warm; largest remaining buckets are linkedit finalization about `23-28ms`, relocation application about `18-21ms`, symbol resolution about `11-14ms`, and output write about `8-12ms`.
  - The linkedit symbol-plan slices reduced the measured symbol-plan bucket from about `51ms` to about `13-17ms`, and the symbol string-table sub-bucket from about `32ms` to about `4.4-4.7ms`.
  - The targeted TBD slice reduced the measured TBD decode bucket from about `22-45ms` depending on cache/double-decode path to about `3-4ms`.
  - The sorted relocation slices avoid per-atom full-section relocation scans and speed section-backed target lookup; observed relocation-apply samples now range from about `18-20ms` on the fortsh fixture, with release direct warm runs around `0.09s`.
  - The linkedit convergence slice removed one full plan rebuild per finalize call, reducing observed linkedit finalization from about `40-46ms` to about `27-31ms`.
  - The unwind-indexing slice reduced observed unwind synthesis from about `8-9ms` to about `1.2ms`.
- Load-command shape is improved by dropping debug/LLVM payloads, but afs-ld still emits classic `LC_DYLD_INFO_ONLY` rather than Apple's chained-fixup load-command shape for this executable.
