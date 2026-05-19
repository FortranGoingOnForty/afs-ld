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
- Regression coverage:
  - `layout_omits_debug_and_llvm_payload_sections`
  - `linker_run_omits_debug_and_llvm_payload_sections_like_ld`
  - `tests/parity_corpus/fortsh_debug_llvm_payload_exec`

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
  - Direct linker invocation on the same object list: afs-ld `0.13s`, Apple `ld` `0.03s`.
  - Current profile for the fortsh fixture: total about `168ms`; largest buckets are linkedit symbol planning about `51ms`, input read/TBD decode about `50ms` combined, relocation application about `22ms`, and output write about `8-10ms`.
- Load-command shape is improved by dropping debug/LLVM payloads, but afs-ld still emits classic `LC_DYLD_INFO_ONLY` rather than Apple's chained-fixup load-command shape for this executable.
