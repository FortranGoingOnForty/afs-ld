# Sprint 31 Final Audit

Date: 2026-05-23

Status: default-swap deferred.

Sprint 31 is the final gate before afs-ld can be treated as the permanent
armfortas default linker. This report records hard evidence, not intent.
Most technical gates below are passing, but the default swap is intentionally
deferred while remaining Apple-parity concerns are audited.

## 1. Parity Corpus

Status: passing.

Command:

```text
PARITY_MATRIX_MAX_SECONDS=120 cargo test -p afs-ld --test parity_matrix parity_corpus -- --nocapture
```

Result:

```text
parity matrix timing: 56 case(s) in 6.63s
test parity_corpus ... ok
```

Notes:

- The corpus exceeds the Sprint 27 50-case minimum.
- The closeout budget was enforced with `PARITY_MATRIX_MAX_SECONDS=120`.
- The slowest reported cases were runtime-heavy direct-bind/reexport/TLV
  cases, not linker byte-comparison failures.

## 2. Determinism Sweep

Status: passing.

Focused prior guardrail:

```text
cargo test -p afs-ld --test determinism
```

Result:

```text
3 passed; 0 failed
```

Sprint 31 corpus-wide gate:

```text
cargo test -p afs-ld --test parity_determinism -- --nocapture
```

Result:

```text
parity determinism: 56 case(s), 10 run(s) per case, afs-ld -j 8
test parity_corpus_outputs_are_deterministic_across_ten_parallel_runs ... ok
```

Per-case baseline hashes from the 10-run sweep:

```text
archive_order_exec len=16864 hash=996ecff7934c81e3
backtrace_metadata_exec len=50048 hash=0a876b9d1b43469e
classic_lazy_batched_got_calls len=50096 hash=7b799152de6d7b1a
classic_lazy_branch_calls len=50048 hash=f9ad879872d8b72f
classic_lazy_branch_only_calls len=50048 hash=f9ad879872d8b72f
classic_lazy_deduped_import len=49984 hash=2c38db7f9a5a4193
common_symbol_promotion_exec len=16800 hash=65a8303273fdd4fd
data_in_code_exec len=16800 hash=2608cf008d8d29c5
data_in_code_large_first_exec len=16832 hash=11f6f5d5e913a87b
data_in_code_late_exec len=16832 hash=24efd330d77b685f
dead_strip_import_exec len=16800 hash=6d0d31ff94504944
direct_bind_data len=33376 hash=e464946dc626f1c8
direct_bind_deduped len=33408 hash=d3a8ae52a0a5cadb
direct_bind_mixed len=50032 hash=7e136ba909f2bae1
direct_bind_multi_data len=33440 hash=c55bde9b690f7455
export_bss_dylib len=16752 hash=44fe8e956243f710
export_filter_dylib len=16784 hash=d9d8f24d6c9479ee
export_ordering_dylib len=16800 hash=6f5baec540449e03
export_prefix_fanout_dylib len=16832 hash=93000fd0ba8489ab
export_shared_data_prefix_dylib len=33360 hash=25f6ae2ead07ee0d
export_text_const_dylib len=16784 hash=63c8eea24521fa8c
export_text_data_dylib len=33344 hash=8e3d0ebc81dc8bbf
fortsh_debug_llvm_payload_exec len=16800 hash=baa7651d5b4ca41c
function_starts_exec len=49984 hash=4950067253bfa89f
function_starts_textcoal_exec len=16832 hash=978c2865a1442384
hello_classic len=16800 hash=725d9489022ff7d8
hello_dead_strip len=16800 hash=725d9489022ff7d8
hidden_got_exec len=33328 hash=c11f6baccb601314
imported_tlv_exec len=33360 hash=2c8721879ce82b77
local_got_exec len=49872 hash=6e00d5167558627e
local_rebase_exec len=33376 hash=b0919dab6acac50e
loh_adrp_add_dylib len=16784 hash=53c805d628d79b9e
loh_adrp_add_exec len=16832 hash=5ebd4013fa5b55ec
loh_adrp_ldr_exec len=16832 hash=0b8380ca136950c8
loh_adrp_ldr_got_ldr_exec len=49872 hash=6e00d5167558627e
reexport_chain_exec len=49984 hash=5d458129018bb581
reloc_adrp_add_backward len=33328 hash=3364159e7a132ae4
reloc_adrp_add_forward len=33328 hash=b7da6aebe00ff0bc
reloc_adrp_ldr_w len=16816 hash=e80d0c46d37c40cc
reloc_adrp_ldr_x len=16816 hash=7f4afaeebf5a4f1e
reloc_adrp_ldrb len=16816 hash=6ce12b272336fd57
reloc_adrp_ldrh len=16816 hash=1522c19fd9c71ae0
reloc_branch_and_subtractor len=16848 hash=ec057eb3e11dafb8
reloc_branch_backward len=16832 hash=769eb3d180fc48e5
reloc_branch_forward len=16816 hash=1cdd45f8d76098c2
reloc_mixed_branch_adrp_text len=16848 hash=c5f70ed65583658f
reloc_subtractor_negative len=16848 hash=21decae719121e83
reloc_subtractor_positive len=16848 hash=ecf1aa547d8bde8a
runtime_fortran_three_func_exec len=1803408 hash=fdbe7b0dd38a5b21
strip_locals_exec len=33392 hash=8eb62647598e7a50
symtab_partition_exec len=33440 hash=77b8627b34bcee74
synthetic_import_classic_lazy len=49984 hash=531f33a3d7d1efb1
unexport_filter_dylib len=16768 hash=4069288838ae2f63
unwind_leaf_exec len=16800 hash=d316db769a0d23bd
unwind_multi_exec len=16832 hash=e3b24f4f68d13f7a
weak_def_coalescing_exec len=49968 hash=e01c8e80badadafa
```

Notes:

- The determinism hash is a test-local FNV-1a hash of the afs-ld output.
- The sweep relinks each prepared parity case 10 times to the same output path
  with `afs-ld -j 8` and requires byte-for-byte equality.

## 3. Spec Conformance Survey

Status: passing for the supported executable/dylib final-gate surface.

Command:

```text
cargo test -p afs-ld --test spec_conformance -- --nocapture
```

Result:

```text
7 passed; 0 failed
```

Coverage:

- `public_macho_constants_match_supported_apple_wire_values` pins the supported
  `<mach-o/loader.h>`, `<mach-o/nlist.h>`, `<mach-o/arm64/reloc.h>`, export
  trie, rebase, and bind opcode constants.
- `writer_outputs_have_spec_shaped_headers_load_commands_and_code_signature`
  validates executable and dylib `mach_header_64`, load-command accounting,
  `LC_MAIN` / `LC_ID_DYLIB` kind-specific presence, `__TEXT`, and
  `LC_CODE_SIGNATURE` SuperBlob magic in writer output.
- `every_arm64_relocation_wire_type_is_parsed_or_fused_intentionally` covers
  every `ARM64_RELOC_*` wire type, including `ADDEND` prefix fusion and
  `SUBTRACTOR + UNSIGNED` pair fusion.
- `nlist_symbol_types_decode_supported_spec_variants` covers `N_UNDF`,
  `N_ABS`, `N_SECT`, `N_INDR`, `N_STAB`, `N_EXT`, and `N_PEXT`.
- `export_trie_round_trips_all_terminal_payload_forms` covers regular,
  thread-local, absolute, re-export, weak-definition, and stub/resolver export
  trie terminal payloads.
- `chained_fixups_blob_uses_supported_header_starts_imports_and_pointer_formats`
  validates `LC_DYLD_CHAINED_FIXUPS` header/starts/import/symbol-string
  shape plus rebase and bind pointer-write formats.
- `code_signature_superblob_has_ad_hoc_codedirectory_shape` validates the
  ad-hoc SuperBlob and CodeDirectory fields used by afs-ld outputs.

Existing differential coverage that remains part of this gate:

- `cargo test -p afs-ld --test load_command_parity`
- `cargo test -p afs-ld --test parity_matrix parity_corpus -- --nocapture`

These cover Apple `ld` load-command order, segment/section parity, dyld-info
streams, rebased `__unwind_info`, compact-unwind consumption, code-signature
tolerance, and the broader relocation corpus.

Current results:

```text
load_command_parity: 3 passed; 0 failed
parity matrix timing: 56 case(s) in 7.04s
parity_corpus ... ok
```

## 4. CLI Parity Survey

Status: passing for the current armfortas and fortsh link surface.

Inputs reviewed:

- `armfortas/src/driver/mod.rs` normal linker invocation.
- `armfortas/src/driver/mod.rs` `AFS_LD` / `AFS_LD_PATH` override invocation.
- `../fortsh/Makefile` armfortas profile.
- Sprint 19 CLI list in `.docs/sprints/sprint19.md`.

Findings:

- The armfortas executable link path passes object inputs, `libarmfortas_rt.a`,
  `libSystem.tbd`, `-arch arm64`, `-e _main`, `-o`, user `-L`, user `-l`,
  and user `-rpath`. afs-ld parses and wires all of these.
- The armfortas shared-library path now maps the driver `-shared` flag to
  afs-ld `-dylib` and omits the executable-only `_main` entry override.
- The armfortas `-static` mode remains deliberately rejected by the afs-ld
  override. The system linker path only approximates it with
  `-search_paths_first`, and neither the current fortsh armfortas profile nor
  the default-swap executable path depends on it.
- The fortsh armfortas Makefile links with:

```text
$(FC) $(C_STRING_OBJ) $(CORE_C_OBJS) $(OBJECTS) -o $@ $(LDFLAGS)
```

  For `FC_KIND=armfortas`, `LDFLAGS` is empty unless `USE_C_STRINGS=1`, where
  it adds a direct static archive path. That is inside the current afs-ld input
  and archive-drain surface.

Verification:

```text
cargo test --test standalone_toolchain -- --nocapture
```

Result:

```text
6 passed; 0 failed
```

Coverage added during this audit:

- `shared_library_runs_through_driver_with_standalone_linker_override` builds a
  Fortran dylib through `AFS_LD_PATH`, links a consumer through that dylib with
  `-I`, `-L`, `-rpath`, and `-l`, then runs the result.

## 5. Binary Size Audit

Status: passing.

Command:

```text
cargo test -p afs-ld --test binary_size_audit -- --nocapture
```

Result:

```text
hello_classic size audit: afs-ld=16792 Apple ld=16792 ratio=1.000
runtime_fortran_three_func_exec size audit: afs-ld=1803400 Apple ld=1692680 ratio=1.065
test hello_and_runtime_binary_sizes_stay_near_apple_ld ... ok
```

Fortsh evidence remains the Sprint 29 audit measurement:

```text
afs-ld: 14,573,584 bytes
Apple ld: 14,327,424 bytes
delta: about 1.7%
```

Notes:

- The current automated binary-size audit covers hello-world and a
  libarmfortas_rt-linked Fortran program from the parity corpus.
- Fortsh size remains below the Sprint 29 5% budget in the recorded real
  fortsh fixture audit.

## 6. Performance Audit

Status: passing.

Command:

```text
AFS_LD_HELLO_BUDGET_MS=25 AFS_LD_RUNTIME_BUDGET_MS=150 cargo test -p afs-ld --test perf_baseline -- --nocapture
```

Result:

```text
hello: total=2.65975ms
runtime: total=34.676083ms
bench_fortsh_fixture_profile_reports_baseline_timings ... ok
test result: ok. 3 passed; 0 failed
```

Fortsh fixture note:

- The local `perf_baseline` fortsh test is opt-in and skipped unless
  `AFS_LD_FORTSH_INPUTS_FILE` points at a newline-delimited fortsh object list.
- The Sprint 29 real fortsh audit remains the current 2x evidence:

```text
Through the armfortas final-link path with release afs-ld: afs-ld 0.16-0.17s, Apple ld 0.06s
Direct linker invocation on the same object list: afs-ld 58.7-62.4ms, Apple ld 32.8-35.6ms
Direct-link ratio: about 1.8x Apple ld
```

Notes:

- Hello and runtime budgets are enforced by environment variables in the test
  command above.
- The fortsh runtime matrix remains blocked by the armfortas invalid-free bug
  recorded in `.docs/audits/sprint29_fortsh.md`; the direct linker comparison
  itself is within the documented Sprint 29/Sprint 31 cutoff.

## 7. Diagnostic Quality Audit

Status: passing as of Sprint 30 closeout.

Reference:

- `.docs/audits/sprint30_diagnostic_audit.md`

Remaining Sprint 31 action:

- Re-review diagnostics during final full-suite runs and fix any new low-quality
  message found by the broader audit.

## 8. Dead Code And Panic Sweep

Status: passing.

Commands:

```text
rg -n "todo!|unimplemented!|panic!|unwrap\\(|expect\\(" src --glob '!**/tests/**'
rg -n "allow\\(dead_code\\)|dead_code|TODO|FIXME|XXX" src --glob '!**/tests/**'
cargo clippy -p afs-ld --all-targets -- -D warnings
cargo test -p afs-ld --test cli_diagnostics malformed_local_symbol_section_index_reports_error_instead_of_panicking -- --nocapture
```

Results:

```text
cargo clippy -p afs-ld --all-targets -- -D warnings
Finished `dev` profile [optimized + debuginfo]

test malformed_local_symbol_section_index_reports_error_instead_of_panicking ... ok
test result: ok. 1 passed; 0 failed; 37 filtered out
```

Action taken:

- Replaced the final-output local-symbol-table `expect("section symbol without
  section")` with a user-facing `WriteError::MalformedLocalSymbolSection`.
- Added a CLI regression that assembles an object, corrupts a local section
  symbol's `n_sect`, and verifies afs-ld exits with a diagnostic instead of
  panicking.

Remaining reviewed production panic/unwrap classes:

- Fixed-width byte-slice conversions after explicit size checks.
- Formatting into `String` buffers.
- Internal layout/linkedit convergence invariants.
- Scoped worker `join` and mutex poison checks, where a panic would indicate a
  separate internal bug in the worker body.
- Unit-test-only unwraps and panics inside `#[cfg(test)]` modules.

No `todo!` or `unimplemented!` remains in production `src/`.

## 9. Documentation Refresh

Status: passing.

Updated files:

- `CLAUDE.md`
- `README.md`
- `.docs/overview.md`

Changes:

- Replaced the stale README "Sprint 0 scaffolding only" status with the
  current Sprint 31 final-gate state.
- Added final-gate parity, determinism, spec, size, and perf commands to the
  README.
- Refreshed `CLAUDE.md` test commands and test architecture table to use the
  current integration-test filenames.
- Documented the current parent-driver reality: Apple `ld` remains the
  default, `AFS_LD=1` selects the sibling afs-ld binary, and
  `AFS_LD_PATH=<path>` selects an explicit afs-ld build.
- Refreshed `.docs/overview.md` for the 56-case parity matrix, fortsh audit
  status, and Sprint 30/Sprint 31 audit state.

The sprint index did not need a scope change; Sprint 31 remains the active
final-audit/default-swap gate.

## 10. Submodule Pin And Tag

Status: deferred.

Rationale:

- Do not publish `v0.1.0` until the default-swap decision is approved.
- Keep parent armfortas pinned to the latest afs-ld audit work as needed, but
  do not treat that pin as a release declaration.

Local note:

- A local `v0.1.0` tag may exist from the premature closeout attempt. It should
  be deleted or moved before any tag push.

## 11. Default-Swap Removal

Status: deferred.

Decision:

- Keep Apple `ld` as the parent armfortas default.
- Keep afs-ld available through `AFS_LD=1` and `AFS_LD_PATH=<path>`.
- Keep `AFS_LD=0` covered as the explicit Apple `ld` path.
- Revisit default swap after the remaining Apple-parity gaps are resolved or
  explicitly accepted.

Command:

```text
cargo test --test standalone_toolchain -- --nocapture
```

Result:

```text
running 7 tests
test hello_world_keeps_apple_ld_path_with_afs_ld_zero ... ok
test result: ok. 7 passed; 0 failed
```

Current blocker status:

- The known shared-library override blocker has been removed and covered by
  `tests/standalone_toolchain.rs`.
- The default flip is intentionally deferred because afs-ld is not yet accepted
  as Apple `ld` parity-equivalent for the full parent-driver surface.
