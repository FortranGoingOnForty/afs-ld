# Sprint 31 Final Audit

Date: 2026-05-23

Status: in progress.

Sprint 31 is the final gate before afs-ld can be treated as the permanent
armfortas default linker. This report records hard evidence, not intent. Any
unchecked section below is still open work.

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

Status: open.

Required checklist:

- Header and magic.
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

Status: open.

Required comparisons:

- hello-world.
- libarmfortas_rt-linked Fortran program.
- fortsh.

## 6. Performance Audit

Status: open.

Required comparisons:

- Sprint 28 benchmark rerun.
- fortsh link within 2x Apple `ld`.

## 7. Diagnostic Quality Audit

Status: passing as of Sprint 30 closeout.

Reference:

- `.docs/audits/sprint30_diagnostic_audit.md`

Remaining Sprint 31 action:

- Re-review diagnostics during final full-suite runs and fix any new low-quality
  message found by the broader audit.

## 8. Dead Code And Panic Sweep

Status: open.

Required checks:

- Review `.unwrap()` / `.expect()` usage.
- Review `panic!`, `todo!`, and `unimplemented!`.
- Remove or document dead code.

## 9. Documentation Refresh

Status: open.

Required files:

- `CLAUDE.md`
- `README.md`
- `.docs/overview.md`
- sprint index if scope changed.

## 10. Submodule Pin And Tag

Status: open.

Required actions:

- Pin parent armfortas to the final afs-ld commit.
- Tag afs-ld `v0.1.0`.

## 11. Default-Swap Removal

Status: open.

Required action:

- Make afs-ld the armfortas default linker with the documented one-sprint
  `AFS_LD=0` fallback.

Current blocker status:

- The known shared-library override blocker has been removed and covered by
  `tests/standalone_toolchain.rs`.
- The default flip itself is still intentionally open until the remaining
  Sprint 31 audit sections pass.
