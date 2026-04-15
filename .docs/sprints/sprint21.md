# Sprint 21: Runtime Archive Linking

## Prerequisites
Sprints 4, 8, 20 — archives, resolution, driver swap.

## Goals
Link `libarmfortas_rt.a` end-to-end into every armfortas-produced binary. The full parent integration suite runs green under `AFS_LD=1`. This is the sprint that proves afs-ld can do real work on real armfortas output, not just staging fixtures.

## Deliverables

### 1. Runtime inventory
Walk `libarmfortas_rt.a` and catalog every exported symbol. Groups:

- Lifecycle: `_afs_program_init`, `_afs_program_finalize`.
- Array: `_afs_allocate_array`, `_afs_deallocate_array`, `_afs_check_bounds`, `_afs_fill_*`, `_afs_array_add_*`, `_afs_array_mul_*`, `_afs_transpose_*`, `_afs_matmul_*`.
- I/O: `_afs_write_*`, `_afs_read_*`, `_afs_open_file`, `_afs_close_file`, `_afs_flush`, formatted/unformatted/list-directed helpers.
- String: `_afs_string_*` (allocatable, deferred-length variants).
- Math intrinsics: `_afs_i128_*`, `_afs_cmplx_*`, etc.
- System: `_afs_stop`, `_afs_command_argument_*`, `_afs_get_environment`.

This inventory gets persisted as `tests/runtime_symbols.txt` so the test suite can assert no symbol silently disappears between runtime rebuilds.

### 2. Archive fetch verification
Verify Sprint 4's archive reader pulls members correctly:

- Parse `libarmfortas_rt.a`, walk its BSD symbol index.
- For each inventory symbol, look up the defining member.
- Cross-check: `nm` on each member file agrees.

### 3. End-to-end integration tests
Run the parent `armfortas/tests/` suite under `AFS_LD=1`:

- `tests/run_programs.rs`: full program tests (array, I/O, derived types, modules).
- `tests/multifile.rs`: multi-object link; module globals resolved correctly.
- `tests/i128_cross_object.rs`: 128-bit integer interop across C/Fortran boundary.
- `tests/fortsh_module_graph.rs`: complex USE chains.
- `tests/incremental.rs`: incremental module dependency tracking.

Every failure here is a real linker bug — triage and fix.

### 4. Known gotchas to verify
Based on afs-as + runtime history, pay particular attention to:

- **`_afs_program_init` lifecycle wrapping**: the driver-synthesized `_main` at `src/driver/mod.rs:371-392` calls `_afs_program_init` → user prog → `_afs_program_finalize`. All three must resolve.
- **I/O state machine in `libarmfortas_rt`**: references `_errno`, `_malloc`, `_free` from libSystem; `_afs_io_state` as a BSS symbol. Verify `__DATA,__bss` placement matches ld.
- **Common symbols**: some module globals come through as common; verify promotion to BSS (Sprint 7 matrix).
- **Weak refs** to optional runtime hooks (if any). Check that unresolved weak refs evaluate to 0 and the call-site null-check dispatches correctly.

### 5. Archive-ordering edge cases
Some programs pull symbols that create new undefined references in the middle of resolution. Fixed-point loop from Sprint 8 handles this; verify it holds for the runtime archive with its ~40 members.

### 6. Diagnostic polish
Every runtime symbol that fails to resolve must produce a diagnostic that:
- Names the missing symbol.
- Cites at least one referrer in user code.
- Hints at the rebuild path (`cargo build -p armfortas-rt`).

### 7. Regression corpus
Any test that once broke becomes a permanent corpus entry. The afs-ld `tests/runtime_*.rs` pattern mirrors armfortas's.

## Testing Strategy
- Full parent integration suite under `AFS_LD=1` (this is the primary deliverable).
- `tests/runtime_inventory.rs`: assert every symbol in `tests/runtime_symbols.txt` is still defined by the current `libarmfortas_rt.a`.
- Archive fetch coverage: every inventoried symbol pulls its member exactly once.

## Definition of Done
- `AFS_LD=1 cargo test -p armfortas` green.
- Runtime inventory stable and asserted.
- No silent skips; every test that was passing under `AFS_LD=0` passes under `AFS_LD=1`.
- Diagnostics on missing runtime symbols are actionable.
