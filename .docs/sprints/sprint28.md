# Sprint 28: Performance & Parallelism

## Prerequisites
Sprint 27 — correctness gate in place; can freely refactor for speed.

## Goals
Make afs-ld fast enough to feel like a production tool. Sprint 28 establishes
the profiling surface, parallelizes the obvious hot paths, and enforces
hello/runtime-link budgets in CI. The fortsh 2× Apple `ld` gate remains the
production target, but Sprint 29 owns the fortsh fixture and final comparison.
Mold demonstrates linkers can be very fast; we don't need mold's speed, but we
need to not be painful.

## Deliverables

### 1. Baseline profile

Profile representative hello-world and runtime-archive links in Sprint 28.
Sprint 29 extends the same profile surface to the fortsh link once the fixture
exists. Categorize wall time:

- Input parsing (Mach-O headers, sections, symbols, relocations).
- Symbol resolution (hash-map probes, archive lookups).
- Atomization.
- Layout.
- Reloc application.
- Synth sections (`__unwind_info` is often a hotspot).
- Writing output.
- Code signature hashing.

Identify the biggest bucket; optimize there first.

### 2. Parallel input parsing

Parse each `.o` in a separate worker thread; results collected into the symbol table after all parsing completes. Archive member parsing also parallel. Uses std's `thread::scope` — no external crates. Parallelism bounded by `std::thread::available_parallelism()`.

### 3. Parallel reloc application

Each atom's relocs are independent. Process per-atom in parallel; the output buffer is preallocated and each atom writes to a disjoint slice.

### 4. Parallel SHA-256 for code signing

One thread per 4 KiB page. SHA-256 is inherently sequential within a page but trivially parallel across pages. Drop-in speedup for large binaries.

### 5. Bump allocator for ephemeral data

Deferred. The current Sprint 28 profile work did not prove allocation churn is
the next limiting bucket after the parallel parsing/relocation/signature and
string-table clone fixes. If Sprint 29's fortsh profile shows parser allocation
pressure, implement `src/arena.rs` as a std-only `Vec<Box<[u8]>>` chunker.

### 6. mmap for large inputs

Deferred. Object/archive loading still uses `fs::read`; this keeps the Sprint 28
closeout safe and std-only. If fortsh-sized inputs show file-read overhead as a
real bucket in Sprint 29, add an unsafe `src/mmap.rs` wrapper and keep a
`fs::read` fallback for archive members whose external path cannot be mapped.

### 7. Symbol-table hash map

Profile shows std `HashMap` is fine for our scale. If not: replace with an open-addressing table keyed by `Istr` (handle-equality), linear probing, power-of-2 capacity. ~100 LoC.

### 8. String interner

Deferred. Sprint 28 made the global string table thread-shareable and removed
the cloned string-table offset map during output writing. Per-input local
interners remain a candidate if Sprint 29 identifies symbol seeding as a
fortsh-scale bottleneck.

### 9. No-alloc hot paths

Reloc application and chain construction should not allocate per-reloc. Preallocated scratch buffers, reused across the relocation pass.

### 10. Benchmarks

Sprint 28 uses CI-enforced integration benchmarks in `tests/perf_baseline.rs`:

- `bench_hello_world_profile_reports_baseline_timings`: small, measures startup overhead.
- `bench_runtime_link_profile_reports_baseline_timings`: mid, measures symbol-table, archive parsing, and reloc-apply.
- `bench_fortsh_link`: deferred to Sprint 29 with the real fortsh fixture.

Budget targets:
- hello-world: ≤ 20 ms.
- runtime link: ≤ 150 ms.
- fortsh link: ≤ 2× Apple `ld`'s wall time on the same machine, enforced in Sprint 29.

### 11. Determinism preserved

Parallelism must not reorder output. Each worker produces a deterministic result; join order is fixed; sorts are stable. A parallel and sequential run must produce byte-identical outputs.

## Testing Strategy

- Benchmark gate: CI runs `tests/perf_baseline.rs` with hello/runtime budgets on every push and PR.
- Nightly throughput recording and a relative >10% regression gate are deferred until the fortsh fixture lands in Sprint 29.
- Determinism: 100 parallel runs of the same input, assert byte-identical output every time.
- Sprint 27 parity must remain green — no correctness regression.
- Single-threaded fallback (`-j 1`) for debugging.

## Definition of Done

- hello/runtime performance budgets are enforced in CI.
- fortsh 2× comparison is explicitly handed to Sprint 29 with its fixture.
- All Sprint 27 scenarios still byte-identical.
- Determinism bulletproof across parallelism.
- No external dependencies added.
