# Sprint 28: Performance & Parallelism

## Prerequisites
Sprint 27 — correctness gate in place; can freely refactor for speed.

## Goals
Make afs-ld fast enough to feel like a production tool. Target: within 2× of Apple `ld`'s wall time on the fortsh link. Mold demonstrates linkers can be very fast; we don't need mold's speed, but we need to not be painful.

## Deliverables

### 1. Baseline profile

Profile the fortsh link (Sprint 29 produces the fixture). Categorize wall time:

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

Parser produces many small allocations (strings, reloc lists, atom descriptors). A per-input arena avoids fragmentation and makes bulk drop free. Implement as `src/arena.rs` — a std-only `Vec<Box<[u8]>>` chunker.

### 6. mmap for large inputs

`std::fs::File` + `memmap2`? No — memmap2 is an external crate. Use `libc::mmap` via an unsafe `src/mmap.rs` wrapper. Input files are always read-only; mmap saves a read syscall and lets us share parse state across threads cheaply. Fall back to `fs::read` for GNU-thin archive members whose external path doesn't mmap cleanly (rare).

### 7. Symbol-table hash map

Profile shows std `HashMap` is fine for our scale. If not: replace with an open-addressing table keyed by `Istr` (handle-equality), linear probing, power-of-2 capacity. ~100 LoC.

### 8. String interner

Single global `StringInterner` shared across inputs. Interning cost: one hash lookup per name. Optimize by batching per-input: each input parses its strings into a local table, then merges into the global interner in one pass.

### 9. No-alloc hot paths

Reloc application and chain construction should not allocate per-reloc. Preallocated scratch buffers, reused across the relocation pass.

### 10. Benchmarks

`afs-ld/bench/` (or a `#[bench]` behind `cargo +nightly bench`) with:
- `bench_hello_world`: small, measures startup overhead.
- `bench_runtime_link`: mid, measures symbol-table & reloc-apply.
- `bench_fortsh_link`: large, measures end-to-end throughput.

Budget targets:
- hello-world: ≤ 20 ms.
- runtime link: ≤ 150 ms.
- fortsh link: ≤ 2× Apple `ld`'s wall time on the same machine.

### 11. Determinism preserved

Parallelism must not reorder output. Each worker produces a deterministic result; join order is fixed; sorts are stable. A parallel and sequential run must produce byte-identical outputs.

## Testing Strategy

- Benchmarks land as regression gates: nightly CI records throughput; > 10% regression fails.
- Determinism: 100 parallel runs of the same input, assert byte-identical output every time.
- Sprint 27 parity must remain green — no correctness regression.
- Single-threaded fallback (`-j 1`) for debugging.

## Definition of Done

- fortsh link wall time within 2× of `ld`'s.
- All Sprint 27 scenarios still byte-identical.
- Determinism bulletproof across parallelism.
- No external dependencies added.
