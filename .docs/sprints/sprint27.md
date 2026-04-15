# Sprint 27: Differential Harness vs Apple ld

## Prerequisites
All prior sprints, especially 18, 18.5, 21 — end-to-end milestones.

## Goals
Industrial-strength parity harness. Automated byte-level comparison of afs-ld output against `ld` across a curated corpus. Explicit tolerance lists, regression-gated CI. This is the Sprint 20 default-swap gate: afs-ld becomes the armfortas default only after this sprint's corpus is green.

## Deliverables

### 1. Corpus

`tests/parity_corpus/` contains 50+ link scenarios, each a small test directory with:
- `inputs/` (the `.o`, `.a`, `.tbd` files).
- `args.txt` (the afs-ld / `ld` command-line).
- `notes.md` (what this exercises).

Scenarios cover:
- Hello-world variants (classic vs chained, with/without `-dead_strip`, with/without `-icf`).
- Every relocation type in isolation.
- GOT and stub exercises.
- TLV exercises.
- Weak-def coalescing.
- Common-symbol promotion.
- Multi-archive resolution with order dependence.
- Dylib-with-reexport chain.
- LSystem links with real system SDK.
- `libarmfortas_rt.a` + a 3-function Fortran program.

### 2. Diff dimensions

For each scenario, compare:
- Load commands: count, order, contents (with tolerated-diff for UUID/timestamp).
- Segment sizes and file offsets.
- Section bytes (byte-level equality after reloc application).
- Symbol table: same nlist entries in the same partition order.
- String table: same content (byte-level is ideal, length within 5% is tolerated for suffix-dedup variation).
- `LC_DYLD_INFO_ONLY` opcode streams (classic) or `LC_DYLD_CHAINED_FIXUPS` chains (chained).
- Export trie walk equivalence (may differ in byte layout but must export the same names with the same flags and addresses).
- `__unwind_info` byte-level.
- Code signature: ignored in diff (ld signs with sha256 hashes over its output's bytes; we sign over ours; different bytes, different hashes — expected).

### 3. Tolerated-diff rules

```rust
pub enum ToleratedDiff {
    UuidBytes,
    Timestamp,
    PathHashInString(&'static str),      // e.g. temp path in stabs
    StringTableSuffixDedupVariance,
    CodeSignatureHashes,
}
```

Each tolerance has a precise predicate — no loose "any byte in __LINKEDIT". Unknown diffs fail.

### 4. Harness structure

`afs-ld/tests/parity_matrix.rs` walks `tests/parity_corpus/` and runs each scenario:

```rust
#[test]
fn parity_corpus() {
    for case in load_corpus("tests/parity_corpus/") {
        let ours = link_with_afs_ld(&case).unwrap();
        let theirs = link_with_system_ld(&case).unwrap();
        let diffs = diff_macho(&ours, &theirs);
        let critical: Vec<_> = diffs.into_iter().filter(|d| !is_tolerated(d)).collect();
        assert!(critical.is_empty(),
            "{}: {} critical diff(s):\n{:#?}", case.name, critical.len(), critical);
    }
}
```

### 5. CI gating

GitHub Actions job runs on every PR:
- `cargo test --test parity_matrix` green.
- Artifact uploaded: per-scenario HTML diff viewer for debugging.
- A failing scenario blocks merge.

### 6. Per-scenario allowed-diff annotation

Some scenarios might have legitimate small differences we don't want to suppress globally. Each scenario's `notes.md` can declare case-specific tolerances:

```yaml
tolerated:
  - region: __LINKEDIT  bytes 0x1000-0x1010  reason: "ld emits padding here"
```

Use sparingly; each tolerance must be justified and date-stamped.

### 7. Runtime parity

Beyond byte-level: each scenario that produces a runnable executable is also executed; stdout, stderr, and exit code must match between the two linked binaries.

### 8. Parity budget

The goal is **zero** critical diffs across the corpus. Sprint 27 is not done until the harness is fully green; if a diff can't be resolved within the sprint, it must be filed as a bug blocking default-swap in Sprint 20.

## Testing Strategy

- `cargo test --test parity_matrix` green.
- Intentional-regression: mutate one byte in afs-ld's writer, confirm the harness catches it.
- Scale test: full corpus runs in <2 minutes on a reasonable machine (gates Sprint 28 perf work).

## Definition of Done

- 50+ corpus scenarios all pass with zero critical diffs.
- CI-enforced.
- Every tolerated-diff category has a justification and a test that proves it triggers.
- Intentional-regression canary detects any change outside the allowlist.
- Sprint 20's default-swap is unblocked.
