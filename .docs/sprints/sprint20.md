# Sprint 20: Driver Swap

## Prerequisites
Sprints 18–19 — hello-world works, CLI complete.

## Goals
Wire afs-ld into the armfortas driver. Initially gated behind `AFS_LD=1`. After the Sprint 27 parity gate, flip the default. Keep a fallback to system `ld` for at least one sprint after default-on.

## Deliverables

### 1. Driver change site
`armfortas/src/driver/mod.rs`:

Two call sites ship today:
- Single-file link path at lines 497–530.
- Multi-file link path at lines 533–565.

Both build a `Command::new("ld")`. Refactor to:

```rust
fn linker_command() -> (Command, &'static str) {
    match env::var("AFS_LD").as_deref() {
        Ok("1") | Ok("true") => (Command::new(find_afs_ld()), "afs-ld"),
        _                    => (Command::new("ld"),        "system ld"),
    }
}
```

`find_afs_ld()`:
1. `AFS_LD_PATH` env var (full path to the binary).
2. `<workspace>/target/debug/afs-ld`.
3. `<workspace>/target/release/afs-ld`.
4. `PATH` lookup.

Failure produces a clear diagnostic pointing to the env var and build commands.

### 2. Testing harness update
`armfortas/src/testing.rs:871-908` (used by integration tests) — same refactor. Integration tests respect `AFS_LD=1`.

### 3. Flag pass-through parity
The driver today builds a fixed command. After this sprint it still builds the same command — afs-ld accepts the same flags. Differential in practice:

```
# System ld
ld hello.o libarmfortas_rt.a -lSystem -no_uuid -syslibroot <SDK> -e _main -o hello

# afs-ld (same args)
afs-ld hello.o libarmfortas_rt.a -lSystem -no_uuid -syslibroot <SDK> -e _main -o hello
```

### 4. Fallback semantics
If afs-ld errors, produce a driver-level diagnostic that cites afs-ld's exit status and stderr, plus a hint to retry with `AFS_LD=0`. Do **not** automatically retry with system `ld` — silently falling back masks real bugs.

### 5. Test coverage on both paths
`cargo test --workspace` runs all integration tests twice: once with `AFS_LD=0` (baseline), once with `AFS_LD=1`. Divergence is a test failure. This is the CI gate for afs-ld adoption.

### 6. Preserving `-no_uuid` determinism
Driver passes `-no_uuid` today. Verify afs-ld honors it byte-identically: same inputs under same seed produce the same output (no process-id, no timestamp, no random padding).

### 7. Docs
Update `armfortas/CLAUDE.md` with a note about `AFS_LD=1` and how to enable/disable. `armfortas/README.md` if/when it mentions linking.

## Testing Strategy
- `tests/linker_swap.rs`: runs hello-world both ways, asserts the binaries differ only in tolerated regions.
- Integration suite under `AFS_LD=1`: every existing integration test must pass. This is the gate.
- Failure-path test: a deliberately-broken link (missing symbol); both paths produce an error, not a segfault.

## Definition of Done
- `AFS_LD=1 cargo test --workspace` passes every test green.
- Driver refactor lands on a branch that can be rolled back cleanly by flipping the env-var default.
- Diagnostic quality on afs-ld failures matches or exceeds system ld's.
- No silent fallback — afs-ld failures surface loudly.
