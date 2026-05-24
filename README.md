# afs-ld

**Bespoke ARM64 Mach-O linker for Apple Silicon. Rust stdlib only.**

Sister project to [afs-as](https://github.com/FortranGoingOnForty/afs-as) (the assembler) and [armfortas](https://github.com/FortranGoingOnForty/armfortas) (the compiler). Together they form a complete Fortran-to-executable toolchain with zero dependencies on LLVM or external compiler infrastructure.

## Status

Sprint 31 final-gate work. `afs-ld` now emits runnable arm64 `MH_EXECUTE`
and `MH_DYLIB` outputs, links the armfortas runtime corpus, and has a
56-case Apple `ld` parity matrix. The parent armfortas driver uses afs-ld by
default, with `AFS_LD=0` retained as the one-sprint Apple `ld` fallback and
`AFS_LD_PATH=<path>` available for explicit linker builds.

## Build

```bash
cargo build -p afs-ld
cargo test  -p afs-ld
cargo clippy -p afs-ld --all-targets -- -D warnings
```

Tests require macOS on Apple Silicon and a working Xcode command-line toolchain (`xcrun`).

Useful final-gate checks:

```bash
cargo test -p afs-ld --test parity_matrix parity_corpus -- --nocapture
cargo test -p afs-ld --test parity_determinism -- --nocapture
cargo test -p afs-ld --test spec_conformance -- --nocapture
cargo test -p afs-ld --test binary_size_audit -- --nocapture
AFS_LD_HELLO_BUDGET_MS=25 AFS_LD_RUNTIME_BUDGET_MS=150 \
  cargo test -p afs-ld --test perf_baseline -- --nocapture
```

## Design

- Reads `.o` (MH_OBJECT) Mach-O produced by `afs-as`, static archives (`.a`), binary dylibs, and TAPI TBD text stubs.
- Emits `MH_EXECUTE` or `MH_DYLIB` PIE Mach-O files.
- Ad-hoc code signing so binaries run directly on macOS 11+ arm64 hardware.
- Supports both classic `LC_DYLD_INFO` opcodes and modern `LC_DYLD_CHAINED_FIXUPS`.

See `.docs/overview.md` for full architecture and `.docs/sprints/index.md` for the development roadmap.

## Non-goals

- ELF / COFF / PE — Mach-O only.
- Architectures other than arm64.
- LTO / bitcode.

## License

GPL-3.0-only.
