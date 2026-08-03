# afs-ld

**Bespoke ARM64 Mach-O and x86_64 ELF linker. Rust stdlib only.**

Sister project to [afs-as](https://github.com/FortranGoingOnForty/afs-as) (the assembler) and [armfortas](https://github.com/FortranGoingOnForty/armfortas) (the compiler). It provides the standalone final-link component of the toolchain without depending on LLVM or external compiler infrastructure.

## Status

`afs-ld` has two working final-link pipelines:

- ARM64 Mach-O: reads objects, archives, dylibs, and TAPI TBD stubs; resolves and lays out atoms; applies relocations; synthesizes dyld, unwind, and symbol metadata; and atomically emits ad-hoc-signed `MH_EXECUTE` or `MH_DYLIB` images.
- x86_64 ELF: reads relocatable objects, archives, linker scripts, and shared objects, then emits static or dynamically linked non-PIE `ET_EXEC` images. The ELF path supports ordered archive selection, garbage collection, GOT/PLT, TLS, IFUNC/IPLT, init arrays, unwind headers, and symbol versioning.

The supported surface is intentionally narrower than a drop-in replacement for every Apple or GNU linker mode. Unsupported targets, output kinds, and flags fail with diagnostics instead of producing placeholder output.

## Build

```bash
cargo build -p afs-ld
cargo test  -p afs-ld
cargo clippy -p afs-ld --all-targets -- -D warnings
```

The full Mach-O differential and runtime suite requires macOS on Apple Silicon with the Xcode command-line tools (`xcrun`). ELF end-to-end tests run on supported x86_64 Linux and FreeBSD hosts; host-specific tests report an explicit skip when their native toolchain is unavailable.

## Design

- Reads `.o` (MH_OBJECT) Mach-O produced by `afs-as`, static archives (`.a`), binary dylibs, and TAPI TBD text stubs.
- Emits `MH_EXECUTE` or `MH_DYLIB` PIE Mach-O files.
- Ad-hoc code signing so binaries run directly on macOS 11+ arm64 hardware.
- Emits classic `LC_DYLD_INFO_ONLY` rebase, bind, lazy-bind, weak-bind, and
  export metadata. `-no_fixup_chains` explicitly selects this supported mode;
  `-fixup_chains` is recognized for compatibility but rejected because the
  writer does not yet produce `LC_DYLD_CHAINED_FIXUPS`.
- Reads x86_64 ELF `ET_REL`, archives, linker scripts, and `ET_DYN` dependencies; emits static and dynamically linked `ET_EXEC` files.
- Publishes completed outputs atomically and keeps output ordering deterministic across supported worker counts.

See `.docs/overview.md` for full architecture and `.docs/sprints/index.md` for the development roadmap.

## Non-goals

- COFF / PE.
- Mach-O architectures other than arm64 and ELF architectures other than x86_64.
- ELF PIE and shared-object output.
- LTO / bitcode.

## License

GPL-3.0-only.
