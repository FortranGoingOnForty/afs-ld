# afs-ld Sprint Index

32 sprints across 10 phases. Small bites, clear milestones, testable deliverables at every stage. Each sprint is independently reviewable and mergeable; every sprint that lands new surface area also lands corpus fixtures and differential coverage.

## Phase 0 — Scaffolding
- [Sprint 0](sprint00.md) — Scaffolding, References, Harness

## Phase 1 — Mach-O Reading
- [Sprint 1](sprint01.md) — MH_OBJECT Header & Load Commands
- [Sprint 2](sprint02.md) — Sections, Symbols, String Tables
- [Sprint 3](sprint03.md) — Relocations (Read-Side)

## Phase 2 — Archives & Dylibs
- [Sprint 4](sprint04.md) — Static Archives (ar)
- [Sprint 5](sprint05.md) — Dylibs (MH_DYLIB binary)
- [Sprint 6](sprint06.md) — TAPI TBD Text Stubs

## Phase 3 — Symbol Resolution
- [Sprint 7](sprint07.md) — Symbol Model & Table
- [Sprint 8](sprint08.md) — Name Resolution Pass
- [Sprint 9](sprint09.md) — Subsections-via-Symbols Atomization

## Phase 4 — Output Construction (MH_EXECUTE and MH_DYLIB both first-class)
- [Sprint 10](sprint10.md) — Output Segment & Section Layout (dylib-aware)
- [Sprint 11](sprint11.md) — Core Relocation Application (ARM64)
- [Sprint 12](sprint12.md) — GOT, Stubs, Lazy Pointers
- [Sprint 13](sprint13.md) — TLV Relocations
- [Sprint 14](sprint14.md) — LC_SYMTAB / LC_DYSYMTAB / String Table

## Phase 5 — Dynamic Linker Metadata
- [Sprint 15](sprint15.md) — Classic LC_DYLD_INFO Opcodes
- [Sprint 15.5](sprint15_5.md) — Chained Fixups (LC_DYLD_CHAINED_FIXUPS)
- [Sprint 16](sprint16.md) — LC_FUNCTION_STARTS & LC_DATA_IN_CODE
- [Sprint 17](sprint17.md) — Unwind Info

## Phase 6 — First End-to-End
- [Sprint 18](sprint18.md) — HELLO WORLD MILESTONE (Executable)
- [Sprint 18.5](sprint18_5.md) — HELLO LIBRARY MILESTONE (Dylib)

## Phase 7 — CLI & Driver Integration
- [Sprint 19](sprint19.md) — CLI Surface + Diagnostics (-map, -why_live)
- [Sprint 20](sprint20.md) — Driver Swap

## Phase 8 — Runtime Compatibility
- [Sprint 21](sprint21.md) — Runtime Archive Linking
- [Sprint 22](sprint22.md) — Code Signature (Ad-Hoc)

## Phase 9 — Advanced Features
- [Sprint 23](sprint23.md) — Dead Strip (`-dead_strip`)
- [Sprint 24](sprint24.md) — ICF (`-icf=safe`)
- [Sprint 25](sprint25.md) — LOH Relaxation
- [Sprint 26](sprint26.md) — Thunks for Out-of-Range Branches

## Phase 10 — Production Hardening
- [Sprint 27](sprint27.md) — Differential Harness vs Apple ld
- [Sprint 28](sprint28.md) — Performance & Parallelism
- [Sprint 29](sprint29.md) — fortsh Link Audit
- [Sprint 30](sprint30.md) — Diagnostics & Polish
- [Sprint 31](sprint31.md) — Final Audit
