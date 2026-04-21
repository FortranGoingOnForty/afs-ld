Shared-prefix dylib export parity case lifted from the existing `linker_run`
export matrix. This gives the Sprint 27 corpus a real export-trie fanout shape
where multiple exported symbols share a common prefix but diverge later,
without relying on export filtering to create the prefix structure.
