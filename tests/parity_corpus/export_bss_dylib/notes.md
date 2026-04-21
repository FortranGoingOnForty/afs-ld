Exported-BSS dylib parity case lifted from the existing `linker_run` export
matrix. This broadens the Sprint 27 corpus into zerofill/export-trie behavior,
so the dedicated parity harness checks Apple agreement when an exported symbol
lives in `__DATA,__bss` instead of only text or initialized data.
