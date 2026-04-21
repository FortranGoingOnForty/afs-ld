Export-filter dylib parity case lifted from the existing `linker_run` coverage.
This extends the Sprint 27 corpus to handle sidecar list files and verifies
that exported-symbol filtering matches Apple `ld` in both the export trie and
the final symtab surface.
