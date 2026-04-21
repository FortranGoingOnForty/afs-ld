Unexport-filter dylib parity case lifted from the existing `linker_run`
coverage. This keeps the Sprint 27 corpus honest about `-unexported_symbol`
and `-unexported_symbols_list` matching Apple `ld` in both the export trie and
the final symtab surface.
