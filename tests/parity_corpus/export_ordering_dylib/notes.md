Export-ordering dylib parity case lifted from the existing `linker_run`
export matrix. This gives the Sprint 27 corpus a direct check that export trie
and final symtab ordering semantics stay in Apple-parity agreement even when
symbols are declared out of lexical order.
