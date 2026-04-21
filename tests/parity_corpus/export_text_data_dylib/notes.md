Mixed text-plus-data dylib export parity case lifted from the existing
`linker_run` export matrix. This broadens the Sprint 27 corpus beyond
text-only dylibs and checks that both the export trie and final symtab stay in
Apple-parity agreement when exported symbols live in different sections.
