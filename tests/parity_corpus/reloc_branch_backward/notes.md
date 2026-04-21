Backward branch relocation parity case lifted from the existing
`relocated_sections_match_apple_ld_across_fixture_matrix` coverage. This keeps
the shared Sprint 27 corpus growing on the relocation side with a simple exact
`__TEXT,__text` byte-parity check after reloc application.
