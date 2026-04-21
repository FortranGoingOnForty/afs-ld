Forward branch relocation parity case lifted from the existing
`relocated_sections_match_apple_ld_across_fixture_matrix` coverage. This is the
first explicit relocation-matrix migration into the Sprint 27 corpus and keeps
the check intentionally simple: exact `__TEXT,__text` byte parity after reloc
application.
