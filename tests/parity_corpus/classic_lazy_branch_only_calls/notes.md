Classic lazy-binding branch-only parity case lifted from the existing
`linker_run` matrix. This rounds out the Sprint 27 classic-lazy corpus by
covering pure branch-driven imports without explicit GOT loads, while keeping
the Apple-parity dyld-info and stub-surface checks in the dedicated harness.
