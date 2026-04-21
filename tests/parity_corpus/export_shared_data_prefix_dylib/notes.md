Shared-prefix data-only dylib export parity case lifted from the existing
`linker_run` export matrix. This closes the remaining obvious export-matrix gap
by checking Apple parity when all exported symbols live in `__DATA,__data` and
share a long common prefix.
