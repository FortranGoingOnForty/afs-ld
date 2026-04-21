Dylib reexport-chain parity case. The executable links only the middle dylib,
which itself reexports a leaf dylib. The executable resolves a direct symbol
from the middle dylib while carrying the same dependency-chain surface Apple
`ld` produces.
