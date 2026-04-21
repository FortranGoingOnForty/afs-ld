Multi-archive resolution parity case. `main` pulls `top` from the first archive,
and that object in turn requires `mid` from the second archive, so archive
fetch order must match Apple `ld`.
