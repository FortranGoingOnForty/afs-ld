Minimal runtime parity case for a three-function Fortran program. The input
object is compiled with `armfortas`, and the sidecar `libarmfortas_rt.a` is a
real archive copied from the runtime build so this scenario stays standalone
inside the `afs-ld` repo.
