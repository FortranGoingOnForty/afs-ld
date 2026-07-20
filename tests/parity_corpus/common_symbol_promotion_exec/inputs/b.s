.comm _shared,32,3

.data
.globl _overridden
.p2align 3
_overridden:
    .quad 0x1122334455667788
