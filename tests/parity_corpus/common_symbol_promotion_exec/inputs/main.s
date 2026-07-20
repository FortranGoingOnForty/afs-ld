.text
.globl _main
.p2align 2
_main:
    adrp x0, _shared@PAGE
    add x0, x0, _shared@PAGEOFF
    adrp x1, _shared@PAGE
    ldr w0, [x1, _shared@PAGEOFF]
    ret
