.section __TEXT,__text,regular,pure_instructions
.globl _main
_main:
    adrp x8, _value@GOTPAGE
    ldr x8, [x8, _value@GOTPAGEOFF]
    ldr w0, [x8]
    ret

.private_extern _value
.section __DATA,__data
.p2align 2
_value:
    .long 7
.subsections_via_symbols
