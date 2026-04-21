.section __TEXT,__text,regular,pure_instructions
.globl _main
_main:
    adrp x0, _write@GOTPAGE
    ldr x0, [x0, _write@GOTPAGEOFF]
    bl _write
    ret
.subsections_via_symbols
