.section __TEXT,__text,regular,pure_instructions
.globl _main
.globl _value
_main:
Lloh0:
    adrp x8, _value@GOTPAGE
Lloh1:
    ldr x8, [x8, _value@GOTPAGEOFF]
Lloh2:
    ldr w0, [x8]
    ret

.section __DATA,__data
.p2align 2
_value:
    .long 7
.loh AdrpLdrGotLdr Lloh0, Lloh1, Lloh2
.subsections_via_symbols
