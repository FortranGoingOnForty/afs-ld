        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _write@GOTPAGE
            ldr x0, [x0, _write@GOTPAGEOFF]
            bl _write
            bl _write
            adrp x1, _write@GOTPAGE
            ldr x1, [x1, _write@GOTPAGEOFF]
            ret
        .subsections_via_symbols
