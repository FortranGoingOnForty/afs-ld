        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _write@GOTPAGE
            ldr x0, [x0, _write@GOTPAGEOFF]
            bl _write
            adrp x1, _close@GOTPAGE
            ldr x1, [x1, _close@GOTPAGEOFF]
            bl _close
            adrp x2, _read@GOTPAGE
            ldr x2, [x2, _read@GOTPAGEOFF]
            bl _read
            ret
        .subsections_via_symbols
