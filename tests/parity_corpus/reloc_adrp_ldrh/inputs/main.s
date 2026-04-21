        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@PAGE
            ldrh w1, [x0, _target@PAGEOFF]
            ret
        .space 0x1f4
        _target:
            .hword 0x3344
        .subsections_via_symbols
