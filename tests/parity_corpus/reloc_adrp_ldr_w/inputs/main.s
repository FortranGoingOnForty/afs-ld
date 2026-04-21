        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@PAGE
            ldr w1, [x0, _target@PAGEOFF]
            ret
        .space 0x2f4
        _target:
            .long 0x11223344
        .subsections_via_symbols
