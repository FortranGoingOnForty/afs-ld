        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@PAGE
            ldrb w1, [x0, _target@PAGEOFF]
            ret
        .space 0xf4
        _target:
            .byte 0x44
        .subsections_via_symbols
