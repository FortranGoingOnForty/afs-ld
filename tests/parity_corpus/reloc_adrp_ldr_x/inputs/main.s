        .section __TEXT,__text,regular,pure_instructions
        .globl _main
        _main:
            adrp x0, _target@PAGE
            ldr x1, [x0, _target@PAGEOFF]
            ret
        .space 0x3f4
        _target:
            .quad 0x1122334455667788
        .subsections_via_symbols
