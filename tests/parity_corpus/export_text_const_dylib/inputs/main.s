        .section __TEXT,__text,regular,pure_instructions
        .globl _entry
        _entry:
            ret
        .section __TEXT,__const
        .p2align 3
        .globl _ro_value
        _ro_value:
            .quad 0xfeedface
        .subsections_via_symbols
