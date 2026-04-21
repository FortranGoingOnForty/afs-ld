        .section __TEXT,__text,regular,pure_instructions
        .globl _code_symbol
        _code_symbol:
            ret
        .section __DATA,__data
        .p2align 3
        .globl _data_symbol
        _data_symbol:
            .quad 0x1234
        .globl _more_data
        _more_data:
            .long 7
        .subsections_via_symbols
