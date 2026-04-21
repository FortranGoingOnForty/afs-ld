.text
.private_extern _hidden
.globl _visible
.globl _main
.p2align 2
_local:
    ret
_hidden:
    ret
_visible:
    ret
_main:
    ret

.data
.quad _ext_data
.subsections_via_symbols
