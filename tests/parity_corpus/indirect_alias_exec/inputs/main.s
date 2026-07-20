.text
.p2align 2
.globl _main
_main:
    bl _alias_chain
    ret

.globl _target
_target:
    mov w0, #0
    ret

.globl _alias
_alias = _target

.globl _alias_chain
_alias_chain = _alias

.private_extern _hidden_alias
_hidden_alias = _target

.subsections_via_symbols
