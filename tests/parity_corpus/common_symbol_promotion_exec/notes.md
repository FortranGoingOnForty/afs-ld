Common-symbol promotion parity case. Two objects contribute the same `.comm`
symbol, and the linked executable should promote that storage into the final
image and record it the same way Apple `ld` does.
