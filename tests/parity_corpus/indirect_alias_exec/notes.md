Indirect-symbol parity case. The entry point calls a public alias chain whose
leaf is defined in the same object, while a private alias exercises symbol-table
visibility. Symbol records, export records, partitions, text, and runtime are
compared with Apple `ld`.
Apple linker versions disagree on the `N_ALT_ENTRY` descriptor bit for
indirect aliases, so this case compares all other symbol-record fields exactly.
