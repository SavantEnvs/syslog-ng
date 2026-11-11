# static-entry-null-deref

`input` is a `fuzz_logmsg_deserialize` input: a serialized v2x message holding an indirect (referenced) value
entry whose reference handle is 0 or names an unset static slot.

Reproduce: `/mayhem/fuzz_logmsg_deserialize-standalone mayhem/fuzz_logmsg_deserialize/known-findings/static-entry-null-deref/input`

Result: ASan SEGV on address 0x1 in `_is_static_entry` (`lib/logmsg/logmsg-serialize-fixup.c:179`), reached
through `_allocate_handle_for_entry_name` (line 198), `_allocate_handle_of_referenced_entry` (line 212) and
`_fixup_handle_in_indirect_entry` (line 224). `nv_table_get_entry()` returns NULL for such a handle and
`_is_static_entry(NULL)` reads `entry->name_len` (offset 1). `_validate_entry` checks the indirect entry's own
bounds but never that the handle it references exists.

Triage: reachable by deserializing a corrupted or crafted disk-buffer file, not from the network. Present upstream;
not fixed here.
