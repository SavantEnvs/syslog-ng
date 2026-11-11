# name-not-terminated

`input` is a `fuzz_logmsg_deserialize` input: a serialized v2x message whose NV table holds a dynamic entry
whose name is not NUL-terminated inside the table.

Reproduce: `/mayhem/fuzz_logmsg_deserialize-standalone mayhem/fuzz_logmsg_deserialize/known-findings/name-not-terminated/input`

Result: ASan heap-buffer-overflow READ of 33 bytes in `strlen`, called by `nv_registry_alloc_handle`
(`lib/logmsg/nvtable.c:62`) from `log_msg_get_value_handle` (`logmsg.c:425`) in `_fixup_entry`
(`logmsg-serialize-fixup.c:305`). The fixup passes `nv_entry_get_name(entry)` to a function that treats it as a
C string, but `_validate_entry` only checks that `alloc_len` covers `name_len + 1` bytes, never that a NUL actually follows the name.

Triage: reachable by deserializing a corrupted or crafted disk-buffer / reliable-queue file, not from the
network. Present upstream; not fixed here.
