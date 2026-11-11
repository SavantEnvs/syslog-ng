# entry-offset-misaligned

`input` is a `fuzz_logmsg_deserialize` input: a serialized v2x message whose index/static-entry offsets are not
4-byte aligned.

Reproduce: `/mayhem/fuzz_logmsg_deserialize-standalone mayhem/fuzz_logmsg_deserialize/known-findings/entry-offset-misaligned/input`

Result: UBSan `lib/logmsg/nvtable-serialize.c:83: member access within misaligned address ... for type 'NVEntry',
which requires 4 byte alignment` in `_validate_entry_offset`. The function bounds-checks the offset
(`NV_ENTRY_DIRECT_HDR <= ofs <= used`) but not its alignment, then reads `entry->flags` through an `NVEntry *`.
Most of the Mayhem defects on this target (several inputs, same frame) are this one.

Triage: harmless on x86 (unaligned loads work) but undefined behaviour, and it means the validator rejects
nothing about alignment. Reachable by deserializing a crafted disk-buffer file. Present upstream; not fixed here.
