# zero-index-vla

`input` is a `fuzz_logmsg_deserialize` input: a serialized v2x message whose NV table has `index_size == 0`
(no dynamic values).

Reproduce: `/mayhem/fuzz_logmsg_deserialize-standalone mayhem/fuzz_logmsg_deserialize/known-findings/zero-index-vla/input`

Result: UBSan `lib/logmsg/logmsg-serialize-fixup.c:328: variable length array bound evaluates to non-positive
value 0`. `log_msg_fixup_handles_after_deserialization` declares `NVIndexEntry _updated_index[nvtable->index_size]`;
a zero-length VLA is undefined behaviour in C.

Triage: low severity. Undefined behaviour in the language sense (compilers allocate nothing and the later
`memset`/copy are zero-length), but it is a defect UBSan reports on any table with an empty index. Present
upstream; not fixed here.
