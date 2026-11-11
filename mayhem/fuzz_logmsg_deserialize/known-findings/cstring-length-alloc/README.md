# cstring-length-alloc

`input` is a `fuzz_logmsg_deserialize` input: an 11-byte serialized **v1x** message (version `0x0b`, flags, pri) whose
first string, the source, claims a length of `0x94000000` (~2.5 GB) and then ends.

Reproduce: `/mayhem/fuzz_logmsg_deserialize mayhem/fuzz_logmsg_deserialize/known-findings/cstring-length-alloc/input`
(the libFuzzer binary reports it; the standalone binary only attempts the allocation and exits normally).

Result: `libFuzzer: out-of-memory (malloc(2483027969))` from `serialize_read_cstring` (`lib/serialize.h:269`), called by
`_deserialize_message_version_1x` (and, for later strings, `log_msg_read_common_values`, `logmsg-serialize.c:250`) via
`log_msg_deserialize`. This is the v1x (`version < 20`) path; the v2x tag-name path is the separate `tag-length-alloc`.

Not a crash: `serialize_read_cstring` allocates with `g_try_malloc(len + 1)` and returns `FALSE` when that fails, and
`len == G_MAXUINT32` wraps to `malloc(0)`, which also ends in `FALSE`. The report comes from libFuzzer's 2 GB
`-malloc_limit_mb` check, which fires before the allocator is asked. Without the limit, the allocation either fails
cleanly or succeeds lazily and the following `serialize_archive_read_bytes` fails on the short input.

Assessment: an OOM-class artifact, not memory corruption. The remaining issue is a missing sanity bound: the 32-bit
length is trusted without comparing it with the bytes left in the archive, so a corrupted disk-buffer file can request
gigabytes transiently. Hardening, low severity. Present upstream; not fixed here.
