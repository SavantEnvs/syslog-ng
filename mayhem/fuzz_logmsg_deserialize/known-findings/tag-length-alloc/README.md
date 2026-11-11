# tag-length-alloc

`input` is a `fuzz_logmsg_deserialize` input: a serialized v2x message whose tag-name length field claims
~2.4 GB.

Reproduce: `/mayhem/fuzz_logmsg_deserialize mayhem/fuzz_logmsg_deserialize/known-findings/tag-length-alloc/input`
(the libFuzzer binary reports it; the standalone just attempts the allocation).

Result: `libFuzzer: out-of-memory (malloc(2499805186))` from `serialize_read_string` (`lib/serialize.h:236`) called by
`tags_deserialize` (`lib/logmsg/tags-serialize.c:36`) — the deserializer trusts an attacker-controlled 32-bit
length and reallocs the string to it before reading. Present upstream; not fixed here.

Not a crash: `serialize_read_string` allocates with `g_try_realloc(str->str, len + 1)` and returns `FALSE` when that
fails (`len == G_MAXUINT32` is rejected up front). The report comes from libFuzzer's 2 GB `-malloc_limit_mb` check, not
from a memory error; the standalone binary only attempts the allocation. Assessment: an OOM-class artifact, not memory
corruption. The real gap is a missing bound against the bytes left in the archive (hardening, low severity). The
v1x counterpart is `cstring-length-alloc` (`serialize_read_cstring`).
