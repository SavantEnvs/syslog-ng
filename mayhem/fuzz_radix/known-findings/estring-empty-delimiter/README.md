# estring-empty-delimiter

`input` is a `fuzz_radix` input: extra pattern `user @ESTRING:x:@` (an ESTRING parser with an empty delimiter),
key `user abc`.

Reproduce: `/mayhem/fuzz_radix-standalone mayhem/fuzz_radix/known-findings/estring-empty-delimiter/input`

Result: ASan heap-buffer-overflow READ in `_find_child_by_remaining_key` (`modules/correlation/radix.c:1319`).
With an empty delimiter `r_parser_estring_c` calls `strchr(str, '\0')`, which "finds" the terminator, and
returns `len = strlen(str) + 1`. The caller then continues at `remaining_key + len`, one byte past the
terminator, and reads `remaining_key[0]` there.

Triage: match-time crash, but only for a pattern with an empty ESTRING delimiter. A config-validation gap
(`r_new_pnode` does not reject it), not reachable from message content alone. Present upstream; not fixed here.
