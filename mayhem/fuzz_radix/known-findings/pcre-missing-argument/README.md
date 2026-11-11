# pcre-missing-argument

`input` is a `fuzz_radix` input: extra pattern `user @PCRE@` (no name and no regex), key `user abc`.

Reproduce: `/mayhem/fuzz_radix-standalone mayhem/fuzz_radix/known-findings/pcre-missing-argument/input`

Result: ASan SEGV inside libpcre2 called from `r_parser_pcre_compile_state` (`modules/correlation/radix.c:232`)
via `r_new_pnode` (`radix.c:764`). `g_strsplit("PCRE", ":", 3)` returns a two-slot array, but `r_new_pnode`
tests `params[2]` for the "missing regular expression" case, which reads past the end of the array. The value
is uninitialised heap (0xbebe... under ASan), non-NULL, so it is passed to `pcre2_compile` as the regex.
`PCRE:x` (two tokens) is handled; only the bare `@PCRE@` form reads past the end.

Triage: pattern-load-time, only for a malformed pattern. The crash frame is in the distro's libpcre2; the
defect is in `r_new_pnode`'s argument check. Present upstream; not fixed here.
