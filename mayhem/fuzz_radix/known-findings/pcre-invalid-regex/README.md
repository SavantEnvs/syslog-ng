# pcre-invalid-regex

`input` is a `fuzz_radix` input: extra pattern `user @PCRE:x:[a@` (an unterminated character class), key
`user abc`.

Reproduce: `/mayhem/fuzz_radix-standalone mayhem/fuzz_radix/known-findings/pcre-invalid-regex/input`

Result: ASan SEGV on a NULL pointer in `r_parser_pcre` (`modules/correlation/radix.c:198`). When
`pcre2_compile` fails, `r_parser_pcre_compile_state` logs "Error while compiling regular expression" and
returns NULL, but `r_new_pnode` still installs the parser node with `state == NULL`. At match time
`r_parser_pcre` passes `self->re` (self is NULL) to PCRE2.

Triage: match-time crash, but only for a pattern whose regex does not compile. A config-validation gap: the
load logs an error and keeps the rule. Not reachable from message content alone. Present upstream; not fixed here.
