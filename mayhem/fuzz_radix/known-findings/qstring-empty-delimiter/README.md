# qstring-empty-delimiter

`input` is a `fuzz_radix` input: the text before the first newline is an extra pattern, `@QSTRING:x:@`
(a QSTRING parser with an empty delimiter argument); the rest is the key.

Reproduce: `/mayhem/fuzz_radix-standalone mayhem/fuzz_radix/known-findings/qstring-empty-delimiter/input`

Result: ASan heap-buffer-overflow READ in `r_parser_qstring` (`modules/correlation/radix.c:120`). The delimiter
string is empty, so `param[0]` is the terminator and `gchar stop_char = param[1] ? ...` reads one byte past it.
`r_new_pnode` accepts an empty QSTRING delimiter and nothing at pdb load time rejects it.

Triage: match-time crash, but only for a pattern with an empty QSTRING delimiter, which a pdb author would
have to write. A config-validation gap rather than something a log message can trigger. Present upstream; not fixed here.
