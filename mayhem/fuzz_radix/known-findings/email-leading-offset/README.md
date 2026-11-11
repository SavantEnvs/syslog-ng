# email-leading-offset

`input` is a `fuzz_radix` input: extra pattern `@EMAIL:x@` at the start of a pattern, key `\0` (a key whose
first byte is not an e-mail character).

Reproduce: `/mayhem/fuzz_radix-standalone mayhem/fuzz_radix/known-findings/email-leading-offset/input`

Result: ASan heap-buffer-overflow READ in `r_parser_email` (`modules/correlation/radix.c:336`). When the
parser is tried at the start of the key and no e-mail character is consumed, `*len` is 0 and
`str[*len - 1]` reads `str[-1]`, the byte before the key.

Triage: match-time, driven by message content. It needs a valid pattern that begins with `@EMAIL@`, matched
against a message that does not start with an e-mail character. Inside a real message buffer the byte before
is usually still mapped, so it is mostly a latent out-of-bounds read; under ASan on an exact-size copy it
is reported. Present upstream; not fixed here.
