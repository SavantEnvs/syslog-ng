# octet-overflow

`input` is a `fuzz_radix` input: a key with a very long digit run where an `@IPv4@` parser is tried.

Reproduce: `/mayhem/fuzz_radix-standalone mayhem/fuzz_radix/known-findings/octet-overflow/input`

Result: UBSan `modules/correlation/radix.c:491: signed integer overflow: 222222222 * 10 cannot be represented
in type 'int'` — `r_parser_ipv4` does `octet *= 10; octet += digit` and only range-checks the octet when it reaches a `.`.
Present upstream; not fixed here.
