# ipv6-octet-overflow

`input` is a `fuzz_radix` input (no newline, so it is only the key): `ip=` followed by a long hex digit run
where the fixed `@IPvANY:ip@` pattern tries the IPv6 parser.

Reproduce: `/mayhem/fuzz_radix-standalone mayhem/fuzz_radix/known-findings/ipv6-octet-overflow/input`

Result: UBSan `modules/correlation/radix.c:542: signed integer overflow: 266884437 * 16 cannot be represented
in type 'gint'` in `r_parser_ipv6`: `octet *= digit; octet += digit_value` is range-checked only when a `:` or
`.` is reached. The same missing-bound pattern as `octet-overflow` (`r_parser_ipv4`, line 491), in a
different function and line, so it is reported separately.

Triage: match-time, driven by message content, no unusual pattern needed. Present upstream; not fixed here.
