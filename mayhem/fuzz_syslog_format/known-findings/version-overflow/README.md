# version-overflow

`input` is a `fuzz_syslog_format` input (2 flag bytes, then an RFC5424-style message) whose `<PRI>VERSION` field
has more digits than fit in an `int`.

Reproduce: `/mayhem/fuzz_syslog_format-standalone mayhem/fuzz_syslog_format/known-findings/version-overflow/input`

Result: UBSan `modules/syslogformat/syslog-format.c:333: signed integer overflow: 999999999 * 10 cannot be
represented in type 'int'` — `_syslog_format_parse_version` accumulates `version = version * 10 + digit` with no
bound. Present upstream; not fixed here (the mirror is untouched).
