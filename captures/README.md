# Contributed captures

This directory holds contributed `<name>.share.jsonl.gz` files only - the
redacted output of `didscout share` (or the `share` step `record` runs
automatically on Ctrl-C), never a raw log.

A capture PR is: run `record`, attach the resulting `.share.jsonl.gz` here,
nothing else - no raw `capture.jsonl`, no `state.json`, no screenshots of the
display. `validate_share` (see `AGENTS.md`) checks every file here against the
redaction rules on every test run, so a file that still carries an identity
payload, a non-marker note, an absolute timestamp, or anything VIN-like fails
the test suite automatically.

Maintainers derive profile drafts from contributed captures with
`didscout derive`, same as from their own runs.
