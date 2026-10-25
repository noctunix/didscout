## Vehicle profile / capture checklist

See `CONTRIBUTING.md` for the full guide - a profile PR and a capture PR are
the two ways to contribute what `record` found.

- [ ] This profile is data only - headers and DIDs, no commands (profile PR)
- [ ] Sources are cited with their licence (or `license = "own discovery"`)
      (profile PR)
- [ ] The only capture file attached is `share`'s redacted
      `<name>.share.jsonl.gz` output - no raw log, `state.json`, or screenshot
      (capture PR)
- [ ] No personal data: no VIN, raw logs, measured values, odometer reading,
      BLE MAC address, or location anywhere in this PR
- [ ] `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`,
      and `uv run mypy` all pass
- [ ] Tested vehicle and its state are named below

**Tested vehicle(s) and state:**
