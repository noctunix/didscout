## Vehicle profile checklist

See `CONTRIBUTING.md` for the full guide.

- [ ] This profile is data only - headers and DIDs, no commands
- [ ] Sources are cited with their licence (or `license = "own discovery"`)
- [ ] No personal data: no VIN, raw logs, measured values, odometer reading,
      BLE MAC address, or location anywhere in this PR
- [ ] `uv run pytest`, `uv run ruff check .`, `uv run ruff format --check .`,
      and `uv run mypy` all pass
- [ ] Tested vehicle and its state are named below

**Tested vehicle(s) and state:**
