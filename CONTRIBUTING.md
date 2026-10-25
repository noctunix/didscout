# Contributing a vehicle profile

A vehicle profile (`profiles/<id>.toml`) is a candidate header/DID list for one
platform - the data `probe --profile`/`session --profile` need to read gateway,
tyre, or other module DIDs on top of the legislative mode-01/OBDonUDS traffic this
tool already does safely on any vehicle.

## What a profile can and cannot contain

A profile is **data only**: it names CAN headers and `ReadDataByIdentifier` DIDs,
never commands. Everything built from it - header/filter setup
(`module_setup_commands`) and the `22<did>` reads themselves - still goes through
`check_sweep_allowed` before anything is sent, so a profile can never introduce a
service other than ReadDataByIdentifier (`0x22`) or a VIN read; the latter is
rejected outright by the loader (`VIN_DIDS`).

A profile, and your PR, must **never** contain:

- a VIN, or anything that looks like one (the loader rejects any 17-character
  string matching the ISO 3779 shape, anywhere in the file)
- raw adapter responses, logs, or `*.jsonl` files
- measured/decoded values (state of charge, range, temperature, ...)
- an odometer reading
- a BLE MAC address
- a GPS location or any other way to identify a specific vehicle or its owner

If you captured any of the above while finding a DID, keep it out of the PR -
only the header, the DID, and what you learned about it (name, status) belong
here.

## File naming and schema

One file per platform: `profiles/<make>-<platform>.toml`, e.g. `vag-ppe.toml`. The
file stem must equal the profile's `id` field. See `profiles/vag-ppe.toml` for a
complete example; the schema itself is documented in `AGENTS.md` and enforced by
`load_profile` in `didscout.py`.

Each DID's `status` says how much to trust it:

- `unverified` - seen to answer, nothing cross-checked yet
- `plausible` - the value looks right for what it should be, not confirmed
  against a second source
- `validated` - checked against the vehicle's own display or another
  independent reading

`poll` says how `probe`/`session` treat it:

- `once` - read once per pass, value doesn't change within a session (e.g. a
  software version)
- `watch` - poll repeatedly at its own `interval` (seconds, >= 5) - a value
  worth tracking live
- `survey` - poll at `session --survey`'s shared interval, for DIDs that answer
  but aren't confirmed interesting enough yet for their own `watch` interval;
  `name` is optional here since these are often still unidentified

## Sources

Cite where a header or DID came from, with its licence, in `[[sources]]`. If you
found it yourself (a sweep, inspecting captures you aren't sharing), say so with
`license = "own discovery"` - no external licence needed, but no fabricated
citation either.

## Before opening the PR

Run the checks from `AGENTS.md`:

```
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

`pytest` loads every file in `profiles/` and validates it the same way
`load_profile` would at runtime, so a broken or unsafe profile fails the test
suite automatically - fix what it reports before opening the PR.
