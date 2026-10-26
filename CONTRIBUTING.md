# Contributing

Two ways to contribute what `record` found on your vehicle:

- **A profile PR** (this file): review `didscout derive`'s draft against the
  display, confirm/correct values, and open a PR with the resulting
  `profiles/<make>-<platform>.toml`. See below for the schema.
- **A capture PR**: run `record`, attach the `share` output - a redacted
  `<name>.share.jsonl.gz` - under `captures/` via a PR, nothing else. No raw
  log, no `state.json`, no screenshots. Maintainers derive profile drafts from
  contributed captures the same way.

## What's a profile

A vehicle profile (`profiles/<id>.toml`) is a candidate header/DID list for one
platform - the data `probe --profile`/`session --profile`/`record` need to read
gateway, tyre, or other module DIDs on top of the legislative mode-01/OBDonUDS
traffic this tool already does safely on any vehicle. `didscout derive` writes
one (`profile-draft.toml`) from a `record` run as a starting point - review every
DID against the display before it becomes a real PR.

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
- raw adapter responses, logs, `*.jsonl`/`*.jsonl.gz` files, or `state.json`
  (a capture PR attaches only `share`'s redacted output, see above)
- measured/decoded values (state of charge, range, temperature, ...)
- an odometer reading
- a BLE MAC address
- a GPS location or any other way to identify a specific vehicle or its owner

If you captured any of the above while finding a DID, keep it out of the PR -
only the header, the DID, and what you learned about it (name, status) belong
here.

## File naming and schema

One file per platform: `profiles/<make>-<platform>.toml`, e.g. `vag-ppe.toml`. The
file stem must equal the profile's `id` field. `profiles/vag-ppe.toml` is a
complete example; `load_profile` in `didscout.py` enforces the schema and rejects
any key not listed here:

| Key | Required | Meaning |
|---|---|---|
| `schema` | yes | always `1` |
| `id` | yes | `[a-z0-9-]+`, equal to the file stem |
| `name`, `description` | yes | free text |
| `protocol` | yes | `"6"` (ISO 15765-4, 11-bit, 500k) or `"7"` (29-bit, 500k) |
| `vehicles` | yes | list of free-text vehicle names, at least one; mark what you tested |
| `address_schemes` | no, default `[]` | opt-in non-standard 29-bit addressing schemes `record` should also probe for; currently only `"vag-29bit"` (VAG's `17FC00xx`/`17FE00xx` scheme) |
| `[[sources]]` | at least one | `title`, `url`, `license` |
| `[[modules]]` | yes | `id` (unique), `request` (11-bit up to `7FF`, or `18DAxxF1` with the module's effective protocol `"7"`), optional `response` (`77A`-style or `18DAF1xx`; omit if unknown, then only single-frame replies work), optional `protocol` (`"6"`/`"7"`, overrides the profile's protocol for this module only), optional `discover` (list of `["start", "end"]` DID ranges) |
| `[[modules.dids]]` | yes | `did` (4 hex, unique per module), `name` (optional when `status` is `unverified` or `poll` is `survey`), `status`, `poll`, `interval` (seconds, >= 5, required for `watch`/`survey`, not allowed for `once`) |

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

Run the checks:

```
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

`pytest` loads every file in `profiles/` and validates it the same way
`load_profile` would at runtime, so a broken or unsafe profile fails the test
suite automatically - fix what it reports before opening the PR. The same goes
for a capture PR: every file in `captures/` is checked against `validate_share`
on each run.

## Code changes

Pull requests that touch `didscout.py` must keep these invariants; they are what
makes the tool safe to point at a vehicle:

- Every outgoing command passes an allow-list validator before it is sent. No
  code path may send a command that bypasses validation.
- Only read services ever leave the allow-lists: mode 01, UDS
  ReadDataByIdentifier (`0x22`) and passive `ATMA` monitoring. No write,
  clear-DTC, routine-control, security-access, session-control or reset service
  may become reachable, regardless of range or header arguments.
- VIN DIDs (`F190`, `F802`) and the ECU serial number (`F18C`) are never read.
- A timeout or transport error marks the session unusable; no further requests
  are sent on it.
- `derive` and `share` never talk to the adapter.

Tests use synthetic fixtures only - never real vehicle responses. Identifiers,
comments and messages are English; comments explain a non-obvious why, a
protocol quirk or point at an external spec.

## What `share` removes

`share` drops connection events, adapter identity (`ATI`, `STI`, `STDI`) and
free-text notes (a note survives only as a canonical phase marker), the
responses of `F187`/`F189`/`F191` (only `F197`, the system name, stays) and the
response text of `TIMEOUT`/`TRANSPORT_ERROR` exchanges, which can embed the
adapter's BLE address. Times become seconds since the start of the run.
`validate_share` rejects unknown keys, absolute timestamps, non-marker notes,
identification payloads and any VIN-, MAC- or UUID-looking string; the test
suite runs it on every file in `captures/`.
