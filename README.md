# didscout

`didscout` finds out what a vehicle's diagnostic port actually reports, using only
read services, through an ELM327/STN-compatible BLE UART adapter (service `FFF0`,
notify `FFF1`, write `FFF2`). It was developed and tested with an OBDLink CX, but
works with any adapter exposing that UART service. It works for any vehicle,
combustion or electric — nothing here assumes a particular make, model, or
powertrain.

## Safety model

Every command passes an allow-list validator before it is sent, and the three
modes have three different, narrower allow-lists:

- `sweep` can only emit UDS ReadDataByIdentifier (`0x22`) plus header/filter `AT`
  commands (`ATSH`, `ATCRA`, `ATFCSH`, including the 29-bit `18DAxxF1`/`18DAF1xx`
  forms) — brute-forcing a DID range never reaches any other service, independent
  of the range given.
- `obduds` only follows SAE J1979-2 discovery: a functional request (`22F810`),
  then each responding ECU's own support bitmaps (`F400`, `F420`, ...), and reads
  only the DIDs those bitmaps announce (`F4xx`/`F5xx`).
- `identify` follows the same discovery but reads only four fixed identification
  DIDs (`F187`, `F189`, `F191`, `F197`) per ECU — never the serial number (`F18C`).
- `record` only ever sends mode-01 reads, the same OBDonUDS discovery, or a
  profile/ECU's own `ReadDataByIdentifier` reads — all through the same
  allow-lists as `sweep`/`obduds`.
- VIN DIDs (`F190`, `F802`) are never read, in any mode.

No write, clear-DTC, routine-control, security-access, session-control, or reset
service is reachable through any of these paths. `derive` and `share` never talk
to the adapter at all — they only read a log already on disk.

That said: read-only diagnostic requests are still requests on the vehicle's bus.
Use this with the vehicle stationary. You take on all risk by running it — this is
AGPL-licensed software with no warranty of any kind.

## Setup

```
uv sync
uv run pytest
```

## Quick start: `record`

One command for a whole outing - no address needed (it scans for a UART adapter),
no `--state` label to pick:

```
uv run python didscout.py record
```

It connects, runs a one-time vehicle inventory (adapter, protocol, mode-01,
OBDonUDS, 11-bit and 29-bit manufacturer ECUs - the latter with VAG's own
29-bit scheme too, if the profile opts in via `address_schemes`), then keeps
logging every known value and discovering more DIDs on every known ECU while
the vehicle is stationary - discovery pauses the moment it's moving again.
It also re-probes for ECUs that only wake in some vehicle state (e.g. a
charger ECU while charging) on every phase change and every 30 minutes
stationary, folding any newly found one straight into the running session.
Watch polling backs off an unchanged value's interval over time and the log
only records a read when its value changes (plus an occasional keep-alive),
so a long stationary stretch doesn't drown the capture in repeats. Press
Ctrl-C when you're done (e.g. back home from a drive/charge). A dropped BLE
connection reconnects with backoff and resumes where it left off; starting
`record` again later resumes the same unfinished run automatically (`--new`
to start fresh instead).

On Ctrl-C, `record` automatically runs `derive` and `share` (see below) on its
own run directory and prints the resulting paths plus a one-line hint for how
to contribute what it found.

Type a note (e.g. a reading off the display) any time and press Enter; it's
timestamped into `capture.jsonl` even while disconnected or reconnecting.
`idle`/`drive`/`charge`/`park` (German `leerlauf`/`fahrt`/`laden`/`parken` too)
are recognized as phase markers. `record` also tries to hold a
`systemd-inhibit` sleep/idle/lid-switch lock for as long as it runs, since a
suspended laptop kills the BLE connection (`--no-inhibit` to skip it, e.g. on a
non-systemd system) - run it inside `tmux` too, so closing the terminal
doesn't stop the recording.

## `derive` and `share`

`derive <RUN_DIR>` turns one `record` run's log into:

- `report.md` - per module (and DID), how many samples, which byte positions
  vary, when it changed, and whether it correlates with vehicle speed or rises/
  falls monotonically while stationary (a charging/energy candidate).
- `profile-draft.toml` (or `<id>.toml` with `--id`) - a candidate profile for
  every manufacturer module with at least one DID actually found by discovery,
  classified `once`/`watch` with an interval suggestion. Always validated via
  `load_profile` before being written out, and skipped entirely if nothing
  manufacturer-specific was found.

```
uv run python didscout.py derive logs/record_20260101_120000_vehicle --vehicle "my car"
```

`share <RUN_DIR>` writes a redacted `<name>.share.jsonl.gz`, safe to attach to
a PR: connection events, adapter identity, and free-text notes are dropped;
only `F197` keeps its decoded content among the identification DIDs; a typed
note survives only as a canonical phase marker (`idle`/`drive`/`charge`/`park`,
German included). `CONTRIBUTING.md` lists the exact rules `validate_share` enforces.

```
uv run python didscout.py share logs/record_20260101_120000_vehicle --vehicle "my car"
```

## Contributing what you found

Two ways, see `CONTRIBUTING.md` for the full guide:

- **A profile PR**: review `derive`'s draft against the display, fill in real
  `name`s and promote `status` as you confirm values, then open a PR with the
  resulting `profiles/<make>-<platform>.toml`.
- **A capture PR**: run `record`, attach the `share` output under `captures/`,
  nothing else - maintainers derive profiles from contributed captures too.

## Advanced

Lower-level commands for one-off, targeted runs instead of `record`'s
continuous autonomous loop.

### `scan`

List nearby BLE devices and flag which ones advertise the UART service:

```
uv run python didscout.py scan
```

### `probe`

Run a fixed set of allow-listed stages (A-E) against one adapter, logging every
exchange. Stage E - vehicle-specific module/DID reads - needs a vehicle profile:

```
uv run python didscout.py probe <ADDRESS> --stages ABCE --state ignitionOn --profile vag-ppe
```

### `sweep`

Brute-force `ReadDataByIdentifier` over a bounded DID range at one CAN header:

```
uv run python didscout.py sweep <ADDRESS> --header 710 --start 2A00 --end 2AFF --state stationary
```

`--header` also accepts a 29-bit ECU request header (`18DAxxF1`); this forces
protocol 7 and defaults `--rax` to the matching `18DAF1xx` response id:

```
uv run python didscout.py sweep <ADDRESS> --header 18DA10F1 --start F400 --end F4FF --state stationary
```

`--obduds-ecus` discovers all regulated 29-bit ECUs (as `obduds` does) and runs the
same range sweep at every one of them, instead of a fixed `--header`:

```
uv run python didscout.py sweep <ADDRESS> --obduds-ecus --start F400 --end F4FF --state stationary
```

### `obduds`

Safely discover SAE J1979-2/-3 (OBDonUDS) ECUs and read only their advertised
current-data DIDs:

```
uv run python didscout.py obduds <ADDRESS> --state stationary
```

### `identify`

Discover regulated 29-bit ECUs and read only their spare part number, software
version, hardware number, and system name - never the serial number or any VIN.
Identification responses contain part/software numbers and stay in local logs only:

```
uv run python didscout.py identify <ADDRESS> --state stationary
```

### `session`

One continuous log for a whole outing: a full one-shot pass, then indefinite
polling of each profile DID marked `watch` until Ctrl-C. Without `--profile`,
stage E and the watch loop are skipped - only the adapter/protocol/mode-01 parts
run:

```
uv run python didscout.py session <ADDRESS> --state chargingDrive --profile vag-ppe
```

Add `--survey` to also poll each DID marked `survey` - module DIDs that answered
positively during discovery but aren't `watch`-worthy yet - at `--survey-interval`
seconds (default 60, minimum 15), logged with stage `E-survey`:

```
uv run python didscout.py session <ADDRESS> --state chargingDrive --profile vag-ppe --survey --survey-interval 30
```

During `probe` and `session`, anything you type on stdin (e.g. a display reading)
is captured as a timestamped note and lands in the same log next to the polled
exchanges.

### Vehicle profiles

`--profile` takes either an id resolved against `profiles/<id>.toml`, or a path to
a profile file. A profile is a candidate header/DID list for one platform - see
`profiles/vag-ppe.toml` for VAG's PPE platform (gateway `710`/`77A`, tyre module
`70B`/`775`). Profiles are data only: they name addresses and DIDs, never
commands, and everything built from one still goes through the same read-only
allow-list validation as `sweep`. See `CONTRIBUTING.md` to add a profile for
another platform.

## Status meanings

`OK` means a complete, matching positive response was received — not that the
value has been validated against anything. `PENDING`, `UNMATCHED`, and `MALFORMED`
are all not success; they mean the exchange needs another look before you trust
anything from it.

## Privacy

Logs go to `logs/`, which is git-ignored, as is every `*.jsonl` file (and raw
`*.jsonl.gz`) anywhere in the repo. Logs contain timestamps, ECU addresses,
adapter/software version strings, and any free-text notes you typed. Never
attach a raw log or `state.json` to an issue or PR - only `share`'s redacted
output (see above) is meant to leave your machine, and only into `captures/`.

## License

AGPL-3.0-or-later. See `LICENSE`.
