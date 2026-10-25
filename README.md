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
  commands (`ATSH`, `ATCRA`, `ATFCSH`) — brute-forcing a DID range never reaches
  any other service, independent of the range given.
- `obduds` only follows SAE J1979-2 discovery: a functional request (`22F810`),
  then each responding ECU's own support bitmaps (`F400`, `F420`, ...), and reads
  only the DIDs those bitmaps announce (`F4xx`/`F5xx`).
- VIN DIDs (`F190`, `F802`) are never read, in any mode.

No write, clear-DTC, routine-control, security-access, session-control, or reset
service is reachable through any of these paths.

That said: read-only diagnostic requests are still requests on the vehicle's bus.
Use this with the vehicle stationary. You take on all risk by running it — this is
AGPL-licensed software with no warranty of any kind.

## Setup

```
uv sync
uv run pytest
```

## Commands

### `scan`

List nearby BLE devices and flag which ones advertise the UART service:

```
uv run python didscout.py scan
```

### `probe`

Run a fixed set of allow-listed stages (A-E) against one adapter, logging every
exchange:

```
uv run python didscout.py probe <ADDRESS> --stages ABCE --state ignitionOn
```

### `sweep`

Brute-force `ReadDataByIdentifier` over a bounded DID range at one CAN header:

```
uv run python didscout.py sweep <ADDRESS> --header 710 --start 2A00 --end 2AFF --state stationary
```

### `obduds`

Safely discover SAE J1979-2/-3 (OBDonUDS) ECUs and read only their advertised
current-data DIDs:

```
uv run python didscout.py obduds <ADDRESS> --state stationary
```

### `session`

One continuous log for a whole outing: a full one-shot pass, then indefinite
polling of a watch list until Ctrl-C:

```
uv run python didscout.py session <ADDRESS> --state chargingDrive
```

During `probe` and `session`, anything you type on stdin (e.g. a display reading)
is captured as a timestamped note and lands in the same log next to the polled
exchanges.

The current built-in candidate header/DID set used by `probe`'s and `session`'s
stage E targets VAG PPE-platform vehicles specifically (gateway `710`/`77A`, tyre
module `70B`/`775`). Vehicle-specific candidate sets (profiles) for other
platforms are planned but not implemented yet.

## Status meanings

`OK` means a complete, matching positive response was received — not that the
value has been validated against anything. `PENDING`, `UNMATCHED`, and `MALFORMED`
are all not success; they mean the exchange needs another look before you trust
anything from it.

## Privacy

Logs go to `logs/`, which is git-ignored, as is every `*.jsonl` file anywhere in
the repo. Logs contain timestamps, ECU addresses, adapter/software version
strings, and any free-text notes you typed. Redact before sharing, and never
attach raw logs to an issue.

## License

AGPL-3.0-or-later. See `LICENSE`.
