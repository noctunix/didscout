#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only discovery of what a vehicle reports through an ELM327/STN-compatible BLE OBD adapter.

Sends only commands from a fixed allow-list, logs every exchange raw as JSONL and
never decodes on its own: interpretation happens afterwards against the display.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import re
import sys
import threading
import time
import tomllib
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

UART_SERVICE = "0000fff0-0000-1000-8000-00805f9b34fb"
UART_NOTIFY = "0000fff1-0000-1000-8000-00805f9b34fb"
UART_WRITE = "0000fff2-0000-1000-8000-00805f9b34fb"

PROMPT = b">"
MAX_RESPONSE_BYTES = 64 * 1024
MONITOR_SECONDS = 10.0
MONITOR_STOP_TIMEOUT = 3.0

ADAPTER_SETUP = ["ATZ", "ATE0", "ATL0", "ATS0", "ATH1"]
STAGES: dict[str, list[str]] = {
    "A": ADAPTER_SETUP + ["ATI", "STI", "STDI", "ATRV"],
    "B": ["ATSP0", "0100", "ATDPN"],
    # Stage C is expanded at runtime from the supported-PID bitmaps.
    "C": ["0100", "0120", "0140", "0160", "0180", "01A0"],
    "D": ["ATMA"],
    # Stage E has no fixed commands of its own - it is entirely generated at
    # runtime from a vehicle profile (see `profiles/` and `load_profile`).
    "E": [],
}
STAGE_C_CANDIDATES = {"0D": "010D", "46": "0146", "5B": "015B", "A6": "01A6"}
# ATSP0 auto-detect can pick the wrong CAN protocol on some vehicles (e.g. settle on
# 29-bit/500k with everything NO DATA while the correct protocol is 11-bit/500k);
# override explicitly as a fallback.
FORCE_PROTOCOL = {"6": "ATSP6", "7": "ATSP7"}

# SAE J1979-2/-3 OBDonUDS/ZEVonUDS over ISO 15765-4 29-bit CAN.
OBDUDS_FUNCTIONAL_HEADER = "18DB33F1"
OBDUDS_RESPONDER_PATTERN = "18DAF1XX"
OBDUDS_PROTOCOL_DID = 0xF810
OBDUDS_FIRST_SUPPORT_DID = 0xF400
OBDUDS_LAST_SUPPORT_DID = 0xF5C0
OBDUDS_MAX_DATA_DIDS = 512

# Adapter-control commands used to set up/tear down a profile module's header,
# response filter, and flow control - contributed to ALLOWED directly since
# module headers themselves are data (see check_sweep_allowed), not fixed commands.
MODULE_CONTROL_COMMANDS = frozenset(
    {"ATFCSD300000", "ATFCSM0", "ATFCSM1", "ATAR", "ATD", "ATSP6", "ATSP7"}
)

ALLOWED = (
    frozenset(cmd for cmds in STAGES.values() for cmd in cmds)
    | frozenset(STAGE_C_CANDIDATES.values())
    | frozenset(FORCE_PROTOCOL.values())
    | MODULE_CONTROL_COMMANDS
)

# Upper bound on a single `sweep` run, ~15 min at the ~130-220 ms/DID seen so far;
# split a wider search into several calls instead of raising this.
MAX_SWEEP_DIDS = 4096

SLOW_COMMANDS = {"ATZ": 5.0, "ATSP0": 2.0, "0100": 15.0}
DEFAULT_TIMEOUT = 5.0

NRC_NAMES = {
    "10": "generalReject",
    "11": "serviceNotSupported",
    "12": "subFunctionNotSupported",
    "13": "incorrectMessageLength",
    "14": "responseTooLong",
    "22": "conditionsNotCorrect",
    "31": "requestOutOfRange",
    "33": "securityAccessDenied",
    "78": "responsePending",
    "7E": "subFunctionNotSupportedInActiveSession",
    "7F": "serviceNotSupportedInActiveSession",
}


class ForbiddenCommandError(Exception):
    pass


def normalize(command: str) -> str:
    return re.sub(r"\s+", "", command).upper()


def check_allowed(command: str) -> str:
    cmd = normalize(command)
    if cmd not in ALLOWED:
        raise ForbiddenCommandError(cmd)
    return cmd


# Classic UDS VIN and the SAE J1979-2 OBDonUDS VIN.
VIN_DIDS = frozenset({"F190", "F802"})


def check_sweep_allowed(command: str) -> str:
    """For `sweep`: any 11-bit header, or an explicit 29-bit OBDonUDS ECU header/
    filter (18DAxxF1 request, 18DAF1xx response - never the functional broadcast
    header), but only ReadDataByIdentifier (22 xx xx) ever leaves the fixed
    allow-list - no SID outside 0x22 can ever match, so a reset/write/security
    service is structurally unreachable here, independent of range bounds."""
    cmd = normalize(command)
    if cmd in ALLOWED:
        return cmd
    if re.fullmatch(r"22[0-9A-F]{4}", cmd):
        if cmd[2:] in VIN_DIDS:
            raise ForbiddenCommandError(cmd)
        return cmd
    if re.fullmatch(r"AT(SH|CRA|FCSH)[0-9A-F]{3}", cmd):
        return cmd
    if re.fullmatch(r"ATSH18DA[0-9A-F]{2}F1", cmd):
        return cmd
    if re.fullmatch(r"ATFCSH18DA[0-9A-F]{2}F1", cmd):
        return cmd
    if re.fullmatch(r"ATCRA18DAF1[0-9A-F]{2}", cmd):
        return cmd
    raise ForbiddenCommandError(cmd)


def _obduds_transport_allowed(cmd: str) -> bool:
    """Adapter setup, functional-request discovery header, and per-ECU 29-bit
    header/filter commands shared by every OBDonUDS allow-list (`check_obduds_allowed`
    and `check_identify_allowed`) - only the set of permitted 22-xx-xx data reads
    differs between them."""
    adapter = {
        *ADAPTER_SETUP,
        "ATSP7",
        "ATDPN",
        "ATD",
        "ATAR",
        "ATFCSM0",
        "ATFCSD300000",
        "ATFCSM1",
    }
    if cmd in adapter:
        return True
    if cmd == f"ATSH{OBDUDS_FUNCTIONAL_HEADER}" or cmd == f"22{OBDUDS_PROTOCOL_DID:04X}":
        return True
    return bool(re.fullmatch(r"AT(SH|FCSH)18DA[0-9A-F]{2}F1|ATCRA18DAF1[0-9A-F]{2}", cmd))


def check_obduds_allowed(command: str) -> str:
    """Allow only standardized, read-only OBDonUDS discovery/current-data traffic."""
    cmd = normalize(command)
    if _obduds_transport_allowed(cmd):
        return cmd
    if re.fullmatch(r"22F[45][0-9A-F]{2}", cmd):
        return cmd
    raise ForbiddenCommandError(cmd)


# Spare part number, software version, hardware number, system name - never the
# serial number (F18C) or any VIN.
IDENTIFY_DIDS = frozenset({"F187", "F189", "F191", "F197"})


def check_identify_allowed(command: str) -> str:
    """Allow only OBDonUDS discovery/header setup plus the four ECU identification
    reads in IDENTIFY_DIDS - never the serial number or any VIN DID."""
    cmd = normalize(command)
    if _obduds_transport_allowed(cmd):
        return cmd
    if cmd.startswith("22") and cmd[2:] in IDENTIFY_DIDS:
        return cmd
    raise ForbiddenCommandError(cmd)


def check_mode01_allowed(command: str) -> str:
    """For `record`'s mode-01 inventory: any `01<two hex digits>` current-data
    read, on top of the fixed adapter/protocol allow-list - mode 01 is read-only
    by definition, so no other service can ever match here."""
    cmd = normalize(command)
    if cmd in ALLOWED:
        return cmd
    if re.fullmatch(r"01[0-9A-F]{2}", cmd):
        return cmd
    raise ForbiddenCommandError(cmd)


# Broad adapter receive filter/mask that accepts any 11-bit id in 0x700-0x7FF,
# used only to discover manufacturer ECUs - never contributed to ALLOWED or any
# other validator, since it has no place outside this one discovery step.
ECU11_FILTER_COMMANDS = frozenset({"ATCF700", "ATCM700"})


def check_ecus11_allowed(command: str) -> str:
    """For `record`'s 11-bit manufacturer-ECU inventory: adapter setup, the broad
    0x700-0x7FF receive filter (ECU11_FILTER_COMMANDS), header/response/flow-
    control setup at any 11-bit header, and the same four identification reads as
    check_identify_allowed - never the serial number or any VIN DID."""
    cmd = normalize(command)
    base = {
        *ADAPTER_SETUP,
        "ATSP6",
        "ATDPN",
        "ATD",
        "ATAR",
        "ATFCSM0",
        "ATFCSD300000",
        "ATFCSM1",
        *ECU11_FILTER_COMMANDS,
    }
    if cmd in base:
        return cmd
    if re.fullmatch(r"AT(SH|CRA|FCSH)[0-9A-F]{3}", cmd):
        return cmd
    if cmd.startswith("22") and cmd[2:] in IDENTIFY_DIDS:
        return cmd
    raise ForbiddenCommandError(cmd)


PROFILES_DIR = Path(__file__).parent / "profiles"
PROFILE_ID_PATTERN = re.compile(r"[a-z0-9-]+")
# Guards against a pasted VIN ending up in a profile (and thus a public PR) by
# accident - ISO 3779 excludes I, O, Q from the check-digit-bearing positions.
VIN_LIKE_PATTERN = re.compile(r"[A-HJ-NPR-Z0-9]{17}")
HEADER_11BIT_PATTERN = re.compile(r"[0-9A-F]{3}")
HEADER_29BIT_REQUEST_PATTERN = re.compile(r"18DA[0-9A-F]{2}F1")
HEADER_29BIT_RESPONSE_PATTERN = re.compile(r"18DAF1[0-9A-F]{2}")
PROFILE_DID_PATTERN = re.compile(r"[0-9A-F]{4}")
PROFILE_STATUSES = frozenset({"unverified", "plausible", "validated"})
PROFILE_POLL_MODES = frozenset({"once", "watch", "survey"})
MIN_PROFILE_INTERVAL = 5.0


class ProfileError(Exception):
    """Raised by `load_profile` for anything wrong with a profile file, naming
    the file and the offending field so a broken or unsafe PR fails review with
    a message that points straight at the problem."""

    def __init__(self, path: Path, field: str, message: str) -> None:
        super().__init__(f"{path.name}: {field}: {message}")
        self.path = path
        self.field = field


@dataclass
class ProfileSource:
    title: str
    url: str
    license: str


@dataclass
class ModuleDid:
    did: str
    status: str
    poll: str
    name: str | None = None
    interval: float | None = None


@dataclass
class Module:
    id: str
    request: str
    dids: list[ModuleDid]
    response: str | None = None
    discover: list[tuple[str, str]] | None = None


@dataclass
class Profile:
    schema: int
    id: str
    name: str
    description: str
    protocol: str
    vehicles: list[str]
    sources: list[ProfileSource]
    modules: list[Module]


def _scan_for_vin_like(value: object, path: Path, context: str) -> None:
    if isinstance(value, str):
        if VIN_LIKE_PATTERN.fullmatch(value):
            raise ProfileError(
                path, context, "looks like a VIN; personal data must never appear in a profile"
            )
    elif isinstance(value, dict):
        for key, item in value.items():
            _scan_for_vin_like(item, path, f"{context}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_for_vin_like(item, path, f"{context}[{index}]")


def _check_keys(
    data: dict[str, object], allowed: set[str], required: set[str], path: Path, context: str
) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise ProfileError(path, context, f"unknown key(s): {', '.join(sorted(unknown))}")
    missing = required - set(data)
    if missing:
        raise ProfileError(path, context, f"missing required key(s): {', '.join(sorted(missing))}")


def _expect_str(data: dict[str, object], key: str, path: Path, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ProfileError(path, f"{context}.{key}", "must be a non-empty string")
    return value


def _load_sources(raw: object, path: Path) -> list[ProfileSource]:
    if not isinstance(raw, list) or not raw:
        raise ProfileError(path, "sources", "must be a non-empty list")
    sources: list[ProfileSource] = []
    for index, entry in enumerate(raw):
        context = f"sources[{index}]"
        if not isinstance(entry, dict):
            raise ProfileError(path, context, "must be a table")
        _check_keys(entry, {"title", "url", "license"}, {"title", "url", "license"}, path, context)
        sources.append(
            ProfileSource(
                title=_expect_str(entry, "title", path, context),
                url=_expect_str(entry, "url", path, context),
                license=_expect_str(entry, "license", path, context),
            )
        )
    return sources


def _load_discover(raw: object, path: Path, context: str) -> list[tuple[str, str]] | None:
    if raw is None:
        return None
    if not isinstance(raw, list) or not raw:
        raise ProfileError(
            path, f"{context}.discover", "must be a non-empty list of [start, end] pairs"
        )
    ranges: list[tuple[str, str]] = []
    total = 0
    for index, pair in enumerate(raw):
        sub = f"{context}.discover[{index}]"
        is_str_pair = (
            isinstance(pair, list) and len(pair) == 2 and all(isinstance(x, str) for x in pair)
        )
        if not is_str_pair:
            raise ProfileError(path, sub, "must be a [start, end] pair of 4-hex-digit strings")
        start, end = pair
        if not (PROFILE_DID_PATTERN.fullmatch(start) and PROFILE_DID_PATTERN.fullmatch(end)):
            raise ProfileError(path, sub, "start/end must be 4 hex digits")
        start_i, end_i = int(start, 16), int(end, 16)
        if start_i > end_i:
            raise ProfileError(path, sub, "start must be <= end")
        total += end_i - start_i + 1
        ranges.append((start, end))
    if total > MAX_SWEEP_DIDS:
        raise ProfileError(
            path, f"{context}.discover", f"{total} DIDs exceeds MAX_SWEEP_DIDS ({MAX_SWEEP_DIDS})"
        )
    return ranges


def _load_dids(raw: object, path: Path, context: str) -> list[ModuleDid]:
    if not isinstance(raw, list) or not raw:
        raise ProfileError(path, f"{context}.dids", "must be a non-empty list")
    dids: list[ModuleDid] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        sub = f"{context}.dids[{index}]"
        if not isinstance(entry, dict):
            raise ProfileError(path, sub, "must be a table")
        did_keys = {"did", "name", "status", "poll", "interval"}
        _check_keys(entry, did_keys, {"did", "status", "poll"}, path, sub)

        did = _expect_str(entry, "did", path, sub)
        if not PROFILE_DID_PATTERN.fullmatch(did):
            raise ProfileError(path, f"{sub}.did", "must be 4 hex digits")
        if did in VIN_DIDS:
            raise ProfileError(path, f"{sub}.did", "VIN DIDs must never be read")
        if did in seen:
            raise ProfileError(path, f"{sub}.did", f"duplicate DID {did!r} in module")
        seen.add(did)

        status = entry.get("status")
        if status not in PROFILE_STATUSES:
            raise ProfileError(path, f"{sub}.status", f"must be one of {sorted(PROFILE_STATUSES)}")

        poll = entry.get("poll")
        if poll not in PROFILE_POLL_MODES:
            raise ProfileError(path, f"{sub}.poll", f"must be one of {sorted(PROFILE_POLL_MODES)}")

        name = entry.get("name")
        if name is not None and (not isinstance(name, str) or not name):
            raise ProfileError(path, f"{sub}.name", "must be a non-empty string if present")
        if poll != "survey" and name is None:
            raise ProfileError(path, f"{sub}.name", 'required unless poll is "survey"')

        interval_raw = entry.get("interval")
        interval: float | None
        if poll in ("watch", "survey"):
            if (
                not isinstance(interval_raw, int | float)
                or isinstance(interval_raw, bool)
                or interval_raw < MIN_PROFILE_INTERVAL
            ):
                raise ProfileError(
                    path,
                    f"{sub}.interval",
                    f"required for watch/survey, must be a number >= {MIN_PROFILE_INTERVAL}",
                )
            interval = float(interval_raw)
        elif interval_raw is not None:
            raise ProfileError(path, f"{sub}.interval", "only allowed for poll watch/survey")
        else:
            interval = None

        dids.append(ModuleDid(did=did, name=name, status=status, poll=poll, interval=interval))
    return dids


def _load_modules(raw: object, protocol: str, path: Path) -> list[Module]:
    if not isinstance(raw, list) or not raw:
        raise ProfileError(path, "modules", "must be a non-empty list")
    modules: list[Module] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(raw):
        context = f"modules[{index}]"
        if not isinstance(entry, dict):
            raise ProfileError(path, context, "must be a table")
        _check_keys(
            entry,
            {"id", "request", "response", "discover", "dids"},
            {"id", "request", "dids"},
            path,
            context,
        )

        module_id = _expect_str(entry, "id", path, context)
        if module_id in seen_ids:
            raise ProfileError(path, f"{context}.id", f"duplicate module id {module_id!r}")
        seen_ids.add(module_id)

        request = _expect_str(entry, "request", path, context)
        if HEADER_29BIT_REQUEST_PATTERN.fullmatch(request):
            if protocol != "7":
                raise ProfileError(
                    path, f"{context}.request", '29-bit header requires profile protocol "7"'
                )
        elif HEADER_11BIT_PATTERN.fullmatch(request):
            if int(request, 16) > 0x7FF:
                raise ProfileError(path, f"{context}.request", "11-bit header must be <= 7FF")
        else:
            raise ProfileError(
                path, f"{context}.request", "must be 3 hex digits (<= 7FF) or 18DAxxF1"
            )

        response = entry.get("response")
        if response is not None and (
            not isinstance(response, str)
            or not (
                HEADER_11BIT_PATTERN.fullmatch(response)
                or HEADER_29BIT_RESPONSE_PATTERN.fullmatch(response)
            )
        ):
            raise ProfileError(path, f"{context}.response", "must be 3 hex digits or 18DAF1xx")

        discover = _load_discover(entry.get("discover"), path, context)
        dids = _load_dids(entry.get("dids"), path, context)

        modules.append(
            Module(id=module_id, request=request, response=response, discover=discover, dids=dids)
        )
    return modules


def load_profile(path: Path) -> Profile:
    """Loads and validates one vehicle profile. Profiles are data only: they name
    addresses and DIDs, never commands, and `module_setup_commands`/the `22<did>`
    reads built from them still go through `check_sweep_allowed` like any other
    sweep traffic, so a profile can never introduce a service other than
    ReadDataByIdentifier (0x22) or a VIN read - the latter is rejected outright."""
    path = Path(path)
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ProfileError(path, "<file>", f"invalid TOML: {error}") from error
    except OSError as error:
        raise ProfileError(path, "<file>", str(error)) from error

    _scan_for_vin_like(raw, path, "<root>")

    root_keys = {
        "schema",
        "id",
        "name",
        "description",
        "protocol",
        "vehicles",
        "sources",
        "modules",
    }
    _check_keys(raw, root_keys, root_keys, path, "<root>")

    if raw.get("schema") != 1:
        raise ProfileError(path, "schema", "must be 1")

    profile_id = _expect_str(raw, "id", path, "<root>")
    if not PROFILE_ID_PATTERN.fullmatch(profile_id):
        raise ProfileError(path, "id", "must match [a-z0-9-]+")
    if profile_id != path.stem:
        raise ProfileError(path, "id", f"must equal the file stem {path.stem!r}")

    name = _expect_str(raw, "name", path, "<root>")
    description = _expect_str(raw, "description", path, "<root>")

    protocol = raw.get("protocol")
    if protocol not in FORCE_PROTOCOL:
        raise ProfileError(path, "protocol", f"must be one of {sorted(FORCE_PROTOCOL)}")

    vehicles = raw.get("vehicles")
    if (
        not isinstance(vehicles, list)
        or not vehicles
        or not all(isinstance(v, str) and v for v in vehicles)
    ):
        raise ProfileError(path, "vehicles", "must be a non-empty list of non-empty strings")

    sources = _load_sources(raw.get("sources"), path)
    modules = _load_modules(raw.get("modules"), protocol, path)

    return Profile(
        schema=1,
        id=profile_id,
        name=name,
        description=description,
        protocol=protocol,
        vehicles=list(vehicles),
        sources=sources,
        modules=modules,
    )


def resolve_profile(spec: str) -> Profile:
    """Resolves `--profile` either as a path to a profile file or as an id looked
    up in `profiles/` next to this script, then loads and validates it."""
    candidate = Path(spec)
    if not candidate.is_file():
        candidate = PROFILES_DIR / f"{spec}.toml"
    if not candidate.is_file():
        raise ProfileError(
            candidate, "<profile>", f"no profile found for {spec!r} (tried path and profiles/)"
        )
    return load_profile(candidate)


def module_setup_commands(module: Module) -> list[str]:
    """The AT header/filter/flow-control commands that put the adapter in a state
    to talk to one profile module - with flow control for a known response id, or
    plain receive-any for single-frame-only modules. Every command here still
    needs `check_sweep_allowed` before it is sent."""
    if module.response:
        return [
            f"ATSH{module.request}",
            f"ATCRA{module.response}",
            f"ATFCSH{module.request}",
            "ATFCSD300000",
            "ATFCSM1",
        ]
    return ["ATFCSM0", "ATAR", f"ATSH{module.request}"]


@dataclass
class ScheduledDid:
    """One profile DID due for repeated polling, keeping its owning module so the
    watch loop knows when a header re-setup is needed."""

    module: Module
    did: ModuleDid
    command: str
    interval: float

    @property
    def key(self) -> tuple[str, str]:
        return (self.module.id, self.did.did)


def build_watch_schedule(
    modules: list[Module], survey: bool, survey_interval: float
) -> list[ScheduledDid]:
    """The DIDs to poll repeatedly across all of a profile's modules: every `watch`
    DID at its own profile interval, plus every `survey` DID at `survey_interval`
    when `survey` is enabled."""
    schedule: list[ScheduledDid] = []
    for module in modules:
        for did in module.dids:
            if did.poll == "watch":
                assert did.interval is not None
                schedule.append(ScheduledDid(module, did, f"22{did.did}", did.interval))
            elif did.poll == "survey" and survey:
                schedule.append(ScheduledDid(module, did, f"22{did.did}", survey_interval))
    return schedule


@dataclass
class IsotpParse:
    messages: list[tuple[str, bytes]]
    malformed: bool
    incomplete: bool
    # Headers of frames that opened a multi-frame reply but never completed - a
    # "first frame" alone still proves an ECU answered, even with no decodable
    # message (see check_ecus11_allowed's discovery sweep).
    partial_headers: frozenset[str]


def parse_isotp(command: str, response: str) -> IsotpParse:
    """Reassemble explicit CAN ISO-TP frames while retaining responder headers."""
    text = response.upper()
    messages: list[tuple[str, bytes]] = []
    partial: dict[str, tuple[int, bytearray, int]] = {}
    malformed = False
    for line in text.splitlines():
        flat = re.sub(r"\s+", "", line)
        if not flat or flat == command or flat == "SEARCHING...":
            continue
        if not re.fullmatch(r"[0-9A-F]+", flat):
            malformed = True
            continue
        header_len = 3 if len(flat) % 2 else 8
        header, body = flat[:header_len], flat[header_len:]
        if (
            not body
            or len(body) % 2
            or int(header, 16) > (0x7FF if header_len == 3 else 0x1FFFFFFF)
        ):
            malformed = True
            continue
        data = bytes.fromhex(body)
        if len(data) > 8:
            malformed = True
            continue
        kind = data[0] >> 4
        if kind == 0:
            size = data[0] & 0xF
            if not 1 <= size <= 7 or len(data) < size + 1 or header in partial:
                malformed = True
            else:
                messages.append((header, data[1 : size + 1]))
        elif kind == 1 and len(data) == 8:
            size = ((data[0] & 0xF) << 8) | data[1]
            if size <= 7 or header in partial:
                malformed = True
            else:
                partial[header] = (size, bytearray(data[2:]), 1)
        elif kind == 2 and header in partial:
            size, payload, sequence = partial[header]
            if data[0] & 0xF != sequence or len(data) < 2:
                malformed = True
                continue
            payload.extend(data[1:])
            if len(payload) >= size:
                messages.append((header, bytes(payload[:size])))
                del partial[header]
            else:
                partial[header] = (size, payload, (sequence + 1) % 16)
        else:
            malformed = True
    return IsotpParse(messages, malformed, bool(partial), frozenset(partial))


def _responder_matches(header: str, pattern: str) -> bool:
    return len(header) == len(pattern) and all(
        expected == "X" or actual == expected
        for actual, expected in zip(header, pattern, strict=True)
    )


def classify(command: str, response: str, responder: str | None = None) -> str:
    text = response.upper()
    for marker in (
        "NO DATA",
        "CAN ERROR",
        "BUS INIT",
        "UNABLE TO CONNECT",
        "BUFFER FULL",
        "STOPPED",
        "?",
    ):
        if marker in text:
            return marker
    if command == "ATMA":
        return "MONITOR" if text.strip() else "EMPTY"
    if command.startswith(("AT", "ST")):
        lines = {line.strip() for line in text.splitlines()}
        if command == "ATZ":
            banner = any("ELM" in line or "OBDLINK" in line or "STN" in line for line in lines)
            return "OK" if banner else "UNMATCHED"
        if command in {"ATI", "STI", "STDI", "ATRV", "ATDPN"}:
            return "RESPONSE" if text.strip() else "EMPTY"
        return "OK" if "OK" in lines else "UNMATCHED"

    # Reassemble only explicit CAN ISO-TP frames. Unknown ELM formatting is evidence,
    # but cannot establish a successful vehicle response.
    parsed = parse_isotp(command, response)
    expected = bytes.fromhex(command)
    positive = bytes([expected[0] + 0x40]) + expected[1:]
    pending = False
    matched = False
    terminal = None
    for header, message in parsed.messages:
        if (
            command.startswith("22")
            and responder is not None
            and not _responder_matches(header, responder)
        ):
            continue
        if command.startswith("01") and not (
            len(header) == 3
            and 0x7E8 <= int(header, 16) <= 0x7EF
            or len(header) == 8
            and header.startswith("18DAF1")
        ):
            continue
        if message[:2] == bytes([0x7F, expected[0]]) and len(message) == 3:
            code = f"{message[2]:02X}"
            if code == "78":
                pending = True
            else:
                terminal = f"NRC {code} {NRC_NAMES.get(code, '')}".strip()
        elif message.startswith(positive) and len(message) > len(positive):
            matched = True
    if terminal:
        return terminal
    if parsed.malformed or parsed.incomplete:
        return "MALFORMED"
    if matched:
        return "OK"
    return "PENDING" if pending else ("UNMATCHED" if text.strip() else "EMPTY")


def supported_pids(responses: list[str]) -> set[str]:
    """Collects mode-01 PIDs flagged in `41 xx` bitmap replies from any ECU."""
    found: set[str] = set()
    for response in responses:
        flat = re.sub(r"\s+", "", response.upper())
        for base, bitmap in re.findall(r"41(00|20|40|60|80|A0)([0-9A-F]{8})", flat):
            bits = int(bitmap, 16)
            for i in range(32):
                if bits & (1 << (31 - i)):
                    found.add(f"{int(base, 16) + i + 1:02X}")
    return found


def obduds_responders(response: str) -> list[str]:
    """Return regulated 29-bit responders that positively identify via F810."""
    responders = {
        header
        for header, payload in parse_isotp(f"22{OBDUDS_PROTOCOL_DID:04X}", response).messages
        if _responder_matches(header, OBDUDS_RESPONDER_PATTERN)
        and payload[:3] == bytes.fromhex("62F810")
        and len(payload) >= 4
        and payload[3] == 1
    }
    return sorted(responders)


def decode_positive_payload(command: str, response: str, responder: str) -> bytes | None:
    """Returns the data bytes of a positive ReadDataByIdentifier reply from one
    responder, or None if no matching positive response was found."""
    expected = bytes.fromhex(command)
    prefix = bytes([expected[0] + 0x40]) + expected[1:]
    for header, message in parse_isotp(command, response).messages:
        if _responder_matches(header, responder) and message.startswith(prefix):
            return message[len(prefix) :]
    return None


def obduds_supported_dids(command: str, response: str, responder: str) -> set[int]:
    """Decode one F4xx/F5xx support bitmap from a matching ECU response."""
    did = int(command[2:], 16)
    prefix = bytes([0x62, did >> 8, did & 0xFF])
    found: set[int] = set()
    for header, payload in parse_isotp(command, response).messages:
        if (
            _responder_matches(header, responder)
            and payload.startswith(prefix)
            and len(payload) >= 7
        ):
            bitmap = int.from_bytes(payload[3:7])
            for offset in range(1, 33):
                if bitmap & (1 << (32 - offset)):
                    found.add(did + offset)
    return found


@dataclass
class Exchange:
    command: str
    response: str
    status: str
    started_utc: str
    duration_ms: float


def note_exchange(text: str) -> Exchange:
    """Wraps a manually typed note (e.g. a display reading) as an Exchange so it
    lands in the same log, at the time it was typed, next to the polled DIDs."""
    return Exchange("NOTE", text, "NOTE", datetime.now(UTC).isoformat(), 0.0)


def _read_stdin_lines(loop: asyncio.AbstractEventLoop, notes: asyncio.Queue[str]) -> None:
    """Runs in a separate thread: sys.stdin.readline() blocks, so it can't live on
    the asyncio loop that's also driving the BLE session."""
    for line in sys.stdin:
        line = line.strip()
        if line:
            loop.call_soon_threadsafe(notes.put_nowait, line)


async def _drain_notes(notes: asyncio.Queue[str], record: Callable[[Exchange, str], None]) -> None:
    while True:
        line = await notes.get()
        record(note_exchange(line), "display")


@dataclass
class NoteReader:
    drain_task: asyncio.Task[None]

    async def stop(self) -> None:
        self.drain_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self.drain_task


def start_note_reader(record: Callable[[Exchange, str], None]) -> NoteReader:
    """Starts the background stdin thread + its draining task; call `.stop()` before
    the BLE connection closes. Freeform text, any format - nothing here parses it."""
    notes: asyncio.Queue[str] = asyncio.Queue()
    threading.Thread(
        target=_read_stdin_lines, args=(asyncio.get_running_loop(), notes), daemon=True
    ).start()
    return NoteReader(asyncio.create_task(_drain_notes(notes, record)))


@dataclass
class LiveValue:
    """Last known value for one polled command, with its own fetch time so a
    consumer (terminal summary today, an app later) can show age and never has
    to block waiting for a fresher read - see `build_watch_schedule`."""

    response: str
    status: str
    fetched_monotonic: float

    def age_seconds(self, now: float | None = None) -> float:
        return (now if now is not None else time.monotonic()) - self.fetched_monotonic


def format_live_summary(latest: dict[str, LiveValue]) -> str:
    now = time.monotonic()
    parts = [f"{cmd}={v.status}(+{v.age_seconds(now):.0f}s)" for cmd, v in sorted(latest.items())]
    return "live: " + (" ".join(parts) if parts else "-")


def _due_commands[K](next_due: dict[K, float], now: float) -> list[K]:
    return [key for key, t in next_due.items() if t <= now]


class ElmSession:
    """One outstanding command at a time; a reply ends at the `>` prompt."""

    def __init__(self, write: Callable[[bytes], Awaitable[None]], chunk_size: int):
        self._write = write
        self._chunk_size = max(1, chunk_size)
        self._buffer = bytearray()
        self._data = asyncio.Event()
        self._truncated = False
        self.usable = True

    def on_notify(self, data: bytes) -> None:
        if len(self._buffer) + len(data) > MAX_RESPONSE_BYTES:
            data = data[: MAX_RESPONSE_BYTES - len(self._buffer)]
            self._truncated = True
        self._buffer.extend(data)
        self._data.set()

    async def _send_raw(self, payload: bytes) -> None:
        for i in range(0, len(payload), self._chunk_size):
            await self._write(payload[i : i + self._chunk_size])

    async def _read_until_prompt(self, deadline: float) -> tuple[str, bool]:
        while True:
            if self._truncated or len(self._buffer) >= MAX_RESPONSE_BYTES:
                raise BufferError("response buffer limit exceeded")
            if PROMPT in self._buffer:
                if self._buffer.split(PROMPT, 1)[1].strip():
                    raise BufferError("unexpected bytes after response prompt")
                return self._take(), True
            remaining = deadline - time.monotonic()
            if remaining <= 0 or len(self._buffer) >= MAX_RESPONSE_BYTES:
                return self._take(), False
            self._data.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._data.wait(), remaining)

    def _take(self) -> str:
        raw = bytes(self._buffer)
        self._buffer.clear()
        if self._truncated:
            self._truncated = False
            raw += b"\n[truncated]"
        return raw.decode("ascii", errors="replace").replace(">", "").strip()

    async def drain(self, settle: float = 0.3) -> str:
        """Discards anything still arriving, e.g. a late reply after a timeout."""
        await asyncio.sleep(settle)
        return self._take()

    async def run(
        self,
        command: str,
        validator: Callable[[str], str] = check_allowed,
        responder: str | None = None,
    ) -> Exchange:
        cmd = validator(command)
        if not self.usable:
            raise RuntimeError("session lost synchronization; reconnect before retrying")
        stale = ""
        started = datetime.now(UTC).isoformat()
        t0 = time.monotonic()
        response = ""
        timeout = (
            MONITOR_SECONDS + MONITOR_STOP_TIMEOUT
            if cmd == "ATMA"
            else SLOW_COMMANDS.get(cmd, DEFAULT_TIMEOUT)
        )
        try:
            async with asyncio.timeout(timeout):
                if self._truncated:
                    raise BufferError("response buffer limit exceeded before send")
                stale = await self.drain(0.05)
                await self._send_raw(cmd.encode("ascii") + b"\r")
                if cmd == "ATMA":
                    await asyncio.sleep(MONITOR_SECONDS)
                    await self._send_raw(b"\r")
                response, prompt_seen = await self._read_until_prompt(t0 + timeout)
                if not prompt_seen:
                    raise TimeoutError
            status = classify(cmd, response, responder)
        except asyncio.CancelledError:
            self.usable = False
            raise
        except Exception as error:
            self.usable = False
            response += self._take()
            status = "TIMEOUT" if isinstance(error, TimeoutError) else "TRANSPORT_ERROR"
            response += f"\n[{type(error).__name__}] {error}"
        duration = (time.monotonic() - t0) * 1000
        if stale:
            response = f"[stale before send] {stale}\n{response}"
        return Exchange(cmd, response, status, started, round(duration, 1))


async def scan(seconds: float) -> None:
    from bleak import BleakScanner

    devices = await BleakScanner.discover(timeout=seconds, return_adv=True)
    for device, adv in devices.values():
        uuids = [u.lower() for u in adv.service_uuids]
        marker = "  <- OBD UART service" if UART_SERVICE in uuids else ""
        print(f"{device.address}  {adv.rssi:4d} dBm  {device.name or '?'}{marker}")


class ProbeAbortedError(Exception):
    pass


# AT commands whose non-OK reply doesn't abort a probe: informational banners/
# voltage/protocol-name queries, and ATMA, which never replies OK.
DEFAULT_NON_CRITICAL_AT = frozenset({"ATI", "ATRV", "ATDPN", "ATMA"})


@dataclass
class AdapterLink:
    """One connected BLE UART adapter, wired up for ELM327/STN command/response
    traffic and JSONL logging. Yielded by `connect_adapter`."""

    session: ElmSession
    record: Callable[[Exchange, str], None]
    non_critical_at: frozenset[str] = DEFAULT_NON_CRITICAL_AT

    async def execute(
        self,
        command: str,
        stage: str,
        validator: Callable[[str], str] = check_allowed,
        responder: str | None = None,
    ) -> Exchange:
        """Runs and logs `command`; fails closed by raising ProbeAbortedError if the
        session became unusable or a critical AT command did not come back OK."""
        ex = await self.session.run(command, validator, responder)
        self.record(ex, stage)
        critical = command.startswith("AT") and command not in self.non_critical_at
        if not self.session.usable or (critical and ex.status != "OK"):
            raise ProbeAbortedError(f"{command}: {ex.status}; disconnect and retry")
        return ex


@contextlib.asynccontextmanager
async def connect_adapter(
    address: str,
    pair: bool,
    log_path: Path,
    label: str,
    non_critical_at: frozenset[str] = DEFAULT_NON_CRITICAL_AT,
    extra_fields: dict[str, object] | None = None,
) -> AsyncIterator[AdapterLink | None]:
    """Connects to the BLE UART adapter and yields an AdapterLink shared by every
    mode - or None if the adapter has no UART write characteristic (wrong device),
    in which case the caller must return 2 without sending anything."""
    from bleak import BleakClient

    async with BleakClient(address, timeout=20.0) as client:
        chunk = max(20, client.mtu_size - 3)
        write_char = client.services.get_characteristic(UART_WRITE)
        if write_char is None:
            print("UART write characteristic not found - wrong device?", file=sys.stderr)
            yield None
            return
        with_response = "write-without-response" not in write_char.properties
        session = ElmSession(
            lambda data: client.write_gatt_char(write_char, data, response=with_response), chunk
        )
        await client.start_notify(UART_NOTIFY, lambda _c, data: session.on_notify(bytes(data)))

        with log_path.open("a", encoding="utf-8") as log:

            def record(ex: Exchange, stage: str) -> None:
                entry = {
                    "stage": stage,
                    "state": label,
                    "mtu": client.mtu_size,
                    **ex.__dict__,
                    **(extra_fields or {}),
                }
                log.write(json.dumps(entry, ensure_ascii=False) + "\n")
                log.flush()
                first = ex.response.splitlines()[0] if ex.response else ""
                status = f"[{stage}] {ex.command:<14} {ex.status:<32} {ex.duration_ms:7.1f} ms"
                print(f"{status}  {first[:60]}")

            if pair:
                # The adapter may already be bonded from a previous run - pair()
                # raising then is expected, not a reason to abort the connection.
                try:
                    await client.pair()
                except Exception as error:
                    record(
                        Exchange(
                            "PAIR", str(error), "PAIR_FAILED", datetime.now(UTC).isoformat(), 0.0
                        ),
                        "connection",
                    )

            yield AdapterLink(session, record, non_critical_at)
        await client.stop_notify(UART_NOTIFY)


async def run_watch_loop(
    execute: Callable[[str, str, Callable[[str], str], str | None], Awaitable[Exchange]],
    schedule: list[ScheduledDid],
    deadline: float | None,
    watch_stage: str,
    survey_stage: str,
) -> None:
    """Polls `schedule` forever (`deadline=None`) or until `deadline`
    (a `time.monotonic()` value), grouping due DIDs by module so a header/filter
    re-setup (`module_setup_commands`) only runs when the module actually changes."""
    if not schedule:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(remaining)
        return
    next_due = dict.fromkeys((entry.key for entry in schedule), time.monotonic())
    by_key = {entry.key: entry for entry in schedule}
    latest: dict[str, LiveValue] = {}
    current_module_id: str | None = None
    while deadline is None or time.monotonic() < deadline:
        now = time.monotonic()
        due = sorted(_due_commands(next_due, now))
        if not due:
            await asyncio.sleep(min(1.0, min(next_due.values()) - now))
            continue
        for key in due:
            entry = by_key[key]
            if entry.module.id != current_module_id:
                for cmd in module_setup_commands(entry.module):
                    await execute(cmd, f"{watch_stage}-setup", check_sweep_allowed, None)
                current_module_id = entry.module.id
            stage = watch_stage if entry.did.poll == "watch" else survey_stage
            ex = await execute(entry.command, stage, check_sweep_allowed, entry.module.response)
            latest[entry.command] = LiveValue(ex.response, ex.status, time.monotonic())
            next_due[key] = time.monotonic() + entry.interval
        print(format_live_summary(latest))


async def _probe(
    address: str,
    stages: str,
    label: str,
    out_dir: Path,
    pair: bool,
    protocol: str | None = None,
    watch_seconds: float = 0.0,
    profile: Profile | None = None,
) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"didscout_{stamp}_{label}.jsonl"

    async with connect_adapter(address, pair, log_path, label) as link:
        if link is None:
            return 2
        execute = link.execute

        print(
            "(notes - e.g. a reading off the display - type any time + Enter, "
            "land timestamped in the same log)"
        )
        note_reader = start_note_reader(link.record)

        if "A" not in stages:
            for cmd in ADAPTER_SETUP:
                await execute(cmd, "setup")
        for stage in stages:
            if stage == "E":
                assert profile is not None  # enforced by argument parsing in main()
                for module in profile.modules:
                    for cmd in module_setup_commands(module):
                        await execute(cmd, stage, check_sweep_allowed)
                    for did in module.dids:
                        if did.poll in ("once", "watch"):
                            await execute(
                                f"22{did.did}", stage, check_sweep_allowed, module.response
                            )
                if watch_seconds > 0:
                    schedule = build_watch_schedule(
                        profile.modules, survey=False, survey_interval=0.0
                    )
                    await run_watch_loop(
                        execute, schedule, time.monotonic() + watch_seconds, "E-watch", "E-watch"
                    )
                continue
            commands = list(STAGES[stage])
            if stage == "B" and protocol is not None:
                commands[0] = FORCE_PROTOCOL[protocol]
            bitmaps: list[str] = []
            for cmd in commands:
                ex = await execute(cmd, stage)
                if stage == "C" and ex.status == "OK":
                    bitmaps.append(ex.response)
            if stage == "C":
                supported = supported_pids(bitmaps)
                print(f"[C] supported mode-01 PIDs: {' '.join(sorted(supported)) or '-'}")
                for pid, cmd in STAGE_C_CANDIDATES.items():
                    if pid in supported:
                        await execute(cmd, stage)
        await note_reader.stop()
    print(f"log: {log_path}")
    return 0


async def sweep_range(
    session: ElmSession,
    record: Callable[[Exchange, str], None],
    start_i: int,
    end_i: int,
    stage: str = "sweep",
    responder: str | None = None,
) -> list[tuple[str, str]]:
    """Reads 22<DID> for every DID in [start_i, end_i] under whatever header/filter
    is currently set on `session`. Caller is responsible for ATSH/ATCRA/flow control."""
    hits: list[tuple[str, str]] = []
    for did in range(start_i, end_i + 1):
        cmd = f"22{did:04X}"
        if cmd[2:] in VIN_DIDS:
            print(f"[{stage}] {cmd} skipped (VIN, never read)")
            continue
        ex = await session.run(cmd, check_sweep_allowed, responder)
        record(ex, stage)
        if ex.status not in ("NO DATA", "NRC 31 requestOutOfRange"):
            hits.append((cmd, ex.status))
    return hits


async def obduds_discover(
    execute: Callable[[str, str, str | None], Awaitable[Exchange]],
) -> list[str]:
    """Runs the SAE J1979-2 functional-request discovery (ATSP7, functional header,
    22F810) and returns the positively-identifying 29-bit responders. Shared by
    `obduds_probe`, `identify`, and `sweep --obduds-ecus`."""
    await execute("ATSP7", "obduds-setup", None)
    await execute("ATDPN", "obduds-setup", None)
    await execute("ATAR", "obduds-setup", None)
    await execute(f"ATSH{OBDUDS_FUNCTIONAL_HEADER}", "obduds-setup", None)
    protocol = await execute(
        f"22{OBDUDS_PROTOCOL_DID:04X}", "obduds-discovery", OBDUDS_RESPONDER_PATTERN
    )
    return obduds_responders(protocol.response)


async def obduds_collect_supported_dids(
    execute: Callable[[str, str, str | None], Awaitable[Exchange]],
    responder: str,
    ecu: str,
) -> list[int]:
    """Walks one responder's F400/F420/... support bitmaps, following chained
    continuation bits, and returns the announced current-data DIDs (F4xx/F5xx).
    Shared by `obduds_probe` and `record`'s `obduds` inventory stage."""
    supported: set[int] = set()
    base = OBDUDS_FIRST_SUPPORT_DID
    while base <= OBDUDS_LAST_SUPPORT_DID:
        command = f"22{base:04X}"
        ex = await execute(command, f"obduds-support-{ecu}", responder)
        if ex.status != "OK":
            break
        announced = obduds_supported_dids(command, ex.response, responder)
        supported.update(announced)
        next_base = base + 0x20
        if next_base not in announced:
            break
        base = next_base
    return sorted(did for did in supported if did & 0x1F)


async def read_identify_dids(
    execute: Callable[[str, str, str | None], Awaitable[Exchange]],
    responder: str,
    ecu: str,
) -> dict[str, str]:
    """Reads the four ECU identification DIDs (never the serial number or any
    VIN) for one responder; F197 is decoded as ascii, everything else reported
    as its exchange status. Shared by `identify` and `record`'s inventory
    stages."""
    values: dict[str, str] = {}
    for did in sorted(IDENTIFY_DIDS):
        command = f"22{did}"
        ex = await execute(command, f"identify-{ecu}", responder)
        if did == "F197" and ex.status == "OK":
            payload = decode_positive_payload(command, ex.response, responder)
            value = payload.decode("ascii", errors="replace") if payload else ex.status
        else:
            value = ex.status
        values[did] = value
    return values


async def obduds_select_responder(
    execute: Callable[[str, str, str | None], Awaitable[Exchange]],
    responder: str,
    stage: str,
) -> str:
    """Sets header/filter/flow-control for one 29-bit OBDonUDS responder, exactly as
    `obduds_probe` does; returns the responder's two-hex ECU id. Shared by
    `obduds_probe`, `identify`, and `sweep --obduds-ecus`."""
    ecu = responder[-2:]
    request = f"18DA{ecu}F1"
    await execute(f"ATSH{request}", stage, None)
    await execute(f"ATCRA{responder}", stage, None)
    await execute(f"ATFCSH{request}", stage, None)
    await execute("ATFCSD300000", stage, None)
    await execute("ATFCSM1", stage, None)
    return ecu


async def sweep(
    address: str,
    header: str | None,
    rax: str | None,
    start: str,
    end: str,
    label: str,
    out_dir: Path,
    pair: bool,
    protocol: str | None,
    obduds_ecus: bool = False,
) -> int:
    """Brute-forces ReadDataByIdentifier (22 xx xx) over [start, end], either at one
    fixed header or, with `obduds_ecus`, at every regulated 29-bit ECU discovered via
    SAE J1979-2. Only service 0x22 ever leaves check_sweep_allowed, so this can't
    drift into a write/reset/security service regardless of the DID range."""
    start_i, end_i = int(start, 16), int(end, 16)
    if not (0 <= start_i <= end_i <= 0xFFFF):
        print("--start/--end must be 0000-FFFF with start <= end", file=sys.stderr)
        return 2
    count = end_i - start_i + 1
    if not obduds_ecus and count > MAX_SWEEP_DIDS:
        print(
            f"{count} DIDs exceeds MAX_SWEEP_DIDS ({MAX_SWEEP_DIDS}) - split the range",
            file=sys.stderr,
        )
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = "obduds-ecus" if obduds_ecus else header
    log_path = out_dir / f"didscout_{stamp}_{label}_sweep{suffix}.jsonl"

    async with connect_adapter(address, pair, log_path, label, frozenset({"ATDPN"})) as link:
        if link is None:
            return 2
        session = link.session
        record = link.record

        if obduds_ecus:
            result = 0
            hits: list[tuple[str, str]] = []

            async def execute(command: str, stage: str, responder: str | None = None) -> Exchange:
                return await link.execute(command, stage, check_obduds_allowed, responder)

            try:
                for cmd in ADAPTER_SETUP:
                    await execute(cmd, "setup")
                responders = await obduds_discover(execute)
                print(f"[sweep] regulated responders: {' '.join(responders) or '-'}")
                if not responders:
                    result = 2
                elif count * len(responders) > MAX_SWEEP_DIDS:
                    print(
                        f"{count} DIDs x {len(responders)} ECUs exceeds MAX_SWEEP_DIDS "
                        f"({MAX_SWEEP_DIDS}) - split the range",
                        file=sys.stderr,
                    )
                    result = 2
                else:
                    for responder in responders:
                        ecu = await obduds_select_responder(execute, responder, "setup")
                        hits.extend(
                            await sweep_range(
                                session, record, start_i, end_i, f"sweep-{ecu}", responder
                            )
                        )
            except ProbeAbortedError as error:
                print(f"sweep --obduds-ecus aborted: {error}", file=sys.stderr)
                result = 2
            finally:
                if session.usable:
                    for cmd in ("ATFCSM0", "ATAR", "ATD"):
                        record(await session.run(cmd, check_obduds_allowed), "cleanup")
        else:
            result = 0
            for cmd in ADAPTER_SETUP:
                record(await session.run(cmd), "setup")
            record(await session.run(FORCE_PROTOCOL[protocol] if protocol else "ATSP0"), "setup")
            record(await session.run(f"ATSH{header}", check_sweep_allowed), "setup")
            if rax:
                record(await session.run(f"ATCRA{rax}", check_sweep_allowed), "setup")
                record(await session.run(f"ATFCSH{header}", check_sweep_allowed), "setup")
                record(await session.run("ATFCSD300000"), "setup")
                record(await session.run("ATFCSM1"), "setup")

            hits = await sweep_range(session, record, start_i, end_i, responder=rax)

            if rax:
                record(await session.run("ATFCSM0"), "cleanup")
            record(await session.run("ATAR"), "cleanup")
            record(await session.run("ATD"), "cleanup")
    print(f"log: {log_path}")
    print(f"hits: {hits or '-'}")
    return result


async def obduds_probe(
    address: str,
    label: str,
    out_dir: Path,
    pair: bool,
    support_only: bool,
) -> int:
    """Discover regulated UDS ECUs, then read only their advertised F4xx/F5xx DIDs."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"didscout_{stamp}_{label}_obduds.jsonl"
    result = 0

    async with connect_adapter(address, pair, log_path, label, frozenset({"ATDPN"})) as link:
        if link is None:
            return 2

        async def execute(command: str, stage: str, responder: str | None = None) -> Exchange:
            return await link.execute(command, stage, check_obduds_allowed, responder)

        try:
            for cmd in ADAPTER_SETUP:
                await execute(cmd, "obduds-setup")
            responders = await obduds_discover(execute)
            print(f"[obduds] regulated responders: {' '.join(responders) or '-'}")
            if not responders:
                result = 2

            for responder in responders:
                ecu = await obduds_select_responder(execute, responder, "obduds-setup")

                data_dids = await obduds_collect_supported_dids(execute, responder, ecu)
                print(
                    f"[obduds {responder}] supported data DIDs: "
                    f"{' '.join(f'{did:04X}' for did in data_dids) or '-'}"
                )
                if support_only:
                    continue
                if len(data_dids) > OBDUDS_MAX_DATA_DIDS:
                    raise ProbeAbortedError(
                        f"{responder} announced {len(data_dids)} DIDs; "
                        f"limit is {OBDUDS_MAX_DATA_DIDS}"
                    )
                for did in data_dids:
                    await execute(f"22{did:04X}", f"obduds-data-{ecu}", responder)
        except ProbeAbortedError as error:
            print(f"OBDonUDS probe aborted: {error}", file=sys.stderr)
            result = 2
        finally:
            if link.session.usable:
                for cmd in ("ATFCSM0", "ATAR", "ATD"):
                    ex = await link.session.run(cmd, check_obduds_allowed)
                    link.record(ex, "obduds-cleanup")
    print(f"log: {log_path}")
    return result


async def identify(
    address: str,
    label: str,
    out_dir: Path,
    pair: bool,
) -> int:
    """Discover regulated 29-bit OBDonUDS ECUs, then read only each one's spare part
    number, software version, hardware number, and system name (never the serial
    number or any VIN) via check_identify_allowed."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"didscout_{stamp}_{label}_identify.jsonl"
    result = 0

    async with connect_adapter(address, pair, log_path, label, frozenset({"ATDPN"})) as link:
        if link is None:
            return 2

        async def execute(command: str, stage: str, responder: str | None = None) -> Exchange:
            return await link.execute(command, stage, check_identify_allowed, responder)

        try:
            for cmd in ADAPTER_SETUP:
                await execute(cmd, "identify-setup")
            responders = await obduds_discover(execute)
            print(f"[identify] regulated responders: {' '.join(responders) or '-'}")
            if not responders:
                result = 2

            for responder in responders:
                ecu = await obduds_select_responder(execute, responder, "identify-setup")
                values = await read_identify_dids(execute, responder, ecu)
                summary = [f"{did}={value}" for did, value in values.items()]
                print(f"[identify {responder}] " + " ".join(summary))
        except ProbeAbortedError as error:
            print(f"identify aborted: {error}", file=sys.stderr)
            result = 2
        finally:
            if link.session.usable:
                for cmd in ("ATFCSM0", "ATAR", "ATD"):
                    ex = await link.session.run(cmd, check_identify_allowed)
                    link.record(ex, "identify-cleanup")
    print(f"log: {log_path}")
    return result


RECORD_STATE_SCHEMA = 1


class RunState:
    """Typed accessor over `record`'s persisted `state.json` - a plain dict so
    the file stays ordinary JSON, never pickled."""

    def __init__(self, data: dict[str, object]) -> None:
        self.data = data

    @classmethod
    def new(cls, label: str, address: str | None) -> RunState:
        return cls(
            {
                "schema": RECORD_STATE_SCHEMA,
                "label": label,
                "created_utc": datetime.now(UTC).isoformat(),
                "address": address,
                "finished": False,
                "stages": {},
                "results": {},
            }
        )

    @classmethod
    def load(cls, path: Path) -> RunState:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        if data.get("schema") != RECORD_STATE_SCHEMA:
            raise ValueError(f"{path}: unsupported state schema {data.get('schema')!r}")
        return cls(data)

    def save(self, path: Path) -> None:
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, path)

    @property
    def label(self) -> str:
        return self.data["label"]  # type: ignore[return-value]

    @property
    def address(self) -> str | None:
        return self.data.get("address")  # type: ignore[return-value]

    @address.setter
    def address(self, value: str | None) -> None:
        self.data["address"] = value

    @property
    def finished(self) -> bool:
        return bool(self.data["finished"])

    def mark_finished(self) -> None:
        self.data["finished"] = True

    def stage_status(self, stage: str) -> str | None:
        return self.data["stages"].get(stage)  # type: ignore[union-attr]

    def mark_stage(self, stage: str, status: str) -> None:
        self.data["stages"][stage] = status  # type: ignore[index]

    def result(self, key: str, default: object = None) -> object:
        return self.data["results"].get(key, default)  # type: ignore[union-attr]

    def set_result(self, key: str, value: object) -> None:
        self.data["results"][key] = value  # type: ignore[index]


RECORD_RUN_DIR_PATTERN = re.compile(r"record_(\d{8}_\d{6})_(.+)")


def find_resumable_run(out_dir: Path, label: str) -> Path | None:
    """The newest run directory under `out_dir` (by its embedded timestamp) whose
    `state.json` is unfinished and carries the same label, or None if there is
    none - what `record` resumes unless `--new` is given."""
    if not out_dir.is_dir():
        return None
    candidates: list[tuple[str, Path]] = []
    for entry in out_dir.iterdir():
        match = RECORD_RUN_DIR_PATTERN.fullmatch(entry.name)
        if not entry.is_dir() or not match:
            continue
        state_path = entry / "state.json"
        if not state_path.is_file():
            continue
        try:
            state = RunState.load(state_path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if state.label == label and not state.finished:
            candidates.append((match.group(1), entry))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


async def _scan_uart_devices(seconds: float) -> list[tuple[str, int]]:
    from bleak import BleakScanner

    devices = await BleakScanner.discover(timeout=seconds, return_adv=True)
    found = [
        (device.address, adv.rssi)
        for device, adv in devices.values()
        if UART_SERVICE in [u.lower() for u in adv.service_uuids]
    ]
    found.sort(key=lambda item: item[1], reverse=True)
    return found


RECORD_SCAN_SECONDS = 8.0
RECORD_RESCAN_INTERVAL = 10.0


async def find_adapter_address(
    seconds: float = RECORD_SCAN_SECONDS, rescan_interval: float = RECORD_RESCAN_INTERVAL
) -> str:
    """Scans for a BLE device advertising the OBD UART service: the sole match if
    there is one, the strongest RSSI if several, or rescans every
    `rescan_interval` seconds until one appears - the adapter or vehicle may
    still be asleep."""
    while True:
        found = await _scan_uart_devices(seconds)
        if len(found) == 1:
            return found[0][0]
        if len(found) > 1:
            address, rssi = found[0]
            print(f"[record] multiple UART adapters found; using strongest: {address} ({rssi} dBm)")
            return address
        print(f"[record] no UART adapter found yet; rescanning every {rescan_interval:.0f}s...")
        await asyncio.sleep(rescan_interval)


async def _inventory_adapter(link: AdapterLink, state: RunState, _profile: Profile | None) -> None:
    values: dict[str, str] = {}
    for cmd in ("ATI", "STI", "STDI", "ATRV"):
        ex = await link.execute(cmd, "adapter")
        values[cmd] = ex.response
    state.set_result("adapter", values)


# Mode-01 current-data support bitmaps chain 0100 -> 0120 -> ... -> 01A0, each
# continuing only while the next base PID is flagged supported in the previous
# bitmap (see SAE J1979).
MODE01_BITMAP_BASES = ("00", "20", "40", "60", "80", "A0")


async def _inventory_protocol(
    link: AdapterLink, state: RunState, profile: Profile | None
) -> None:
    answered: list[str] = []
    for proto, cmd in (("6", "ATSP6"), ("7", "ATSP7")):
        await link.execute(cmd, "protocol")
        ex = await link.execute("0100", "protocol")
        await link.execute("ATDPN", "protocol")
        if ex.status == "OK":
            answered.append(proto)
    if profile is not None:
        chosen: str | None = profile.protocol
    elif "6" in answered:
        chosen = "6"
    elif "7" in answered:
        chosen = "7"
    else:
        chosen = None
    state.set_result("protocol", {"answered": answered, "chosen": chosen})


async def _inventory_mode01(link: AdapterLink, state: RunState, _profile: Profile | None) -> None:
    protocol_result = state.result("protocol")
    chosen = protocol_result.get("chosen") if isinstance(protocol_result, dict) else None
    if chosen:
        await link.execute(FORCE_PROTOCOL[chosen], "mode01", check_mode01_allowed)

    bitmaps: list[str] = []
    for index, base in enumerate(MODE01_BITMAP_BASES):
        ex = await link.execute(f"01{base}", "mode01", check_mode01_allowed)
        if ex.status != "OK":
            break
        bitmaps.append(ex.response)
        if index + 1 >= len(MODE01_BITMAP_BASES):
            break
        next_pid = MODE01_BITMAP_BASES[index + 1]
        if next_pid not in supported_pids([ex.response]):
            break

    supported = sorted(supported_pids(bitmaps))
    for pid in supported:
        await link.execute(f"01{pid}", "mode01", check_mode01_allowed)
    state.set_result("mode01", {"supported_pids": supported})


async def _inventory_obduds(link: AdapterLink, state: RunState, _profile: Profile | None) -> None:
    async def execute_obduds(command: str, stage: str, responder: str | None = None) -> Exchange:
        return await link.execute(command, stage, check_obduds_allowed, responder)

    async def execute_identify(command: str, stage: str, responder: str | None = None) -> Exchange:
        return await link.execute(command, stage, check_identify_allowed, responder)

    responders = await obduds_discover(execute_obduds)
    results: dict[str, object] = {}
    for responder in responders:
        ecu = await obduds_select_responder(execute_obduds, responder, "obduds-setup")
        data_dids = await obduds_collect_supported_dids(execute_obduds, responder, ecu)
        if len(data_dids) > OBDUDS_MAX_DATA_DIDS:
            raise ProbeAbortedError(
                f"{responder} announced {len(data_dids)} DIDs; limit is {OBDUDS_MAX_DATA_DIDS}"
            )
        for did in data_dids:
            await execute_obduds(f"22{did:04X}", f"obduds-data-{ecu}", responder)
        identify_values = await read_identify_dids(execute_identify, responder, ecu)
        results[responder] = {
            "ecu": ecu,
            "supported_dids": [f"{did:04X}" for did in data_dids],
            "identify": identify_values,
        }
        await execute_obduds("ATFCSM0", "obduds-cleanup", None)
    await execute_obduds("ATAR", "obduds-cleanup", None)
    await execute_obduds("ATD", "obduds-cleanup", None)
    state.set_result("obduds", results)


# 11-bit manufacturer-ECU request ids: 0x700-0x7EF, excluding the legislative
# functional broadcast 0x7DF (that belongs to mode 01/OBDonUDS, not here).
ECU11_REQUEST_IDS = [request for request in range(0x700, 0x7F0) if request != 0x7DF]


async def _inventory_ecus11(link: AdapterLink, state: RunState, profile: Profile | None) -> None:
    async def execute(command: str, stage: str, responder: str | None = None) -> Exchange:
        return await link.execute(command, stage, check_ecus11_allowed, responder)

    await execute("ATSP6", "ecus11-setup")
    await execute("ATDPN", "ecus11-setup")
    await execute("ATAR", "ecus11-setup")
    await execute("ATCF700", "ecus11-setup")
    await execute("ATCM700", "ecus11-setup")

    found: dict[str, str] = {}
    if profile is not None and profile.protocol == "6":
        for module in profile.modules:
            if HEADER_11BIT_PATTERN.fullmatch(module.request) and module.response:
                found.setdefault(module.request, module.response)

    for request in ECU11_REQUEST_IDS:
        req_hex = f"{request:03X}"
        await execute(f"ATSH{req_hex}", "ecus11-discovery")
        ex = await execute("22F189", "ecus11-discovery")
        parsed = parse_isotp("22F189", ex.response)
        seen = {header for header, _payload in parsed.messages} | parsed.partial_headers
        for header in seen:
            if header != req_hex:
                found[req_hex] = header
    await execute("ATAR", "ecus11-discovery-done")

    ecus: dict[str, object] = {}
    for request, response in sorted(found.items()):
        await execute(f"ATSH{request}", "ecus11-identify-setup")
        await execute(f"ATCRA{response}", "ecus11-identify-setup")
        await execute(f"ATFCSH{request}", "ecus11-identify-setup")
        await execute("ATFCSD300000", "ecus11-identify-setup")
        await execute("ATFCSM1", "ecus11-identify-setup")
        identify_values = await read_identify_dids(execute, response, request)
        ecus[request] = {"response": response, "identify": identify_values}
        await execute("ATFCSM0", "ecus11-identify-setup")

    await execute("ATAR", "ecus11-cleanup")
    state.set_result("ecus11", ecus)


INVENTORY_STAGE_ORDER = ("adapter", "protocol", "mode01", "obduds", "ecus11")
INVENTORY_STAGE_FUNCS: dict[
    str, Callable[[AdapterLink, RunState, Profile | None], Awaitable[None]]
] = {
    "adapter": _inventory_adapter,
    "protocol": _inventory_protocol,
    "mode01": _inventory_mode01,
    "obduds": _inventory_obduds,
    "ecus11": _inventory_ecus11,
}


def print_inventory_summary(state: RunState) -> None:
    protocol = state.result("protocol") or {}
    mode01 = state.result("mode01") or {}
    obduds = state.result("obduds") or {}
    ecus11 = state.result("ecus11") or {}
    assert isinstance(protocol, dict) and isinstance(mode01, dict)
    assert isinstance(obduds, dict) and isinstance(ecus11, dict)

    print()
    print("[record] inventory complete")
    print(f"  protocol: chosen={protocol.get('chosen')} answered={protocol.get('answered')}")
    print(f"  mode-01 PIDs: {' '.join(mode01.get('supported_pids', [])) or '-'}")
    if obduds:
        for responder, info in obduds.items():
            assert isinstance(info, dict)
            print(f"  OBDonUDS {responder}: {len(info.get('supported_dids', []))} DID(s)")
    else:
        print("  OBDonUDS: none found")
    if ecus11:
        for request, info in ecus11.items():
            assert isinstance(info, dict)
            name = info.get("identify", {}).get("F197", "-")
            print(f"  11-bit ECU {request} -> {info.get('response')}: F197={name}")
    else:
        print("  11-bit ECUs: none found")


RECORD_INITIAL_BACKOFF = 5.0
RECORD_MAX_BACKOFF = 60.0


def _log_connection_event(log_path: Path, label: str, status: str, detail: str = "") -> None:
    ex = Exchange("CONNECTION", detail, status, datetime.now(UTC).isoformat(), 0.0)
    entry = {"stage": "connection", "state": label, "mtu": None, "mode": "record", **ex.__dict__}
    with log_path.open("a", encoding="utf-8") as log:
        log.write(json.dumps(entry, ensure_ascii=False) + "\n")


async def record(
    address: str | None,
    profile: Profile | None,
    label: str,
    out_dir: Path,
    new: bool,
) -> int:
    """First half of `record`: connects (scanning if no address is given),
    maintains a resumable run directory, reconnects with backoff through BLE
    drops, and runs the one-time vehicle inventory (adapter, protocol, mode01,
    obduds, ecus11). Ends after the inventory - the continuous scheduler that
    plugs in after it is the next step."""
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = None if new else find_resumable_run(out_dir, label)
    if run_dir is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = out_dir / f"record_{stamp}_{label}"
        run_dir.mkdir(parents=True, exist_ok=True)
        state = RunState.new(label, address)
    else:
        print(f"[record] resuming {run_dir}")
        state = RunState.load(run_dir / "state.json")
        if address:
            state.address = address

    state_path = run_dir / "state.json"
    log_path = run_dir / "capture.jsonl"
    state.save(state_path)

    failures: dict[str, int] = {}
    pair_pending = True
    backoff = RECORD_INITIAL_BACKOFF

    while True:
        try:
            resolved = state.address or await find_adapter_address()
            if resolved != state.address:
                state.address = resolved
                state.save(state_path)

            async with connect_adapter(
                resolved, pair_pending, log_path, label, extra_fields={"mode": "record"}
            ) as link:
                if link is None:
                    return 2
                pair_pending = False
                _log_connection_event(log_path, label, "CONNECTED")
                for cmd in ADAPTER_SETUP:
                    await link.execute(cmd, "setup")

                for stage in INVENTORY_STAGE_ORDER:
                    if state.stage_status(stage) in ("done", "failed"):
                        continue
                    try:
                        await INVENTORY_STAGE_FUNCS[stage](link, state, profile)
                    except ProbeAbortedError as error:
                        failures[stage] = failures.get(stage, 0) + 1
                        link.record(
                            Exchange(
                                "STAGE_FAILURE",
                                str(error),
                                "STAGE_FAILURE",
                                datetime.now(UTC).isoformat(),
                                0.0,
                            ),
                            stage,
                        )
                        if failures[stage] >= 3:
                            state.mark_stage(stage, "failed")
                            state.save(state_path)
                            continue
                        raise
                    else:
                        state.mark_stage(stage, "done")
                        state.save(state_path)
                        failures[stage] = 0
                else:
                    state.mark_finished()
                    state.save(state_path)
                    print_inventory_summary(state)
                    return 0
        except ProbeAbortedError as error:
            _log_connection_event(log_path, label, "DISCONNECTED", str(error))
        except Exception as error:
            # Anything else here is a connection/transport failure (BLE connect
            # timeout, OS-level disconnect, ...) - reconnect rather than crash.
            _log_connection_event(log_path, label, "DISCONNECTED", str(error))

        _log_connection_event(log_path, label, "RECONNECTING")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2.0, RECORD_MAX_BACKOFF)
        if address is None:
            state.address = None


async def run_session(
    address: str,
    label: str,
    out_dir: Path,
    pair: bool,
    protocol: str | None,
    profile: Profile | None = None,
    survey: bool = False,
    survey_interval: float = 60.0,
) -> int:
    """One continuous log for a whole outing (ignition on -> driving -> charging ->
    driving home): a single thorough pass (adapter, protocol, legislative OBD, then -
    with a profile - every module's one-shot DIDs and discovery sweeps), then an
    indefinite watch-DID poll that only stops on Ctrl-C - so the whole trip ends up
    in one log file instead of several `probe`/`sweep` runs. Without `profile`, stage
    E and the watch loop are skipped entirely; the adapter/protocol/mode-01 parts
    still run."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"didscout_{stamp}_{label}.jsonl"
    cancelled = False

    async with connect_adapter(address, pair, log_path, label) as link:
        if link is None:
            return 2
        session = link.session
        record = link.record

        async def execute(
            command: str,
            stage: str,
            validator: Callable[[str], str] = check_allowed,
            responder: str | None = None,
        ) -> Exchange:
            ex = await session.run(command, validator, responder)
            record(ex, stage)
            return ex

        note_reader = start_note_reader(record)

        for cmd in ADAPTER_SETUP:
            await execute(cmd, "setup")
        for cmd in ("ATI", "STI", "STDI", "ATRV"):
            await execute(cmd, "A")
        await execute(FORCE_PROTOCOL[protocol] if protocol else "ATSP0", "B")
        await execute("0100", "B")
        await execute("ATDPN", "B")

        bitmaps: list[str] = []
        for cmd in STAGES["C"]:
            ex = await execute(cmd, "C")
            bitmaps.append(ex.response)
        supported = supported_pids(bitmaps)
        print(f"[C] supported mode-01 PIDs: {' '.join(sorted(supported)) or '-'}")
        for pid, cmd in STAGE_C_CANDIDATES.items():
            if pid in supported:
                await execute(cmd, "C")

        if profile is not None:
            for module in profile.modules:
                for cmd in module_setup_commands(module):
                    await execute(cmd, "E", check_sweep_allowed)
                for did in module.dids:
                    if did.poll in ("once", "watch"):
                        await execute(f"22{did.did}", "E", check_sweep_allowed, module.response)
                for start, end in module.discover or []:
                    await sweep_range(
                        session,
                        record,
                        int(start, 16),
                        int(end, 16),
                        f"sweep-{module.id}",
                        module.response,
                    )

            print()
            print(
                "Now type and Enter: state of charge, odometer, outside temperature, "
                "battery temperature - then drive. Keeps running in the background, "
                "press Ctrl-C after the drive home to stop."
            )
            print()

        schedule = build_watch_schedule(profile.modules, survey, survey_interval) if profile else []
        try:
            await run_watch_loop(execute, schedule, None, "E-watch", "E-survey")
        except asyncio.CancelledError:
            cancelled = True
            print("\n[session] Ctrl-C detected, shutting down cleanly...")
        finally:
            end_status = "CANCELLED" if cancelled else "COMPLETE"
            record(
                Exchange(
                    "SESSION_END",
                    "Ctrl-C" if cancelled else "watch ended",
                    end_status,
                    datetime.now(UTC).isoformat(),
                    0.0,
                ),
                "session",
            )
            for cmd in ("ATFCSM0", "ATAR", "ATD"):
                if not session.usable:
                    break
                record(await session.run(cmd), "cleanup")
            await note_reader.stop()
    print(f"log: {log_path}")
    return 130 if cancelled else 0


async def probe(
    address: str,
    stages: str,
    label: str,
    out_dir: Path,
    pair: bool,
    protocol: str | None = None,
    watch_seconds: float = 0.0,
    profile: Profile | None = None,
) -> int:
    try:
        return await _probe(address, stages, label, out_dir, pair, protocol, watch_seconds, profile)
    except ProbeAbortedError as error:
        print(f"Probe aborted: {error}", file=sys.stderr)
        return 2


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("scan", help="list nearby BLE devices")
    s.add_argument("--seconds", type=float, default=8.0)
    r = sub.add_parser(
        "record",
        help="one start, then autonomous: connect, maintain a resumable run, and run the "
        "one-time vehicle inventory (the continuous scheduler is a later step)",
    )
    r.add_argument("address", nargs="?", help="BLE address; omit to scan for a UART adapter")
    r.add_argument("--profile", help="vehicle profile id (profiles/<id>.toml) or path")
    r.add_argument("--label", default="vehicle", help="run label (default: vehicle)")
    r.add_argument("--out", type=Path, default=Path(__file__).parent / "logs")
    r.add_argument(
        "--new", action="store_true", help="start a fresh run instead of resuming an unfinished one"
    )
    p = sub.add_parser("probe", help="run allow-listed stages against the adapter")
    p.add_argument("address", help="BLE address from `scan`")
    p.add_argument(
        "--stages", default="ABCE", help="subset of ABCDE, in order (D = 10 s bus monitor)"
    )
    p.add_argument(
        "--state",
        required=True,
        help="vehicle state label, e.g. ignitionOn, readyToDrive, charging",
    )
    p.add_argument("--out", type=Path, default=Path(__file__).parent / "logs")
    p.add_argument(
        "--pair", action="store_true", help="bond first (within 5 min of plugging in the adapter)"
    )
    p.add_argument(
        "--protocol",
        choices=sorted(FORCE_PROTOCOL),
        help="force CAN protocol instead of ATSP0 auto-detect: 6 = 11-bit/500k, 7 = 29-bit/500k",
    )
    p.add_argument(
        "--watch-seconds",
        type=float,
        default=0.0,
        help="after stage E's one-shot reads, poll every profile DID marked watch at its own "
        "interval for this long (e.g. during AC charging)",
    )
    p.add_argument(
        "--profile", help="vehicle profile id (profiles/<id>.toml) or path; required for stage E"
    )
    w = sub.add_parser(
        "sweep",
        help="brute-force 22 xx xx (ReadDataByIdentifier) over a bounded DID range at one "
        "header - read-only, never any other service, see check_sweep_allowed",
    )
    w.add_argument("address", help="BLE address from `scan`")
    w.add_argument(
        "--header",
        help="3-hex-digit (11-bit) or 18DAxxF1 (29-bit) request header; omit with --obduds-ecus",
    )
    w.add_argument(
        "--rax",
        help="response id (ATCRA): 3 hex digits, or 18DAF1xx for a 29-bit --header; omit if "
        "unknown (11-bit) or to use the derived default (29-bit)",
    )
    w.add_argument(
        "--obduds-ecus",
        action="store_true",
        help="discover regulated 29-bit OBDonUDS ECUs (as `obduds` does) and sweep the range "
        "at each one instead of a fixed --header/--rax",
    )
    w.add_argument("--start", required=True, help="first DID, 4 hex digits, e.g. 2A00")
    w.add_argument("--end", required=True, help="last DID, inclusive, 4 hex digits, e.g. 2AFF")
    w.add_argument(
        "--state",
        required=True,
        help="vehicle state label, e.g. ignitionOn, readyToDrive, charging",
    )
    w.add_argument("--out", type=Path, default=Path(__file__).parent / "logs")
    w.add_argument(
        "--pair", action="store_true", help="bond first (within 5 min of plugging in the adapter)"
    )
    w.add_argument(
        "--protocol",
        choices=sorted(FORCE_PROTOCOL),
        help="force CAN protocol instead of ATSP0 auto-detect: 6 = 11-bit/500k, 7 = 29-bit/500k",
    )
    u = sub.add_parser(
        "obduds",
        help="safely discover SAE J1979-2/-3 ECUs, then read only advertised F4xx/F5xx data",
    )
    u.add_argument("address", help="BLE address from `scan`")
    u.add_argument(
        "--state", required=True, help="vehicle state label, e.g. ignitionOn, stationary, charging"
    )
    u.add_argument("--out", type=Path, default=Path(__file__).parent / "logs")
    u.add_argument(
        "--pair", action="store_true", help="bond first (within 5 min of plugging in the adapter)"
    )
    u.add_argument(
        "--support-only",
        action="store_true",
        help="stop after each ECU's chained F400/F420/... support bitmaps",
    )
    ident = sub.add_parser(
        "identify",
        help="discover regulated 29-bit OBDonUDS ECUs and read only their part/software/"
        "hardware numbers and system name - never the serial number or VIN",
    )
    ident.add_argument("address", help="BLE address from `scan`")
    ident.add_argument(
        "--state", required=True, help="vehicle state label, e.g. ignitionOn, stationary, charging"
    )
    ident.add_argument("--out", type=Path, default=Path(__file__).parent / "logs")
    ident.add_argument(
        "--pair", action="store_true", help="bond first (within 5 min of plugging in the adapter)"
    )
    n = sub.add_parser(
        "session",
        help="one continuous log for a whole outing: full one-shot pass (incl. the profile's "
        "discovery sweeps), then indefinite watch-DID polling until Ctrl-C",
    )
    n.add_argument("address", help="BLE address from `scan`")
    n.add_argument(
        "--state", required=True, help="label for the single log file, e.g. chargingDrive"
    )
    n.add_argument("--out", type=Path, default=Path(__file__).parent / "logs")
    n.add_argument(
        "--pair", action="store_true", help="bond first (within 5 min of plugging in the adapter)"
    )
    n.add_argument(
        "--protocol",
        choices=sorted(FORCE_PROTOCOL),
        help="force CAN protocol instead of ATSP0 auto-detect: 6 = 11-bit/500k, 7 = 29-bit/500k",
    )
    n.add_argument(
        "--profile",
        help="vehicle profile id (profiles/<id>.toml) or path; without it, stage E and the "
        "watch loop are skipped",
    )
    n.add_argument(
        "--survey",
        action="store_true",
        help="also poll each profile DID marked survey (not yet watch-worthy) at --survey-interval",
    )
    n.add_argument(
        "--survey-interval",
        type=float,
        default=60.0,
        help="poll interval in seconds for --survey (default 60, minimum 15)",
    )
    args = parser.parse_args(argv)

    if args.mode == "scan":
        asyncio.run(scan(args.seconds))
        return 0
    if args.mode == "record":
        profile = None
        if args.profile:
            try:
                profile = resolve_profile(args.profile)
            except ProfileError as error:
                parser.error(str(error))
        record_label = re.sub(r"[^a-z0-9_-]", "", args.label.lower()) or "vehicle"
        return asyncio.run(record(args.address, profile, record_label, args.out, args.new))
    label = re.sub(r"[^a-z0-9_-]", "", args.state.lower()) or "unlabeled"
    if args.mode == "obduds":
        return asyncio.run(
            obduds_probe(args.address, label, args.out, args.pair, args.support_only)
        )
    if args.mode == "identify":
        return asyncio.run(identify(args.address, label, args.out, args.pair))
    if args.mode == "sweep":
        if args.obduds_ecus:
            if args.header or args.rax:
                parser.error("--obduds-ecus is mutually exclusive with --header/--rax")
            return asyncio.run(
                sweep(
                    args.address,
                    None,
                    None,
                    args.start,
                    args.end,
                    label,
                    args.out,
                    args.pair,
                    None,
                    obduds_ecus=True,
                )
            )
        if not args.header:
            parser.error("--header is required unless --obduds-ecus is given")
        header = args.header.upper()
        rax = args.rax.upper() if args.rax else None
        protocol = args.protocol
        if len(header) == 8:
            if not re.fullmatch(r"18DA[0-9A-F]{2}F1", header):
                parser.error("an 8-digit --header must match 18DAxxF1")
            if args.protocol == "6":
                parser.error("--header 18DAxxF1 is 29-bit CAN; incompatible with --protocol 6")
            protocol = "7"
            if rax is None:
                rax = f"18DAF1{header[4:6]}"
        elif len(header) != 3:
            parser.error("--header must be 3 hex digits or 18DAxxF1")
        return asyncio.run(
            sweep(
                args.address,
                header,
                rax,
                args.start,
                args.end,
                label,
                args.out,
                args.pair,
                protocol,
            )
        )
    if args.mode == "session":
        if args.survey_interval < 15:
            parser.error("--survey-interval must be >= 15 seconds")
        profile = None
        if args.profile:
            try:
                profile = resolve_profile(args.profile)
            except ProfileError as error:
                parser.error(str(error))
        return asyncio.run(
            run_session(
                args.address,
                label,
                args.out,
                args.pair,
                args.protocol,
                profile,
                args.survey,
                args.survey_interval,
            )
        )
    stages = args.stages.upper()
    if not stages or any(st not in STAGES for st in stages):
        parser.error("--stages must only contain A-E")
    if args.watch_seconds and "E" not in stages:
        parser.error("--watch-seconds requires stage E")
    profile = None
    if "E" in stages:
        if not args.profile:
            parser.error("stage E requires --profile")
        try:
            profile = resolve_profile(args.profile)
        except ProfileError as error:
            parser.error(str(error))
    if "E" in stages and "B" not in stages:
        stages = "B" + stages
    return asyncio.run(
        probe(
            args.address,
            stages,
            label,
            args.out,
            args.pair,
            args.protocol,
            args.watch_seconds,
            profile,
        )
    )


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[didscout] Ctrl-C detected; disconnecting.", file=sys.stderr)
        sys.exit(130)
