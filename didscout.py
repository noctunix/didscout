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
import difflib
import gzip
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

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


# The mode-01 functional broadcast header for each CAN protocol - `record`'s
# continuous loop needs to reset to this after another module's setup pointed
# ATSH at a specific ECU.
MODE01_FUNCTIONAL_HEADER = {"6": "7DF", "7": OBDUDS_FUNCTIONAL_HEADER}


def check_mode01_watch_allowed(command: str) -> str:
    """`check_mode01_allowed` plus the header reset `record`'s continuous loop
    needs between polling a specific ECU and polling mode 01 - still only
    adapter/header setup and `01xx` reads, never anything that could reach a
    write/reset/security service."""
    cmd = normalize(command)
    if cmd in {f"ATSH{header}" for header in MODE01_FUNCTIONAL_HEADER.values()}:
        return cmd
    return check_mode01_allowed(cmd)


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


def check_ecus29_allowed(command: str) -> str:
    """For `record`'s 29-bit normal-fixed-addressing ECU inventory (ISO
    15765-4, protocol 7): adapter/protocol setup, 18DAxxF1 request/18DAF1xx
    response header/flow-control setup at any target, and the same four
    identification reads as check_identify_allowed - never the serial number
    or any VIN DID."""
    cmd = normalize(command)
    base = {*ADAPTER_SETUP, "ATSP7", "ATDPN", "ATD", "ATAR", "ATFCSM0", "ATFCSD300000", "ATFCSM1"}
    if cmd in base:
        return cmd
    if re.fullmatch(r"AT(SH|FCSH)18DA[0-9A-F]{2}F1", cmd):
        return cmd
    if re.fullmatch(r"ATCRA18DAF1[0-9A-F]{2}", cmd):
        return cmd
    if cmd.startswith("22") and cmd[2:] in IDENTIFY_DIDS:
        return cmd
    raise ForbiddenCommandError(cmd)


def check_vag29_allowed(command: str) -> str:
    """For VAG's 29-bit addressing scheme (profile opt-in only, see
    `address_schemes`): adapter/protocol setup, the ATSH/ATFCSH/ATCRA header
    forms over 17FC00xx (request) / 17FE00xx (response), and
    ReadDataByIdentifier (0x22) like any other sweep traffic - never a VIN
    DID. These header forms are accepted nowhere else: check_sweep_allowed
    and every other validator reject them."""
    cmd = normalize(command)
    base = {*ADAPTER_SETUP, "ATSP7", "ATDPN", "ATD", "ATAR", "ATFCSM0", "ATFCSD300000", "ATFCSM1"}
    if cmd in base:
        return cmd
    if re.fullmatch(r"AT(SH|FCSH)17FC00[0-9A-F]{2}", cmd):
        return cmd
    if re.fullmatch(r"ATCRA17FE00[0-9A-F]{2}", cmd):
        return cmd
    if re.fullmatch(r"22[0-9A-F]{4}", cmd):
        if cmd[2:] in VIN_DIDS:
            raise ForbiddenCommandError(cmd)
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
# Opt-in non-standard 29-bit addressing schemes a profile may request beyond
# plain ISO 15765-4 normal fixed addressing (see check_vag29_allowed).
KNOWN_ADDRESS_SCHEMES = frozenset({"vag-29bit"})


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
    # Overrides the profile's protocol for this module only; None means "use the
    # profile's". A 29-bit request header requires the effective protocol - this
    # override or the profile's - to be "7".
    protocol: str | None = None
    discover: list[tuple[str, str]] | None = None
    # Opt-in: `record --discover-while-moving` runs background discovery on this
    # module even while the vehicle moves. Still gated in code by an F197 system
    # name blocklist (steering/braking systems), which overrides this flag.
    discover_while_moving: bool = False


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
    address_schemes: list[str] = field(default_factory=list)


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
        if status != "unverified" and poll != "survey" and name is None:
            raise ProfileError(
                path, f"{sub}.name", 'required unless status is "unverified" or poll is "survey"'
            )

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
            {
                "id",
                "request",
                "response",
                "protocol",
                "discover",
                "dids",
                "discover_while_moving",
            },
            {"id", "request", "dids"},
            path,
            context,
        )

        module_id = _expect_str(entry, "id", path, context)
        if module_id in seen_ids:
            raise ProfileError(path, f"{context}.id", f"duplicate module id {module_id!r}")
        seen_ids.add(module_id)

        module_protocol = entry.get("protocol")
        if module_protocol is not None and module_protocol not in FORCE_PROTOCOL:
            raise ProfileError(
                path, f"{context}.protocol", f"must be one of {sorted(FORCE_PROTOCOL)}"
            )
        effective_protocol = module_protocol or protocol

        request = _expect_str(entry, "request", path, context)
        if HEADER_29BIT_REQUEST_PATTERN.fullmatch(request):
            if effective_protocol != "7":
                raise ProfileError(
                    path,
                    f"{context}.request",
                    '29-bit header requires the module\'s effective protocol to be "7"',
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

        discover_while_moving = entry.get("discover_while_moving", False)
        if not isinstance(discover_while_moving, bool):
            raise ProfileError(path, f"{context}.discover_while_moving", "must be a boolean")

        modules.append(
            Module(
                id=module_id,
                request=request,
                response=response,
                protocol=module_protocol,
                discover=discover,
                dids=dids,
                discover_while_moving=discover_while_moving,
            )
        )
    return modules


def module_effective_protocol(module: Module, profile_protocol: str) -> str:
    """The CAN protocol `module` actually talks: its own override if set, else
    the profile's."""
    return module.protocol or profile_protocol


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
        "address_schemes",
    }
    _check_keys(raw, root_keys, root_keys - {"address_schemes"}, path, "<root>")

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

    address_schemes_raw = raw.get("address_schemes", [])
    if not isinstance(address_schemes_raw, list) or not all(
        isinstance(s, str) for s in address_schemes_raw
    ):
        raise ProfileError(path, "address_schemes", "must be a list of strings")
    unknown_schemes = set(address_schemes_raw) - KNOWN_ADDRESS_SCHEMES
    if unknown_schemes:
        raise ProfileError(path, "address_schemes", f"unknown scheme(s): {sorted(unknown_schemes)}")

    return Profile(
        schema=1,
        id=profile_id,
        name=name,
        description=description,
        protocol=protocol,
        vehicles=list(vehicles),
        sources=sources,
        modules=modules,
        address_schemes=list(address_schemes_raw),
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


def decode_positive_payload(command: str, response: str, responder: str | None) -> bytes | None:
    """Returns the data bytes of a positive ReadDataByIdentifier reply from one
    responder, or None if no matching positive response was found. `responder`
    may be None for a single-frame-only module (no known response id), in which
    case the first matching message is taken regardless of its header."""
    expected = bytes.fromhex(command)
    prefix = bytes([expected[0] + 0x40]) + expected[1:]
    for header, message in parse_isotp(command, response).messages:
        if (responder is None or _responder_matches(header, responder)) and message.startswith(
            prefix
        ):
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


def detect_format_lost(command: str, status: str, response: str) -> bool:
    """True if `response`/`status` show the adapter reverted to echo-on/
    headers-off formatting mid-run - e.g. after an ATD a stage's own cleanup
    should never have sent: its first line echoes `command` back, or - for a
    01xx/22xx data read - `classify` already couldn't reassemble a header
    and ISO-TP frame from it (`status == "MALFORMED"`; a header's first 3
    (or, 29-bit, 8) hex digits can't otherwise be told apart from plain data
    bytes, so this reuses `parse_isotp`'s own framing check rather than
    re-guessing it from the text). Used only by `record`, whose long-running
    inventory/watch/discovery reads need the adapter's formatting to stay put
    for the whole run (see `AdapterLink.execute_guarded`)."""
    lines = [line.strip() for line in response.splitlines() if line.strip()]
    if lines and normalize(lines[0]) == normalize(command):
        return True
    return status == "MALFORMED" and command.startswith(("01", "22"))


# AT commands whose non-OK reply doesn't abort a probe: informational banners/
# voltage/protocol-name queries, and ATMA, which never replies OK.
DEFAULT_NON_CRITICAL_AT = frozenset({"ATI", "ATRV", "ATDPN", "ATMA"})


class RecordFn(Protocol):
    """Callable shape of `AdapterLink.record`/the `record` closure in
    `connect_adapter`: `module` is optional, so this is callable both as a
    plain `Callable[[Exchange, str], None]` (every pre-existing call site) and
    with the module key `record`'s watch/discovery reads tag along."""

    def __call__(self, ex: Exchange, stage: str, module: str | None = None) -> None: ...


@dataclass
class AdapterLink:
    """One connected BLE UART adapter, wired up for ELM327/STN command/response
    traffic and JSONL logging. Yielded by `connect_adapter`."""

    session: ElmSession
    record: RecordFn
    non_critical_at: frozenset[str] = DEFAULT_NON_CRITICAL_AT

    async def execute(
        self,
        command: str,
        stage: str,
        validator: Callable[[str], str] = check_allowed,
        responder: str | None = None,
        module: str | None = None,
        log: bool = True,
    ) -> Exchange:
        """Runs `command`, logging it unless `log` is False; fails closed by
        raising ProbeAbortedError if the session became unusable or a
        critical AT command did not come back OK. `module` is only given for
        `record`'s watch/discovery reads, so the log alone says which known
        ECU a given exchange belongs to. `log=False` lets a caller - `record`'s
        watch scheduler and discovery batches - decide whether an exchange is
        worth writing only after seeing its result, without skipping the
        transport-failure check below."""
        ex = await self.session.run(command, validator, responder)
        if log:
            self.record(ex, stage, module)
        critical = command.startswith("AT") and command not in self.non_critical_at
        if not self.session.usable or (critical and ex.status != "OK"):
            raise ProbeAbortedError(f"{command}: {ex.status}; disconnect and retry")
        return ex

    async def execute_guarded(
        self,
        command: str,
        stage: str,
        validator: Callable[[str], str] = check_allowed,
        responder: str | None = None,
        module: str | None = None,
        log: bool = True,
    ) -> Exchange:
        """`execute`, but for `record`'s own inventory/watch/discovery reads:
        detects the adapter having silently reverted to echo-on/headers-off
        formatting (`detect_format_lost`), logs that as `FORMAT_LOST`,
        re-asserts ATE0/ATL0/ATS0/ATH1 once, and retries the read once before
        returning whatever that retry got, logged (or not) like a normal
        `execute` call."""
        ex = await self.execute(command, stage, validator, responder, module, log=False)
        if detect_format_lost(command, ex.status, ex.response):
            self.record(
                Exchange(command, ex.response, "FORMAT_LOST", ex.started_utc, ex.duration_ms),
                stage,
                module,
            )
            for cmd in ("ATE0", "ATL0", "ATS0", "ATH1"):
                await self.execute(cmd, f"{stage}-format-recover", validator, None, module)
            ex = await self.execute(command, stage, validator, responder, module, log=False)
        if log:
            self.record(ex, stage, module)
        return ex


def _append_capture_entry(log_path: Path, entry: dict[str, object]) -> None:
    """Appends one JSON line to a run's capture.jsonl, opening and closing the
    file for just this write so it is safe to call from several independent
    places (a live BLE connection, a reconnect gap, a typed note) without a
    long-lived file handle that could interleave with another writer."""
    with log_path.open("a", encoding="utf-8") as log:
        log.write(json.dumps(entry, ensure_ascii=False) + "\n")


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
        # BlueZ needs an explicit MTU exchange before client.mtu_size reflects
        # anything but the ATT default (23) - other backends don't have this
        # method at all, hence the getattr guard, and a failure here just
        # means falling back to that default, not a reason to abort.
        acquire_mtu = getattr(client, "_acquire_mtu", None)
        if acquire_mtu is not None:
            try:
                await acquire_mtu()
            except Exception as error:
                print(f"MTU acquisition failed, using default: {error}", file=sys.stderr)
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

        def record(ex: Exchange, stage: str, module: str | None = None) -> None:
            entry = {
                "stage": stage,
                "state": label,
                "mtu": client.mtu_size,
                **ex.__dict__,
                **({"module": module} if module is not None else {}),
                **(extra_fields or {}),
            }
            _append_capture_entry(log_path, entry)
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
                    Exchange("PAIR", str(error), "PAIR_FAILED", datetime.now(UTC).isoformat(), 0.0),
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
                current_protocol: str | None = None
                for module in profile.modules:
                    effective = module_effective_protocol(module, profile.protocol)
                    if effective != current_protocol:
                        await execute(FORCE_PROTOCOL[effective], stage, check_sweep_allowed)
                        current_protocol = effective
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

        # Tracks every reply across the whole sweep (all responders, with
        # --obduds-ecus) so a run where an ECU fell asleep mid-sweep can be
        # flagged below, regardless of how many DIDs still answered before that.
        sweep_status_counts: dict[str, int] = {}

        def counting_sweep_record(ex: Exchange, stage: str, module: str | None = None) -> None:
            sweep_status_counts[ex.status] = sweep_status_counts.get(ex.status, 0) + 1
            record(ex, stage, module)

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
                                session,
                                counting_sweep_record,
                                start_i,
                                end_i,
                                f"sweep-{ecu}",
                                responder,
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

            hits = await sweep_range(session, counting_sweep_record, start_i, end_i, responder=rax)

            if rax:
                record(await session.run("ATFCSM0"), "cleanup")
            record(await session.run("ATAR"), "cleanup")
            record(await session.run("ATD"), "cleanup")

        if result == 0 and _batch_is_asleep(sweep_status_counts, sum(sweep_status_counts.values())):
            print(
                "sweep: ECU stopped answering (NRC 11 serviceNotSupported on at least half the "
                "replies) - it probably went to sleep or the vehicle was switched off; rerun "
                "this range",
                file=sys.stderr,
            )
            result = 3
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

    def _section(self, key: str) -> dict[str, object]:
        # setdefault rather than a plain lookup: a state.json saved before the
        # continuous loop existed has no "discovery" section yet, and should
        # still load rather than needing a schema migration.
        section = self.data.setdefault(key, {})
        assert isinstance(section, dict)
        return section

    def stage_status(self, stage: str) -> str | None:
        status = self._section("stages").get(stage)
        return status if isinstance(status, str) else None

    def mark_stage(self, stage: str, status: str) -> None:
        self._section("stages")[stage] = status

    def result(self, key: str, default: object = None) -> object:
        return self._section("results").get(key, default)

    def set_result(self, key: str, value: object) -> None:
        self._section("results")[key] = value

    def discovery_state(self, module_key: str) -> tuple[int, list[str], list[str]]:
        """(position, discovered DIDs, conditional DIDs) persisted for one
        continuous-loop module, or (0, [], []) if discovery hasn't touched it yet."""
        info = self._section("discovery").get(module_key)
        if not isinstance(info, dict):
            return 0, [], []
        return (
            int(info.get("position", 0)),
            list(info.get("discovered", [])),
            list(info.get("conditional", [])),
        )

    def save_discovery_state(
        self, module_key: str, position: int, discovered: list[str], conditional: list[str]
    ) -> None:
        self._section("discovery")[module_key] = {
            "position": position,
            "discovered": sorted(discovered),
            "conditional": sorted(conditional),
        }

    def last_rediscover_time(self) -> float | None:
        """Wall-clock `time.time()` of the last ECU rediscovery scan
        (_record_rediscover), persisted across restarts - None if this run
        has never rediscovered yet."""
        value = self.data.get("last_rediscover_epoch")
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
        return float(value)

    def set_last_rediscover_time(self, epoch: float) -> None:
        self.data["last_rediscover_epoch"] = epoch


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


async def _inventory_protocol(link: AdapterLink, state: RunState, profile: Profile | None) -> None:
    answered: list[str] = []
    for proto, cmd in (("6", "ATSP6"), ("7", "ATSP7")):
        await link.execute(cmd, "protocol")
        ex = await link.execute_guarded("0100", "protocol")
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
    # Mode 01 gets its own protocol choice, independent of any profile - a
    # profile forcing protocol 6 for its own modules doesn't mean mode 01
    # actually answers under 6 on that vehicle.
    protocol_result = state.result("protocol")
    answered = protocol_result.get("answered") if isinstance(protocol_result, dict) else None
    if isinstance(answered, list) and "6" in answered:
        mode01_protocol: str | None = "6"
    elif isinstance(answered, list) and "7" in answered:
        mode01_protocol = "7"
    else:
        mode01_protocol = None
    if mode01_protocol:
        await link.execute(FORCE_PROTOCOL[mode01_protocol], "mode01", check_mode01_allowed)

    bitmaps: list[str] = []
    for index, base in enumerate(MODE01_BITMAP_BASES):
        ex = await link.execute_guarded(f"01{base}", "mode01", check_mode01_allowed)
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
        await link.execute_guarded(f"01{pid}", "mode01", check_mode01_allowed)
    state.set_result("mode01", {"supported_pids": supported, "protocol": mode01_protocol})


async def _inventory_obduds(link: AdapterLink, state: RunState, _profile: Profile | None) -> None:
    async def execute_obduds(command: str, stage: str, responder: str | None = None) -> Exchange:
        return await link.execute_guarded(command, stage, check_obduds_allowed, responder)

    async def execute_identify(command: str, stage: str, responder: str | None = None) -> Exchange:
        return await link.execute_guarded(command, stage, check_identify_allowed, responder)

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
    state.set_result("obduds", results)


# 11-bit manufacturer-ECU request ids: 0x700-0x7EF, excluding the legislative
# functional broadcast 0x7DF (that belongs to mode 01/OBDonUDS, not here).
ECU11_REQUEST_IDS = [request for request in range(0x700, 0x7F0) if request != 0x7DF]


async def _inventory_ecus11(link: AdapterLink, state: RunState, profile: Profile | None) -> None:
    async def execute(command: str, stage: str, responder: str | None = None) -> Exchange:
        return await link.execute_guarded(command, stage, check_ecus11_allowed, responder)

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

    for request_id in ECU11_REQUEST_IDS:
        req_hex = f"{request_id:03X}"
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


# 29-bit normal-fixed-addressing target ids: any two-hex id except the tester
# address (0xF1) - used for both the plain ISO 15765-4 scheme and, with a
# different request/response pair, the VAG scheme (see check_vag29_allowed).
ECU29_IDS = [f"{i:02X}" for i in range(0x100) if i != 0xF1]
VAG29_IDS = [f"{i:02X}" for i in range(0x100)]


async def _discover_ecus(
    execute: Callable[[str, str, str | None], Awaitable[Exchange]],
    stage: str,
    candidates: list[str],
    skip: set[str],
    make_request: Callable[[str], str],
    make_response: Callable[[str], str] | None,
) -> dict[str, str]:
    """Probes `make_request(id)` with `22F189` for every id in `candidates`
    not in `skip`; any reply frame - even a first frame alone - proves an ECU
    answered (the same rule `_inventory_ecus11` uses). Returns newly found
    {id: response_header}. `make_response` gives the expected response header
    directly for a fixed-addressing scheme (29-bit); pass None to use
    whatever header actually answered instead (11-bit, where the response id
    isn't implied by the request)."""
    found: dict[str, str] = {}
    for candidate in candidates:
        if candidate in skip:
            continue
        request = make_request(candidate)
        await execute(f"ATSH{request}", stage, None)
        ex = await execute("22F189", stage, None)
        parsed = parse_isotp("22F189", ex.response)
        seen = {header for header, _payload in parsed.messages} | parsed.partial_headers
        if make_response is not None:
            if seen:
                found[candidate] = make_response(candidate)
        else:
            for header in seen:
                if header != request:
                    found[candidate] = header
    return found


async def _identify_new_ecus(
    execute: Callable[[str, str, str | None], Awaitable[Exchange]],
    found: dict[str, str],
    make_request: Callable[[str], str],
    stage: str,
) -> dict[str, object]:
    """Identifies every newly found {id: response} pair the same way
    `_inventory_ecus11` does for its own ECUs: full header/filter/flow-
    control setup, then the four identification DIDs."""
    results: dict[str, object] = {}
    for candidate, response in sorted(found.items()):
        request = make_request(candidate)
        await execute(f"ATSH{request}", stage, None)
        await execute(f"ATCRA{response}", stage, None)
        await execute(f"ATFCSH{request}", stage, None)
        await execute("ATFCSD300000", stage, None)
        await execute("ATFCSM1", stage, None)
        identify_values = await read_identify_dids(execute, response, request)
        results[candidate] = {"response": response, "identify": identify_values}
        await execute("ATFCSM0", stage, None)
    return results


async def _inventory_ecus29(link: AdapterLink, state: RunState, profile: Profile | None) -> None:
    """29-bit normal-fixed-addressing ECU inventory (ISO 15765-4, protocol 7):
    probes every target except the tester address and any ECU already known
    from OBDonUDS, then - only if the profile opts in via `address_schemes`
    (see check_vag29_allowed) - also probes VAG's 17FC00xx/17FE00xx scheme."""

    async def execute(command: str, stage: str, responder: str | None = None) -> Exchange:
        return await link.execute_guarded(command, stage, check_ecus29_allowed, responder)

    await execute("ATSP7", "ecus29-setup")
    await execute("ATDPN", "ecus29-setup")
    await execute("ATAR", "ecus29-setup")

    obduds = state.result("obduds") or {}
    known_obduds_ecus = (
        {responder[-2:] for responder in obduds} if isinstance(obduds, dict) else set()
    )

    found = await _discover_ecus(
        execute,
        "ecus29-discovery",
        ECU29_IDS,
        known_obduds_ecus,
        lambda ecu: f"18DA{ecu}F1",
        lambda ecu: f"18DAF1{ecu}",
    )
    await execute("ATAR", "ecus29-discovery-done")
    identified = await _identify_new_ecus(
        execute, found, lambda ecu: f"18DA{ecu}F1", "ecus29-identify-setup"
    )
    await execute("ATAR", "ecus29-cleanup")
    state.set_result("ecus29", identified)

    if profile is not None and "vag-29bit" in profile.address_schemes:

        async def execute_vag(command: str, stage: str, responder: str | None = None) -> Exchange:
            return await link.execute_guarded(command, stage, check_vag29_allowed, responder)

        await execute_vag("ATSP7", "ecus29-vag-setup")
        await execute_vag("ATDPN", "ecus29-vag-setup")
        await execute_vag("ATAR", "ecus29-vag-setup")
        vag_found = await _discover_ecus(
            execute_vag,
            "ecus29-vag-discovery",
            VAG29_IDS,
            set(),
            lambda ecu: f"17FC00{ecu}",
            lambda ecu: f"17FE00{ecu}",
        )
        await execute_vag("ATAR", "ecus29-vag-discovery-done")
        vag_identified = await _identify_new_ecus(
            execute_vag, vag_found, lambda ecu: f"17FC00{ecu}", "ecus29-vag-identify-setup"
        )
        await execute_vag("ATAR", "ecus29-vag-cleanup")
        state.set_result("vag29", vag_identified)


INVENTORY_STAGE_ORDER = ("adapter", "protocol", "mode01", "obduds", "ecus11", "ecus29")
INVENTORY_STAGE_FUNCS: dict[
    str, Callable[[AdapterLink, RunState, Profile | None], Awaitable[None]]
] = {
    "adapter": _inventory_adapter,
    "protocol": _inventory_protocol,
    "mode01": _inventory_mode01,
    "obduds": _inventory_obduds,
    "ecus11": _inventory_ecus11,
    "ecus29": _inventory_ecus29,
}


def print_inventory_summary(state: RunState) -> None:
    protocol = state.result("protocol") or {}
    mode01 = state.result("mode01") or {}
    obduds = state.result("obduds") or {}
    ecus11 = state.result("ecus11") or {}
    ecus29 = state.result("ecus29") or {}
    vag29 = state.result("vag29") or {}
    assert isinstance(protocol, dict) and isinstance(mode01, dict)
    assert isinstance(obduds, dict) and isinstance(ecus11, dict)
    assert isinstance(ecus29, dict) and isinstance(vag29, dict)

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
    if ecus29 or vag29:
        for ecu, info in {**ecus29, **vag29}.items():
            assert isinstance(info, dict)
            name = info.get("identify", {}).get("F197", "-")
            print(f"  29-bit ECU {ecu} -> {info.get('response')}: F197={name}")
    else:
        print("  29-bit ECUs: none found")


# `record`'s continuous loop, after the inventory: keeps polling everything it
# already knows about and, while the vehicle is stationary, discovers further
# DIDs on every known ECU in the background - until Ctrl-C.
RECORD_LOAD_LIMIT = 4.0  # max summed watch-poll rate, reads/second
RECORD_SPEED_INTERVAL = 5.0  # speed usually now costs a protocol switch too
RECORD_SPEED_MAX_AGE = 12.0
RECORD_MODE01_WATCH_INTERVAL = 10.0
RECORD_OBDUDS_WATCH_INTERVAL = 10.0
RECORD_DISCOVERED_WATCH_INTERVAL = 30.0
RECORD_DISCOVERY_BATCH = 16
RECORD_STATUS_INTERVAL = 10.0
# --discover-while-moving: at most one discovery batch in this many seconds
# while the vehicle is moving, regardless of how often the idle branch runs.
RECORD_MOVING_DISCOVERY_INTERVAL = 5.0

# Discovery DID order, per module: a module's own profile `discover` ranges
# first, then the standardized ranges most likely to answer, then the rest of
# the DID space ascending.
DISCOVERY_PRIORITY_RANGES = ((0xF180, 0xF1FF), (0x0100, 0x0FFF), (0x1000, 0x1FFF), (0x2000, 0x2FFF))
# F4xx/F5xx and F8xx stay announcement-only via OBDonUDS (see _inventory_obduds);
# never offered to the generic per-ECU discovery scan.
DISCOVERY_EXCLUDED_RANGES = ((0xF400, 0xF5FF), (0xF800, 0xF8FF))
DISCOVERY_FULL_RANGE = (0x0000, 0xFFFF)


def discovery_did_order(profile_ranges: list[tuple[int, int]]) -> list[int]:
    """The DID scan order for one module's background discovery - skipping VIN
    DIDs, the serial number, and the OBDonUDS-only standardized ranges
    (DISCOVERY_EXCLUDED_RANGES), and never visiting the same DID twice even if
    it falls in more than one range."""
    ordered: list[int] = []
    seen: set[int] = set()

    def add_range(start: int, end: int) -> None:
        for did in range(start, end + 1):
            if did in seen:
                continue
            seen.add(did)
            hex_did = f"{did:04X}"
            if hex_did in VIN_DIDS or hex_did == "F18C":
                continue
            if any(lo <= did <= hi for lo, hi in DISCOVERY_EXCLUDED_RANGES):
                continue
            ordered.append(did)

    for start, end in profile_ranges:
        add_range(start, end)
    for start, end in DISCOVERY_PRIORITY_RANGES:
        add_range(start, end)
    add_range(*DISCOVERY_FULL_RANGE)
    return ordered


def stretch_watch_intervals[K](
    entries: list[tuple[K, float, bool]], limit: float = RECORD_LOAD_LIMIT
) -> dict[K, float]:
    """Scales every non-speed interval in `entries` (key, base interval,
    is_speed) up proportionally so the summed poll rate fits `limit` reads per
    second - the speed source is exempt, since motion gating depends on it
    staying fresh."""
    rate = sum(1.0 / interval for _key, interval, is_speed in entries if not is_speed)
    factor = max(1.0, rate / limit) if rate else 1.0
    return {
        key: (interval if is_speed else interval * factor) for key, interval, is_speed in entries
    }


def motion_phase(speed: int | None, age: float | None) -> str:
    """'stationary' only for a fresh (<= RECORD_SPEED_MAX_AGE), successful,
    zero speed reading - no speed source, a failed read, or a stale one all
    count as 'moving' so discovery never runs blind to motion."""
    if speed is None or age is None or age > RECORD_SPEED_MAX_AGE:
        return "moving"
    return "stationary" if speed == 0 else "moving"


# Substrings (case-insensitive) of an F197 system name that block
# `record --discover-while-moving` on that ECU regardless of the profile's
# own discover_while_moving flag - steering/braking systems should never see
# discovery traffic while the vehicle is in motion.
MOVING_DISCOVERY_BLOCKED_NAME_PARTS = (
    "abs",
    "esc",
    "esp",
    "eps",
    "lenk",
    "steer",
    "airbag",
    "brems",
    "brake",
    "parksp",
)


def moving_discovery_blocked(f197_name: str | None) -> bool:
    """True if `f197_name` (an ECU's identified system name, or None if
    unknown) matches MOVING_DISCOVERY_BLOCKED_NAME_PARTS - this guard is
    enforced in code and overrides any profile `discover_while_moving` flag."""
    if f197_name is None:
        return False
    lowered = f197_name.lower()
    return any(part in lowered for part in MOVING_DISCOVERY_BLOCKED_NAME_PARTS)


def decode_speed(command: str, ex: Exchange, responder: str | None) -> int | None:
    """Decodes a speed reading (km/h) from a positive mode-01 010D or OBDonUDS
    22F40D exchange, or None if it wasn't a usable positive reply."""
    if ex.status != "OK":
        return None
    if command == "010D":
        match = re.search(r"410D([0-9A-F]{2})", re.sub(r"\s+", "", ex.response.upper()))
        return int(match.group(1), 16) if match else None
    if responder is not None:
        payload = decode_positive_payload(command, ex.response, responder)
        return payload[0] if payload else None
    return None


@dataclass
class RecordModule:
    """One ECU `record`'s continuous loop can poll and discover on - a profile
    module, an `_inventory_ecus11` ECU, or an `_inventory_obduds` responder,
    normalized to the same setup/validator shape so the scheduler treats them
    identically. `discover_ranges` is None for the one module (mode 01) that
    isn't discoverable at all."""

    key: str
    protocol: str
    setup: list[str]
    validator: Callable[[str], str]
    responder: str | None
    discover_ranges: list[tuple[int, int]] | None
    # The module's request header, when it has a fixed one - None for mode 01,
    # whose "module" is really just a functional-header reset. Lets
    # `_record_ensure_module` build the cheap ATSH/ATCRA/ATFCSH-only switch
    # between two flow-control modules without resending ATFCSD/ATFCSM1.
    request: str | None = None
    order: list[int] = field(default_factory=list)
    position: int = 0
    discovered: set[int] = field(default_factory=set)
    conditional: set[int] = field(default_factory=set)
    retry_queue: list[int] = field(default_factory=list)
    # Opt-in for `record --discover-while-moving` (profile modules only - see
    # Module.discover_while_moving); always False for a synthetic ECU module.
    discover_while_moving: bool = False
    # The ECU's own F197 system name, when already known from the inventory
    # (ecus11/ecus29/obduds/vag29) - None for a profile module, which is never
    # identified this way. Used only to block discovery-while-moving on a
    # steering/braking ECU, never to gate anything else.
    f197_name: str | None = None
    # Monotonic deadline before which this module's discovery is paused after
    # a sleeping-ECU detection (see run_discovery_batch); 0 means not paused.
    discovery_paused_until: float = 0.0

    @property
    def discoverable(self) -> bool:
        return self.discover_ranges is not None

    def has_discovery_work(self) -> bool:
        return self.discoverable and (self.position < len(self.order) or bool(self.retry_queue))


@dataclass
class RecordWatch:
    module_key: str
    command: str
    base_interval: float
    stage: str
    is_speed: bool = False


def _ecu_record_module(
    key: str,
    request: str,
    response: str,
    protocol: str,
    validator: Callable[[str], str],
    f197_name: str | None = None,
) -> RecordModule:
    """One synthetic RecordModule for an ECU found outside a profile (ecus11,
    ecus29, VAG, OBDonUDS) - same shape as a profile module, full background
    discovery (no profile discover ranges of its own), continuous polling
    through `validator`. Never opts into discovery-while-moving on its own -
    only a profile module can, via its own `discover_while_moving` key."""
    synthetic = Module(id=key, request=request, dids=[], response=response)
    module = RecordModule(
        key=key,
        protocol=protocol,
        setup=module_setup_commands(synthetic),
        validator=validator,
        responder=response,
        discover_ranges=[],
        request=request,
        f197_name=f197_name,
    )
    module.order = discovery_did_order([])
    return module


def _identified_f197_name(info: object) -> str | None:
    """The F197 system name from one ecus11/ecus29/obduds/vag29 state entry's
    `identify` dict, or None if it wasn't read (e.g. NRC/timeout status
    strings never look like a real system name a human would type)."""
    if not isinstance(info, dict):
        return None
    name = info.get("identify", {}).get("F197")
    return name if isinstance(name, str) else None


def build_record_modules(profile: Profile | None, state: RunState) -> dict[str, RecordModule]:
    """Every module `record`'s continuous loop knows about after the
    inventory: a synthetic mode-01 module (if mode 01 answered at all), every
    profile module, every ECU `_inventory_ecus11`/`_inventory_ecus29` found,
    and every responder `_inventory_obduds` found - each with its own
    protocol (mode-01 module: whichever protocol answered mode 01; profile
    modules: `profile.protocol`; ecus11: "6"; ecus29/VAG/OBDonUDS: "7") and
    its discovery progress restored from `state`."""
    modules: dict[str, RecordModule] = {}
    mode01 = state.result("mode01") or {}
    mode01_protocol = mode01.get("protocol") if isinstance(mode01, dict) else None
    if mode01_protocol in MODE01_FUNCTIONAL_HEADER:
        header = MODE01_FUNCTIONAL_HEADER[mode01_protocol]
        modules["mode01"] = RecordModule(
            key="mode01",
            protocol=mode01_protocol,
            setup=["ATFCSM0", "ATAR", f"ATSH{header}"],
            validator=check_mode01_watch_allowed,
            responder=None,
            discover_ranges=None,
        )

    if profile is not None:
        for pm in profile.modules:
            key = f"profile:{pm.id}"
            modules[key] = RecordModule(
                key=key,
                protocol=module_effective_protocol(pm, profile.protocol),
                setup=module_setup_commands(pm),
                validator=check_sweep_allowed,
                responder=pm.response,
                discover_ranges=[
                    (int(start, 16), int(end, 16)) for start, end in (pm.discover or [])
                ],
                request=pm.request,
                discover_while_moving=pm.discover_while_moving,
            )

    ecus11 = state.result("ecus11") or {}
    if isinstance(ecus11, dict):
        for request, info in ecus11.items():
            assert isinstance(info, dict)
            response = info.get("response")
            assert isinstance(response, str)
            key = f"ecus11:{request}"
            modules[key] = _ecu_record_module(
                key, request, response, "6", check_sweep_allowed, _identified_f197_name(info)
            )

    obduds = state.result("obduds") or {}
    if isinstance(obduds, dict):
        for responder, info in obduds.items():
            assert isinstance(info, dict)
            key = f"obduds:{responder}"
            request = f"18DA{responder[-2:]}F1"
            modules[key] = _ecu_record_module(
                key, request, responder, "7", check_sweep_allowed, _identified_f197_name(info)
            )

    ecus29 = state.result("ecus29") or {}
    if isinstance(ecus29, dict):
        for ecu, info in ecus29.items():
            assert isinstance(info, dict)
            response = info.get("response")
            assert isinstance(response, str)
            key = f"ecus29:{ecu}"
            request = f"18DA{ecu}F1"
            modules[key] = _ecu_record_module(
                key, request, response, "7", check_sweep_allowed, _identified_f197_name(info)
            )

    vag29 = state.result("vag29") or {}
    if isinstance(vag29, dict):
        for ecu, info in vag29.items():
            assert isinstance(info, dict)
            response = info.get("response")
            assert isinstance(response, str)
            key = f"vag29:{ecu}"
            request = f"17FC00{ecu}"
            modules[key] = _ecu_record_module(
                key, request, response, "7", check_vag29_allowed, _identified_f197_name(info)
            )

    for key, module in modules.items():
        if not module.discoverable:
            continue
        position, discovered, conditional = state.discovery_state(key)
        module.order = discovery_did_order(module.discover_ranges or [])
        module.position = min(position, len(module.order))
        module.discovered = {int(did, 16) for did in discovered}
        module.conditional = {int(did, 16) for did in conditional}
    return modules


def select_speed_source(
    modules: dict[str, RecordModule], state: RunState
) -> tuple[str, str] | None:
    """The speed source `record`'s motion gating polls every
    RECORD_SPEED_INTERVAL seconds: mode-01 010D if supported, else the first
    (by responder id) OBDonUDS responder that announces F40D, else None - no
    speed source means discovery always stays paused."""
    mode01 = state.result("mode01") or {}
    supported = mode01.get("supported_pids", []) if isinstance(mode01, dict) else []
    if "mode01" in modules and "0D" in supported:
        return "mode01", "010D"
    obduds = state.result("obduds") or {}
    if isinstance(obduds, dict):
        for responder, info in sorted(obduds.items()):
            assert isinstance(info, dict)
            if "F40D" in info.get("supported_dids", []):
                return f"obduds:{responder}", "22F40D"
    return None


def build_record_watch(
    profile: Profile | None,
    state: RunState,
    modules: dict[str, RecordModule],
    speed_key: tuple[str, str] | None,
) -> list[RecordWatch]:
    """Every value `record`'s continuous loop polls on a fixed schedule: the
    speed source (if any), every profile watch/survey DID at its own interval,
    every supported mode-01 PID and every OBDonUDS announced data DID (10 s
    each), and every DID a previous discovery run already found (30 s each) -
    see RECORD_*_WATCH_INTERVAL."""
    watch: list[RecordWatch] = []
    if speed_key is not None:
        watch.append(RecordWatch(speed_key[0], speed_key[1], RECORD_SPEED_INTERVAL, "speed", True))

    mode01 = state.result("mode01") or {}
    supported = mode01.get("supported_pids", []) if isinstance(mode01, dict) else []
    if "mode01" in modules:
        for pid in supported:
            command = f"01{pid}"
            if speed_key == ("mode01", command):
                continue
            watch.append(RecordWatch("mode01", command, RECORD_MODE01_WATCH_INTERVAL, "watch"))

    if profile is not None:
        for pm in profile.modules:
            module_key = f"profile:{pm.id}"
            for did in pm.dids:
                if did.poll in ("watch", "survey"):
                    assert did.interval is not None
                    watch.append(RecordWatch(module_key, f"22{did.did}", did.interval, "watch"))

    obduds = state.result("obduds") or {}
    if isinstance(obduds, dict):
        # Every regulated OBDonUDS ECU reports the same standardized DIDs -
        # watch each one from only the first (lowest-address) responder that
        # announces it; the rest already got it once during the inventory
        # (`_inventory_obduds`'s own data-DID pass), see "Watch standardized
        # OBDonUDS DIDs once".
        did_owner: dict[str, str] = {}
        for responder, info in sorted(obduds.items()):
            assert isinstance(info, dict)
            for did in info.get("supported_dids", []):
                did_owner.setdefault(did, responder)
        for responder, info in sorted(obduds.items()):
            assert isinstance(info, dict)
            module_key = f"obduds:{responder}"
            for did in info.get("supported_dids", []):
                if did_owner[did] != responder:
                    continue
                command = f"22{did}"
                if speed_key == (module_key, command):
                    continue
                entry = RecordWatch(module_key, command, RECORD_OBDUDS_WATCH_INTERVAL, "watch")
                watch.append(entry)

    for key, module in modules.items():
        if not module.discoverable:
            continue
        for discovered_did in sorted(module.discovered):
            entry = RecordWatch(
                key, f"22{discovered_did:04X}", RECORD_DISCOVERED_WATCH_INTERVAL, "watch"
            )
            watch.append(entry)

    return watch


DISCOVERY_SILENT_STATUSES = frozenset({"NO DATA", "NRC 31 requestOutOfRange"})
# How long a module's discovery pauses after a batch where at least half the
# replies were NRC 11 (serviceNotSupported) - the ECU has most likely gone to
# sleep, so hammering it further is pointless until it wakes back up.
RECORD_ASLEEP_PAUSE_SECONDS = 60.0


def _batch_is_asleep(status_counts: dict[str, int], batch_size: int) -> bool:
    """True if at least half of one discovery batch's replies were NRC 11
    (serviceNotSupported) - the signature of an ECU that stopped answering,
    typically because the vehicle itself was switched off."""
    if batch_size == 0:
        return False
    nrc11 = sum(count for status, count in status_counts.items() if status.startswith("NRC 11"))
    return nrc11 * 2 >= batch_size


async def run_discovery_batch(
    link: AdapterLink, module: RecordModule, state: RunState, state_path: Path
) -> list[int]:
    """Reads one batch (RECORD_DISCOVERY_BATCH DIDs) of `module`'s discovery
    work - its pending conditional retries first, else the next slice of its
    scan order. If the batch looks asleep (_batch_is_asleep), it is logged as
    a single ASLEEP summary, module progress does not advance, and the
    module's discovery pauses for RECORD_ASLEEP_PAUSE_SECONDS; otherwise it
    persists the updated position/discovered/conditional set and returns the
    DIDs newly found OK. A normal batch writes an individual log entry only
    for a status other than NO DATA/NRC 31 (the overwhelming majority of a
    scan); every DID in it, found or not, is folded into one trailing
    `BATCH <first>-<last>`/SUMMARY entry mapping status to count, so the log
    stays readable without losing the full picture."""
    from_retry = bool(module.retry_queue)
    batch = (
        module.retry_queue[:RECORD_DISCOVERY_BATCH]
        if from_retry
        else module.order[module.position : module.position + RECORD_DISCOVERY_BATCH]
    )

    stage = f"discover-{module.key}"
    status_counts: dict[str, int] = {}
    replies: list[tuple[int, Exchange]] = []
    for did in batch:
        ex = await link.execute_guarded(
            f"22{did:04X}", stage, module.validator, module.responder, module=module.key, log=False
        )
        status_counts[ex.status] = status_counts.get(ex.status, 0) + 1
        replies.append((did, ex))

    if _batch_is_asleep(status_counts, len(batch)):
        summary = Exchange(
            f"BATCH {batch[0]:04X}-{batch[-1]:04X}",
            json.dumps(status_counts),
            "ASLEEP",
            datetime.now(UTC).isoformat(),
            0.0,
        )
        link.record(summary, stage, module.key)
        module.discovery_paused_until = time.monotonic() + RECORD_ASLEEP_PAUSE_SECONDS
        return []

    if from_retry:
        module.retry_queue = module.retry_queue[len(batch) :]
    else:
        module.position += len(batch)

    newly_found: list[int] = []
    for did, ex in replies:
        if ex.status == "OK":
            module.discovered.add(did)
            module.conditional.discard(did)
            newly_found.append(did)
        elif ex.status in ("NRC 22 conditionsNotCorrect", "NRC 33 securityAccessDenied"):
            module.conditional.add(did)
        else:
            module.conditional.discard(did)
        if ex.status not in DISCOVERY_SILENT_STATUSES:
            link.record(ex, stage, module.key)

    if batch:
        summary = Exchange(
            f"BATCH {batch[0]:04X}-{batch[-1]:04X}",
            json.dumps(status_counts),
            "SUMMARY",
            datetime.now(UTC).isoformat(),
            0.0,
        )
        link.record(summary, stage, module.key)

    state.save_discovery_state(
        module.key,
        module.position,
        [f"{did:04X}" for did in module.discovered],
        [f"{did:04X}" for did in module.conditional],
    )
    state.save(state_path)
    return newly_found


def record_status_line(
    phase: str,
    watching: int,
    modules: dict[str, RecordModule],
    discovery_rate: float,
    setup_commands_sent: int = 0,
) -> str:
    parts = [f"phase={phase}", f"watching={watching}", f"setup={setup_commands_sent}"]
    for key, module in sorted(modules.items()):
        if not module.discoverable:
            continue
        total = len(module.order)
        pct = 100.0 if total == 0 else module.position / total * 100
        remaining = total - module.position
        eta = f"{remaining / discovery_rate:.0f}s" if discovery_rate > 0 and remaining else "-"
        parts.append(f"{key}={pct:.0f}%(eta {eta})")
    return " ".join(parts)


@dataclass
class RecordLoopState:
    """Everything `record_loop_tick` carries between iterations - split out of
    `run_record_loop` so a test can drive one tick at a time instead of racing
    a background task against real wall-clock intervals."""

    modules: dict[str, RecordModule]
    speed_key: tuple[str, str] | None
    by_key: dict[tuple[str, str], RecordWatch]
    next_due: dict[tuple[str, str], float]
    profile: Profile | None = None
    latest: dict[str, LiveValue] = field(default_factory=dict)
    current_module_key: str | None = None
    # None after a fresh connect/reconnect: the adapter's actual protocol is
    # unknown then, so the first module switch always sends ATSP.
    current_protocol: str | None = None
    phase: str = "moving"
    speed_value: int | None = None
    speed_fetched: float | None = None
    discovery_start: float = field(default_factory=time.monotonic)
    discovery_done_initial: int = 0
    last_status: float = field(default_factory=time.monotonic)
    # Adaptive polling (non-speed watch entries only - see
    # _record_update_backoff) and change-only logging (every watch entry -
    # see _record_watch_should_log) bookkeeping, keyed the same as by_key.
    watch_interval: dict[tuple[str, str], float] = field(default_factory=dict)
    watch_unchanged: dict[tuple[str, str], int] = field(default_factory=dict)
    watch_payload: dict[tuple[str, str], str] = field(default_factory=dict)
    watch_last_logged: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    watch_last_log_time: dict[tuple[str, str], float] = field(default_factory=dict)
    last_rediscover: float = field(default_factory=time.monotonic)
    # True for exactly one `_record_maybe_rediscover` call after a fresh
    # connect/resume whose persisted last-rediscovery timestamp was less than
    # RECORD_REDISCOVER_INTERVAL ago - suppresses that one phase-change
    # rediscovery (periodic due_for_interval rediscovery still applies), then
    # clears itself. See build_record_loop_state.
    skip_initial_phase_rediscover: bool = False
    # Successful module-switch setup commands (see `_record_ensure_module`) -
    # no longer logged individually, counted here for `record_status_line`.
    setup_commands_sent: int = 0
    # --discover-while-moving (default off): lets discovery run on opted-in
    # modules while the vehicle is moving, see RECORD_MOVING_DISCOVERY_INTERVAL.
    discover_while_moving: bool = False
    last_moving_discovery: float = field(default_factory=time.monotonic)

    def current_phase(self) -> str:
        if self.speed_key is None:
            return "moving"
        age = None if self.speed_fetched is None else time.monotonic() - self.speed_fetched
        return motion_phase(self.speed_value, age)


def build_record_loop_state(
    profile: Profile | None, state: RunState, discover_while_moving: bool = False
) -> RecordLoopState:
    modules = build_record_modules(profile, state)
    speed_key = select_speed_source(modules, state)
    watch = build_record_watch(profile, state, modules, speed_key)
    by_key = {(w.module_key, w.command): w for w in watch}
    next_due = {key: time.monotonic() for key in by_key}
    watch_interval = {key: entry.base_interval for key, entry in by_key.items()}
    discovery_done_initial = sum(m.position for m in modules.values() if m.discoverable)

    # Seed the rediscovery cooldown from state.json, if a previous run (or an
    # earlier connection within this one) already rediscovered recently - a
    # fresh connect/resume should not immediately rediscover again just
    # because the vehicle happens to be stationary at startup.
    now = time.monotonic()
    last_rediscover = now
    skip_initial_phase_rediscover = False
    persisted = state.last_rediscover_time()
    if persisted is not None:
        elapsed = max(0.0, time.time() - persisted)
        if elapsed < RECORD_REDISCOVER_INTERVAL:
            last_rediscover = now - elapsed
            skip_initial_phase_rediscover = True

    return RecordLoopState(
        modules=modules,
        speed_key=speed_key,
        by_key=by_key,
        next_due=next_due,
        profile=profile,
        watch_interval=watch_interval,
        discovery_done_initial=discovery_done_initial,
        discover_while_moving=discover_while_moving,
        last_rediscover=last_rediscover,
        skip_initial_phase_rediscover=skip_initial_phase_rediscover,
    )


async def _record_run_setup_command(
    link: AdapterLink, cmd: str, validator: Callable[[str], str]
) -> Exchange:
    """Runs one `record-setup` AT command without logging it on success -
    these commands run every module switch, so logging all of them drowns
    the log in traffic that doesn't change (see `record_status_line`'s
    `setup` count instead). A failure is still logged and still aborts the
    session, exactly like a normal critical `AdapterLink.execute` call."""
    ex = await link.session.run(cmd, validator, None)
    if ex.status != "OK":
        link.record(ex, "record-setup")
    if not link.session.usable or ex.status != "OK":
        raise ProbeAbortedError(f"{cmd}: {ex.status}; disconnect and retry")
    return ex


async def _record_ensure_module(link: AdapterLink, loop_state: RecordLoopState, key: str) -> None:
    if key == loop_state.current_module_key:
        return
    module = loop_state.modules[key]
    protocol_changed = module.protocol != loop_state.current_protocol
    if protocol_changed:
        await _record_run_setup_command(link, FORCE_PROTOCOL[module.protocol], module.validator)
        loop_state.current_protocol = module.protocol

    previous_module = (
        loop_state.modules.get(loop_state.current_module_key)
        if loop_state.current_module_key is not None
        else None
    )
    # Reuse the previous module's flow-control state (ATFCSD/ATFCSM1 persist
    # on the adapter) when switching between two flow-control modules on the
    # same protocol - only the header/filter/response-id actually change.
    reuse_flow_control = (
        not protocol_changed
        and previous_module is not None
        and previous_module.responder is not None
        and module.responder is not None
        and module.request is not None
    )
    commands = (
        [f"ATSH{module.request}", f"ATCRA{module.responder}", f"ATFCSH{module.request}"]
        if reuse_flow_control
        else module.setup
    )
    for cmd in commands:
        await _record_run_setup_command(link, cmd, module.validator)
        loop_state.setup_commands_sent += 1
    loop_state.current_module_key = key


def _record_apply_phase(link: AdapterLink, loop_state: RecordLoopState) -> bool:
    """Applies a motion-phase change, if any, and reports whether one
    happened (the caller uses that to decide whether to rediscover - see
    RECORD_REDISCOVER_INTERVAL)."""
    new_phase = loop_state.current_phase()
    if new_phase == loop_state.phase:
        return False
    if new_phase == "stationary":
        for module in loop_state.modules.values():
            if module.discoverable:
                module.retry_queue = sorted(module.conditional)
    for key, entry in loop_state.by_key.items():
        if not entry.is_speed:
            loop_state.watch_interval[key] = entry.base_interval
            loop_state.watch_unchanged[key] = 0
    link.record(
        Exchange("PHASE", new_phase, new_phase.upper(), datetime.now(UTC).isoformat(), 0.0), "phase"
    )
    print(f"[record] phase -> {new_phase}")
    loop_state.phase = new_phase
    return True


RECORD_WATCH_UNCHANGED_THRESHOLD = 3
RECORD_WATCH_BACKOFF_CAP = 1800.0  # seconds
RECORD_WATCH_KEEPALIVE_SECONDS = 900.0
# While stationary, re-probe for ECUs that only wake in some vehicle states
# (e.g. a charger ECU while charging) even without a phase change.
RECORD_REDISCOVER_INTERVAL = 900.0  # seconds


def _record_update_backoff(
    loop_state: RecordLoopState, key: tuple[str, str], entry: RecordWatch, ex: Exchange
) -> None:
    """Adaptive polling for one non-speed watch entry: after
    RECORD_WATCH_UNCHANGED_THRESHOLD consecutive unchanged positive reads,
    double its interval up to RECORD_WATCH_BACKOFF_CAP; any change - a
    different payload, or a non-OK status - resets it to `entry.base_interval`."""
    if ex.status == "OK" and loop_state.watch_payload.get(key) == ex.response:
        count = loop_state.watch_unchanged.get(key, 0) + 1
        loop_state.watch_unchanged[key] = count
        if count >= RECORD_WATCH_UNCHANGED_THRESHOLD:
            loop_state.watch_interval[key] = min(
                loop_state.watch_interval.get(key, entry.base_interval) * 2.0,
                RECORD_WATCH_BACKOFF_CAP,
            )
    else:
        loop_state.watch_unchanged[key] = 0
        loop_state.watch_interval[key] = entry.base_interval
    if ex.status == "OK":
        loop_state.watch_payload[key] = ex.response


def _record_watch_should_log(
    loop_state: RecordLoopState, key: tuple[str, str], ex: Exchange, now: float
) -> bool:
    """Change-only logging for one watch/survey read: true for the first
    read of a key, any change in status or response since the last WRITTEN
    entry for it, or a keep-alive after RECORD_WATCH_KEEPALIVE_SECONDS even
    without one."""
    last = loop_state.watch_last_logged.get(key)
    if last is None or (ex.status, ex.response) != last:
        return True
    return now - loop_state.watch_last_log_time.get(key, 0.0) >= RECORD_WATCH_KEEPALIVE_SECONDS


async def _record_rediscover(
    link: AdapterLink, state: RunState, state_path: Path, loop_state: RecordLoopState
) -> None:
    """Re-probes for ECUs that only wake in some vehicle states - ecus11 and
    ecus29 (plus the VAG scheme if the profile opts in), skipping anything
    already known - and folds any newly found ECU into the running loop as a
    fresh RecordModule, joining watch/discovery exactly like one found at
    startup. The adapter's header/protocol state is unknown to the scheduler
    afterwards, the same as right after a reconnect."""
    stage = "rediscover"
    profile = loop_state.profile

    async def execute11(command: str, s: str, responder: str | None = None) -> Exchange:
        return await link.execute_guarded(command, s, check_ecus11_allowed, responder)

    async def execute29(command: str, s: str, responder: str | None = None) -> Exchange:
        return await link.execute_guarded(command, s, check_ecus29_allowed, responder)

    known_ecus11 = state.result("ecus11") or {}
    assert isinstance(known_ecus11, dict)
    candidates11 = [f"{i:03X}" for i in ECU11_REQUEST_IDS if f"{i:03X}" not in known_ecus11]
    if candidates11:
        await execute11("ATSP6", stage)
        await execute11("ATDPN", stage)
        await execute11("ATAR", stage)
        await execute11("ATCF700", stage)
        await execute11("ATCM700", stage)
        new11 = await _discover_ecus(execute11, stage, candidates11, set(), lambda c: c, None)
        await execute11("ATAR", f"{stage}-done")
        identified11 = await _identify_new_ecus(execute11, new11, lambda c: c, f"{stage}-identify")
        if identified11:
            state.set_result("ecus11", {**known_ecus11, **identified11})
            for request, info in identified11.items():
                assert isinstance(info, dict)
                key = f"ecus11:{request}"
                response = info["response"]
                assert isinstance(response, str)
                loop_state.modules[key] = _ecu_record_module(
                    key, request, response, "6", check_sweep_allowed
                )

    known_obduds = state.result("obduds") or {}
    known_obduds_ecus = {r[-2:] for r in known_obduds} if isinstance(known_obduds, dict) else set()
    known_ecus29 = state.result("ecus29") or {}
    assert isinstance(known_ecus29, dict)
    skip29 = set(known_ecus29) | known_obduds_ecus
    candidates29 = [ecu for ecu in ECU29_IDS if ecu not in skip29]
    if candidates29:
        await execute29("ATSP7", stage)
        await execute29("ATDPN", stage)
        await execute29("ATAR", stage)
        new29 = await _discover_ecus(
            execute29,
            stage,
            candidates29,
            set(),
            lambda ecu: f"18DA{ecu}F1",
            lambda ecu: f"18DAF1{ecu}",
        )
        await execute29("ATAR", f"{stage}-done")
        identified29 = await _identify_new_ecus(
            execute29, new29, lambda ecu: f"18DA{ecu}F1", f"{stage}-identify"
        )
        if identified29:
            state.set_result("ecus29", {**known_ecus29, **identified29})
            for ecu, info in identified29.items():
                assert isinstance(info, dict)
                key = f"ecus29:{ecu}"
                response = info["response"]
                assert isinstance(response, str)
                loop_state.modules[key] = _ecu_record_module(
                    key, f"18DA{ecu}F1", response, "7", check_sweep_allowed
                )

    if profile is not None and "vag-29bit" in profile.address_schemes:

        async def execute_vag(command: str, s: str, responder: str | None = None) -> Exchange:
            return await link.execute_guarded(command, s, check_vag29_allowed, responder)

        known_vag29 = state.result("vag29") or {}
        assert isinstance(known_vag29, dict)
        candidates_vag = [ecu for ecu in VAG29_IDS if ecu not in known_vag29]
        if candidates_vag:
            await execute_vag("ATSP7", stage)
            await execute_vag("ATDPN", stage)
            await execute_vag("ATAR", stage)
            new_vag = await _discover_ecus(
                execute_vag,
                stage,
                candidates_vag,
                set(),
                lambda ecu: f"17FC00{ecu}",
                lambda ecu: f"17FE00{ecu}",
            )
            await execute_vag("ATAR", f"{stage}-done")
            identified_vag = await _identify_new_ecus(
                execute_vag, new_vag, lambda ecu: f"17FC00{ecu}", f"{stage}-identify"
            )
            if identified_vag:
                state.set_result("vag29", {**known_vag29, **identified_vag})
                for ecu, info in identified_vag.items():
                    assert isinstance(info, dict)
                    key = f"vag29:{ecu}"
                    response = info["response"]
                    assert isinstance(response, str)
                    loop_state.modules[key] = _ecu_record_module(
                        key, f"17FC00{ecu}", response, "7", check_vag29_allowed
                    )

    state.set_last_rediscover_time(time.time())
    state.save(state_path)
    # The scans above left the adapter's actual header/protocol in whatever
    # state the last probe set it to - unknown to the scheduler, same as a
    # fresh reconnect, so the next module switch always resends setup.
    loop_state.current_module_key = None
    loop_state.current_protocol = None
    loop_state.last_rediscover = time.monotonic()


async def _record_maybe_rediscover(
    link: AdapterLink, state: RunState, state_path: Path, loop_state: RecordLoopState, changed: bool
) -> None:
    due_for_interval = (
        loop_state.phase == "stationary"
        and time.monotonic() - loop_state.last_rediscover >= RECORD_REDISCOVER_INTERVAL
    )
    # Probing hundreds of unknown diagnostic ids is discovery traffic, so like
    # DID discovery it never runs while the vehicle is moving.
    entered_stationary = changed and loop_state.phase == "stationary"
    if entered_stationary and loop_state.skip_initial_phase_rediscover:
        # Consumed once: a fresh connect/resume whose persisted last
        # rediscovery was less than RECORD_REDISCOVER_INTERVAL ago skips this
        # one phase-change trigger; due_for_interval still applies normally
        # afterwards, and any later phase change in this run is unaffected.
        loop_state.skip_initial_phase_rediscover = False
        entered_stationary = False
    if entered_stationary or due_for_interval:
        await _record_rediscover(link, state, state_path, loop_state)


def _select_discovery_module(loop_state: RecordLoopState, now: float) -> RecordModule | None:
    """The module `record_loop_tick`'s idle branch should run one discovery
    batch on next - honoring a sleeping-ECU pause (discovery_paused_until)
    and, while moving, `--discover-while-moving`'s extra restrictions: only
    modules opted in via their profile's discover_while_moving, never one
    whose F197 name matches moving_discovery_blocked (overrides the profile),
    and at most one batch per RECORD_MOVING_DISCOVERY_INTERVAL seconds."""

    def available(module: RecordModule) -> bool:
        return module.has_discovery_work() and now >= module.discovery_paused_until

    if loop_state.phase == "stationary":
        return next((m for m in loop_state.modules.values() if available(m)), None)
    if (
        not loop_state.discover_while_moving
        or now - loop_state.last_moving_discovery < RECORD_MOVING_DISCOVERY_INTERVAL
    ):
        return None
    module = next(
        (
            m
            for m in loop_state.modules.values()
            if m.discover_while_moving
            and available(m)
            and not moving_discovery_blocked(m.f197_name)
        ),
        None,
    )
    if module is not None:
        loop_state.last_moving_discovery = now
    return module


async def record_loop_tick(
    link: AdapterLink, state: RunState, state_path: Path, loop_state: RecordLoopState
) -> None:
    """One scheduler iteration: poll whatever's due, grouped by module; else,
    while stationary, run one discovery batch on whichever known module still
    has work - or, with `--discover-while-moving` on, at most one such batch
    every RECORD_MOVING_DISCOVERY_INTERVAL seconds on an opted-in, unblocked
    module even while moving (see _select_discovery_module); else sleep until
    the next due time."""
    now = time.monotonic()
    due = sorted(key for key, due_at in loop_state.next_due.items() if due_at <= now)
    if due:
        entries = [
            (key, loop_state.watch_interval.get(key, entry.base_interval), entry.is_speed)
            for key, entry in loop_state.by_key.items()
        ]
        intervals = stretch_watch_intervals(entries)
        for key in due:
            entry = loop_state.by_key[key]
            await _record_ensure_module(link, loop_state, entry.module_key)
            module = loop_state.modules[entry.module_key]
            ex = await link.execute_guarded(
                entry.command,
                entry.stage,
                module.validator,
                module.responder,
                module=entry.module_key,
                log=False,
            )
            poll_now = time.monotonic()
            if _record_watch_should_log(loop_state, key, ex, poll_now):
                link.record(ex, entry.stage, entry.module_key)
                loop_state.watch_last_logged[key] = (ex.status, ex.response)
                loop_state.watch_last_log_time[key] = poll_now
            loop_state.latest[entry.command] = LiveValue(ex.response, ex.status, poll_now)
            loop_state.next_due[key] = poll_now + intervals[key]
            if entry.is_speed:
                loop_state.speed_value = decode_speed(entry.command, ex, module.responder)
                loop_state.speed_fetched = poll_now
            else:
                _record_update_backoff(loop_state, key, entry, ex)
        changed = _record_apply_phase(link, loop_state)
        await _record_maybe_rediscover(link, state, state_path, loop_state, changed)
        print(format_live_summary(loop_state.latest))
    else:
        changed = _record_apply_phase(link, loop_state)
        await _record_maybe_rediscover(link, state, state_path, loop_state, changed)
        discovering = _select_discovery_module(loop_state, now)
        if discovering is not None:
            await _record_ensure_module(link, loop_state, discovering.key)
            newly_found = await run_discovery_batch(link, discovering, state, state_path)
            for did in newly_found:
                key = (discovering.key, f"22{did:04X}")
                loop_state.by_key[key] = RecordWatch(
                    discovering.key, f"22{did:04X}", RECORD_DISCOVERED_WATCH_INTERVAL, "watch"
                )
                loop_state.watch_interval[key] = RECORD_DISCOVERED_WATCH_INTERVAL
                loop_state.watch_unchanged[key] = 0
                loop_state.next_due[key] = time.monotonic()
        else:
            due_times = loop_state.next_due.values()
            sleep_for = min(1.0, max(0.0, min(due_times, default=now + 1.0) - now))
            await asyncio.sleep(sleep_for)

    if time.monotonic() - loop_state.last_status >= RECORD_STATUS_INTERVAL:
        elapsed = time.monotonic() - loop_state.discovery_start
        done_now = sum(m.position for m in loop_state.modules.values() if m.discoverable)
        rate = (done_now - loop_state.discovery_done_initial) / elapsed if elapsed > 0 else 0.0
        watching = len(loop_state.by_key)
        line = record_status_line(
            loop_state.phase, watching, loop_state.modules, rate, loop_state.setup_commands_sent
        )
        print(f"[record] {line}")
        loop_state.last_status = time.monotonic()


async def run_record_loop(
    link: AdapterLink,
    state: RunState,
    profile: Profile | None,
    state_path: Path,
    discover_while_moving: bool = False,
) -> None:
    """Runs until cancelled (Ctrl-C): continuously polls every known value and,
    while the vehicle is stationary, discovers further DIDs on every known ECU
    in the background - plus, with `discover_while_moving`, a throttled slice
    of that discovery on opted-in modules while moving too (see
    _select_discovery_module). Persists watch/discovery progress as it goes,
    so both a reconnect within this run and a fresh `record` start later
    resume exactly where this left off."""
    loop_state = build_record_loop_state(profile, state, discover_while_moving)
    if loop_state.speed_key is None:
        print("[record] no speed source available; discovery stays paused until one appears")
    if discover_while_moving:
        print(
            "[record] discovery while moving enabled: opted-in modules only, "
            "steering/braking ECUs always excluded"
        )
    while True:
        await record_loop_tick(link, state, state_path, loop_state)


# ---------------------------------------------------------------------------
# derive: turn one `record` run's capture.jsonl into a profile draft + report.
# ---------------------------------------------------------------------------

# English/German free-text markers recognised in typed notes, canonicalized to
# one of these four - never anything attempted to fully parse arbitrary notes.
MARKER_PATTERNS: dict[str, re.Pattern[str]] = {
    "idle": re.compile(r"\bidle\b|\bleerlauf\b", re.IGNORECASE),
    "drive": re.compile(r"\bdriv(e|ing)\b|\bfahrt\b", re.IGNORECASE),
    "charge": re.compile(r"\bcharg(e|ing)\b|\blad(en|ung)\b", re.IGNORECASE),
    "park": re.compile(r"\bpark(ed|ing|en)?\b", re.IGNORECASE),
}

SPEED_COMMANDS = frozenset({"010D", "22F40D"})
SPEED_ALIGN_SECONDS = 5.0
DERIVE_INTERVAL_FAST = 15.0
DERIVE_INTERVAL_SLOW = 60.0
DERIVE_CHANGE_MEDIAN_THRESHOLD = 60.0
DERIVE_STATIONARY_MIN_SECONDS = 600.0
DERIVE_MODULE_HEADER_PATTERN = re.compile(r"ATSH(18DA[0-9A-F]{2}F1|[0-9A-F]{3})")
DERIVE_RESPONSE_HEADER_PATTERN = re.compile(r"ATCRA(18DAF1[0-9A-F]{2}|[0-9A-F]{3})")
DERIVE_DID_COMMAND_PATTERN = re.compile(r"22([0-9A-F]{4})")
CONDITIONAL_STATUSES = frozenset({"NRC 22 conditionsNotCorrect", "NRC 33 securityAccessDenied"})

# Typed-note ground truth, tokenized into numbers and words: a number may be
# preceded by context words ("soc 54"), followed by them ("54 soc", "176 km
# rest") or have a unit glued directly to it ("89kw", "54%") - the words on
# either side, plus a glued unit, resolve to a canonical key via
# NOTE_KEY_KEYWORDS/_canonical_note_key below. ':'/'=' between a word and a
# number are just separators.
NOTE_TOKEN_PATTERN = re.compile(
    r"(?P<num>\d+(?:[.,]\d+)?)(?P<unit>[a-zA-Z%\N{DEGREE SIGN}]+)?|(?P<word>[A-Za-zÄÖÜäöüß/]+)",
)
# Bare number+unit with no other context word - preserved for backward
# compatibility with readings that carry no other hint (e.g. a lone "54%").
# Anything with an actual keyword match (NOTE_KEY_KEYWORDS) takes priority.
NOTE_UNIT_KEYS: dict[str, str] = {
    "%": "percent",
    "kw": "kw",
    "km": "km",
    "\N{DEGREE SIGN}c": "c",
    "c": "c",
    "v": "v",
    "a": "a",
}
# Canonical note keys and the words (German/English, full or abbreviated)
# that identify them - fuzzy-matched per token (see _word_matches) so a typo
# like "sooc" or "reichweote" still resolves. A multi-word phrase (contains a
# space) only matches as an adjacent run and always wins over a single-word
# match (see _canonical_note_key).
NOTE_KEY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "soc": ("so", "soc", "sooc", "ladestand", "state of charge"),
    "range": ("reichweite", "rest", "restreichweite", "reichw", "range"),
    "battery_temp": ("batt", "battemp", "batterietemp", "akku", "battery temp"),
    "outside_temp": ("aussen", "aussentemp", "außentemperatur", "outside"),
    "charge_power": ("ladeleistung", "ladung", "leistung", "kw"),
    "odometer": ("km stand", "kmstand", "kilometerstand", "odometer"),
    "speed": ("kmh", "km/h"),
}
# "max"/"maximal" next to any charge_power word always means max_charge_power,
# regardless of which charge_power keyword triggered it.
NOTE_MAX_WORDS = ("max", "maximal")
# A bare number next to the word "km" (not "kmh") is the odometer only if it
# has the digit count a real odometer reading would have.
NOTE_ODOMETER_DIGITS = (5, 6)
NOTE_FUZZY_MIN_RATIO = 0.8
NOTE_MIN_NOTES = 3
NOTE_MIN_DISTINCT_VALUES = 2
NOTE_STALE_SECONDS = 15 * 60.0
NOTE_NAME_MIN_R = 0.99
NOTE_NAME_MIN_NOTES = 4
NOTE_CANDIDATE_FIELDS: tuple[tuple[int, bool], ...] = (
    (1, False),
    (2, False),
    (2, True),
    (4, False),
)


def _word_matches(word: str, keyword: str) -> bool:
    """Exact match, or a fuzzy one (difflib, ratio >= NOTE_FUZZY_MIN_RATIO) -
    only attempted for words of at least 3 characters, so a short word like
    "km" can never accidentally fuzzy-match an unrelated keyword like
    "kmh"."""
    if word == keyword:
        return True
    if len(word) < 3 or len(keyword) < 3:
        return False
    return difflib.SequenceMatcher(None, word, keyword).ratio() >= NOTE_FUZZY_MIN_RATIO


def _phrase_matches(words: list[str], phrase: str) -> bool:
    tokens = phrase.split()
    if len(tokens) < 2:
        return False
    return any(
        all(_word_matches(words[i + j], tokens[j]) for j in range(len(tokens)))
        for i in range(len(words) - len(tokens) + 1)
    )


def _canonical_note_key(words: list[str]) -> str | None:
    """Maps a typed note's context words to one of NOTE_KEY_KEYWORDS's
    canonical keys, tolerating typos (see _word_matches). "max"/"maximal"
    together with any charge_power word always means max_charge_power; a
    multi-word keyword phrase, if it matches as an adjacent run, always wins
    over a single-word one."""
    if any(_word_matches(w, m) for w in words for m in NOTE_MAX_WORDS) and any(
        _word_matches(w, kw) for w in words for kw in NOTE_KEY_KEYWORDS["charge_power"]
    ):
        return "max_charge_power"
    for key, keywords in NOTE_KEY_KEYWORDS.items():
        if any(_phrase_matches(words, kw) for kw in keywords if " " in kw):
            return key
    for key, keywords in NOTE_KEY_KEYWORDS.items():
        for keyword in keywords:
            if " " not in keyword and any(_word_matches(w, keyword) for w in words):
                return key
    return None


def parse_note(text: str) -> list[tuple[str, float]]:
    """Extracts (key, value) ground-truth pairs typed during `record` - a
    number with context words before it ("soc 54", "soc: 54,5", "soc=54",
    "soc54"), after it ("54 soc", "176 km rest", "14 batt temp"), or a unit
    glued directly to it ("89kw", "100kmh", "54%"); typos in the words
    resolve via NOTE_KEY_KEYWORDS/_canonical_note_key. A bare 5-6 digit
    number next to "km" is always the odometer (NOTE_ODOMETER_DIGITS). A
    word that is itself a phase marker (MARKER_PATTERNS) never contributes to
    a key; a number with no usable context - not even a bare unit
    (NOTE_UNIT_KEYS) - is silently ignored."""
    tokens = list(NOTE_TOKEN_PATTERN.finditer(text))
    pairs: list[tuple[str, float]] = []
    for i, token in enumerate(tokens):
        if token.group("num") is None:
            continue
        value = float(token.group("num").replace(",", "."))
        unit = token.group("unit")
        forward: list[str] = [unit.lower()] if unit else []
        j = i + 1
        while j < len(tokens) and tokens[j].group("word") is not None:
            forward.append(tokens[j].group("word").lower())
            j += 1
        backward: list[str] = []
        k = i - 1
        while k >= 0 and tokens[k].group("word") is not None:
            backward.insert(0, tokens[k].group("word").lower())
            k -= 1
        words = [
            w for w in backward + forward if not any(p.search(w) for p in MARKER_PATTERNS.values())
        ]
        if not words:
            continue

        if (
            "km" in words
            and value == int(value)
            and NOTE_ODOMETER_DIGITS[0] <= len(str(int(value))) <= NOTE_ODOMETER_DIGITS[1]
        ):
            pairs.append(("odometer", value))
            continue

        key = _canonical_note_key(words)
        if key is None and unit is not None and words == [unit.lower()]:
            key = NOTE_UNIT_KEYS.get(unit.lower())
        if key is not None:
            pairs.append((key, value))
    return pairs


def classify_note_marker(text: str) -> str | None:
    """Canonicalizes a typed note to one of MARKER_PATTERNS's keys, or None if
    it doesn't match exactly one of them - an ambiguous or unrelated note is
    never treated as a phase marker."""
    matches = [name for name, pattern in MARKER_PATTERNS.items() if pattern.search(text)]
    return matches[0] if len(matches) == 1 else None


@dataclass
class DidSample:
    t: float
    payload: bytes
    phase: str


@dataclass
class DidRecord:
    did: str
    samples: list[DidSample] = field(default_factory=list)
    from_discovery: bool = False
    conditional: bool = False


@dataclass
class ModuleRecord:
    request: str | None
    response: str | None
    dids: dict[str, DidRecord] = field(default_factory=dict)


@dataclass
class NoteSample:
    t: float
    key: str
    value: float


@dataclass
class DerivedData:
    modules: dict[tuple[str | None, str | None], ModuleRecord]
    speed_series: list[tuple[float, int]]
    notes: list[NoteSample] = field(default_factory=list)


def _entry_seconds(entry: dict[str, object], origin: datetime | None) -> float:
    if origin is None:
        return 0.0
    ts = entry.get("started_utc")
    if not isinstance(ts, str) or not ts:
        return 0.0
    return (datetime.fromisoformat(ts) - origin).total_seconds()


_HEADERLESS_NUMBERED_LINE = re.compile(r"^([0-9A-F]):([0-9A-F]+)$")


def _decode_headerless_payload(command: str, response: str) -> bytes | None:
    """`derive`-only fallback for a positive ReadDataByIdentifier reply that
    lost CAN headers and ISO-TP framing mid-run (adapter reverted to
    headers-off formatting - see record's FORMAT_LOST recovery, which
    prevents this going forward but can't fix an already-captured log): a
    bare single-frame hex line, or ELM's numbered multi-frame continuation
    lines ("0: 62 2A B8 00 00 06", "1: 58 00 00 ...", concatenated in index
    order). Returns the data bytes after the ReadDataByIdentifier echo if
    the prefix matches, else None - never used by `record` itself, which
    always has real CAN headers to validate a reply against."""
    expected = bytes.fromhex(command)
    prefix = bytes([expected[0] + 0x40]) + expected[1:]
    lines = [re.sub(r"\s+", "", line.upper()) for line in response.splitlines()]
    lines = [line for line in lines if line and line != command]

    numbered: dict[int, str] = {}
    plain: list[str] = []
    for line in lines:
        match = _HEADERLESS_NUMBERED_LINE.fullmatch(line)
        if match:
            numbered[int(match.group(1), 16)] = match.group(2)
        elif re.fullmatch(r"[0-9A-F]+", line):
            plain.append(line)

    if numbered:
        data = bytes.fromhex("".join(numbered[i] for i in sorted(numbered)))
        return data[len(prefix) :] if data.startswith(prefix) else None

    for line in plain:
        if len(line) % 2:
            continue
        data = bytes.fromhex(line)
        if data.startswith(prefix):
            return data[len(prefix) :]
    return None


def analyze_capture(entries: list[dict[str, object]]) -> DerivedData:
    """Replays a capture log in order, grouping every ReadDataByIdentifier
    exchange by the CAN header pair active at the time (tracked from the
    `ATSH`/`ATCRA` commands that precede it - the log alone is enough, no
    `state.json` or `--profile` needed). Mode-01 reads never match the 22xxxx
    pattern and OBDonUDS support-bitmap reads never carry a `discover-` stage,
    so both are naturally excluded from anything `from_discovery` cares about."""
    modules: dict[tuple[str | None, str | None], ModuleRecord] = {}
    speed_series: list[tuple[float, int]] = []
    notes: list[NoteSample] = []
    origin: datetime | None = None
    current_request: str | None = None
    current_response: str | None = None
    current_phase = "moving"

    for entry in entries:
        ts = entry.get("started_utc")
        if origin is None and isinstance(ts, str) and ts:
            origin = datetime.fromisoformat(ts)
        t = _entry_seconds(entry, origin)
        command = str(entry.get("command", ""))
        status = str(entry.get("status", ""))
        response_raw = str(entry.get("response", ""))
        stage = str(entry.get("stage", ""))

        if status == "SUMMARY" and command.startswith("BATCH "):
            # A discovery-batch summary (see run_discovery_batch) holds
            # aggregate status counts, not a DID sample - every individual
            # DID it covers that answered OK already has its own entry.
            continue

        header_match = DERIVE_MODULE_HEADER_PATTERN.fullmatch(command)
        if header_match:
            current_request = header_match.group(1)
            current_response = None
            continue
        response_header_match = DERIVE_RESPONSE_HEADER_PATTERN.fullmatch(command)
        if response_header_match:
            current_response = response_header_match.group(1)
            continue
        if command == "PHASE":
            current_phase = response_raw.strip().lower() or current_phase
            continue
        if command == "NOTE":
            marker = classify_note_marker(response_raw)
            if marker is not None:
                current_phase = marker
            for note_key, note_value in parse_note(response_raw):
                notes.append(NoteSample(t, note_key, note_value))
            continue

        has_module = entry.get("module") is not None
        if command in SPEED_COMMANDS:
            speed: int | None = None
            if status == "OK":
                speed = decode_speed(
                    command, Exchange(command, response_raw, status, "", 0.0), current_response
                )
            elif has_module and command != "010D":
                # A lost-formatting capture (see FORMAT_LOST) misclassified
                # this as MALFORMED - try the headerless fallback instead of
                # treating motion as unknown for the whole run.
                payload = _decode_headerless_payload(command, response_raw)
                speed = payload[0] if payload else None
            if speed is not None:
                speed_series.append((t, speed))

        did_match = DERIVE_DID_COMMAND_PATTERN.fullmatch(command)
        if not did_match:
            continue
        did = did_match.group(1)
        if did in VIN_DIDS:
            continue
        key = (current_request, current_response)
        module = modules.setdefault(key, ModuleRecord(current_request, current_response))
        record = module.dids.setdefault(did, DidRecord(did))
        if stage.startswith("discover-"):
            record.from_discovery = True
        if status in CONDITIONAL_STATUSES:
            record.conditional = True
            continue
        payload = None
        if status == "OK":
            payload = decode_positive_payload(command, response_raw, current_response)
        elif has_module:
            # Same lost-formatting fallback as above, for a data DID rather
            # than the speed source.
            payload = _decode_headerless_payload(command, response_raw)
        if payload:
            record.samples.append(DidSample(t, payload, current_phase))

    return DerivedData(modules, speed_series, notes)


def _most_common_length(payloads: list[bytes]) -> int:
    counts: dict[int, int] = {}
    for payload in payloads:
        counts[len(payload)] = counts.get(len(payload), 0) + 1
    return max(counts, key=lambda length: counts[length])


def _varying_byte_positions(payloads: list[bytes]) -> dict[int, tuple[int, int]]:
    length = _most_common_length(payloads)
    same_length = [p for p in payloads if len(p) == length]
    varying: dict[int, tuple[int, int]] = {}
    for pos in range(length):
        values = [p[pos] for p in same_length]
        if min(values) != max(values):
            varying[pos] = (min(values), max(values))
    return varying


def _classify_did(record: DidRecord) -> tuple[str, float | None]:
    """'once' if every sample carries the same payload, else 'watch' with an
    interval suggestion: 15s if the median gap between value changes is under
    a minute, else 60s."""
    if len({s.payload for s in record.samples}) <= 1:
        return "once", None
    change_times = [
        s.t
        for i, s in enumerate(record.samples)
        if i > 0 and s.payload != record.samples[i - 1].payload
    ]
    if len(change_times) >= 2:
        gaps = sorted(b - a for a, b in zip(change_times, change_times[1:], strict=False))
        mid = len(gaps) // 2
        median_gap = gaps[mid] if len(gaps) % 2 else (gaps[mid - 1] + gaps[mid]) / 2
    else:
        median_gap = 0.0
    fast = median_gap < DERIVE_CHANGE_MEDIAN_THRESHOLD
    interval = DERIVE_INTERVAL_FAST if fast else DERIVE_INTERVAL_SLOW
    return "watch", interval


def _changed_phases(record: DidRecord) -> set[str]:
    return {
        s.phase
        for i, s in enumerate(record.samples)
        if i > 0 and s.payload != record.samples[i - 1].payload
    }


def _pearson(xs: list[float], ys: list[float]) -> float | None:
    n = len(xs)
    if n < 3:
        return None
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    var_x = sum((x - mean_x) ** 2 for x in xs)
    var_y = sum((y - mean_y) ** 2 for y in ys)
    if var_x == 0 or var_y == 0:
        return None
    return cov / math.sqrt(var_x * var_y)


def _align_to_speed(
    points: list[tuple[float, int]], speed_series: list[tuple[float, int]]
) -> tuple[list[float], list[float]]:
    xs: list[float] = []
    ys: list[float] = []
    for t, value in points:
        best: int | None = None
        best_dt = SPEED_ALIGN_SECONDS
        for st, sv in speed_series:
            dt = abs(st - t)
            if dt <= best_dt:
                best_dt, best = dt, sv
        if best is not None:
            xs.append(float(value))
            ys.append(float(best))
    return xs, ys


def speed_correlation(
    record: DidRecord, speed_series: list[tuple[float, int]]
) -> tuple[int, int, float] | None:
    """Strongest |Pearson r| of any 1- or 2-byte big-endian field in `record`'s
    most common payload length against `speed_series`, time-aligned to within
    SPEED_ALIGN_SECONDS - or None if there's nothing to align against."""
    if not speed_series or not record.samples:
        return None
    length = _most_common_length([s.payload for s in record.samples])
    best: tuple[int, int, float] | None = None
    for width in (1, 2):
        for offset in range(0, length - width + 1):
            points = [
                (s.t, int.from_bytes(s.payload[offset : offset + width], "big"))
                for s in record.samples
                if len(s.payload) >= offset + width
            ]
            xs, ys = _align_to_speed(points, speed_series)
            r = _pearson(xs, ys)
            if r is not None and (best is None or abs(r) > abs(best[2])):
                best = (offset, width, r)
    return best


def stationary_monotonic_candidates(record: DidRecord) -> list[tuple[int, int, str, float]]:
    """Fields that rise or fall monotonically while stationary for at least
    DERIVE_STATIONARY_MIN_SECONDS - candidates for a charging/energy value."""
    stationary = [s for s in record.samples if s.phase == "stationary"]
    if len(stationary) < 2 or stationary[-1].t - stationary[0].t < DERIVE_STATIONARY_MIN_SECONDS:
        return []
    length = _most_common_length([s.payload for s in stationary])
    duration = stationary[-1].t - stationary[0].t
    found: list[tuple[int, int, str, float]] = []
    for width in (1, 2):
        for offset in range(0, length - width + 1):
            values = [
                int.from_bytes(s.payload[offset : offset + width], "big")
                for s in stationary
                if len(s.payload) >= offset + width
            ]
            if len(values) < 2 or values[0] == values[-1]:
                continue
            if all(a <= b for a, b in zip(values, values[1:], strict=False)):
                found.append((offset, width, "rising", duration))
            elif all(a >= b for a, b in zip(values, values[1:], strict=False)):
                found.append((offset, width, "falling", duration))
    return found


@dataclass
class NoteMatch:
    label: str
    did: str
    offset: int
    width: int
    signed: bool
    r: float
    a: float
    b: float
    rmse: float
    n: int
    # True if this candidate matched the note against the field's time
    # derivative (per hour) rather than its raw value - see
    # DERIVATIVE_CANDIDATE_KEYWORD and _derivative_at.
    derivative: bool = False


def _holding_sample(samples: list[DidSample], t: float, max_age: float) -> DidSample | None:
    """The last sample at or before `t` (samples are in capture order, so
    ascending in time) - a change-only watch entry holds until the next one
    for the same module+command, so this is the value that was showing at
    `t`. None if the newest eligible sample is older than `max_age`."""
    best: DidSample | None = None
    for sample in samples:
        if sample.t > t:
            break
        best = sample
    if best is None or t - best.t > max_age:
        return None
    return best


def _lstsq_fit(xs: list[float], ys: list[float]) -> tuple[float, float, float] | None:
    """Least-squares `y = a*x + b` and its RMSE, or None if `xs` is constant."""
    n = len(xs)
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    var_x = sum((x - mean_x) ** 2 for x in xs)
    if var_x == 0:
        return None
    a = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True)) / var_x
    b = mean_y - a * mean_x
    rmse = math.sqrt(sum((y - (a * x + b)) ** 2 for x, y in zip(xs, ys, strict=True)) / n)
    return a, b, rmse


# Charging power never shows on its own curve - it tracks how fast an energy
# field moves, not any field's absolute value - so a note about it (or any
# derived "max" variant) is also matched against each candidate field's time
# derivative, not just its raw value.
DERIVATIVE_CANDIDATE_KEYWORD = "power"
DERIV_WINDOW_SECONDS = 150.0
DERIV_MIN_SAMPLES = 3


def _derivative_at(
    samples: list[DidSample], offset: int, width: int, signed: bool, t: float
) -> float | None:
    """Per-hour rate of change of one byte field around `t`, from a local
    least-squares fit over the samples within DERIV_WINDOW_SECONDS of it -
    None if fewer than DERIV_MIN_SAMPLES fall in that window."""
    window = [
        (s.t, float(int.from_bytes(s.payload[offset : offset + width], "big", signed=signed)))
        for s in samples
        if abs(s.t - t) <= DERIV_WINDOW_SECONDS and len(s.payload) >= offset + width
    ]
    if len(window) < DERIV_MIN_SAMPLES:
        return None
    fit = _lstsq_fit([w[0] for w in window], [w[1] for w in window])
    return fit[0] * 3600.0 if fit is not None else None


def match_notes(data: DerivedData) -> dict[str, list[NoteMatch]]:
    """For every typed-note key seen at least NOTE_MIN_NOTES times with at
    least NOTE_MIN_DISTINCT_VALUES distinct values, the top 5 raw fields
    (across every module/DID with positive samples) whose value held at each
    note's time best predicts that note's number, ranked by |r| then RMSE."""
    by_key: dict[str, list[NoteSample]] = {}
    for note in data.notes:
        by_key.setdefault(note.key, []).append(note)

    results: dict[str, list[NoteMatch]] = {}
    for key, notes in by_key.items():
        if len(notes) < NOTE_MIN_NOTES or len({n.value for n in notes}) < NOTE_MIN_DISTINCT_VALUES:
            continue
        candidates: list[NoteMatch] = []
        for (request, response), module in data.modules.items():
            if request is None:
                continue
            label = _module_label(request, response)
            for did, record in module.dids.items():
                if not record.samples:
                    continue
                length = _most_common_length([s.payload for s in record.samples])
                samples = [s for s in record.samples if len(s.payload) == length]
                for width, signed in NOTE_CANDIDATE_FIELDS:
                    for offset in range(0, length - width + 1):
                        xs: list[float] = []
                        ys: list[float] = []
                        for note in notes:
                            held = _holding_sample(samples, note.t, NOTE_STALE_SECONDS)
                            if held is None:
                                continue
                            raw = int.from_bytes(
                                held.payload[offset : offset + width], "big", signed=signed
                            )
                            xs.append(float(raw))
                            ys.append(note.value)
                        if len(xs) >= 3 and len(set(xs)) > 1:
                            r = _pearson(xs, ys)
                            fit = _lstsq_fit(xs, ys)
                            if r is not None and fit is not None:
                                a, b, rmse = fit
                                candidates.append(
                                    NoteMatch(
                                        label, did, offset, width, signed, r, a, b, rmse, len(xs)
                                    )
                                )

                        if DERIVATIVE_CANDIDATE_KEYWORD not in key.lower():
                            continue
                        dxs: list[float] = []
                        dys: list[float] = []
                        for note in notes:
                            deriv = _derivative_at(samples, offset, width, signed, note.t)
                            if deriv is None:
                                continue
                            dxs.append(deriv)
                            dys.append(note.value)
                        if len(dxs) < 3 or len(set(dxs)) <= 1:
                            continue
                        dr = _pearson(dxs, dys)
                        dfit = _lstsq_fit(dxs, dys)
                        if dr is None or dfit is None:
                            continue
                        da, db, drmse = dfit
                        candidates.append(
                            NoteMatch(
                                label,
                                did,
                                offset,
                                width,
                                signed,
                                dr,
                                da,
                                db,
                                drmse,
                                len(dxs),
                                derivative=True,
                            )
                        )
        candidates.sort(key=lambda c: (-abs(c.r), c.rmse))
        results[key] = candidates[:5]
    return results


def named_candidates(matches: dict[str, list[NoteMatch]]) -> dict[tuple[str, str], str]:
    """(module label, DID) -> key for every DID whose best matched field
    reaches NOTE_NAME_MIN_R over at least NOTE_NAME_MIN_NOTES notes - these
    get `name = "<key> candidate"` in the profile draft."""
    best: dict[tuple[str, str], tuple[str, float]] = {}
    for key, top in matches.items():
        for m in top:
            # A derivative match means the field itself is an energy/distance
            # counter, not the rate the note describes - naming the DID after
            # the note's key would be misleading, so only a direct match
            # names it in the draft (the derivative still shows in the report).
            if m.derivative or abs(m.r) < NOTE_NAME_MIN_R or m.n < NOTE_NAME_MIN_NOTES:
                continue
            did_key = (m.label, m.did)
            current = best.get(did_key)
            if current is None or abs(m.r) > current[1]:
                best[did_key] = (key, abs(m.r))
    return {did_key: name_r[0] for did_key, name_r in best.items()}


def _module_label(request: str | None, response: str | None) -> str:
    req = request or "unknown"
    return f"{req}/{response}" if response else req


def _system_name(module: ModuleRecord) -> str:
    record = module.dids.get("F197")
    if record is None or not record.samples:
        return "unknown"
    try:
        name = record.samples[-1].payload.decode("ascii").strip()
    except UnicodeDecodeError:
        return "unknown"
    return name or "unknown"


@dataclass
class DraftModule:
    id: str
    request: str
    response: str | None
    protocol: str
    dids: list[tuple[str, str, float | None, str | None]]


def build_draft_modules(
    modules: dict[tuple[str | None, str | None], ModuleRecord],
    named: dict[tuple[str, str], str] | None = None,
) -> list[DraftModule]:
    """Manufacturer modules eligible for the draft profile: any header pair
    with at least one DID that was actually found by discovery (a `discover-`
    stage entry) and read positively at least once. Mode-01 PIDs and announced
    OBDonUDS F4xx/F5xx DIDs never carry a `discover-` stage, so they never
    qualify - only genuinely new, manufacturer-specific finds do. `named`
    (from `named_candidates`) supplies a "<key> candidate" name for any DID
    whose best field matched a typed note strongly enough."""
    named = named or {}
    drafts: list[DraftModule] = []
    for (request, response), module in modules.items():
        if request is None:
            continue
        eligible = sorted(
            did for did, record in module.dids.items() if record.from_discovery and record.samples
        )
        if not eligible:
            continue
        protocol = "7" if len(request) == 8 else "6"
        label = _module_label(request, response)
        dids: list[tuple[str, str, float | None, str | None]] = []
        for did in eligible:
            poll, interval = _classify_did(module.dids[did])
            key = named.get((label, did))
            name = f"{key} candidate" if key is not None else None
            dids.append((did, poll, interval, name))
        drafts.append(DraftModule(f"ecu-{request.lower()}", request, response, protocol, dids))
    return sorted(drafts, key=lambda m: m.id)


def _choose_profile_protocol(drafts: list[DraftModule]) -> str:
    if not drafts:
        return "6"
    counts = {"6": 0, "7": 0}
    for module in drafts:
        counts[module.protocol] += 1
    return "7" if counts["7"] > counts["6"] else "6"


def _toml_str(value: str) -> str:
    return json.dumps(value)


def render_profile_draft_toml(*, profile_id: str, vehicle: str, drafts: list[DraftModule]) -> str:
    protocol = _choose_profile_protocol(drafts)
    description = "Draft profile generated by didscout derive - review every DID before use."
    lines = [
        "schema = 1",
        f"id = {_toml_str(profile_id)}",
        f"name = {_toml_str(f'{vehicle} (draft)')}",
        f"description = {_toml_str(description)}",
        f"protocol = {_toml_str(protocol)}",
        f"vehicles = [{_toml_str(vehicle)}]",
        "",
        "[[sources]]",
        f"title = {_toml_str('own discovery (didscout record)')}",
        'url = "https://github.com/noctunix/didscout"',
        'license = "own discovery"',
    ]
    for module in drafts:
        lines += [
            "",
            "[[modules]]",
            f"id = {_toml_str(module.id)}",
            f"request = {_toml_str(module.request)}",
        ]
        if module.response:
            lines.append(f"response = {_toml_str(module.response)}")
        if module.protocol != protocol:
            lines.append(f"protocol = {_toml_str(module.protocol)}")
        for did, poll, interval, name in module.dids:
            lines += [
                "",
                "[[modules.dids]]",
                f"did = {_toml_str(did)}",
            ]
            if name is not None:
                lines.append(f"name = {_toml_str(name)}")
            lines += [
                'status = "unverified"',
                f"poll = {_toml_str(poll)}",
            ]
            if interval is not None:
                lines.append(f"interval = {interval:.0f}")
    return "\n".join(lines) + "\n"


def _collapse_identical_candidates(top: list[NoteMatch]) -> list[tuple[NoteMatch, int]]:
    """Collapses candidates that give the same DID's r/RMSE for more than one
    field - several byte widths at the same offset often decode to the same
    value when the wider field's extra byte is always zero - keeping the
    narrowest field and counting the rest as aliases. `top` is already
    sorted by (-|r|, RMSE), so equal-key candidates are always adjacent."""
    groups: dict[tuple[str, str, bool, float, float], list[NoteMatch]] = {}
    order: list[tuple[str, str, bool, float, float]] = []
    for m in top:
        gkey = (m.label, m.did, m.derivative, m.r, m.rmse)
        if gkey not in groups:
            groups[gkey] = []
            order.append(gkey)
        groups[gkey].append(m)
    return [(min(groups[gkey], key=lambda c: c.width), len(groups[gkey]) - 1) for gkey in order]


def _render_note_matches(matches: dict[str, list[NoteMatch]], notes: list[NoteSample]) -> list[str]:
    counts: dict[str, int] = {}
    for note in notes:
        counts[note.key] = counts.get(note.key, 0) + 1
    lines = ["## Matches with your notes", ""]
    if not matches:
        lines += ["- no key had enough notes to match", ""]
        return lines
    for key in sorted(matches):
        lines.append(f"### {key} ({counts.get(key, 0)} notes)")
        lines.append("")
        top = matches[key]
        if not top:
            lines += ["- no candidate field found", ""]
            continue
        for m, alias_count in _collapse_identical_candidates(top):
            signedness = "signed" if m.signed else "unsigned"
            named = not m.derivative and abs(m.r) >= NOTE_NAME_MIN_R and m.n >= NOTE_NAME_MIN_NOTES
            suffix = f' - named "{key} candidate" in the draft' if named else ""
            quantity = "d/dt raw" if m.derivative else "raw"
            alias_suffix = (
                f" ({alias_count} alias field(s) with identical r/RMSE)" if alias_count else ""
            )
            lines.append(
                f"- {m.label} / DID {m.did} / field (offset {m.offset}, width {m.width}, "
                f"{signedness}): r={m.r:+.3f}, "
                f"display ≈ {m.a:.4f}·{quantity} {'-' if m.b < 0 else '+'} {abs(m.b):.4f}, "
                f"RMSE={m.rmse:.3f}, n={m.n}{suffix}{alias_suffix}"
            )
        lines.append("")
    return lines


def render_derive_report(
    data: DerivedData, vehicle: str, source: Path, matches: dict[str, list[NoteMatch]]
) -> str:
    modules = sorted(data.modules.items(), key=lambda kv: (kv[0][0] or "", kv[0][1] or ""))
    speed_candidates: list[tuple[str, str, int, int, float]] = []
    stationary_candidates: list[tuple[str, str, int, int, str, float]] = []
    for (request, response), module in modules:
        label = _module_label(request, response)
        for did, record in sorted(module.dids.items()):
            corr = speed_correlation(record, data.speed_series)
            if corr is not None and abs(corr[2]) >= 0.5:
                speed_candidates.append((label, did, corr[0], corr[1], corr[2]))
            for offset, width, direction, duration in stationary_monotonic_candidates(record):
                stationary_candidates.append((label, did, offset, width, direction, duration))
    speed_candidates.sort(key=lambda c: -abs(c[4]))

    lines = [
        "# didscout derive report",
        "",
        f"Source: `{source}`",
        f"Vehicle: {vehicle}",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        *_render_note_matches(matches, data.notes),
        "## Candidates",
        "",
        "### Speed-correlated fields",
        "",
    ]
    if speed_candidates:
        for label, did, offset, width, r in speed_candidates:
            lines.append(f"- {label} DID {did}: offset {offset} width {width}, r={r:+.2f}")
    else:
        lines.append("- none found")
    lines += ["", "### Stationary rise/fall (charging/energy candidates)", ""]
    if stationary_candidates:
        for label, did, offset, width, direction, duration in stationary_candidates:
            lines.append(
                f"- {label} DID {did}: offset {offset} width {width}, {direction} over "
                f"{duration:.0f}s"
            )
    else:
        lines.append("- none found")

    lines += ["", "## Modules", ""]
    for (request, response), module in modules:
        label = _module_label(request, response)
        lines += [f"### {label} - system: {_system_name(module)}", ""]
        for did, record in sorted(module.dids.items()):
            if not record.samples and not record.conditional:
                continue
            header = f"#### DID {did}" + (" (conditional)" if record.conditional else "")
            lines.append(header)
            if not record.samples:
                lines += ["- NRC 22/33 only; no positive read", ""]
                continue
            payloads = [s.payload for s in record.samples]
            distinct = {p.hex() for p in payloads}
            lines.append(f"- samples: {len(record.samples)}, distinct values: {len(distinct)}")
            varying = _varying_byte_positions(payloads)
            if varying:
                positions = ", ".join(
                    f"{pos} (min {lo:02X} max {hi:02X})"
                    for pos, (lo, hi) in sorted(varying.items())
                )
                lines.append(f"- varying byte positions: {positions}")
            else:
                lines.append("- varying byte positions: none (constant)")
            phases = _changed_phases(record)
            if phases:
                shown = ", ".join(
                    sorted(p.upper() if p in ("moving", "stationary") else p for p in phases)
                )
                lines.append(f"- changed during: {shown}")
            corr = speed_correlation(record, data.speed_series)
            if corr is not None:
                offset, width, r = corr
                lines.append(f"- speed correlation: r={r:+.2f} at offset {offset} width {width}")
            else:
                lines.append("- speed correlation: none")
            poll, interval = _classify_did(record)
            if record.from_discovery:
                suggestion = f"poll={poll}" + (f" interval={interval:.0f}s" if interval else "")
                lines.append(f"- draft classification: {suggestion}")
            lines.append("")
    return "\n".join(lines) + "\n"


def resolve_capture_path(run_dir_or_file: Path) -> Path:
    path = Path(run_dir_or_file)
    return path / "capture.jsonl" if path.is_dir() else path


def read_capture_entries(capture_path: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for line in capture_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def derive(
    run_dir_or_file: Path,
    *,
    id_: str | None = None,
    vehicle: str | None = None,
    out: Path | None = None,
) -> tuple[Path | None, Path]:
    """Writes `<id>.toml` (a profile draft, `profile-draft.toml` by default)
    and `report.md` from one `record` run's capture log. Returns
    `(profile_path, report_path)` - `profile_path` is None if nothing
    manufacturer-specific was found by discovery, since an empty profile would
    never pass `load_profile` anyway. The written draft is always loaded back
    through `load_profile` before returning, so a broken draft fails loudly
    here rather than silently reaching a PR."""
    capture_path = resolve_capture_path(run_dir_or_file)
    entries = read_capture_entries(capture_path)
    data = analyze_capture(entries)
    note_matches = match_notes(data)
    drafts = build_draft_modules(data.modules, named_candidates(note_matches))
    vehicle_name = vehicle or "unknown vehicle"
    profile_id = id_ or "profile-draft"
    out_dir = out or capture_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    report_path = out_dir / "report.md"
    report_path.write_text(
        render_derive_report(data, vehicle_name, run_dir_or_file, note_matches), encoding="utf-8"
    )

    profile_path: Path | None = None
    if drafts:
        profile_path = out_dir / f"{profile_id}.toml"
        profile_path.write_text(
            render_profile_draft_toml(profile_id=profile_id, vehicle=vehicle_name, drafts=drafts),
            encoding="utf-8",
        )
        load_profile(profile_path)
    return profile_path, report_path


# ---------------------------------------------------------------------------
# share: a redacted capture, safe to publish, for others to derive profiles
# from without ever seeing a raw log.
# ---------------------------------------------------------------------------

ADAPTER_IDENTITY_COMMANDS = frozenset({"ATI", "STI", "STDI"})
IDENTITY_DID_COMMANDS = frozenset({"22F187", "22F189", "22F191"})
# Never a vehicle/adapter reply: the response text is a transport exception
# message, which can embed the adapter's own BLE address (see ElmSession.run).
NO_RESPONSE_STATUSES = frozenset({"TIMEOUT", "TRANSPORT_ERROR"})
SHARE_ENTRY_KEYS = frozenset({"t", "stage", "module", "command", "status", "response"})
ISO_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
MAC_ADDRESS_PATTERN = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
UUID_PATTERN = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)


def _redact_entry(entry: dict[str, object], origin: datetime | None) -> dict[str, object] | None:
    """One capture entry, redacted for `share`, or None if it must be dropped
    entirely."""
    command = str(entry.get("command", ""))
    stage = str(entry.get("stage", ""))
    if stage == "connection" or command in ADAPTER_IDENTITY_COMMANDS:
        return None
    if command == "NOTE":
        marker = classify_note_marker(str(entry.get("response", "")))
        if marker is None:
            return None
        return {
            "t": round(_entry_seconds(entry, origin), 1),
            "stage": "phase",
            "status": "MARKER",
            "response": marker,
        }

    out: dict[str, object] = {"t": round(_entry_seconds(entry, origin), 1), "stage": stage}
    module = entry.get("module")
    if module is not None:
        out["module"] = module
    out["command"] = command
    status = entry.get("status")
    out["status"] = status
    if command not in IDENTITY_DID_COMMANDS and status not in NO_RESPONSE_STATUSES:
        out["response"] = entry.get("response")
    return out


def share(run_dir_or_file: Path, *, vehicle: str | None = None, out: Path | None = None) -> Path:
    """Writes a redacted `<name>.share.jsonl.gz`, safe to attach to a PR under
    `captures/` - see `validate_share` for the rules it enforces."""
    capture_path = resolve_capture_path(run_dir_or_file)
    entries = read_capture_entries(capture_path)
    origin: datetime | None = None
    for entry in entries:
        ts = entry.get("started_utc")
        if isinstance(ts, str) and ts:
            origin = datetime.fromisoformat(ts)
            break

    vehicle_name = vehicle or "unknown vehicle"
    if out is not None:
        out_path = out
    else:
        source_path = Path(run_dir_or_file)
        name = source_path.stem if source_path.is_file() else capture_path.parent.name
        out_path = capture_path.parent / f"{name}.share.jsonl.gz"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with gzip.open(out_path, "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({"didscout_share": 1, "vehicle": vehicle_name}) + "\n")
        for entry in entries:
            redacted = _redact_entry(entry, origin)
            if redacted is not None:
                handle.write(json.dumps(redacted, ensure_ascii=False) + "\n")
    return out_path


def _scan_share_value(value: object, path: Path, index: int) -> None:
    if isinstance(value, str):
        if ISO_TIMESTAMP_PATTERN.search(value):
            raise ValueError(f"{path}: line {index}: absolute-time-looking value {value!r}")
        if VIN_LIKE_PATTERN.fullmatch(value):
            raise ValueError(f"{path}: line {index}: VIN-like string {value!r}")
        if MAC_ADDRESS_PATTERN.search(value):
            raise ValueError(f"{path}: line {index}: MAC-address-looking value {value!r}")
        if UUID_PATTERN.search(value):
            raise ValueError(f"{path}: line {index}: UUID-looking value {value!r}")
    elif isinstance(value, dict):
        for item in value.values():
            _scan_share_value(item, path, index)
    elif isinstance(value, list):
        for item in value:
            _scan_share_value(item, path, index)


def validate_share(path: Path) -> None:
    """Raises ValueError on any violation of the `share` format: unknown keys,
    absolute-time-looking values, non-marker notes, identification payloads,
    or a VIN-like 17-character, MAC-address-looking, or UUID-looking string
    anywhere. Run by the test suite against every file in `captures/`."""
    path = Path(path)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        lines = [json.loads(line) for line in handle if line.strip()]
    if not lines:
        raise ValueError(f"{path}: empty share file")
    header = lines[0]
    if not isinstance(header, dict) or set(header) != {"didscout_share", "vehicle"}:
        raise ValueError(f"{path}: invalid header {header!r}")
    if header.get("didscout_share") != 1:
        raise ValueError(f"{path}: header didscout_share must be 1")
    if not isinstance(header.get("vehicle"), str) or not header["vehicle"]:
        raise ValueError(f"{path}: header vehicle must be a non-empty string")

    for index, entry in enumerate(lines[1:], start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: line {index}: not an object")
        unknown = set(entry) - SHARE_ENTRY_KEYS
        if unknown:
            raise ValueError(f"{path}: line {index}: unknown key(s) {sorted(unknown)}")
        if entry.get("command") == "NOTE":
            raise ValueError(f"{path}: line {index}: raw note leaked into share output")
        if entry.get("command") in IDENTITY_DID_COMMANDS and "response" in entry:
            raise ValueError(f"{path}: line {index}: identification payload present")
        if (
            entry.get("stage") == "phase"
            and entry.get("status") == "MARKER"
            and entry.get("response") not in MARKER_PATTERNS
        ):
            raise ValueError(f"{path}: line {index}: not a recognised phase marker")
        if entry.get("status") == "SUMMARY":
            command = entry.get("command")
            if not isinstance(command, str) or not re.fullmatch(
                r"BATCH [0-9A-F]{4}-[0-9A-F]{4}", command
            ):
                raise ValueError(f"{path}: line {index}: SUMMARY has invalid command {command!r}")
            try:
                counts = json.loads(entry.get("response", "")) if "response" in entry else None
            except json.JSONDecodeError:
                counts = None
            if (
                not isinstance(counts, dict)
                or not all(isinstance(k, str) for k in counts)
                or not all(isinstance(v, int) and not isinstance(v, bool) for v in counts.values())
            ):
                raise ValueError(f"{path}: line {index}: SUMMARY response must be status counts")
        _scan_share_value(entry, path, index)


RECORD_INITIAL_BACKOFF = 5.0
RECORD_MAX_BACKOFF = 60.0


def _log_connection_event(
    log_path: Path, label: str, status: str, detail: str = "", command: str = "CONNECTION"
) -> None:
    ex = Exchange(command, detail, status, datetime.now(UTC).isoformat(), 0.0)
    entry = {"stage": "connection", "state": label, "mtu": None, "mode": "record", **ex.__dict__}
    _append_capture_entry(log_path, entry)


def _record_note_sink(log_path: Path, label: str) -> Callable[[Exchange, str], None]:
    """Writes a typed note straight to the run's capture.jsonl, independent of
    whatever BLE connection is or isn't open at the time - `record`'s note
    reader runs for the whole life of the run, not just while connected."""

    def write(ex: Exchange, stage: str) -> None:
        entry = {"stage": stage, "state": label, "mtu": None, "mode": "record", **ex.__dict__}
        _append_capture_entry(log_path, entry)

    return write


def _start_sleep_inhibit(log_path: Path, label: str) -> subprocess.Popen[bytes] | None:
    """Holds a systemd sleep/idle/lid-switch inhibitor for as long as the
    returned process lives - BLE recording cannot survive the laptop
    suspending. Returns None, after printing a warning, if systemd-inhibit
    isn't on PATH or fails to start; the caller must then rely on the owner
    keeping the machine awake manually."""
    if shutil.which("systemd-inhibit") is None:
        print(
            "[record] systemd-inhibit not found; keep this machine awake manually "
            "(disable suspend and lid-close) for the whole recording",
            file=sys.stderr,
        )
        _log_connection_event(log_path, label, "UNAVAILABLE", command="SLEEP_INHIBIT")
        return None
    try:
        proc = subprocess.Popen(
            [
                "systemd-inhibit",
                "--what=sleep:idle:handle-lid-switch",
                "--who=didscout",
                "--why=recording vehicle data",
                "--mode=block",
                "cat",
            ],
            stdin=subprocess.PIPE,
        )
    except OSError as error:
        print(
            f"[record] systemd-inhibit failed to start ({error}); keep this machine awake "
            "manually for the whole recording",
            file=sys.stderr,
        )
        _log_connection_event(log_path, label, "FAILED", str(error), command="SLEEP_INHIBIT")
        return None
    _log_connection_event(log_path, label, "HELD", command="SLEEP_INHIBIT")
    return proc


def _stop_sleep_inhibit(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    if proc.stdin is not None:
        with contextlib.suppress(Exception):
            proc.stdin.close()
    proc.terminate()
    with contextlib.suppress(Exception):
        proc.wait(timeout=5)


def _resume_summary(run_dir: Path, state: RunState, profile: Profile | None) -> str:
    """One line describing a resumed run: when it started, which inventory
    stages already finished, and overall discovery progress across every
    known module - everything a resuming `record` run can show without
    touching the adapter."""
    match = RECORD_RUN_DIR_PATTERN.fullmatch(run_dir.name)
    started = match.group(1) if match else "?"
    done_stages = [s for s in INVENTORY_STAGE_ORDER if state.stage_status(s) == "done"]
    discoverable = [m for m in build_record_modules(profile, state).values() if m.discoverable]
    total = sum(len(m.order) for m in discoverable)
    done = sum(m.position for m in discoverable)
    pct = 100.0 if total == 0 else done / total * 100
    return (
        f"resuming {run_dir} (started {started}, stages done: "
        f"{', '.join(done_stages) or '-'}, discovery {pct:.0f}%)"
    )


async def record(
    address: str | None,
    profile: Profile | None,
    label: str,
    out_dir: Path,
    new: bool,
    inhibit: bool = True,
    discover_while_moving: bool = False,
) -> int:
    """Connects (scanning if no address is given), maintains a resumable run
    directory, reconnects with backoff through BLE drops, runs the one-time
    vehicle inventory (adapter, protocol, mode01, obduds, ecus11), then hands
    off to `run_record_loop`'s continuous watch/discovery scheduler, which
    only ends on Ctrl-C (exit 130). A typed-note reader and (unless `inhibit`
    is False) a sleep inhibitor both run for the whole call, independent of
    any single BLE connection."""
    out_dir.mkdir(parents=True, exist_ok=True)
    run_dir = None if new else find_resumable_run(out_dir, label)
    if run_dir is None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = out_dir / f"record_{stamp}_{label}"
        run_dir.mkdir(parents=True, exist_ok=True)
        state = RunState.new(label, address)
    else:
        state = RunState.load(run_dir / "state.json")
        if address:
            state.address = address
        print(f"[record] {_resume_summary(run_dir, state, profile)}")

    state_path = run_dir / "state.json"
    log_path = run_dir / "capture.jsonl"
    state.save(state_path)

    print(
        "(notes - type idle/drive/charge/park, or German leerlauf/fahrt/laden/parken, as phase "
        "markers, or any other text + Enter - land timestamped in capture.jsonl any time, even "
        "while disconnected or reconnecting)"
    )
    note_reader = start_note_reader(_record_note_sink(log_path, label))
    inhibit_proc = _start_sleep_inhibit(log_path, label) if inhibit else None

    failures: dict[str, int] = {}
    pair_pending = True
    backoff = RECORD_INITIAL_BACKOFF

    try:
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
                            # A stage's own cleanup may have left the adapter in an
                            # unexpected formatting state (see FORMAT_LOST) - never
                            # trust it across a stage boundary, reassert explicitly.
                            for cmd in ("ATE0", "ATL0", "ATS0", "ATH1"):
                                await link.execute(cmd, "setup")
                    else:
                        print_inventory_summary(state)

                    try:
                        await run_record_loop(
                            link, state, profile, state_path, discover_while_moving
                        )
                    except asyncio.CancelledError:
                        link.record(
                            Exchange(
                                "SESSION_END",
                                "Ctrl-C",
                                "CANCELLED",
                                datetime.now(UTC).isoformat(),
                                0.0,
                            ),
                            "session",
                        )
                        for cmd in ("ATFCSM0", "ATAR"):
                            if not link.session.usable:
                                break
                            link.record(await link.session.run(cmd), "cleanup")
                        # finished stays False: the next `record` start resumes
                        # discovery exactly where this run left off.
                        state.save(state_path)
                        try:
                            profile_path, report_path = derive(run_dir)
                            share_path = share(run_dir)
                            print(f"[record] report: {report_path}")
                            if profile_path:
                                print(f"[record] profile draft: {profile_path}")
                            else:
                                print("[record] profile draft: none (no manufacturer DIDs yet)")
                            print(f"[record] share: {share_path}")
                            print(
                                "[record] contribute: open a profile PR with the draft, or a "
                                "capture PR with the share file in captures/ - see "
                                "CONTRIBUTING.md"
                            )
                        except Exception as error:
                            print(f"[record] derive/share failed: {error}", file=sys.stderr)
                        return 130
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
    finally:
        await note_reader.stop()
        _stop_sleep_inhibit(inhibit_proc)


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
            current_protocol: str | None = None
            for module in profile.modules:
                effective = module_effective_protocol(module, profile.protocol)
                if effective != current_protocol:
                    await execute(FORCE_PROTOCOL[effective], "E", check_sweep_allowed)
                    current_protocol = effective
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
        help="one start, then autonomous: connect, run the one-time vehicle inventory, then "
        "keep logging every known value and discovering more while stationary, until Ctrl-C",
    )
    r.add_argument("address", nargs="?", help="BLE address; omit to scan for a UART adapter")
    r.add_argument("--profile", help="vehicle profile id (profiles/<id>.toml) or path")
    r.add_argument("--label", default="vehicle", help="run label (default: vehicle)")
    r.add_argument("--out", type=Path, default=Path(__file__).parent / "logs")
    r.add_argument(
        "--new", action="store_true", help="start a fresh run instead of resuming an unfinished one"
    )
    r.add_argument(
        "--no-inhibit",
        action="store_true",
        help="don't hold a systemd-inhibit sleep/idle lock; keep the machine awake yourself",
    )
    r.add_argument(
        "--discover-while-moving",
        action="store_true",
        help="also run background DID discovery while the vehicle is moving, limited to "
        "modules opted in via discover_while_moving in the profile (default: off)",
    )
    d = sub.add_parser(
        "derive",
        help="write a profile draft + report.md from one `record` run's capture log",
    )
    d.add_argument("run", type=Path, help="a `record` run directory, or its capture.jsonl")
    d.add_argument("--id", help="profile id for the draft (default: profile-draft)")
    d.add_argument("--vehicle", help="vehicle name for the draft/report (default: unknown vehicle)")
    d.add_argument("--out", type=Path, help="output directory (default: the run directory)")
    sh = sub.add_parser(
        "share",
        help="write a redacted <name>.share.jsonl.gz, safe to attach to a captures/ PR",
    )
    sh.add_argument("run", type=Path, help="a `record` run directory, or its capture.jsonl")
    sh.add_argument(
        "--vehicle", help="vehicle name for the share header (default: unknown vehicle)"
    )
    sh.add_argument("--out", type=Path, help="output file path (default: <name>.share.jsonl.gz)")
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
        return asyncio.run(
            record(
                args.address,
                profile,
                record_label,
                args.out,
                args.new,
                not args.no_inhibit,
                args.discover_while_moving,
            )
        )
    if args.mode == "derive":
        try:
            profile_path, report_path = derive(
                args.run, id_=args.id, vehicle=args.vehicle, out=args.out
            )
        except (ProfileError, OSError, ValueError) as error:
            print(f"derive failed: {error}", file=sys.stderr)
            return 2
        print(f"report: {report_path}")
        print(
            f"profile draft: {profile_path}"
            if profile_path
            else "profile draft: none (no manufacturer DIDs discovered yet)"
        )
        return 0
    if args.mode == "share":
        try:
            share_path = share(args.run, vehicle=args.vehicle, out=args.out)
        except OSError as error:
            print(f"share failed: {error}", file=sys.stderr)
            return 2
        print(f"share: {share_path}")
        return 0
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
