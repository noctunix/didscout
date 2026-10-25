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
import re
import sys
import threading
import time
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
    "E": [],  # filled below from STAGE_E_GATEWAY + STAGE_E_REST
}
# This is one example candidate set, scoped to VAG PPE-platform vehicles - not a
# universal header/DID list. Other platforms need their own candidate set.
# Gateway (PPE sibling Macan Electric per OBDb; odometer per OBDb Audi-A6).
STAGE_E_GATEWAY = [
    "ATSH710",
    "ATCRA77A",
    "ATFCSH710",
    "ATFCSD300000",
    "ATFCSM1",
    "22F189",
    "222AF7",
    "222AB8",
    "222AB2",
    "222AB6",
    "222A0A",
]
STAGE_E_REST = [
    # Tyre pressure module.
    "ATSH70B",
    "ATCRA775",
    "ATFCSH70B",
    "2218A0",
    "2218A1",
    "2218A2",
    "2218A3",
    "ATFCSM0",
    "ATAR",
    # Instrument cluster odometer per OBDb Audi-A6 (hdr 714, DID 2203); response ID
    # is unknown there, so no ATCRA/flow control — ATAR above already reset receive
    # filtering to automatic, and a 24-bit odometer fits one single-frame reply.
    "ATSH714",
    "222203",
    "ATD",
]
STAGES["E"] = STAGE_E_GATEWAY + STAGE_E_REST
# Repeated during --watch-seconds, between the gateway reads and the tyre/odometer block,
# while ATSH710/ATCRA77A are still in effect — every DID confirmed OK there so far, each
# at its own interval (fast-changing values more often than near-static ones). 22F189 and
# 222AB2 are already captured once by STAGE_E_GATEWAY above and don't change within a
# session, so they're deliberately not repeated here. Extend this as more DIDs are
# confirmed (including sweep hits from `sweep --header 710 ...`).
WATCH_PLAN: dict[str, float] = {
    "222AF7": 15.0,  # 12-V bundle: current/SoC move fast while charging
    "222AB8": 15.0,  # HV energy
    "222AB6": 60.0,  # range remaining, coarser display granularity
}
# Gateway (710/77A) DIDs that answered positively during earlier sweeps but aren't
# in WATCH_PLAN yet - `session --survey` polls these at a single, coarser interval
# alongside WATCH_PLAN so they get logged over a whole outing without committing to
# one of them being worth a dedicated interval yet.
GATEWAY_SURVEY = [
    f"22{did}"
    for did in [
        "2A04",
        "2A15",
        "2A26",
        "2A27",
        "2A28",
        "2A29",
        "2A2D",
        "2A2F",
        "2A31",
        "2A3C",
        "2A50",
        "2A52",
        "2A53",
        "2A65",
        "2A67",
        "2AB3",
        "2AB4",
        "2AB5",
        "2AB7",
        "2AB9",
        "2AC1",
        "2AF5",
        "2AF6",
        "2AF8",
    ]
]
# `session`'s one-shot neighbourhood sweeps around the signals already confirmed OK,
# run once at the start (710) and once at the end after driving (70B) - see `sweep`.
SESSION_SWEEP_RANGES: dict[str, tuple[int, int]] = {
    "710": (0x2A00, 0x2AFF),
    "70B": (0x1800, 0x18FF),
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

ALLOWED = (
    frozenset(cmd for cmds in STAGES.values() for cmd in cmds)
    | frozenset(STAGE_C_CANDIDATES.values())
    | frozenset(FORCE_PROTOCOL.values())
    | frozenset(GATEWAY_SURVEY)
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


@dataclass
class IsotpParse:
    messages: list[tuple[str, bytes]]
    malformed: bool
    incomplete: bool


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
    return IsotpParse(messages, malformed, bool(partial))


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
    if responder is None and command.startswith("22"):
        responder = "775" if command.startswith("2218A") else "77A"
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
    to block waiting for a fresher read — see WATCH_PLAN."""

    response: str
    status: str
    fetched_monotonic: float

    def age_seconds(self, now: float | None = None) -> float:
        return (now if now is not None else time.monotonic()) - self.fetched_monotonic


def format_live_summary(latest: dict[str, LiveValue]) -> str:
    now = time.monotonic()
    parts = [f"{cmd}={v.status}(+{v.age_seconds(now):.0f}s)" for cmd, v in sorted(latest.items())]
    return "live: " + (" ".join(parts) if parts else "-")


def watch_schedule(survey: bool, survey_interval: float) -> dict[str, float]:
    """The combined per-command poll intervals for `session`'s watch loop: WATCH_PLAN
    always, plus GATEWAY_SURVEY at a single interval when `--survey` is enabled."""
    plan = dict(WATCH_PLAN)
    if survey:
        plan.update(dict.fromkeys(GATEWAY_SURVEY, survey_interval))
    return plan


def _due_commands(next_due: dict[str, float], now: float) -> list[str]:
    return [cmd for cmd, t in next_due.items() if t <= now]


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
) -> AsyncIterator[AdapterLink | None]:
    """Connects to the BLE UART adapter and yields an AdapterLink shared by every
    mode - or None if the adapter has no UART write characteristic (wrong device),
    in which case the caller must return 2 without sending anything."""
    from bleak import BleakClient

    async with BleakClient(address, timeout=20.0) as client:
        if pair:
            await client.pair()
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
                entry = {"stage": stage, "state": label, "mtu": client.mtu_size, **ex.__dict__}
                log.write(json.dumps(entry, ensure_ascii=False) + "\n")
                log.flush()
                first = ex.response.splitlines()[0] if ex.response else ""
                status = f"[{stage}] {ex.command:<14} {ex.status:<32} {ex.duration_ms:7.1f} ms"
                print(f"{status}  {first[:60]}")

            yield AdapterLink(session, record, non_critical_at)
        await client.stop_notify(UART_NOTIFY)


async def _probe(
    address: str,
    stages: str,
    label: str,
    out_dir: Path,
    pair: bool,
    protocol: str | None = None,
    watch_seconds: float = 0.0,
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
                for cmd in STAGE_E_GATEWAY:
                    await execute(cmd, stage)
                if watch_seconds > 0:
                    latest: dict[str, LiveValue] = {}
                    now = time.monotonic()
                    next_due = dict.fromkeys(WATCH_PLAN, now)
                    deadline = now + watch_seconds
                    while time.monotonic() < deadline:
                        now = time.monotonic()
                        due = [cmd for cmd, t in next_due.items() if t <= now]
                        if not due:
                            await asyncio.sleep(min(1.0, min(next_due.values()) - now))
                            continue
                        for cmd in due:
                            ex = await execute(cmd, "E-watch")
                            latest[cmd] = LiveValue(ex.response, ex.status, time.monotonic())
                            next_due[cmd] = time.monotonic() + WATCH_PLAN[cmd]
                        print(format_live_summary(latest))
                for cmd in STAGE_E_REST:
                    await execute(cmd, stage)
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

                data_dids = sorted(did for did in supported if did & 0x1F)
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
                summary: list[str] = []
                for did in sorted(IDENTIFY_DIDS):
                    command = f"22{did}"
                    ex = await execute(command, f"identify-{ecu}", responder)
                    if did == "F197" and ex.status == "OK":
                        payload = decode_positive_payload(command, ex.response, responder)
                        value = (
                            payload.decode("ascii", errors="replace") if payload else ex.status
                        )
                    else:
                        value = ex.status
                    summary.append(f"{did}={value}")
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


async def run_session(
    address: str,
    label: str,
    out_dir: Path,
    pair: bool,
    protocol: str | None,
    survey: bool = False,
    survey_interval: float = 60.0,
) -> int:
    """One continuous log for a whole outing (ignition on -> driving -> charging ->
    driving home): a single thorough pass (adapter, protocol, legislative OBD, gateway +
    its neighbourhood, tyres + their neighbourhood, cluster odometer), then an
    indefinite WATCH_PLAN poll that only stops on Ctrl-C - so the whole trip ends
    up in one log file instead of several `probe`/`sweep` runs."""
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = out_dir / f"didscout_{stamp}_{label}.jsonl"
    cancelled = False

    async with connect_adapter(address, pair, log_path, label) as link:
        if link is None:
            return 2
        session = link.session
        record = link.record

        note_reader = start_note_reader(record)

        for cmd in ADAPTER_SETUP:
            record(await session.run(cmd), "setup")
        for cmd in ("ATI", "STI", "STDI", "ATRV"):
            record(await session.run(cmd), "A")
        record(await session.run(FORCE_PROTOCOL[protocol] if protocol else "ATSP0"), "B")
        record(await session.run("0100"), "B")
        record(await session.run("ATDPN"), "B")

        bitmaps: list[str] = []
        for cmd in STAGES["C"]:
            ex = await session.run(cmd)
            record(ex, "C")
            bitmaps.append(ex.response)
        supported = supported_pids(bitmaps)
        print(f"[C] supported mode-01 PIDs: {' '.join(sorted(supported)) or '-'}")
        for pid, cmd in STAGE_C_CANDIDATES.items():
            if pid in supported:
                record(await session.run(cmd), "C")

        for cmd in STAGE_E_GATEWAY:
            record(await session.run(cmd), "E")
        start_i, end_i = SESSION_SWEEP_RANGES["710"]
        await sweep_range(session, record, start_i, end_i, "sweep-710", "77A")

        record(await session.run("ATSH70B"), "E")
        record(await session.run("ATCRA775"), "E")
        record(await session.run("ATFCSH70B"), "E")
        for cmd in ("2218A0", "2218A1", "2218A2", "2218A3"):
            record(await session.run(cmd), "E")
        start_i, end_i = SESSION_SWEEP_RANGES["70B"]
        await sweep_range(session, record, start_i, end_i, "sweep-70B", "775")
        record(await session.run("ATFCSM0"), "E")
        record(await session.run("ATAR"), "E")
        record(await session.run("ATSH714"), "E")
        record(await session.run("222203"), "E")

        # Keep ATE0/ATL0/ATS0/ATH1 intact. ATD here used to reset those settings
        # and switched watch replies into ELM's numbered assembled format.
        for cmd in ("ATSH710", "ATCRA77A", "ATFCSH710", "ATFCSD300000", "ATFCSM1"):
            record(await session.run(cmd), "E")

        print()
        print(
            "Now type and Enter: state of charge, odometer, outside temperature, "
            "battery temperature - then drive. Keeps running in the background, "
            "press Ctrl-C after the drive home to stop."
        )
        print()

        intervals = watch_schedule(survey, survey_interval)
        latest: dict[str, LiveValue] = {}
        next_due = dict.fromkeys(intervals, time.monotonic())
        try:
            while True:
                now = time.monotonic()
                due = _due_commands(next_due, now)
                if not due:
                    await asyncio.sleep(min(1.0, min(next_due.values()) - now))
                    continue
                for cmd in due:
                    ex = await session.run(cmd)
                    record(ex, "E-survey" if cmd in GATEWAY_SURVEY else "E-watch")
                    latest[cmd] = LiveValue(ex.response, ex.status, time.monotonic())
                    next_due[cmd] = time.monotonic() + intervals[cmd]
                print(format_live_summary(latest))
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
) -> int:
    try:
        return await _probe(address, stages, label, out_dir, pair, protocol, watch_seconds)
    except ProbeAbortedError as error:
        print(f"Probe aborted: {error}", file=sys.stderr)
        return 2


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("scan", help="list nearby BLE devices")
    s.add_argument("--seconds", type=float, default=8.0)
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
        help="after stage E's gateway reads, poll every command in WATCH_PLAN at its own "
        "interval for this long (e.g. during AC charging) before continuing to tyres/odometer",
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
        help="one continuous log for a whole outing: full one-shot pass (incl. both "
        "neighbourhood sweeps), then indefinite WATCH_PLAN polling until Ctrl-C",
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
        "--survey",
        action="store_true",
        help="also poll GATEWAY_SURVEY (710/77A DIDs not yet in WATCH_PLAN) at --survey-interval",
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
        return asyncio.run(
            run_session(
                args.address,
                label,
                args.out,
                args.pair,
                args.protocol,
                args.survey,
                args.survey_interval,
            )
        )
    stages = args.stages.upper()
    if not stages or any(st not in STAGES for st in stages):
        parser.error("--stages must only contain A-E")
    if args.watch_seconds and "E" not in stages:
        parser.error("--watch-seconds requires stage E")
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
        )
    )


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[didscout] Ctrl-C detected; disconnecting.", file=sys.stderr)
        sys.exit(130)
