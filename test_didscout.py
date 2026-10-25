from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

import bleak
import pytest

import didscout as cx

FORBIDDEN_PREFIXES = (
    "04",
    "14",
    "10",
    "11",
    "27",
    "28",
    "2E",
    "2F",
    "31",
    "34",
    "35",
    "36",
    "37",
    "3D",
    "85",
    "0902",
    "22F190",
    "ATPP",
    "STS",
)


def test_no_forbidden_service_is_allowed() -> None:
    for cmd in cx.ALLOWED:
        if cmd.startswith(("AT", "ST")) and not cmd.startswith(("ATPP", "STS")):
            continue
        assert not cmd.startswith(FORBIDDEN_PREFIXES), cmd


def test_force_protocol_commands_are_allowed() -> None:
    assert cx.FORCE_PROTOCOL["6"] in cx.ALLOWED
    assert cx.FORCE_PROTOCOL["7"] in cx.ALLOWED


def test_note_exchange_is_timestamped_and_not_sent() -> None:
    ex = cx.note_exchange("display soc=52% 23:10")
    assert ex.status == "NOTE"
    assert ex.command == "NOTE"
    assert ex.response == "display soc=52% 23:10"
    assert ex.started_utc  # non-empty ISO timestamp, no BLE round trip needed for this


def test_watch_plan_commands_are_allowed_and_known_ok() -> None:
    for cmd in cx.WATCH_PLAN:
        assert cmd in cx.ALLOWED
        assert cmd in cx.STAGE_E_GATEWAY


def test_live_value_age_and_summary() -> None:
    v = cx.LiveValue("622AB8...", "OK", time.monotonic() - 5)
    assert 4.5 < v.age_seconds() < 5.5
    assert "222AB8=OK(+5s)" in cx.format_live_summary({"222AB8": v})
    assert cx.format_live_summary({}) == "live: -"


def test_gateway_survey_commands_are_allowed() -> None:
    for cmd in cx.GATEWAY_SURVEY:
        assert cx.check_allowed(cmd) == cmd
        assert cmd in cx.ALLOWED


def test_survey_interval_rejects_below_minimum() -> None:
    with pytest.raises(SystemExit):
        cx.main(["session", "fake", "--state", "x", "--survey-interval", "10"])


def test_watch_schedule_includes_survey_only_when_enabled() -> None:
    without = cx.watch_schedule(False, 30.0)
    assert set(without) == set(cx.WATCH_PLAN)

    with_survey = cx.watch_schedule(True, 30.0)
    assert set(with_survey) == set(cx.WATCH_PLAN) | set(cx.GATEWAY_SURVEY)
    assert all(with_survey[cmd] == 30.0 for cmd in cx.GATEWAY_SURVEY)
    assert all(with_survey[cmd] == cx.WATCH_PLAN[cmd] for cmd in cx.WATCH_PLAN)


def test_due_commands_is_a_pure_threshold_filter() -> None:
    next_due = {"a": 10.0, "b": 20.0, "c": 20.0}
    assert cx._due_commands(next_due, 15.0) == ["a"]
    assert sorted(cx._due_commands(next_due, 20.0)) == ["a", "b", "c"]
    assert cx._due_commands(next_due, 5.0) == []


def test_sweep_allows_any_header_read_did() -> None:
    assert cx.check_sweep_allowed("222AB9") == "222AB9"
    assert cx.check_sweep_allowed("ATSH715") == "ATSH715"
    assert cx.check_sweep_allowed("ATCRA77F") == "ATCRA77F"
    assert cx.check_sweep_allowed("ATFCSH715") == "ATFCSH715"


def test_sweep_still_rejects_vin_and_other_services() -> None:
    for vin in ("22F190", "22F802"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_sweep_allowed(vin)
    for cmd in ("2E2AB8", "27FFFF", "10FFFF", "31FFFF"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_sweep_allowed(cmd)


def test_sweep_allows_explicit_29bit_ecu_header_and_filter() -> None:
    assert cx.check_sweep_allowed("ATSH18DA10F1") == "ATSH18DA10F1"
    assert cx.check_sweep_allowed("ATFCSH18DA2AF1") == "ATFCSH18DA2AF1"
    assert cx.check_sweep_allowed("ATCRA18DAF110") == "ATCRA18DAF110"
    assert cx.check_sweep_allowed("ATSP7") == "ATSP7"


def test_sweep_rejects_functional_broadcast_and_other_8digit_headers() -> None:
    # 18DB33F1 is the functional broadcast header, not a specific ECU request -
    # sweep must only ever target one already-identified responder.
    for cmd in ("ATSH18DB33F1", "ATFCSH18DB33F1", "ATSH12345678", "ATSHAAAAAAAA"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_sweep_allowed(cmd)


def test_obduds_allowlist_is_read_only_and_standard_scoped() -> None:
    allowed = (
        "ATSP7",
        "ATSH18DB33F1",
        "22F810",
        "ATSH18DA10F1",
        "ATCRA18DAF110",
        "ATFCSH18DA10F1",
        "22F400",
        "22F5FF",
    )
    assert [cx.check_obduds_allowed(cmd) for cmd in allowed] == list(allowed)
    for cmd in ("22F802", "22F190", "22F600", "14FFFF33", "31E000", "2EF44900"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_obduds_allowed(cmd)


def test_identify_allowlist_is_read_only_and_four_dids_only() -> None:
    allowed = (
        "ATSP7",
        "ATSH18DB33F1",
        "22F810",
        "ATSH18DA10F1",
        "ATCRA18DAF110",
        "ATFCSH18DA10F1",
        "22F187",
        "22F189",
        "22F191",
        "22F197",
    )
    assert [cx.check_identify_allowed(cmd) for cmd in allowed] == list(allowed)
    for cmd in ("22F18C", "22F190", "22F802", "22F400", "22F5FF", "14FFFF33", "2EF44900"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_identify_allowed(cmd)


def test_sweep_header_argument_derives_protocol_and_rax(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def fake_sweep(
        address: str,
        header: str | None,
        rax: str | None,
        start: str,
        end: str,
        label: str,
        out_dir: object,
        pair: bool,
        protocol: str | None,
        obduds_ecus: bool = False,
    ) -> int:
        captured.update(
            header=header, rax=rax, protocol=protocol, obduds_ecus=obduds_ecus
        )
        return 0

    monkeypatch.setattr(cx, "sweep", fake_sweep)

    sweep_args = ["sweep", "fake", "--header", "18da10f1", "--start", "2A00", "--end", "2A01"]
    assert cx.main([*sweep_args, "--state", "x"]) == 0
    assert captured == {
        "header": "18DA10F1",
        "rax": "18DAF110",
        "protocol": "7",
        "obduds_ecus": False,
    }

    captured.clear()
    assert cx.main(
        [
            "sweep",
            "fake",
            "--header",
            "18da10f1",
            "--rax",
            "18daf1aa",
            "--start",
            "2A00",
            "--end",
            "2A01",
            "--state",
            "x",
        ]
    ) == 0
    assert captured["rax"] == "18DAF1AA"

    captured.clear()
    assert cx.main(
        ["sweep", "fake", "--header", "710", "--start", "2A00", "--end", "2A01", "--state", "x"]
    ) == 0
    assert captured == {"header": "710", "rax": None, "protocol": None, "obduds_ecus": False}


def test_sweep_obduds_ecus_enforces_max_dids_times_responder_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent: list[str] = []

    class FakeCharacteristic:
        properties = ["write-without-response"]

    class FakeServices:
        def get_characteristic(self, _uuid: str) -> FakeCharacteristic:
            return FakeCharacteristic()

    class FakeClient:
        mtu_size = 23
        services = FakeServices()

        def __init__(self, _address: str, *, timeout: float) -> None:
            self.callback: Callable[[object, bytes], None] | None = None

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(
            self,
            _type: type[BaseException] | None,
            _value: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            pass

        async def pair(self) -> None:
            pass

        async def start_notify(self, _uuid: str, callback: Callable[[object, bytes], None]) -> None:
            self.callback = callback

        async def stop_notify(self, _uuid: str) -> None:
            pass

        async def write_gatt_char(
            self, _characteristic: FakeCharacteristic, data: bytes, *, response: bool
        ) -> None:
            cmd = data.decode().strip()
            sent.append(cmd)
            if cmd == "ATZ":
                reply = b"OBDLINK CX\r>"
            elif cmd == "22F810":
                reply = b"18DAF1100462F81001\r18DAF1200462F81001\r>"
            elif cmd.startswith("AT"):
                reply = b"OK\r>"
            else:
                reply = b"NO DATA\r>"
            assert self.callback is not None
            self.callback(None, reply)

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    monkeypatch.setattr(cx, "MAX_SWEEP_DIDS", 1)
    result = asyncio.run(
        cx.sweep(
            "fake",
            None,
            None,
            "2A00",
            "2A01",
            "stationary",
            tmp_path,
            False,
            None,
            obduds_ecus=True,
        )
    )
    assert result == 2
    assert "222A00" not in sent
    assert "222A01" not in sent


def test_identify_reads_only_four_dids_and_decodes_system_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[str] = []

    replies = {
        "22F810": b"18DAF1100462F81001\r>",
        "22F187": b"18DAF1100562F187ABCD\r>",
        "22F189": b"18DAF1100462F18901\r>",
        "22F191": b"18DAF1100462F19102\r>",
        # Positive 62 F1 97 reply carrying ascii "ECU1" as the system name.
        "22F197": b"18DAF1100762F19745435531\r>",
    }

    class FakeCharacteristic:
        properties = ["write-without-response"]

    class FakeServices:
        def get_characteristic(self, _uuid: str) -> FakeCharacteristic:
            return FakeCharacteristic()

    class FakeClient:
        mtu_size = 23
        services = FakeServices()

        def __init__(self, _address: str, *, timeout: float) -> None:
            self.callback: Callable[[object, bytes], None] | None = None

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(
            self,
            _type: type[BaseException] | None,
            _value: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            pass

        async def pair(self) -> None:
            pass

        async def start_notify(self, _uuid: str, callback: Callable[[object, bytes], None]) -> None:
            self.callback = callback

        async def stop_notify(self, _uuid: str) -> None:
            pass

        async def write_gatt_char(
            self, _characteristic: FakeCharacteristic, data: bytes, *, response: bool
        ) -> None:
            cmd = data.decode().strip()
            sent.append(cmd)
            if cmd == "ATZ":
                reply = b"OBDLINK CX\r>"
            elif cmd.startswith("AT"):
                reply = b"OK\r>"
            else:
                reply = replies[cmd]
            assert self.callback is not None
            self.callback(None, reply)

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    result = asyncio.run(cx.identify("fake", "stationary", tmp_path, False))

    assert result == 0
    assert [cmd for cmd in sent if cmd.startswith("22")] == [
        "22F810",
        "22F187",
        "22F189",
        "22F191",
        "22F197",
    ]
    assert "22F18C" not in sent
    assert "22F190" not in sent
    assert "22F802" not in sent
    entries = [json.loads(line) for line in next(tmp_path.glob("*.jsonl")).read_text().splitlines()]
    assert any(entry["stage"] == "identify-10" for entry in entries)
    assert "F197=ECU1" in capsys.readouterr().out


def test_obduds_protocol_discovery_keeps_all_nonzero_regulated_responders() -> None:
    response = "\n".join(
        (
            "18DAF1100462F81001",
            "18DAF12A0462F81001",
            "18DAF1440462F81000",
            "77A0462F81001",
        )
    )
    assert cx.obduds_responders(response) == ["18DAF110", "18DAF12A"]
    assert cx.classify("22F810", response, cx.OBDUDS_RESPONDER_PATTERN) == "OK"


def test_obduds_support_bitmap_maps_only_set_bits() -> None:
    response = "18DAF1100762F40010080001"
    assert cx.obduds_supported_dids("22F400", response, "18DAF110") == {
        0xF404,
        0xF40D,
        0xF420,
    }


def test_explicit_responder_prevents_sweep_false_hit() -> None:
    response = "775037F2231"
    assert cx.classify("222A00", response, "775") == "NRC 31 requestOutOfRange"
    assert cx.classify("222A00", response, "77A") == "UNMATCHED"


def test_obduds_probe_reads_only_announced_data_dids(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent: list[str] = []

    replies = {
        "22F810": b"18DAF1100462F81001\r>",
        "22F400": b"18DAF1100762F40000080001\r>",  # F40D and continuation F420
        "22F420": b"18DAF1100762F42000000001\r>",  # continuation F440
        "22F440": b"18DAF1100762F44040800000\r>",  # F442 and F449
        "22F40D": b"18DAF1100462F40D00\r>",
        "22F442": b"18DAF1100462F44201\r>",
        "22F449": b"18DAF1100462F44926\r>",
    }

    class FakeCharacteristic:
        properties = ["write-without-response"]

    class FakeServices:
        def get_characteristic(self, _uuid: str) -> FakeCharacteristic:
            return FakeCharacteristic()

    class FakeClient:
        mtu_size = 23
        services = FakeServices()

        def __init__(self, _address: str, *, timeout: float) -> None:
            self.callback: Callable[[object, bytes], None] | None = None

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(
            self,
            _type: type[BaseException] | None,
            _value: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            pass

        async def pair(self) -> None:
            pass

        async def start_notify(self, _uuid: str, callback: Callable[[object, bytes], None]) -> None:
            self.callback = callback

        async def stop_notify(self, _uuid: str) -> None:
            pass

        async def write_gatt_char(
            self, _characteristic: FakeCharacteristic, data: bytes, *, response: bool
        ) -> None:
            cmd = data.decode().strip()
            sent.append(cmd)
            if cmd == "ATZ":
                reply = b"OBDLINK CX\r>"
            elif cmd == "ATDPN":
                reply = b"7\r>"
            elif cmd.startswith("AT"):
                reply = b"OK\r>"
            else:
                reply = replies[cmd]
            assert self.callback is not None
            self.callback(None, reply)

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    result = asyncio.run(cx.obduds_probe("fake", "stationary", tmp_path, False, False))

    assert result == 0
    assert [cmd for cmd in sent if cmd.startswith("22")] == [
        "22F810",
        "22F400",
        "22F420",
        "22F440",
        "22F40D",
        "22F442",
        "22F449",
    ]
    entries = [json.loads(line) for line in next(tmp_path.glob("*.jsonl")).read_text().splitlines()]
    assert any(entry["stage"] == "obduds-data-10" for entry in entries)


def test_session_ctrl_c_cleans_up_and_returns_130(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent: list[str] = []
    watch_cycle = asyncio.Event()
    ab6_count = 0

    class FakeCharacteristic:
        properties = ["write-without-response"]

    class FakeNoteReader:
        async def stop(self) -> None:
            pass

    class FakeServices:
        def get_characteristic(self, _uuid: str) -> FakeCharacteristic:
            return FakeCharacteristic()

    class FakeClient:
        mtu_size = 23
        services = FakeServices()

        def __init__(self, _address: str, *, timeout: float) -> None:
            self.callback: Callable[[object, bytes], None] | None = None

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(
            self,
            _type: type[BaseException] | None,
            _value: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            pass

        async def start_notify(self, _uuid: str, callback: Callable[[object, bytes], None]) -> None:
            self.callback = callback

        async def stop_notify(self, _uuid: str) -> None:
            pass

        async def write_gatt_char(
            self, _characteristic: FakeCharacteristic, data: bytes, *, response: bool
        ) -> None:
            nonlocal ab6_count
            cmd = data.decode().strip()
            sent.append(cmd)
            if cmd == "222AB6":
                ab6_count += 1
                if ab6_count == 3:
                    watch_cycle.set()
            if cmd == "ATZ":
                reply = b"OBDLINK CX\r>"
            elif cmd in {"ATI", "STI", "STDI", "ATRV"}:
                reply = b"test value\r>"
            elif cmd == "ATDPN":
                reply = b"6\r>"
            elif cmd.startswith("AT"):
                reply = b"OK\r>"
            else:
                reply = b"NO DATA\r>"
            assert self.callback is not None
            self.callback(None, reply)

    async def scenario() -> int:
        task = asyncio.create_task(cx.run_session("fake", "drive", tmp_path, False, "6"))
        await asyncio.wait_for(watch_cycle.wait(), 5.0)
        await asyncio.sleep(0)
        task.cancel()
        return await task

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    monkeypatch.setattr(cx, "start_note_reader", lambda _record: FakeNoteReader())
    monkeypatch.setitem(cx.SESSION_SWEEP_RANGES, "710", (0x2AB6, 0x2AB6))
    monkeypatch.setitem(cx.SESSION_SWEEP_RANGES, "70B", (0x18A0, 0x18A0))

    assert asyncio.run(scenario()) == 130
    assert sent[-3:] == ["ATFCSM0", "ATAR", "ATD"]
    assert sent.count("ATD") == 1
    entries = [json.loads(line) for line in next(tmp_path.glob("*.jsonl")).read_text().splitlines()]
    assert entries[-4]["command"] == "SESSION_END"
    assert entries[-4]["status"] == "CANCELLED"


def test_reads_are_mode01_or_uds_22_only() -> None:
    for cmd in cx.ALLOWED:
        if not cmd.startswith(("AT", "ST")):
            assert cmd.startswith(("01", "22")), cmd


def test_unknown_command_is_rejected_before_sending() -> None:
    sent: list[bytes] = []

    async def write(data: bytes) -> None:
        sent.append(data)

    session = cx.ElmSession(write, 20)
    for cmd in ("14FFFFFF", "04", "2E2AB800", "22F190", "ATPP0ESV00"):
        with pytest.raises(cx.ForbiddenCommandError):
            asyncio.run(session.run(cmd))
    assert sent == []


def test_negative_response_codes() -> None:
    assert cx.classify("222AB8", "77A037F2231") == "NRC 31 requestOutOfRange"
    assert cx.classify("222AB8", "77A037F2233") == "NRC 33 securityAccessDenied"


def test_response_pending_then_positive_is_ok() -> None:
    assert cx.classify("222AB8", "77A037F2278\n77A06622AB8000012") == "OK"


def test_positive_payload_containing_7f_is_not_an_nrc() -> None:
    assert cx.classify("222AB8", "77A06622AB87F2231") == "OK"


def test_no_data() -> None:
    assert cx.classify("0100", "NO DATA") == "NO DATA"


def test_bitmap() -> None:
    # 0x00100000 at base 0x40 sets bit index 11 -> PID 0x4C; 0x08000000 at base 0x00 -> 0x05.
    found = cx.supported_pids(["7E80641000800000000", "7E806414000100000"])
    assert "05" in found
    assert "4C" in found


def test_reply_fragmented_across_notifications() -> None:
    async def scenario() -> cx.Exchange:
        session: cx.ElmSession | None = None

        async def write(data: bytes) -> None:
            async def reply() -> None:
                assert session is not None
                for part in (b"77A06", b"622AB8", b"000012\r", b"\r>"):
                    await asyncio.sleep(0.01)
                    session.on_notify(part)

            asyncio.ensure_future(reply())

        session = cx.ElmSession(write, 20)
        return await session.run("222AB8")

    ex = asyncio.run(scenario())
    assert ex.status == "OK"
    assert ex.response == "77A06622AB8000012"


def test_missing_prompt_invalidates_session(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        sent: list[bytes] = []

        async def write(data: bytes) -> None:
            sent.append(data)

        session = cx.ElmSession(write, 20)
        first = await session.run("ATI")
        assert first.status == "TIMEOUT"
        session.on_notify(b"ELM327 late\r>")
        with pytest.raises(RuntimeError, match="reconnect"):
            await session.run("ATRV")
        assert sent == [b"ATI\r"]

    monkeypatch.setattr(cx, "DEFAULT_TIMEOUT", 0.5)
    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("command", "response", "status"),
    [
        ("222AB8", "77A05622AB20012", "UNMATCHED"),
        ("222AB8", "SEARCHING...", "UNMATCHED"),
        ("0100", "SEARCHING...\r7E806410008000000", "OK"),
        ("222AB8", "77A037F2278", "PENDING"),
        ("222AB8", "77A037F2233\n77A21000000000000", "NRC 33 securityAccessDenied"),
        ("222AB8", "77505622AB80012", "UNMATCHED"),
        ("222AB8", "77A07622AB8000012", "MALFORMED"),
        ("222AB8", "77A100A622AB8000000\n77A2100000000", "OK"),
        ("222AB8", "77A100A622AB8000000", "MALFORMED"),
        ("222AB8", "77A100A622AB8000000\n77A2200000000", "MALFORMED"),
        ("010D", "18DAF11003410D32", "OK"),
        ("010D", "7E803410C32", "UNMATCHED"),
        ("ATSH710", "?", "?"),
        ("ATZ", "ELM327 v1.4", "OK"),
        ("ATMA", "77A0100", "MONITOR"),
    ],
)
def test_classification_requires_matching_complete_response(
    command: str, response: str, status: str
) -> None:
    assert cx.classify(command, response) == status


@pytest.mark.parametrize("failure", ["blocked", "error", "overflow", "cancel", "trailing"])
def test_transport_failures_invalidate_session(
    failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        session: cx.ElmSession

        async def write(_data: bytes) -> None:
            if failure == "blocked":
                await asyncio.Event().wait()
            elif failure == "error":
                raise OSError("synthetic disconnect")
            elif failure == "cancel":
                raise asyncio.CancelledError
            elif failure == "trailing":
                session.on_notify(b"OK\r>unattributed")
            else:
                session.on_notify(b"x" * (cx.MAX_RESPONSE_BYTES + 1) + b">")

        session = cx.ElmSession(write, 20)
        if failure == "cancel":
            with pytest.raises(asyncio.CancelledError):
                await session.run("ATE0")
        else:
            ex = await session.run("ATE0")
            assert ex.status == ("TIMEOUT" if failure == "blocked" else "TRANSPORT_ERROR")
        assert not session.usable
        with pytest.raises(RuntimeError):
            await session.run("ATI")

    monkeypatch.setattr(cx, "DEFAULT_TIMEOUT", 0.5)
    asyncio.run(scenario())


def test_monitor_stop_write_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        writes: list[bytes] = []

        async def write(data: bytes) -> None:
            writes.append(data)
            if data == b"\r":
                await asyncio.Event().wait()

        session = cx.ElmSession(write, 20)
        ex = await session.run("ATMA")
        assert ex.status == "TIMEOUT"
        assert writes == [b"ATMA\r", b"\r"]
        assert not session.usable

    monkeypatch.setattr(cx, "MONITOR_SECONDS", 0.01)
    monkeypatch.setattr(cx, "MONITOR_STOP_TIMEOUT", 0.2)
    asyncio.run(scenario())


@pytest.mark.parametrize("failure", ["timeout", "rejected_setup", "rejected_header", "write_error"])
def test_probe_logs_failure_and_disconnects_without_next_command(
    failure: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent: list[str] = []
    disconnected: list[bool] = []
    target = {"rejected_setup": "ATE0", "rejected_header": "ATSH710"}.get(failure, "ATZ")

    class FakeCharacteristic:
        properties = ["write-without-response"]

    class FakeNoteReader:
        async def stop(self) -> None:
            pass

    class FakeServices:
        def get_characteristic(self, _uuid: str) -> FakeCharacteristic:
            return FakeCharacteristic()

    class FakeClient:
        mtu_size = 23
        services = FakeServices()

        def __init__(self, _address: str, *, timeout: float) -> None:
            self.callback: Callable[[object, bytes], None] | None = None

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(
            self,
            _type: type[BaseException] | None,
            _value: BaseException | None,
            _traceback: TracebackType | None,
        ) -> None:
            disconnected.append(True)

        async def start_notify(self, _uuid: str, callback: Callable[[object, bytes], None]) -> None:
            self.callback = callback

        async def stop_notify(self, _uuid: str) -> None:
            pass

        async def write_gatt_char(
            self, _characteristic: FakeCharacteristic, data: bytes, *, response: bool
        ) -> None:
            cmd = data.decode().strip()
            sent.append(cmd)
            if cmd == target:
                if failure == "timeout":
                    return
                if failure == "write_error":
                    raise OSError("synthetic disconnect")
                reply = b"?\r>"
            elif cmd == "ATZ":
                reply = b"ELM327 v1.4\r>"
            elif cmd.startswith("AT"):
                reply = b"OK\r>"
            else:
                reply = b"NO DATA\r>"
            assert self.callback is not None
            self.callback(None, reply)

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    monkeypatch.setattr(cx, "start_note_reader", lambda _record: FakeNoteReader())
    # Keep enough headroom for ElmSession's deliberate 50 ms stale-input drain;
    # 100 ms made this transport test scheduler-dependent under a full suite.
    monkeypatch.setattr(cx, "DEFAULT_TIMEOUT", 0.5)
    monkeypatch.setitem(cx.SLOW_COMMANDS, "ATZ", 0.5)
    result = asyncio.run(cx.probe("fake", "BE", "synthetic", tmp_path, False))
    assert result == 2
    assert disconnected == [True]
    assert sent[-1] == target
    entries = [json.loads(line) for line in next(tmp_path.glob("*.jsonl")).read_text().splitlines()]
    assert entries[-1]["command"] == target
    assert (
        entries[-1]["status"]
        == {
            "timeout": "TIMEOUT",
            "write_error": "TRANSPORT_ERROR",
            "rejected_setup": "?",
            "rejected_header": "?",
        }[failure]
    )
