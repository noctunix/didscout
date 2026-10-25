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


def test_live_value_age_and_summary() -> None:
    v = cx.LiveValue("622AB8...", "OK", time.monotonic() - 5)
    assert 4.5 < v.age_seconds() < 5.5
    assert "222AB8=OK(+5s)" in cx.format_live_summary({"222AB8": v})
    assert cx.format_live_summary({}) == "live: -"


def test_survey_interval_rejects_below_minimum() -> None:
    with pytest.raises(SystemExit):
        cx.main(["session", "fake", "--state", "x", "--survey-interval", "10"])


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


PROFILE_FILES = sorted((Path(__file__).parent / "profiles").glob("*.toml"))


@pytest.mark.parametrize("path", PROFILE_FILES, ids=[p.stem for p in PROFILE_FILES])
def test_shipped_profile_loads_and_only_ever_yields_sweep_allowed_commands(path: Path) -> None:
    """Loads every profile shipped in `profiles/` - this is what makes a broken or
    unsafe profile PR fail the test suite automatically."""
    profile = cx.load_profile(path)
    assert profile.id == path.stem
    for module in profile.modules:
        for cmd in cx.module_setup_commands(module):
            cx.check_sweep_allowed(cmd)
        for did in module.dids:
            cx.check_sweep_allowed(f"22{did.did}")


VALID_PROFILE_TOML = """
schema = 1
id = "testprofile"
name = "Test profile"
description = "A test profile"
protocol = "6"
vehicles = ["Test vehicle"]

[[sources]]
title = "Test source"
url = "https://example.com"
license = "own discovery"

[[modules]]
id = "mod1"
request = "710"
response = "77A"

[[modules.dids]]
did = "2AB8"
name = "test did"
status = "plausible"
poll = "once"
"""


def _load(tmp_path: Path, text: str, filename: str = "testprofile.toml") -> cx.Profile:
    path = tmp_path / filename
    path.write_text(text)
    return cx.load_profile(path)


def test_valid_profile_loads(tmp_path: Path) -> None:
    profile = _load(tmp_path, VALID_PROFILE_TOML)
    assert profile.id == "testprofile"
    assert profile.modules[0].dids[0].did == "2AB8"


def test_resolve_profile_finds_by_id_in_profiles_dir() -> None:
    profile = cx.resolve_profile("vag-ppe")
    assert profile.id == "vag-ppe"


def test_resolve_profile_raises_when_not_found(tmp_path: Path) -> None:
    with pytest.raises(cx.ProfileError):
        cx.resolve_profile(str(tmp_path / "does-not-exist"))


@pytest.mark.parametrize(
    ("name", "broken"),
    [
        ("invalid_toml_syntax", "not valid toml ["),
        ("wrong_schema", VALID_PROFILE_TOML.replace("schema = 1", "schema = 2")),
        (
            "id_not_matching_pattern",
            VALID_PROFILE_TOML.replace('id = "testprofile"', 'id = "Test_Profile"'),
        ),
        ("unknown_root_key", VALID_PROFILE_TOML.replace("schema = 1", "schema = 1\nextra = 1")),
        (
            "missing_required_root_key",
            VALID_PROFILE_TOML.replace('description = "A test profile"\n', ""),
        ),
        ("invalid_protocol", VALID_PROFILE_TOML.replace('protocol = "6"', 'protocol = "8"')),
        (
            "empty_vehicles",
            VALID_PROFILE_TOML.replace('vehicles = ["Test vehicle"]', "vehicles = []"),
        ),
        (
            "unknown_source_key",
            VALID_PROFILE_TOML.replace(
                'license = "own discovery"', 'license = "own discovery"\nextra = 1'
            ),
        ),
        (
            "unknown_module_key",
            VALID_PROFILE_TOML.replace('response = "77A"', 'response = "77A"\nextra = 1'),
        ),
        (
            "duplicate_module_id",
            VALID_PROFILE_TOML
            + """
            [[modules]]
            id = "mod1"
            request = "70B"

            [[modules.dids]]
            did = "18A0"
            name = "dup"
            status = "plausible"
            poll = "once"
            """,
        ),
        (
            "module_request_not_a_header",
            VALID_PROFILE_TOML.replace('request = "710"', 'request = "ZZZZ"'),
        ),
        (
            "module_request_11bit_over_7ff",
            VALID_PROFILE_TOML.replace('request = "710"', 'request = "800"'),
        ),
        (
            "module_29bit_request_needs_protocol_7",
            VALID_PROFILE_TOML.replace('request = "710"', 'request = "18DA10F1"'),
        ),
        (
            "module_response_not_a_header",
            VALID_PROFILE_TOML.replace('response = "77A"', 'response = "ZZZ"'),
        ),
        (
            "did_is_vin",
            VALID_PROFILE_TOML.replace('did = "2AB8"', 'did = "F190"'),
        ),
        (
            "did_wrong_length",
            VALID_PROFILE_TOML.replace('did = "2AB8"', 'did = "2AB"'),
        ),
        (
            "did_invalid_status",
            VALID_PROFILE_TOML.replace('status = "plausible"', 'status = "confirmed"'),
        ),
        (
            "did_invalid_poll",
            VALID_PROFILE_TOML.replace('poll = "once"', 'poll = "always"'),
        ),
        (
            "once_with_interval",
            VALID_PROFILE_TOML.replace('poll = "once"', 'poll = "once"\ninterval = 10'),
        ),
        (
            "watch_without_interval",
            VALID_PROFILE_TOML.replace('poll = "once"', 'poll = "watch"'),
        ),
        (
            "watch_interval_below_minimum",
            VALID_PROFILE_TOML.replace('poll = "once"', 'poll = "watch"\ninterval = 4'),
        ),
        (
            "name_missing_for_non_survey_poll",
            VALID_PROFILE_TOML.replace('name = "test did"\n', ""),
        ),
        (
            "discover_start_after_end",
            VALID_PROFILE_TOML.replace(
                'response = "77A"', 'response = "77A"\ndiscover = [["2A01", "2A00"]]'
            ),
        ),
        (
            "vin_like_string_anywhere",
            VALID_PROFILE_TOML.replace(
                'description = "A test profile"', 'description = "WVWZZZ1KZAW123456"'
            ),
        ),
    ],
)
def test_profile_rejections(tmp_path: Path, name: str, broken: str) -> None:
    with pytest.raises(cx.ProfileError):
        _load(tmp_path, broken)


def test_profile_rejects_duplicate_did_in_one_module(tmp_path: Path) -> None:
    broken = (
        VALID_PROFILE_TOML
        + """
    [[modules.dids]]
    did = "2AB8"
    name = "dup"
    status = "plausible"
    poll = "once"
    """
    )
    with pytest.raises(cx.ProfileError):
        _load(tmp_path, broken)


def test_profile_rejects_discover_range_exceeding_max_sweep_dids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cx, "MAX_SWEEP_DIDS", 1)
    broken = VALID_PROFILE_TOML.replace(
        'response = "77A"', 'response = "77A"\ndiscover = [["2A00", "2A01"]]'
    )
    with pytest.raises(cx.ProfileError):
        _load(tmp_path, broken)


def test_profile_allows_survey_did_without_name(tmp_path: Path) -> None:
    text = VALID_PROFILE_TOML.replace('name = "test did"\n', "").replace(
        'poll = "once"', 'poll = "survey"\ninterval = 30'
    )
    profile = _load(tmp_path, text)
    assert profile.modules[0].dids[0].name is None
    assert profile.modules[0].dids[0].poll == "survey"


def test_profile_id_must_equal_file_stem(tmp_path: Path) -> None:
    with pytest.raises(cx.ProfileError):
        _load(tmp_path, VALID_PROFILE_TOML, filename="other.toml")


def test_module_setup_commands_with_response_use_flow_control() -> None:
    module = cx.Module(id="m", request="710", response="77A", dids=[])
    cmds = cx.module_setup_commands(module)
    assert cmds == ["ATSH710", "ATCRA77A", "ATFCSH710", "ATFCSD300000", "ATFCSM1"]
    for cmd in cmds:
        assert cx.check_sweep_allowed(cmd) == cmd


def test_module_setup_commands_without_response_are_receive_any() -> None:
    module = cx.Module(id="m", request="714", response=None, dids=[])
    cmds = cx.module_setup_commands(module)
    assert cmds == ["ATFCSM0", "ATAR", "ATSH714"]
    for cmd in cmds:
        assert cx.check_sweep_allowed(cmd) == cmd


def test_module_setup_commands_for_29bit_header() -> None:
    module = cx.Module(id="m", request="18DA10F1", response="18DAF110", dids=[])
    cmds = cx.module_setup_commands(module)
    assert cmds == [
        "ATSH18DA10F1",
        "ATCRA18DAF110",
        "ATFCSH18DA10F1",
        "ATFCSD300000",
        "ATFCSM1",
    ]
    for cmd in cmds:
        assert cx.check_sweep_allowed(cmd) == cmd


def test_build_watch_schedule_includes_watch_always_and_survey_when_enabled() -> None:
    module = cx.Module(
        id="m",
        request="710",
        response="77A",
        dids=[
            cx.ModuleDid(did="2AB8", status="plausible", poll="watch", interval=15.0),
            cx.ModuleDid(did="2AB2", status="unverified", poll="once"),
            cx.ModuleDid(did="2A04", status="unverified", poll="survey"),
        ],
    )
    without_survey = cx.build_watch_schedule([module], survey=False, survey_interval=30.0)
    assert [e.command for e in without_survey] == ["222AB8"]

    with_survey = cx.build_watch_schedule([module], survey=True, survey_interval=30.0)
    assert {e.command: e.interval for e in with_survey} == {"222AB8": 15.0, "222A04": 30.0}


def test_watch_loop_resets_up_only_on_module_change(monkeypatch: pytest.MonkeyPatch) -> None:
    module_a = cx.Module(
        id="a",
        request="710",
        response="77A",
        dids=[cx.ModuleDid(did="2AB8", status="plausible", poll="watch", interval=5.0)],
    )
    module_b = cx.Module(
        id="b",
        request="70B",
        response="775",
        dids=[cx.ModuleDid(did="18A0", status="plausible", poll="watch", interval=5.0)],
    )
    schedule = cx.build_watch_schedule([module_a, module_b], survey=False, survey_interval=0.0)

    calls: list[tuple[str, str]] = []
    cycles = 0

    async def fake_execute(
        command: str, stage: str, validator: object = None, responder: str | None = None
    ) -> cx.Exchange:
        calls.append((command, stage))
        return cx.Exchange(command, "NO DATA", "NO DATA", "", 0.0)

    # Run exactly one polling cycle: both modules are due immediately (same
    # `time.monotonic()` seed), so one pass through the loop must set up module
    # `a`, read its DID, set up module `b`, read its DID - then stop.
    real_sleep = asyncio.sleep

    async def fake_sleep(_seconds: float) -> None:
        nonlocal cycles
        cycles += 1
        if cycles > 1:
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cx.run_watch_loop(fake_execute, schedule, None, "E-watch", "E-survey"))

    setup_calls = [cmd for cmd, stage in calls if stage == "E-watch-setup"]
    assert setup_calls == cx.module_setup_commands(module_a) + cx.module_setup_commands(module_b)
    assert ("222AB8", "E-watch") in calls
    assert ("2218A0", "E-watch") in calls


def test_probe_stage_e_without_profile_is_a_parser_error() -> None:
    with pytest.raises(SystemExit):
        cx.main(["probe", "fake", "--state", "x", "--stages", "E"])


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
        captured.update(header=header, rax=rax, protocol=protocol, obduds_ecus=obduds_ecus)
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
    assert (
        cx.main(
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
        )
        == 0
    )
    assert captured["rax"] == "18DAF1AA"

    captured.clear()
    assert (
        cx.main(
            ["sweep", "fake", "--header", "710", "--start", "2A00", "--end", "2A01", "--state", "x"]
        )
        == 0
    )
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

    profile_path = tmp_path / "testgw.toml"
    profile_path.write_text(
        """
        schema = 1
        id = "testgw"
        name = "Test gateway"
        description = "Test fixture"
        protocol = "6"
        vehicles = ["Test vehicle"]

        [[sources]]
        title = "Test"
        url = "https://example.com"
        license = "own discovery"

        [[modules]]
        id = "gateway"
        request = "710"
        response = "77A"
        discover = [["2AB6", "2AB6"]]

        [[modules.dids]]
        did = "2AB6"
        name = "range remaining"
        status = "validated"
        poll = "watch"
        interval = 60
        """
    )
    profile = cx.load_profile(profile_path)

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
        task = asyncio.create_task(
            cx.run_session("fake", "drive", tmp_path, False, "6", profile=profile)
        )
        await asyncio.wait_for(watch_cycle.wait(), 5.0)
        await asyncio.sleep(0)
        task.cancel()
        return await task

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    monkeypatch.setattr(cx, "start_note_reader", lambda _record: FakeNoteReader())

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


def test_adapter_link_execute_logs_and_passes_through_noncritical_status() -> None:
    async def scenario() -> None:
        async def write(_data: bytes) -> None:
            session.on_notify(b"?\r>")

        session = cx.ElmSession(write, 20)
        logged: list[tuple[str, str]] = []
        link = cx.AdapterLink(session, lambda ex, stage: logged.append((ex.command, stage)))

        # ATI is in the default non-critical set, so a reply that doesn't classify
        # as OK must not abort - but it's still recorded.
        ex = await link.execute("ATI", "A")
        assert ex.status == "?"
        assert logged == [("ATI", "A")]

    asyncio.run(scenario())


def test_adapter_link_execute_fails_closed_on_critical_at_not_ok() -> None:
    async def scenario() -> None:
        async def write(_data: bytes) -> None:
            session.on_notify(b"?\r>")

        session = cx.ElmSession(write, 20)
        link = cx.AdapterLink(session, lambda ex, stage: None)

        with pytest.raises(cx.ProbeAbortedError):
            await link.execute("ATE0", "setup")

    asyncio.run(scenario())


def test_adapter_link_execute_fails_closed_on_unusable_session() -> None:
    async def scenario() -> None:
        async def write(_data: bytes) -> None:
            raise OSError("synthetic disconnect")

        session = cx.ElmSession(write, 20)
        link = cx.AdapterLink(session, lambda ex, stage: None)

        # ATRV is non-critical, but a session that lost synchronization must still
        # fail closed rather than let the caller send a next command.
        with pytest.raises(cx.ProbeAbortedError):
            await link.execute("ATRV", "A")
        assert not session.usable

    asyncio.run(scenario())


def test_connect_adapter_yields_link_that_logs_each_exchange(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
            assert self.callback is not None
            self.callback(None, b"OK\r>")

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    log_path = tmp_path / "link.jsonl"

    async def scenario() -> None:
        async with cx.connect_adapter("fake", False, log_path, "mystate") as link:
            assert link is not None
            await link.execute("ATE0", "setup")

    asyncio.run(scenario())

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert entries == [
        {
            "stage": "setup",
            "state": "mystate",
            "mtu": 23,
            "command": "ATE0",
            "response": entries[0]["response"],
            "status": "OK",
            "started_utc": entries[0]["started_utc"],
            "duration_ms": entries[0]["duration_ms"],
        }
    ]


def test_connect_adapter_yields_none_without_write_characteristic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeServices:
        def get_characteristic(self, _uuid: str) -> None:
            return None

    class FakeClient:
        mtu_size = 23
        services = FakeServices()

        def __init__(self, _address: str, *, timeout: float) -> None:
            pass

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

    monkeypatch.setattr(bleak, "BleakClient", FakeClient)
    log_path = tmp_path / "missing.jsonl"

    async def scenario() -> bool:
        async with cx.connect_adapter("fake", False, log_path, "mystate") as link:
            return link is None

    assert asyncio.run(scenario()) is True
    assert not log_path.exists()


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
        return await session.run("222AB8", cx.check_sweep_allowed, "77A")

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


def test_classify_requires_an_explicit_responder_to_filter_wrong_header() -> None:
    # classify() no longer guesses a responder from the DID prefix - callers
    # (profile-driven module reads) must pass it explicitly to filter out a
    # positive reply that came from the wrong module.
    assert cx.classify("222AB8", "77505622AB80012") == "OK"
    assert cx.classify("222AB8", "77505622AB80012", "77A") == "UNMATCHED"


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
    profile = cx.resolve_profile("vag-ppe")
    result = asyncio.run(cx.probe("fake", "BE", "synthetic", tmp_path, False, profile=profile))
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


# --- record mode -------------------------------------------------------------


def test_check_mode01_allowed_is_read_only_current_data() -> None:
    allowed = ("ATZ", "ATSP6", "0100", "010D", "01FF")
    assert [cx.check_mode01_allowed(cmd) for cmd in allowed] == list(allowed)
    for cmd in ("22F18C", "22F190", "22F802", "14FFFF", "2E2AB800"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_mode01_allowed(cmd)


def test_check_ecus11_allowed_is_read_only_and_four_dids_only() -> None:
    allowed = (
        "ATSP6",
        "ATCF700",
        "ATCM700",
        "ATAR",
        "ATSH710",
        "ATCRA77A",
        "ATFCSH710",
        "22F187",
        "22F189",
        "22F191",
        "22F197",
    )
    assert [cx.check_ecus11_allowed(cmd) for cmd in allowed] == list(allowed)
    for cmd in ("22F18C", "22F190", "22F802", "22F400", "14FFFF33", "2EF44900"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_ecus11_allowed(cmd)


def test_run_state_round_trip_and_atomic_write(tmp_path: Path) -> None:
    state = cx.RunState.new("vehicle", "AA:BB:CC:DD:EE:FF")
    state.mark_stage("adapter", "done")
    state.set_result("adapter", {"ATI": "ELM327 v1.4"})
    path = tmp_path / "state.json"
    state.save(path)

    assert path.exists()
    assert not path.with_name("state.json.tmp").exists()

    loaded = cx.RunState.load(path)
    assert loaded.label == "vehicle"
    assert loaded.address == "AA:BB:CC:DD:EE:FF"
    assert loaded.stage_status("adapter") == "done"
    assert loaded.result("adapter") == {"ATI": "ELM327 v1.4"}
    assert loaded.finished is False


def _write_run(out_dir: Path, stamp: str, label: str, *, finished: bool) -> Path:
    run_dir = out_dir / f"record_{stamp}_{label}"
    run_dir.mkdir(parents=True)
    state = cx.RunState.new(label, "AA:BB")
    if finished:
        state.mark_finished()
    state.save(run_dir / "state.json")
    return run_dir


def test_find_resumable_run_picks_newest_unfinished_same_label(tmp_path: Path) -> None:
    _write_run(tmp_path, "20260101_000000", "vehicle", finished=False)
    newest = _write_run(tmp_path, "20260102_000000", "vehicle", finished=False)
    _write_run(tmp_path, "20260103_000000", "vehicle", finished=True)
    _write_run(tmp_path, "20260104_000000", "other", finished=False)

    assert cx.find_resumable_run(tmp_path, "vehicle") == newest
    assert cx.find_resumable_run(tmp_path, "nonexistent-label") is None
    assert cx.find_resumable_run(tmp_path / "missing", "vehicle") is None


def test_find_adapter_address_picks_strongest_rssi(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeDevice:
        def __init__(self, address: str) -> None:
            self.address = address

    class FakeAdv:
        def __init__(self, rssi: int, uuids: list[str]) -> None:
            self.rssi = rssi
            self.service_uuids = uuids

    class FakeScanner:
        @staticmethod
        async def discover(timeout: float, return_adv: bool) -> dict[str, object]:
            return {
                "AA": (FakeDevice("AA"), FakeAdv(-80, [cx.UART_SERVICE])),
                "BB": (FakeDevice("BB"), FakeAdv(-40, [cx.UART_SERVICE])),
                "CC": (FakeDevice("CC"), FakeAdv(-30, ["0000ffff-0000-1000-8000-00805f9b34fb"])),
            }

    monkeypatch.setattr(bleak, "BleakScanner", FakeScanner)
    assert asyncio.run(cx.find_adapter_address(seconds=0.01)) == "BB"


def test_find_adapter_address_rescans_until_device_appears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    class FakeDevice:
        def __init__(self, address: str) -> None:
            self.address = address

    class FakeAdv:
        def __init__(self, rssi: int, uuids: list[str]) -> None:
            self.rssi = rssi
            self.service_uuids = uuids

    class FakeScanner:
        @staticmethod
        async def discover(timeout: float, return_adv: bool) -> dict[str, object]:
            calls["n"] += 1
            if calls["n"] < 2:
                return {}
            return {"AA": (FakeDevice("AA"), FakeAdv(-50, [cx.UART_SERVICE]))}

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(bleak, "BleakScanner", FakeScanner)
    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    address = asyncio.run(cx.find_adapter_address(seconds=0.01, rescan_interval=10.0))
    assert address == "AA"
    assert sleeps == [10.0]


def _ok_responder(cmd: str) -> bytes:
    """A stand-in adapter that answers ATZ with a recognized banner and every
    other AT command with OK - enough to clear ADAPTER_SETUP in `record` tests
    that stub out the inventory stages themselves."""
    if cmd == "ATZ":
        return b"ELM327 v1.4\r>"
    return b"OK\r>"


def _fake_record_client(responder: Callable[[str], bytes]) -> type:
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
            reply = responder(cmd)
            assert self.callback is not None
            self.callback(None, reply)

    return FakeClient


def test_record_resumes_unfinished_run_and_new_flag_starts_fresh(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[str] = []

    def make_stage(name: str) -> Callable[[object, cx.RunState, object], object]:
        async def stage(_link: object, state: cx.RunState, _profile: object) -> None:
            calls.append(name)
            state.set_result(name, {})

        return stage

    async def fake_run_record_loop(
        _link: object, _state: object, _profile: object, _state_path: object
    ) -> None:
        # The inventory is what this test cares about; the continuous loop
        # that follows it is exercised separately (see
        # test_record_loop_discovers_while_stationary_and_pauses_while_moving).
        raise asyncio.CancelledError

    fakes = {name: make_stage(name) for name in cx.INVENTORY_STAGE_ORDER}
    monkeypatch.setattr(cx, "INVENTORY_STAGE_FUNCS", fakes)
    monkeypatch.setattr(cx, "run_record_loop", fake_run_record_loop)
    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(_ok_responder))

    existing = _write_run(tmp_path, "20260101_000000", "vehicle", finished=False)
    state = cx.RunState.load(existing / "state.json")
    state.mark_stage("adapter", "done")
    state.save(existing / "state.json")

    result = asyncio.run(cx.record("fake", None, "vehicle", tmp_path, False))
    assert result == 130
    assert calls == ["protocol", "mode01", "obduds", "ecus11"]
    # finished stays False: a `record` run never ends on its own, only on
    # Ctrl-C, so the next start resumes the continuous loop, not the inventory.
    assert cx.RunState.load(existing / "state.json").finished is False

    calls.clear()
    result = asyncio.run(cx.record("fake", None, "vehicle", tmp_path, True))
    assert result == 130
    assert calls == list(cx.INVENTORY_STAGE_ORDER)
    assert len(list(tmp_path.glob("record_*"))) == 2


def test_record_reconnects_after_transport_error_and_resumes_interrupted_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "RECORD_INITIAL_BACKOFF", 0.0)
    monkeypatch.setattr(cx, "RECORD_MAX_BACKOFF", 0.0)

    calls: list[str] = []
    protocol_attempts = {"n": 0}

    async def fake_adapter(_link: object, state: cx.RunState, _profile: object) -> None:
        calls.append("adapter")
        state.set_result("adapter", {})

    async def fake_protocol(_link: object, state: cx.RunState, _profile: object) -> None:
        calls.append("protocol")
        protocol_attempts["n"] += 1
        if protocol_attempts["n"] == 1:
            raise cx.ProbeAbortedError("synthetic transport error")
        state.set_result("protocol", {"answered": [], "chosen": None})

    async def fake_mode01(_link: object, state: cx.RunState, _profile: object) -> None:
        calls.append("mode01")
        state.set_result("mode01", {"supported_pids": []})

    async def fake_obduds(_link: object, state: cx.RunState, _profile: object) -> None:
        calls.append("obduds")
        state.set_result("obduds", {})

    async def fake_ecus11(_link: object, state: cx.RunState, _profile: object) -> None:
        calls.append("ecus11")
        state.set_result("ecus11", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": fake_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
        },
    )

    async def fake_run_record_loop(
        _link: object, _state: object, _profile: object, _state_path: object
    ) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(cx, "run_record_loop", fake_run_record_loop)
    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(_ok_responder))

    result = asyncio.run(cx.record("fake", None, "vehicle", tmp_path, False))

    assert result == 130
    # adapter must not be redone on the reconnect - only the interrupted stage is retried.
    assert calls == ["adapter", "protocol", "protocol", "mode01", "obduds", "ecus11"]

    run_dir = next(tmp_path.glob("record_*"))
    entries = [json.loads(line) for line in (run_dir / "capture.jsonl").read_text().splitlines()]
    statuses = [entry["status"] for entry in entries if entry["stage"] == "connection"]
    assert statuses.count("CONNECTED") == 2
    assert "DISCONNECTED" in statuses
    assert "RECONNECTING" in statuses
    assert all(entry.get("mode") == "record" for entry in entries)


def test_record_marks_stage_failed_after_three_consecutive_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "RECORD_INITIAL_BACKOFF", 0.0)
    monkeypatch.setattr(cx, "RECORD_MAX_BACKOFF", 0.0)

    attempts = {"n": 0}

    async def fake_adapter(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("adapter", {})

    async def failing_protocol(_link: object, _state: cx.RunState, _profile: object) -> None:
        attempts["n"] += 1
        raise cx.ProbeAbortedError("synthetic rejection")

    async def fake_mode01(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("mode01", {"supported_pids": []})

    async def fake_obduds(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("obduds", {})

    async def fake_ecus11(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus11", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": failing_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
        },
    )

    async def fake_run_record_loop(
        _link: object, _state: object, _profile: object, _state_path: object
    ) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(cx, "run_record_loop", fake_run_record_loop)
    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(_ok_responder))

    result = asyncio.run(cx.record("fake", None, "vehicle", tmp_path, False))

    assert result == 130
    assert attempts["n"] == 3
    run_dir = next(tmp_path.glob("record_*"))
    state = cx.RunState.load(run_dir / "state.json")
    assert state.stage_status("protocol") == "failed"
    assert state.stage_status("mode01") == "done"
    assert state.finished is False


def test_ecus11_discovery_finds_positive_and_negative_responders_and_ignores_silence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    current_header: dict[str, str] = {"value": ""}
    monkeypatch.setattr(cx, "ECU11_REQUEST_IDS", list(range(0x700, 0x712)))
    replies = {
        ("710", "22F189"): b"77A0462F18901\r>",
        ("710", "22F187"): b"77A0462F18701\r>",
        ("710", "22F191"): b"77A0462F19101\r>",
        ("710", "22F197"): b"77A0762F19745435531\r>",
        ("705", "22F189"): b"745037F2231\r>",
        ("705", "22F187"): b"745037F2231\r>",
        ("705", "22F191"): b"745037F2231\r>",
        ("705", "22F197"): b"745037F2231\r>",
    }

    def responder(cmd: str) -> bytes:
        if cmd.startswith("ATSH"):
            current_header["value"] = cmd[4:]
            return b"OK\r>"
        if cmd.startswith("AT"):
            return b"OK\r>"
        return replies.get((current_header["value"], cmd), b"NO DATA\r>")

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    async def scenario() -> cx.RunState:
        state = cx.RunState.new("vehicle", "fake")
        async with cx.connect_adapter("fake", False, tmp_path / "ecus11.jsonl", "vehicle") as link:
            assert link is not None
            await cx._inventory_ecus11(link, state, None)
        return state

    state = asyncio.run(scenario())
    ecus = state.result("ecus11")
    assert isinstance(ecus, dict)
    assert set(ecus) == {"710", "705"}
    assert ecus["710"]["response"] == "77A"
    assert ecus["710"]["identify"]["F189"] == "OK"
    assert ecus["705"]["response"] == "745"
    assert ecus["705"]["identify"]["F189"].startswith("NRC")


def test_stretch_watch_intervals_keeps_speed_and_scales_the_rest() -> None:
    entries = [("speed", 2.0, True), ("a", 1.0, False), ("b", 1.0, False)]
    # rate = 1/1 + 1/1 = 2.0 reads/s; stretched by 2x to fit a 1.0 limit.
    stretched = cx.stretch_watch_intervals(entries, limit=1.0)
    assert stretched["speed"] == 2.0
    assert stretched["a"] == pytest.approx(2.0)
    assert stretched["b"] == pytest.approx(2.0)

    under_limit = cx.stretch_watch_intervals([("a", 10.0, False)], limit=cx.RECORD_LOAD_LIMIT)
    assert under_limit["a"] == 10.0


def test_discovery_did_order_profile_ranges_first_then_priority_then_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cx, "DISCOVERY_PRIORITY_RANGES", ((0x0100, 0x0101),))
    monkeypatch.setattr(cx, "DISCOVERY_FULL_RANGE", (0x0000, 0x0003))
    order = cx.discovery_did_order([(0x0002, 0x0002)])
    assert order == [0x0002, 0x0100, 0x0101, 0x0000, 0x0001, 0x0003]


def test_discovery_did_order_excludes_vin_serial_and_standardized_ranges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cx, "DISCOVERY_PRIORITY_RANGES", ())
    monkeypatch.setattr(cx, "DISCOVERY_FULL_RANGE", (0x0000, 0x0000))
    order = cx.discovery_did_order([(0xF18B, 0xF18E), (0xF190, 0xF190), (0xF802, 0xF802)])
    assert 0xF18C not in order  # serial number
    assert 0xF190 not in order  # VIN
    assert 0xF802 not in order  # OBDonUDS VIN
    assert order == [0xF18B, 0xF18D, 0xF18E, 0x0000]

    monkeypatch.setattr(cx, "DISCOVERY_FULL_RANGE", (0xF400, 0xF810))
    order = cx.discovery_did_order([])
    assert all(did < 0xF400 or did > 0xF5FF for did in order)
    assert all(did < 0xF800 or did > 0xF8FF for did in order)


def test_build_record_modules_resumes_discovery_position_from_state() -> None:
    state = cx.RunState.new("vehicle", "fake")
    state.set_result("protocol", {"answered": [], "chosen": None})
    state.set_result("ecus11", {"710": {"response": "77A", "identify": {}}})
    state.save_discovery_state("ecus11:710", 3, ["1004"], ["1005"])

    modules = cx.build_record_modules(None, state)
    module = modules["ecus11:710"]
    assert module.position == 3
    assert module.discovered == {0x1004}
    assert module.conditional == {0x1005}


def test_motion_phase_rules() -> None:
    assert cx.motion_phase(None, None) == "moving"  # no speed source
    assert cx.motion_phase(None, 1.0) == "moving"  # last speed read failed
    assert cx.motion_phase(0, cx.RECORD_SPEED_MAX_AGE + 1) == "moving"  # stale
    assert cx.motion_phase(0, cx.RECORD_SPEED_MAX_AGE) == "stationary"  # fresh at the edge
    assert cx.motion_phase(0, 0.0) == "stationary"
    assert cx.motion_phase(5, 0.0) == "moving"


def test_decode_speed_from_mode01_and_obduds() -> None:
    mode01_ex = cx.Exchange("010D", "7E803410D1E", "OK", "", 0.0)
    assert cx.decode_speed("010D", mode01_ex, None) == 0x1E

    obduds_ex = cx.Exchange("22F40D", "18DAF1A00462F40D1E", "OK", "", 0.0)
    assert cx.decode_speed("22F40D", obduds_ex, "18DAF1A0") == 0x1E

    failed_ex = cx.Exchange("010D", "NO DATA", "NO DATA", "", 0.0)
    assert cx.decode_speed("010D", failed_ex, None) is None


def test_record_loop_discovers_while_stationary_pauses_while_moving_and_retries_conditional(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "DISCOVERY_PRIORITY_RANGES", ())
    monkeypatch.setattr(cx, "DISCOVERY_FULL_RANGE", (0x1000, 0x100B))
    monkeypatch.setattr(cx, "RECORD_DISCOVERY_BATCH", 2)
    # Large enough that it never elapses on its own during this test - speed
    # reads are instead forced on demand by setting next_due directly, so the
    # test doesn't race a real interval against fake-transport command overhead.
    monkeypatch.setattr(cx, "RECORD_SPEED_INTERVAL", 60.0)

    kmh = {"value": 0}
    did1005_attempts = {"n": 0}

    def hex_reply(header: str, message: bytes) -> bytes:
        data = bytes([len(message)]) + message
        return (header + data.hex().upper()).encode() + b"\r>"

    def responder(cmd: str) -> bytes:
        if cmd == "ATZ":
            return b"ELM327 v1.4\r>"
        if cmd == "010D":
            return hex_reply("7E8", bytes([0x41, 0x0D, kmh["value"]]))
        if cmd.startswith("AT"):
            return b"OK\r>"
        if cmd == "221004":
            return hex_reply("77A", bytes([0x62, 0x10, 0x04, 0xAA]))
        if cmd == "221005":
            did1005_attempts["n"] += 1
            if did1005_attempts["n"] == 1:
                return hex_reply("77A", bytes([0x7F, 0x22, 0x22]))
            return hex_reply("77A", bytes([0x62, 0x10, 0x05, 0xAA]))
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    state = cx.RunState.new("vehicle", "fake")
    state.set_result("protocol", {"answered": ["6"], "chosen": "6"})
    state.set_result("mode01", {"supported_pids": ["0D"]})
    state.set_result("ecus11", {"710": {"response": "77A", "identify": {}}})
    state.set_result("obduds", {})
    state_path = tmp_path / "state.json"
    state.save(state_path)

    async def scenario() -> None:
        async with cx.connect_adapter("fake", False, tmp_path / "capture.jsonl", "vehicle") as link:
            assert link is not None
            loop_state = cx.build_record_loop_state(None, state)

            # Stationary from the start: one tick reads speed, then the next
            # batches cover 0x1000-0x1007, including 0x1004 (OK) and 0x1005
            # (conditionsNotCorrect) together in the third batch.
            for _ in range(6):
                await cx.record_loop_tick(link, state, state_path, loop_state)

            position, discovered, conditional = state.discovery_state("ecus11:710")
            assert position == 8
            assert discovered == ["1004"]
            assert conditional == ["1005"]
            assert ("ecus11:710", "221004") in loop_state.by_key

            speed_key = ("mode01", "010D")

            # Moving: discovery must pause, position stays put. The speed read
            # is forced due right away rather than waiting out a real interval.
            kmh["value"] = 30
            loop_state.next_due[speed_key] = time.monotonic()
            await cx.record_loop_tick(link, state, state_path, loop_state)
            assert loop_state.phase == "moving"
            position, _, _ = state.discovery_state("ecus11:710")
            assert position == 8

            # Stationary again: the phase change retries the conditional DID,
            # which now succeeds, before discovery resumes at its old position.
            kmh["value"] = 0
            loop_state.next_due[speed_key] = time.monotonic()
            await cx.record_loop_tick(link, state, state_path, loop_state)
            assert loop_state.phase == "stationary"
            await cx.record_loop_tick(link, state, state_path, loop_state)
            position, discovered, conditional = state.discovery_state("ecus11:710")
            assert discovered == ["1004", "1005"]
            assert conditional == []
            assert position == 8  # the retry only drained the conditional queue

            for _ in range(4):
                await cx.record_loop_tick(link, state, state_path, loop_state)
            position, discovered, conditional = state.discovery_state("ecus11:710")
            assert position == 12
            assert discovered == ["1004", "1005"]
            assert conditional == []

    asyncio.run(scenario())
    assert state.finished is False
