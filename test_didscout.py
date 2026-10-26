from __future__ import annotations

import asyncio
import gzip
import json
import shutil
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

import bleak
import pytest

import didscout as cx


class _IdleNoteReader:
    async def stop(self) -> None:
        pass


@pytest.fixture(autouse=True)
def _no_stdin_note_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    # pytest captures stdin, so a real reader thread would die on its first read;
    # tests that exercise notes patch start_note_reader themselves.
    monkeypatch.setattr(cx, "start_note_reader", lambda _record: _IdleNoteReader())


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
    assert profile.address_schemes == []


def test_profile_accepts_known_address_scheme(tmp_path: Path) -> None:
    text = VALID_PROFILE_TOML.replace(
        'protocol = "6"', 'protocol = "6"\naddress_schemes = ["vag-29bit"]'
    )
    profile = _load(tmp_path, text)
    assert profile.address_schemes == ["vag-29bit"]


def test_profile_rejects_unknown_address_scheme(tmp_path: Path) -> None:
    text = VALID_PROFILE_TOML.replace(
        'protocol = "6"', 'protocol = "6"\naddress_schemes = ["made-up-scheme"]'
    )
    with pytest.raises(cx.ProfileError):
        _load(tmp_path, text)


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


def test_profile_allows_unnamed_unverified_did(tmp_path: Path) -> None:
    text = VALID_PROFILE_TOML.replace('name = "test did"\n', "").replace(
        'status = "plausible"', 'status = "unverified"'
    )
    profile = _load(tmp_path, text)
    assert profile.modules[0].dids[0].name is None
    assert profile.modules[0].dids[0].status == "unverified"


def test_profile_rejects_unnamed_plausible_did(tmp_path: Path) -> None:
    text = VALID_PROFILE_TOML.replace('name = "test did"\n', "")
    with pytest.raises(cx.ProfileError):
        _load(tmp_path, text)


def test_module_protocol_override_allows_29bit_header_on_protocol_6_profile(
    tmp_path: Path,
) -> None:
    text = VALID_PROFILE_TOML.replace('request = "710"', 'request = "18DA10F1"\nprotocol = "7"')
    profile = _load(tmp_path, text)
    assert profile.protocol == "6"
    assert profile.modules[0].protocol == "7"
    assert cx.module_effective_protocol(profile.modules[0], profile.protocol) == "7"


def test_module_protocol_override_must_be_known_protocol(tmp_path: Path) -> None:
    text = VALID_PROFILE_TOML.replace('request = "710"', 'request = "710"\nprotocol = "9"')
    with pytest.raises(cx.ProfileError):
        _load(tmp_path, text)


def test_module_without_protocol_override_uses_profile_protocol() -> None:
    profile = cx.resolve_profile("vag-ppe")
    module = profile.modules[0]
    assert module.protocol is None
    assert cx.module_effective_protocol(module, profile.protocol) == profile.protocol


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


def test_probe_stage_e_sends_atsp_on_module_protocol_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    profile_path = tmp_path / "mixed.toml"
    profile_path.write_text(
        """
        schema = 1
        id = "mixed"
        name = "Mixed protocol profile"
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

        [[modules.dids]]
        did = "2AB6"
        name = "range remaining"
        status = "validated"
        poll = "once"

        [[modules]]
        id = "obdonuds-ecu"
        request = "18DA10F1"
        response = "18DAF110"
        protocol = "7"

        [[modules.dids]]
        did = "F400"
        name = "support bitmap"
        status = "unverified"
        poll = "once"
        """
    )
    profile = cx.load_profile(profile_path)

    sent: list[str] = []

    def responder(cmd: str) -> bytes:
        sent.append(cmd)
        if cmd == "ATZ":
            return b"ELM327 v1.4\r>"
        return b"OK\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    class FakeNoteReader:
        async def stop(self) -> None:
            pass

    monkeypatch.setattr(cx, "start_note_reader", lambda _record: FakeNoteReader())

    result = asyncio.run(cx.probe("fake", "E", "test", tmp_path, False, profile=profile))
    assert result == 0
    assert sent.index("ATSP6") < sent.index("ATSH710") < sent.index("ATSP7")
    assert sent.index("ATSP7") < sent.index("ATSH18DA10F1")


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
        link = cx.AdapterLink(
            session, lambda ex, stage, module=None: logged.append((ex.command, stage))
        )

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
        link = cx.AdapterLink(session, lambda ex, stage, module=None: None)

        with pytest.raises(cx.ProbeAbortedError):
            await link.execute("ATE0", "setup")

    asyncio.run(scenario())


def test_adapter_link_execute_fails_closed_on_unusable_session() -> None:
    async def scenario() -> None:
        async def write(_data: bytes) -> None:
            raise OSError("synthetic disconnect")

        session = cx.ElmSession(write, 20)
        link = cx.AdapterLink(session, lambda ex, stage, module=None: None)

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


def test_check_ecus29_allowed_is_read_only_and_four_dids_only() -> None:
    allowed = (
        "ATSP7",
        "ATAR",
        "ATSH18DA10F1",
        "ATCRA18DAF110",
        "ATFCSH18DA10F1",
        "22F187",
        "22F189",
        "22F191",
        "22F197",
    )
    assert [cx.check_ecus29_allowed(cmd) for cmd in allowed] == list(allowed)
    for cmd in ("22F18C", "22F190", "22F802", "ATSH17FC0010", "ATCRA17FE0010", "2EF44900"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_ecus29_allowed(cmd)


def test_check_vag29_allowed_accepts_only_vag_headers_and_read_dids() -> None:
    allowed = ("ATSP7", "ATAR", "ATSH17FC0010", "ATFCSH17FC0010", "ATCRA17FE0010", "222AB8")
    assert [cx.check_vag29_allowed(cmd) for cmd in allowed] == list(allowed)
    for cmd in ("22F190", "22F802", "ATSH18DA10F1", "ATCRA18DAF110", "2EF44900"):
        with pytest.raises(cx.ForbiddenCommandError):
            cx.check_vag29_allowed(cmd)


def test_vag_headers_are_rejected_by_every_other_validator() -> None:
    for validator in (
        cx.check_allowed,
        cx.check_sweep_allowed,
        cx.check_ecus11_allowed,
        cx.check_ecus29_allowed,
        cx.check_identify_allowed,
        cx.check_obduds_allowed,
        cx.check_mode01_allowed,
    ):
        for cmd in ("ATSH17FC0010", "ATFCSH17FC0010", "ATCRA17FE0010"):
            with pytest.raises(cx.ForbiddenCommandError):
                validator(cmd)


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
    assert calls == ["protocol", "mode01", "obduds", "ecus11", "ecus29"]
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

    async def fake_ecus29(_link: object, state: cx.RunState, _profile: object) -> None:
        calls.append("ecus29")
        state.set_result("ecus29", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": fake_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
            "ecus29": fake_ecus29,
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
    assert calls == ["adapter", "protocol", "protocol", "mode01", "obduds", "ecus11", "ecus29"]

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

    async def fake_ecus29(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus29", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": failing_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
            "ecus29": fake_ecus29,
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


def test_ecus29_discovery_finds_fake_ecu_and_ignores_silence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "ECU29_IDS", ["0F", "10", "11"])
    current_header: dict[str, str] = {"value": ""}

    def hex_reply(header: str, message: bytes) -> bytes:
        data = bytes([len(message)]) + message
        return (header + data.hex().upper()).encode() + b"\r>"

    identify_payloads = {
        "F187": b"\x62\xf1\x87\x01",
        "F189": b"\x62\xf1\x89\x01",
        "F191": b"\x62\xf1\x91\x01",
        "F197": b"\x62\xf1\x97test",
    }

    def responder(cmd: str) -> bytes:
        if cmd.startswith("ATSH"):
            current_header["value"] = cmd[4:]
            return b"OK\r>"
        if cmd.startswith("AT"):
            return b"OK\r>"
        if current_header["value"] == "18DA10F1" and cmd[2:] in identify_payloads:
            return hex_reply("18DAF110", identify_payloads[cmd[2:]])
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    async def scenario() -> cx.RunState:
        state = cx.RunState.new("vehicle", "fake")
        state.set_result("obduds", {})
        async with cx.connect_adapter("fake", False, tmp_path / "ecus29.jsonl", "vehicle") as link:
            assert link is not None
            await cx._inventory_ecus29(link, state, None)
        return state

    state = asyncio.run(scenario())
    ecus29 = state.result("ecus29")
    assert isinstance(ecus29, dict)
    assert set(ecus29) == {"10"}  # 0F and 11 stayed silent
    assert ecus29["10"]["response"] == "18DAF110"
    assert ecus29["10"]["identify"]["F189"] == "OK"
    # No profile given: the VAG scheme never ran at all.
    assert state.result("vag29") is None


def test_ecus29_vag_scheme_runs_only_when_profile_opts_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "ECU29_IDS", [])
    monkeypatch.setattr(cx, "VAG29_IDS", ["05"])
    current_header: dict[str, str] = {"value": ""}

    def hex_reply(header: str, message: bytes) -> bytes:
        data = bytes([len(message)]) + message
        return (header + data.hex().upper()).encode() + b"\r>"

    def responder(cmd: str) -> bytes:
        if cmd.startswith("ATSH"):
            current_header["value"] = cmd[4:]
            return b"OK\r>"
        if cmd.startswith("AT"):
            return b"OK\r>"
        if current_header["value"] == "17FC0005" and cmd == "22F189":
            return hex_reply("17FE0005", b"\x62\xf1\x89\x01")
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    async def scenario(profile: cx.Profile | None) -> cx.RunState:
        state = cx.RunState.new("vehicle", "fake")
        state.set_result("obduds", {})
        async with cx.connect_adapter("fake", False, tmp_path / "vag29.jsonl", "vehicle") as link:
            assert link is not None
            await cx._inventory_ecus29(link, state, profile)
        return state

    assert asyncio.run(scenario(None)).result("vag29") is None

    profile = cx.Profile(
        schema=1,
        id="p",
        name="n",
        description="d",
        protocol="7",
        vehicles=["v"],
        sources=[],
        modules=[],
        address_schemes=["vag-29bit"],
    )
    vag29 = asyncio.run(scenario(profile)).result("vag29")
    assert isinstance(vag29, dict)
    assert set(vag29) == {"05"}
    assert vag29["05"]["response"] == "17FE0005"
    assert vag29["05"]["identify"]["F189"] == "OK"


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


def _ok_ex(response: str) -> cx.Exchange:
    return cx.Exchange("22AB", response, "OK", "", 0.0)


def _result_dict(state: cx.RunState, key: str) -> dict[str, object]:
    result = state.result(key)
    assert isinstance(result, dict)
    return result


def test_adaptive_backoff_doubles_after_three_unchanged_caps_and_resets() -> None:
    key = ("m", "22AB")
    entry = cx.RecordWatch("m", "22AB", 10.0, "watch")
    loop_state = cx.RecordLoopState(modules={}, speed_key=None, by_key={key: entry}, next_due={})
    loop_state.watch_interval[key] = entry.base_interval

    cx._record_update_backoff(loop_state, key, entry, _ok_ex("same"))
    assert loop_state.watch_interval[key] == 10.0  # first read just establishes the baseline

    for _ in range(2):
        cx._record_update_backoff(loop_state, key, entry, _ok_ex("same"))
    assert loop_state.watch_interval[key] == 10.0  # only 2 consecutive unchanged reads so far

    cx._record_update_backoff(loop_state, key, entry, _ok_ex("same"))
    assert loop_state.watch_interval[key] == 20.0  # 3rd consecutive unchanged read: doubled

    for _ in range(10):
        cx._record_update_backoff(loop_state, key, entry, _ok_ex("same"))
    assert loop_state.watch_interval[key] == cx.RECORD_WATCH_BACKOFF_CAP

    cx._record_update_backoff(loop_state, key, entry, _ok_ex("different"))
    assert loop_state.watch_interval[key] == 10.0  # any change resets to base
    assert loop_state.watch_unchanged[key] == 0

    for _ in range(3):
        cx._record_update_backoff(loop_state, key, entry, _ok_ex("different"))
    assert loop_state.watch_interval[key] == 20.0  # 3 consecutive unchanged reads again
    # a non-OK read is a change too, same as a different payload
    cx._record_update_backoff(
        loop_state, key, entry, cx.Exchange("22AB", "NO DATA", "NO DATA", "", 0.0)
    )
    assert loop_state.watch_interval[key] == 10.0


def test_phase_change_resets_watch_backoff_but_exempts_speed() -> None:
    speed_key = ("m", "010D")
    watch_key = ("m", "22AB")
    by_key = {
        speed_key: cx.RecordWatch("m", "010D", 5.0, "speed", True),
        watch_key: cx.RecordWatch("m", "22AB", 10.0, "watch"),
    }
    loop_state = cx.RecordLoopState(
        modules={},
        speed_key=speed_key,
        by_key=by_key,
        next_due={},
        watch_interval={speed_key: 40.0, watch_key: 80.0},
        watch_unchanged={watch_key: 5},
        speed_value=0,
        speed_fetched=time.monotonic(),
    )

    async def write(_data: bytes) -> None:
        pass

    link = cx.AdapterLink(cx.ElmSession(write, 20), lambda ex, stage, module=None: None)

    changed = cx._record_apply_phase(link, loop_state)  # moving (default) -> stationary
    assert changed is True
    assert loop_state.watch_interval[watch_key] == 10.0
    assert loop_state.watch_unchanged[watch_key] == 0
    assert loop_state.watch_interval[speed_key] == 40.0  # speed is exempt

    changed_again = cx._record_apply_phase(link, loop_state)
    assert changed_again is False  # no phase change this time


def test_watch_should_log_first_read_change_and_keepalive() -> None:
    key = ("m", "22AB")
    loop_state = cx.RecordLoopState(modules={}, speed_key=None, by_key={}, next_due={})

    ex1 = _ok_ex("resp1")
    assert cx._record_watch_should_log(loop_state, key, ex1, now=1000.0) is True

    loop_state.watch_last_logged[key] = ("OK", "resp1")
    loop_state.watch_last_log_time[key] = 1000.0

    # Unchanged, well before the keep-alive interval: not written.
    assert cx._record_watch_should_log(loop_state, key, ex1, now=1000.0 + 10.0) is False

    # A changed response is always written.
    ex2 = _ok_ex("resp2")
    assert cx._record_watch_should_log(loop_state, key, ex2, now=1000.0 + 10.0) is True

    # Unchanged, but the keep-alive interval has elapsed since the last
    # written entry.
    keepalive_due = 1000.0 + cx.RECORD_WATCH_KEEPALIVE_SECONDS
    assert cx._record_watch_should_log(loop_state, key, ex1, now=keepalive_due) is True


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
    # This test changes phase several times, each of which now triggers a
    # rediscovery scan - keep the candidate ranges tiny so it stays fast.
    monkeypatch.setattr(cx, "ECU11_REQUEST_IDS", [0x710])
    monkeypatch.setattr(cx, "ECU29_IDS", [])

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
    state.set_result("mode01", {"supported_pids": ["0D"], "protocol": "6"})
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

    entries = [json.loads(line) for line in (tmp_path / "capture.jsonl").read_text().splitlines()]
    discover_entries = [e for e in entries if e["stage"].startswith("discover-")]
    watch_entries = [e for e in entries if e["stage"] == "watch"]
    assert discover_entries and all(e["module"] == "ecus11:710" for e in discover_entries)
    assert watch_entries and all(e["module"] == "ecus11:710" for e in watch_entries)


def test_rediscovery_on_phase_change_adds_a_newly_awake_ecu(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "ECU11_REQUEST_IDS", [0x710, 0x720])
    monkeypatch.setattr(cx, "ECU29_IDS", [])
    monkeypatch.setattr(cx, "VAG29_IDS", [])

    current_header: dict[str, str] = {"value": ""}

    def hex_reply(header: str, message: bytes) -> bytes:
        data = bytes([len(message)]) + message
        return (header + data.hex().upper()).encode() + b"\r>"

    def responder(cmd: str) -> bytes:
        if cmd.startswith("ATSH"):
            current_header["value"] = cmd[4:]
            return b"OK\r>"
        if cmd == "010D":
            return hex_reply("7E8", bytes([0x41, 0x0D, 0x00]))
        if cmd.startswith("AT"):
            return b"OK\r>"
        if (
            current_header["value"] == "720"
            and cmd.startswith("22")
            and cmd[2:] in cx.IDENTIFY_DIDS
        ):
            return hex_reply("721", bytes([0x62, int(cmd[2:4], 16), int(cmd[4:6], 16), 0x01]))
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    state = cx.RunState.new("vehicle", "fake")
    state.set_result("protocol", {"answered": ["6"], "chosen": "6"})
    state.set_result("mode01", {"supported_pids": ["0D"], "protocol": "6"})
    state.set_result("ecus11", {})
    state.set_result("ecus29", {})
    state.set_result("obduds", {})
    state_path = tmp_path / "state.json"
    state.save(state_path)

    async def scenario() -> None:
        async with cx.connect_adapter("fake", False, tmp_path / "capture.jsonl", "vehicle") as link:
            assert link is not None
            loop_state = cx.build_record_loop_state(None, state)
            assert "ecus11:720" not in loop_state.modules

            # First tick: speed reads 0 km/h, a moving -> stationary phase
            # change, which triggers rediscovery right away.
            await cx.record_loop_tick(link, state, state_path, loop_state)
            assert loop_state.phase == "stationary"
            assert "ecus11:720" in loop_state.modules
            # The scans left the adapter's state unknown to the scheduler,
            # same as right after a reconnect.
            assert loop_state.current_module_key is None

    asyncio.run(scenario())

    ecus11 = state.result("ecus11")
    assert isinstance(ecus11, dict)
    assert set(ecus11) == {"720"}
    assert ecus11["720"]["response"] == "721"

    entries = [json.loads(line) for line in (tmp_path / "capture.jsonl").read_text().splitlines()]
    assert any(e["stage"].startswith("rediscover") for e in entries)


def test_rediscovery_every_30_min_stationary_skips_known_ecus(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "ECU11_REQUEST_IDS", [0x710, 0x720, 0x730])
    monkeypatch.setattr(cx, "ECU29_IDS", [])
    monkeypatch.setattr(cx, "VAG29_IDS", [])
    # Patched clock: rather than fake asyncio's own time source (which would
    # also freeze its internal command timeouts), the elapsed-time check is
    # driven by rewinding loop_state.last_rediscover directly below.
    monkeypatch.setattr(cx, "RECORD_REDISCOVER_INTERVAL", 50.0)

    current_header: dict[str, str] = {"value": ""}
    awake_730 = {"value": False}

    def hex_reply(header: str, message: bytes) -> bytes:
        data = bytes([len(message)]) + message
        return (header + data.hex().upper()).encode() + b"\r>"

    def responder(cmd: str) -> bytes:
        if cmd.startswith("ATSH"):
            current_header["value"] = cmd[4:]
            return b"OK\r>"
        if cmd == "010D":
            return hex_reply("7E8", bytes([0x41, 0x0D, 0x00]))
        if cmd.startswith("AT"):
            return b"OK\r>"
        header = current_header["value"]
        if (
            cmd.startswith("22")
            and cmd[2:] in cx.IDENTIFY_DIDS
            and (header == "720" or (header == "730" and awake_730["value"]))
        ):
            responder_header = "721" if header == "720" else "731"
            payload = bytes([0x62, int(cmd[2:4], 16), int(cmd[4:6], 16), 0x01])
            return hex_reply(responder_header, payload)
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    state = cx.RunState.new("vehicle", "fake")
    state.set_result("protocol", {"answered": ["6"], "chosen": "6"})
    state.set_result("mode01", {"supported_pids": ["0D"], "protocol": "6"})
    state.set_result("ecus11", {})
    state.set_result("ecus29", {})
    state.set_result("obduds", {})
    state_path = tmp_path / "state.json"
    state.save(state_path)

    async def scenario() -> None:
        async with cx.connect_adapter("fake", False, tmp_path / "capture.jsonl", "vehicle") as link:
            assert link is not None
            loop_state = cx.build_record_loop_state(None, state)
            speed_key = ("mode01", "010D")

            # Phase change moving -> stationary: first rediscovery, finds 720
            # only (730 isn't awake yet).
            await cx.record_loop_tick(link, state, state_path, loop_state)
            assert loop_state.phase == "stationary"
            assert set(_result_dict(state, "ecus11")) == {"720"}

            # 730 wakes up, but not enough time has passed yet: still
            # stationary, no phase change, interval not elapsed - skipped.
            awake_730["value"] = True
            loop_state.next_due[speed_key] = time.monotonic()
            await cx.record_loop_tick(link, state, state_path, loop_state)
            assert set(_result_dict(state, "ecus11")) == {"720"}

            # Now the interval has elapsed while remaining stationary:
            # rediscovery runs again, skips the already-known 720, and finds
            # the newly awake 730.
            loop_state.last_rediscover = time.monotonic() - cx.RECORD_REDISCOVER_INTERVAL - 1.0
            loop_state.next_due[speed_key] = time.monotonic()
            await cx.record_loop_tick(link, state, state_path, loop_state)
            assert set(_result_dict(state, "ecus11")) == {"720", "730"}
            assert "ecus11:730" in loop_state.modules

    asyncio.run(scenario())


def test_discovery_batch_writes_summary_and_only_interesting_entries(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "RECORD_DISCOVERY_BATCH", 4)

    def hex_reply(header: str, message: bytes) -> bytes:
        data = bytes([len(message)]) + message
        return (header + data.hex().upper()).encode() + b"\r>"

    def responder(cmd: str) -> bytes:
        if cmd.startswith("AT"):
            return b"OK\r>"
        if cmd == "221000":
            return hex_reply("77A", bytes([0x62, 0x10, 0x00, 0xAA]))
        if cmd == "221001":
            return b"NO DATA\r>"
        if cmd == "221002":
            return hex_reply("77A", bytes([0x7F, 0x22, 0x31]))  # NRC 31 requestOutOfRange
        if cmd == "221003":
            return hex_reply("77A", bytes([0x7F, 0x22, 0x22]))  # NRC 22 conditionsNotCorrect
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    module = cx.RecordModule(
        key="mod",
        protocol="6",
        setup=[],
        validator=cx.check_sweep_allowed,
        responder="77A",
        discover_ranges=[],
    )
    module.order = [0x1000, 0x1001, 0x1002, 0x1003]

    state = cx.RunState.new("vehicle", "fake")
    state_path = tmp_path / "state.json"
    state.save(state_path)

    async def scenario() -> list[int]:
        async with cx.connect_adapter("fake", False, tmp_path / "capture.jsonl", "vehicle") as link:
            assert link is not None
            return await cx.run_discovery_batch(link, module, state, state_path)

    newly_found = asyncio.run(scenario())
    assert newly_found == [0x1000]
    assert module.conditional == {0x1003}

    entries = [json.loads(line) for line in (tmp_path / "capture.jsonl").read_text().splitlines()]
    discover_entries = [e for e in entries if e["stage"] == "discover-mod"]

    summaries = [e for e in discover_entries if e["status"] == "SUMMARY"]
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["command"] == "BATCH 1000-1003"
    assert json.loads(summary["response"]) == {
        "OK": 1,
        "NO DATA": 1,
        "NRC 31 requestOutOfRange": 1,
        "NRC 22 conditionsNotCorrect": 1,
    }

    individual = [e for e in discover_entries if e["status"] != "SUMMARY"]
    assert {e["command"] for e in individual} == {"221000", "221003"}


def test_mode01_protocol_is_whichever_answered_mode01_not_the_profile(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sent: list[str] = []

    def responder(cmd: str) -> bytes:
        sent.append(cmd)
        if cmd.startswith("AT"):
            return b"OK\r>"
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    async def scenario() -> cx.RunState:
        state = cx.RunState.new("vehicle", "fake")
        # A profile pinned to protocol 6, but only 7 actually answered mode 01
        # in the `protocol` stage - mode 01 must still end up on 7.
        state.set_result("protocol", {"answered": ["7"], "chosen": "6"})
        async with cx.connect_adapter("fake", False, tmp_path / "mode01.jsonl", "vehicle") as link:
            assert link is not None
            await cx._inventory_mode01(link, state, None)
        return state

    state = asyncio.run(scenario())
    mode01 = state.result("mode01")
    assert isinstance(mode01, dict)
    assert mode01["protocol"] == "7"
    assert "ATSP7" in sent
    assert "ATSP6" not in sent


def test_check_mode01_watch_allowed_accepts_both_protocol_switches() -> None:
    assert cx.check_mode01_watch_allowed("ATSP6") == "ATSP6"
    assert cx.check_mode01_watch_allowed("ATSP7") == "ATSP7"


def test_record_loop_switches_protocol_between_modules_without_redundant_atsp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "DISCOVERY_PRIORITY_RANGES", ())
    monkeypatch.setattr(cx, "DISCOVERY_FULL_RANGE", (0x1000, 0x1003))
    monkeypatch.setattr(cx, "RECORD_DISCOVERY_BATCH", 2)
    # The speed source reads 0 km/h immediately, so the very first tick is
    # already a moving -> stationary phase change and would otherwise trigger
    # a full rediscovery scan here too - keep it a no-op for this test.
    monkeypatch.setattr(cx, "ECU11_REQUEST_IDS", [])
    monkeypatch.setattr(cx, "ECU29_IDS", [])

    fake_protocol = {"value": "6"}
    atsp_sent: list[str] = []

    def hex_reply(header: str, message: bytes) -> bytes:
        data = bytes([len(message)]) + message
        return (header + data.hex().upper()).encode() + b"\r>"

    def responder(cmd: str) -> bytes:
        if cmd == "ATZ":
            return b"ELM327 v1.4\r>"
        if cmd in ("ATSP6", "ATSP7"):
            atsp_sent.append(cmd)
            fake_protocol["value"] = cmd[-1]
            return b"OK\r>"
        if cmd.startswith("ATSH"):
            header = cmd[4:]
            # A strict vehicle: an 8-digit (29-bit) header only answers under
            # protocol 7, a 3-digit (11-bit) one only under protocol 6.
            if len(header) == 8 and fake_protocol["value"] != "7":
                return b"?\r>"
            if len(header) == 3 and fake_protocol["value"] != "6":
                return b"?\r>"
            return b"OK\r>"
        if cmd.startswith("AT"):
            return b"OK\r>"
        if cmd == "22F40D":
            return hex_reply("18DAF1A0", bytes([0x62, 0xF4, 0x0D, 0x00]))
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    state = cx.RunState.new("vehicle", "fake")
    state.set_result("protocol", {"answered": ["6", "7"], "chosen": "6"})
    state.set_result("mode01", {"supported_pids": [], "protocol": None})
    state.set_result(
        "ecus11",
        {
            "710": {"response": "77A", "identify": {}},
            "705": {"response": "77B", "identify": {}},
        },
    )
    state.set_result(
        "obduds", {"18DAF1A0": {"response": "18DAF1A0", "supported_dids": ["F40D"], "identify": {}}}
    )
    state_path = tmp_path / "state.json"
    state.save(state_path)

    async def scenario() -> None:
        async with cx.connect_adapter("fake", False, tmp_path / "capture.jsonl", "vehicle") as link:
            assert link is not None
            loop_state = cx.build_record_loop_state(None, state)

            # tick1: the speed source (obduds, protocol 7) - first switch ever,
            # so it's unconditional (current protocol starts unknown).
            await cx.record_loop_tick(link, state, state_path, loop_state)
            # tick2: discovery moves to ecus11:710 (protocol 6) - switches.
            await cx.record_loop_tick(link, state, state_path, loop_state)
            # tick3: still ecus11:710 (same module) - no setup, no ATSP at all.
            await cx.record_loop_tick(link, state, state_path, loop_state)
            # tick4: ecus11:705 - a different module, but still protocol 6 -
            # setup is resent (new header/filter), the protocol switch is not.
            await cx.record_loop_tick(link, state, state_path, loop_state)
            # tick5: still ecus11:705 - no setup, no ATSP.
            await cx.record_loop_tick(link, state, state_path, loop_state)
            # tick6: discovery moves to the obduds module (protocol 7) again.
            await cx.record_loop_tick(link, state, state_path, loop_state)

    asyncio.run(scenario())

    assert atsp_sent == ["ATSP7", "ATSP6", "ATSP7"]


def _hex_reply(header: str, message: bytes) -> str:
    data = bytes([len(message)]) + message
    return header + data.hex().upper()


def _capture_entry(
    base: datetime,
    t: float,
    stage: str,
    command: str,
    status: str,
    response: str,
    module: str | None = None,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "stage": stage,
        "state": "vehicle",
        "mtu": 23,
        "command": command,
        "response": response,
        "status": status,
        "started_utc": (base + timedelta(seconds=t)).isoformat(),
        "duration_ms": 10.0,
    }
    if module is not None:
        entry["module"] = module
    return entry


def _write_capture(run_dir: Path, entries: list[dict[str, object]]) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "capture.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")
    return path


def _synthetic_capture(base: datetime) -> list[dict[str, object]]:
    """A small, hand-built `record` capture exercising everything `derive`
    classifies: a constant DID, a fast-changing DID correlated with speed, a
    conditional-only DID, and a DID rising monotonically while stationary for
    over ten minutes."""
    entries = [
        _capture_entry(base, 0, "record-setup", "ATSH710", "OK", "OK"),
        _capture_entry(base, 0.5, "record-setup", "ATCRA77A", "OK", "OK"),
    ]
    t = 1.0
    for i in range(5):
        stage = "discover-profile:gateway" if i == 0 else "watch"
        entries.append(
            _capture_entry(
                base,
                t,
                stage,
                "222A10",
                "OK",
                _hex_reply("77A", bytes([0x62, 0x2A, 0x10, 0xAA])),
                "profile:gateway",
            )
        )
        t += 10
    for i in range(10):
        val = i * 5
        stage = "discover-profile:gateway" if i == 0 else "watch"
        entries.append(
            _capture_entry(
                base,
                t,
                stage,
                "222A20",
                "OK",
                _hex_reply("77A", bytes([0x62, 0x2A, 0x20, val])),
                "profile:gateway",
            )
        )
        t += 0.2
        entries.append(
            _capture_entry(
                base, t, "watch", "010D", "OK", _hex_reply("7E8", bytes([0x41, 0x0D, val]))
            )
        )
        t += 10
    entries.append(
        _capture_entry(
            base,
            t,
            "discover-profile:gateway",
            "222A30",
            "NRC 22 conditionsNotCorrect",
            _hex_reply("77A", bytes([0x7F, 0x22, 0x22])),
            "profile:gateway",
        )
    )
    t += 10
    entries.append(_capture_entry(base, t, "phase", "PHASE", "STATIONARY", "stationary"))
    t += 0.1
    for i in range(5):
        stage = "discover-profile:gateway" if i == 0 else "watch"
        entries.append(
            _capture_entry(
                base,
                t,
                stage,
                "222A40",
                "OK",
                _hex_reply("77A", bytes([0x62, 0x2A, 0x40, i * 10])),
                "profile:gateway",
            )
        )
        t += 700
    return entries


def test_derive_classifies_constant_and_changing_dids(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    _write_capture(run_dir, _synthetic_capture(base))

    profile_path, report_path = cx.derive(run_dir, vehicle="Test Car")
    assert profile_path is not None
    profile = cx.load_profile(profile_path)
    module = next(m for m in profile.modules if m.id == "ecu-710")
    by_did = {d.did: d for d in module.dids}
    assert by_did["2A10"].poll == "once"
    assert by_did["2A20"].poll == "watch"
    assert by_did["2A20"].interval == 15.0  # changes every ~10s, well under a minute
    assert by_did["2A40"].poll == "watch"
    assert by_did["2A40"].interval == 60.0  # changes every ~700s
    assert "2A30" not in by_did  # conditional-only, never positively read

    report = report_path.read_text()
    assert "2A30" in report and "conditional" in report
    assert "2A20" in report


def test_derive_ignores_batch_summary_entries(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    entries = _synthetic_capture(base)
    entries.append(
        _capture_entry(
            base,
            9999,
            "discover-profile:gateway",
            "BATCH 2A50-2A53",
            "SUMMARY",
            json.dumps({"NO DATA": 3, "OK": 1}),
            "profile:gateway",
        )
    )
    _write_capture(run_dir, entries)

    profile_path, _report_path = cx.derive(run_dir, vehicle="Test Car")
    assert profile_path is not None
    profile = cx.load_profile(profile_path)
    module = next(m for m in profile.modules if m.id == "ecu-710")
    by_did = {d.did: d for d in module.dids}
    # The summary itself never names a found DID and must not be mistaken
    # for one.
    assert "2A50" not in by_did
    assert by_did["2A20"].poll == "watch"


def test_derive_detects_speed_correlation_and_stationary_rise(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    _write_capture(run_dir, _synthetic_capture(base))

    _profile_path, report_path = cx.derive(run_dir, vehicle="Test Car")
    report = report_path.read_text()
    assert "Speed-correlated fields" in report
    assert "2A20" in report.split("Speed-correlated fields")[1].split("###")[0]
    assert "Stationary rise/fall" in report


def test_derive_writes_nothing_when_no_dids_were_discovered(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    entries = [
        _capture_entry(base, 0, "record-setup", "ATSH7DF", "OK", "OK"),
        _capture_entry(base, 1, "watch", "010D", "OK", _hex_reply("7E8", bytes([0x41, 0x0D, 0]))),
    ]
    _write_capture(run_dir, entries)

    profile_path, report_path = cx.derive(run_dir, vehicle="Test Car")
    assert profile_path is None
    assert report_path.exists()


def test_derive_rejects_capture_path_directly(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    capture_path = _write_capture(run_dir, _synthetic_capture(base))

    profile_path, report_path = cx.derive(capture_path, vehicle="Test Car")
    assert profile_path is not None
    assert report_path.parent == run_dir


def test_classify_note_marker_recognises_english_and_german() -> None:
    assert cx.classify_note_marker("starting to charge now") == "charge"
    assert cx.classify_note_marker("jetzt laden") == "charge"
    assert cx.classify_note_marker("im Leerlauf") == "idle"
    assert cx.classify_note_marker("Fahrt beginnt") == "drive"
    assert cx.classify_note_marker("parken") == "park"
    assert cx.classify_note_marker("odometer 12345") is None
    assert cx.classify_note_marker("idle but also driving") is None  # ambiguous


def test_share_redacts_identity_connection_and_non_marker_notes(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    entries = [
        _capture_entry(base, 0, "connection", "CONNECTION", "CONNECTED", ""),
        _capture_entry(base, 0.1, "adapter", "ATI", "RESPONSE", "OBDLink CX v4.3.1"),
        _capture_entry(base, 0.2, "identify-10", "22F189", "OK", "77A0462F18941"),
        _capture_entry(base, 0.3, "identify-10", "22F197", "OK", "77A0962F19754617465"),
        _capture_entry(base, 0.4, "display", "NOTE", "NOTE", "odometer reads 84213 km"),
        _capture_entry(base, 0.5, "display", "NOTE", "NOTE", "now charging at home"),
        _capture_entry(base, 0.6, "watch", "222A20", "OK", "77A04622A2005", "profile:gateway"),
    ]
    _write_capture(run_dir, entries)

    share_path = cx.share(run_dir, vehicle="Test Car")
    cx.validate_share(share_path)

    with gzip.open(share_path, "rt", encoding="utf-8") as handle:
        lines = [json.loads(line) for line in handle]

    header = lines[0]
    assert header == {"didscout_share": 1, "vehicle": "Test Car"}
    bodies = lines[1:]
    commands = [entry.get("command") for entry in bodies]
    assert "CONNECTION" not in commands
    assert "ATI" not in commands
    assert "NOTE" not in commands  # the odometer note is dropped entirely
    assert all("started_utc" not in e and "state" not in e and "mtu" not in e for e in bodies)

    f189_entry = next(e for e in bodies if e.get("command") == "22F189")
    assert "response" not in f189_entry and f189_entry["status"] == "OK"
    f197_entry = next(e for e in bodies if e.get("command") == "22F197")
    assert f197_entry["response"] == "77A0962F19754617465"  # F197 stays

    marker_entry = next(e for e in bodies if e.get("status") == "MARKER")
    assert marker_entry == {"t": 0.5, "stage": "phase", "status": "MARKER", "response": "charge"}


def test_share_drops_response_for_transport_failures(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    entries = [
        _capture_entry(
            base,
            0,
            "watch",
            "222A20",
            "TIMEOUT",
            "[TimeoutError] AA:BB:CC:DD:EE:FF did not respond",
            "profile:gateway",
        ),
        _capture_entry(
            base,
            1,
            "watch",
            "222A20",
            "TRANSPORT_ERROR",
            "[OSError] connection to AA:BB:CC:DD:EE:FF lost",
            "profile:gateway",
        ),
        _capture_entry(base, 2, "watch", "222A20", "OK", "77A04622A2005", "profile:gateway"),
    ]
    _write_capture(run_dir, entries)

    share_path = cx.share(run_dir, vehicle="Test Car")
    cx.validate_share(share_path)

    with gzip.open(share_path, "rt", encoding="utf-8") as handle:
        bodies = [json.loads(line) for line in handle][1:]

    timeout_entry = next(e for e in bodies if e["status"] == "TIMEOUT")
    transport_entry = next(e for e in bodies if e["status"] == "TRANSPORT_ERROR")
    ok_entry = next(e for e in bodies if e["status"] == "OK")
    assert "response" not in timeout_entry
    assert "response" not in transport_entry
    assert ok_entry["response"] == "77A04622A2005"


@pytest.mark.parametrize(
    ("name", "mutate"),
    [
        ("unknown_key", lambda e: {**e, "address": "AA:BB:CC:DD:EE:FF"}),
        ("raw_note", lambda e: {**e, "command": "NOTE", "response": "odometer 12345"}),
        (
            "identification_payload",
            lambda e: {**e, "command": "22F189", "response": "77A0462F18941"},
        ),
        (
            "non_marker_phase_status",
            lambda e: {**e, "stage": "phase", "status": "MARKER", "response": "lunch break"},
        ),
        ("absolute_timestamp", lambda e: {**e, "response": "2026-10-25T12:00:00+00:00"}),
        ("vin_like_string", lambda e: {**e, "response": "WVWZZZ1KZAW123456"}),
        ("mac_address_in_response", lambda e: {**e, "response": "seen near AA:BB:CC:DD:EE:FF"}),
        (
            "uuid_in_response",
            lambda e: {**e, "response": "adapter 12345678-1234-5678-1234-567812345678"},
        ),
        (
            "summary_bad_command",
            lambda e: {**e, "command": "BATCH abc", "status": "SUMMARY", "response": '{"OK": 1}'},
        ),
        (
            "summary_non_dict_response",
            lambda e: {
                **e,
                "command": "BATCH 1000-1003",
                "status": "SUMMARY",
                "response": "not json",
            },
        ),
        (
            "summary_non_int_value",
            lambda e: {
                **e,
                "command": "BATCH 1000-1003",
                "status": "SUMMARY",
                "response": '{"OK": "one"}',
            },
        ),
    ],
)
def test_validate_share_rejects_each_violation(
    tmp_path: Path, name: str, mutate: Callable[[dict[str, object]], dict[str, object]]
) -> None:
    base_entry = {
        "t": 1.0,
        "stage": "watch",
        "module": "profile:gateway",
        "command": "222A20",
        "status": "OK",
        "response": "77A04622A2005",
    }
    path = tmp_path / "broken.share.jsonl.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(json.dumps({"didscout_share": 1, "vehicle": "Test"}) + "\n")
        handle.write(json.dumps(mutate(base_entry)) + "\n")
    with pytest.raises(ValueError):
        cx.validate_share(path)


def test_validate_share_accepts_a_clean_file(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    _write_capture(run_dir, _synthetic_capture(base))
    share_path = cx.share(run_dir, vehicle="Test Car")
    cx.validate_share(share_path)  # must not raise


def test_share_and_validate_share_accept_batch_summary_entries(tmp_path: Path) -> None:
    base = datetime(2026, 10, 25, tzinfo=UTC)
    run_dir = tmp_path / "record_test"
    entries = [
        _capture_entry(
            base,
            0,
            "discover-profile:gateway",
            "BATCH 2A50-2A53",
            "SUMMARY",
            json.dumps({"NO DATA": 3, "OK": 1}),
            "profile:gateway",
        ),
    ]
    _write_capture(run_dir, entries)
    share_path = cx.share(run_dir, vehicle="Test Car")
    cx.validate_share(share_path)  # must not raise

    with gzip.open(share_path, "rt", encoding="utf-8") as handle:
        body = [json.loads(line) for line in handle][1]
    assert body["status"] == "SUMMARY"
    assert json.loads(body["response"]) == {"NO DATA": 3, "OK": 1}


@pytest.mark.parametrize(
    "path", sorted((Path(__file__).parent / "captures").glob("*.share.jsonl.gz"))
)
def test_contributed_captures_pass_validate_share(path: Path) -> None:
    cx.validate_share(path)


def test_record_ctrl_c_runs_derive_and_share_on_its_own_run_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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

    watched = asyncio.Event()

    def responder(cmd: str) -> bytes:
        if cmd == "ATZ":
            return b"ELM327 v1.4\r>"
        if cmd.startswith("AT"):
            return b"OK\r>"
        if cmd == "222AB6":
            watched.set()
            return b"77A04622AB6AA\r>"
        return b"NO DATA\r>"

    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(responder))

    async def fake_adapter(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("adapter", {})

    async def fake_protocol(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("protocol", {"answered": ["6"], "chosen": "6"})

    async def fake_mode01(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("mode01", {"supported_pids": [], "protocol": None})

    async def fake_obduds(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("obduds", {})

    async def fake_ecus11(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus11", {})

    async def fake_ecus29(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus29", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": fake_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
            "ecus29": fake_ecus29,
        },
    )

    calls: list[str] = []
    real_derive = cx.derive
    real_share = cx.share

    def tracking_derive(
        run_dir: Path,
        *,
        id_: str | None = None,
        vehicle: str | None = None,
        out: Path | None = None,
    ) -> tuple[Path | None, Path]:
        calls.append(f"derive:{run_dir.name}")
        return real_derive(run_dir, id_=id_, vehicle=vehicle, out=out)

    def tracking_share(
        run_dir: Path, *, vehicle: str | None = None, out: Path | None = None
    ) -> Path:
        calls.append(f"share:{run_dir.name}")
        return real_share(run_dir, vehicle=vehicle, out=out)

    monkeypatch.setattr(cx, "derive", tracking_derive)
    monkeypatch.setattr(cx, "share", tracking_share)

    async def scenario() -> int:
        task = asyncio.create_task(cx.record("fake", profile, "vehicle", tmp_path, True))
        await asyncio.wait_for(watched.wait(), 5.0)
        task.cancel()
        return await task

    result = asyncio.run(scenario())
    assert result == 130
    assert len(calls) == 2
    run_dir_name = next(tmp_path.glob("record_*_vehicle")).name
    assert calls == [f"derive:{run_dir_name}", f"share:{run_dir_name}"]

    run_dir = next(tmp_path.glob("record_*_vehicle"))
    assert (run_dir / "report.md").exists()


def test_record_note_sink_writes_display_entry_with_record_mode_shape(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.jsonl"
    sink = cx._record_note_sink(log_path, "vehicle")

    sink(cx.note_exchange("fahrt"), "display")

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["stage"] == "display"
    assert entry["state"] == "vehicle"
    assert entry["mtu"] is None
    assert entry["mode"] == "record"
    assert entry["command"] == "NOTE"
    assert entry["status"] == "NOTE"
    assert entry["response"] == "fahrt"


def test_record_starts_note_reader_once_across_reconnects_and_stops_on_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "RECORD_INITIAL_BACKOFF", 0.0)
    monkeypatch.setattr(cx, "RECORD_MAX_BACKOFF", 0.0)

    class FakeNoteReader:
        def __init__(self) -> None:
            self.stopped = False

        async def stop(self) -> None:
            self.stopped = True

    sinks: list[Callable[[cx.Exchange, str], None]] = []
    readers: list[FakeNoteReader] = []

    def fake_start_note_reader(record_fn: Callable[[cx.Exchange, str], None]) -> FakeNoteReader:
        sinks.append(record_fn)
        reader = FakeNoteReader()
        readers.append(reader)
        return reader

    monkeypatch.setattr(cx, "start_note_reader", fake_start_note_reader)

    protocol_attempts = {"n": 0}

    async def fake_adapter(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("adapter", {})

    async def fake_protocol(_link: object, state: cx.RunState, _profile: object) -> None:
        protocol_attempts["n"] += 1
        if protocol_attempts["n"] == 1:
            raise cx.ProbeAbortedError("synthetic transport error")
        state.set_result("protocol", {"answered": [], "chosen": None})

    async def fake_mode01(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("mode01", {"supported_pids": []})

    async def fake_obduds(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("obduds", {})

    async def fake_ecus11(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus11", {})

    async def fake_ecus29(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus29", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": fake_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
            "ecus29": fake_ecus29,
        },
    )

    async def fake_run_record_loop(
        _link: object, _state: object, _profile: object, _state_path: object
    ) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(cx, "run_record_loop", fake_run_record_loop)
    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(_ok_responder))

    result = asyncio.run(cx.record("fake", None, "vehicle", tmp_path, False, False))

    assert result == 130
    # One reconnect happened (the synthetic transport error), but the note
    # reader is started exactly once for the whole run, not once per connection.
    assert len(sinks) == 1
    assert readers[0].stopped is True

    run_dir = next(tmp_path.glob("record_*"))
    # The sink writes independent of any BLE connection, so it still works
    # after the run (and, by construction, while disconnected/reconnecting).
    sinks[0](cx.note_exchange("parken"), "display")
    note_entries = [
        json.loads(line)
        for line in (run_dir / "capture.jsonl").read_text().splitlines()
        if json.loads(line).get("command") == "NOTE"
    ]
    assert len(note_entries) == 1
    assert note_entries[0]["stage"] == "display"
    assert note_entries[0]["mode"] == "record"
    assert note_entries[0]["response"] == "parken"


def test_start_sleep_inhibit_spawns_expected_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeProc:
        def __init__(self) -> None:
            self.terminated = False

    spawned: dict[str, object] = {}

    def fake_popen(argv: list[str], **kwargs: object) -> FakeProc:
        spawned["argv"] = argv
        spawned["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/systemd-inhibit")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    log_path = tmp_path / "capture.jsonl"
    proc = cx._start_sleep_inhibit(log_path, "vehicle")

    assert isinstance(proc, FakeProc)
    assert spawned["argv"] == [
        "systemd-inhibit",
        "--what=sleep:idle:handle-lid-switch",
        "--who=didscout",
        "--why=recording vehicle data",
        "--mode=block",
        "cat",
    ]
    assert spawned["kwargs"] == {"stdin": subprocess.PIPE}

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(entries) == 1
    assert entries[0]["stage"] == "connection"
    assert entries[0]["command"] == "SLEEP_INHIBIT"
    assert entries[0]["status"] == "HELD"
    assert entries[0]["mode"] == "record"


def test_start_sleep_inhibit_missing_binary_warns_and_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)

    log_path = tmp_path / "capture.jsonl"
    proc = cx._start_sleep_inhibit(log_path, "vehicle")

    assert proc is None
    assert "systemd-inhibit" in capsys.readouterr().err

    entries = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert entries[0]["command"] == "SLEEP_INHIBIT"
    assert entries[0]["status"] == "UNAVAILABLE"


def test_stop_sleep_inhibit_closes_stdin_and_terminates(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeStdin:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProc:
        def __init__(self) -> None:
            self.stdin = FakeStdin()
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> None:
            pass

    proc = FakeProc()
    cx._stop_sleep_inhibit(proc)  # type: ignore[arg-type]
    assert proc.stdin.closed is True
    assert proc.terminated is True

    cx._stop_sleep_inhibit(None)  # must not raise


def test_record_no_inhibit_flag_spawns_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "RECORD_INITIAL_BACKOFF", 0.0)
    monkeypatch.setattr(cx, "RECORD_MAX_BACKOFF", 0.0)

    def fail_popen(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("--no-inhibit must never spawn a subprocess")

    monkeypatch.setattr(subprocess, "Popen", fail_popen)

    class FakeNoteReader:
        async def stop(self) -> None:
            pass

    monkeypatch.setattr(cx, "start_note_reader", lambda _record: FakeNoteReader())

    async def fake_adapter(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("adapter", {})

    async def fake_protocol(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("protocol", {"answered": [], "chosen": None})

    async def fake_mode01(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("mode01", {"supported_pids": []})

    async def fake_obduds(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("obduds", {})

    async def fake_ecus11(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus11", {})

    async def fake_ecus29(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus29", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": fake_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
            "ecus29": fake_ecus29,
        },
    )

    async def fake_run_record_loop(
        _link: object, _state: object, _profile: object, _state_path: object
    ) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(cx, "run_record_loop", fake_run_record_loop)
    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(_ok_responder))

    result = asyncio.run(cx.record("fake", None, "vehicle", tmp_path, False, False))
    assert result == 130

    run_dir = next(tmp_path.glob("record_*"))
    entries = [json.loads(line) for line in (run_dir / "capture.jsonl").read_text().splitlines()]
    assert not any(entry.get("command") == "SLEEP_INHIBIT" for entry in entries)


def test_record_terminates_inhibit_process_on_ctrl_c(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cx, "RECORD_INITIAL_BACKOFF", 0.0)
    monkeypatch.setattr(cx, "RECORD_MAX_BACKOFF", 0.0)

    class FakeStdin:
        def close(self) -> None:
            pass

    class FakeProc:
        def __init__(self) -> None:
            self.stdin = FakeStdin()
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> None:
            pass

    procs: list[FakeProc] = []

    def fake_popen(*_args: object, **_kwargs: object) -> FakeProc:
        proc = FakeProc()
        procs.append(proc)
        return proc

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/systemd-inhibit")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    class FakeNoteReader:
        async def stop(self) -> None:
            pass

    monkeypatch.setattr(cx, "start_note_reader", lambda _record: FakeNoteReader())

    async def fake_adapter(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("adapter", {})

    async def fake_protocol(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("protocol", {"answered": [], "chosen": None})

    async def fake_mode01(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("mode01", {"supported_pids": []})

    async def fake_obduds(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("obduds", {})

    async def fake_ecus11(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus11", {})

    async def fake_ecus29(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("ecus29", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": fake_protocol,
            "mode01": fake_mode01,
            "obduds": fake_obduds,
            "ecus11": fake_ecus11,
            "ecus29": fake_ecus29,
        },
    )

    async def fake_run_record_loop(
        _link: object, _state: object, _profile: object, _state_path: object
    ) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(cx, "run_record_loop", fake_run_record_loop)
    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(_ok_responder))

    result = asyncio.run(cx.record("fake", None, "vehicle", tmp_path, False, True))
    assert result == 130
    assert len(procs) == 1
    assert procs[0].terminated is True


def test_record_terminates_inhibit_process_on_unhandled_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class FakeStdin:
        def close(self) -> None:
            pass

    class FakeProc:
        def __init__(self) -> None:
            self.stdin = FakeStdin()
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float | None = None) -> None:
            pass

    procs: list[FakeProc] = []

    def fake_popen(*_args: object, **_kwargs: object) -> FakeProc:
        proc = FakeProc()
        procs.append(proc)
        return proc

    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/systemd-inhibit")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    class FakeNoteReader:
        async def stop(self) -> None:
            pass

    monkeypatch.setattr(cx, "start_note_reader", lambda _record: FakeNoteReader())

    async def failing_protocol(_link: object, _state: cx.RunState, _profile: object) -> None:
        raise cx.ProbeAbortedError("synthetic transport error")

    async def fake_adapter(_link: object, state: cx.RunState, _profile: object) -> None:
        state.set_result("adapter", {})

    monkeypatch.setattr(
        cx,
        "INVENTORY_STAGE_FUNCS",
        {
            "adapter": fake_adapter,
            "protocol": failing_protocol,
            "mode01": fake_adapter,
            "obduds": fake_adapter,
            "ecus11": fake_adapter,
            "ecus29": fake_adapter,
        },
    )
    monkeypatch.setattr(bleak, "BleakClient", _fake_record_client(_ok_responder))

    real_sleep = asyncio.sleep

    async def fake_sleep(seconds: float) -> None:
        # Only the reconnect backoff (RECORD_INITIAL_BACKOFF) simulates the
        # Ctrl-C that never reaches run_record_loop's own handling; every
        # other sleep (e.g. ElmSession.drain's 0.05s settle) must run for real
        # so the fake adapter traffic above it still completes.
        if seconds == cx.RECORD_INITIAL_BACKOFF:
            raise asyncio.CancelledError
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cx.record("fake", None, "vehicle", tmp_path, False, True))

    assert len(procs) == 1
    assert procs[0].terminated is True
