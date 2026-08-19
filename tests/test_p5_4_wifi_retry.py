from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_CPP = REPO_ROOT / "src" / "main.cpp"


def _source() -> str:
    return MAIN_CPP.read_text(encoding="utf-8")


def _function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening_brace = source.index("{", start)
    depth = 0
    for index in range(opening_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("WIFI_ASSOCIATION_TIMEOUT_MS", 20000),
        ("WIFI_DISCONNECT_TIMEOUT_MS", 100),
        ("WIFI_RETRY_SETTLE_MS", 250),
    ],
)
def test_wifi_retry_timing_constants_are_explicit(name: str, value: int) -> None:
    source = _source()

    declarations = re.findall(
        rf"static\s+(?:const|constexpr)\s+uint32_t\s+{name}\s*=\s*(\d+)\s*;",
        source,
    )

    assert declarations == [str(value)]


def test_association_wait_is_wrap_safe_and_bounded_to_two_windows() -> None:
    source = _source()
    helper = _function(source, "static bool waitForWiFiAssociation(const char* window)")
    connect = _function(source, "static bool connectWiFi()")

    assert re.search(r"(?:const\s+)?uint32_t\s+\w+\s*=\s*millis\(\)\s*;", helper)
    assert re.search(
        r"while\s*\(\s*WiFi\.status\(\)\s*!=\s*WL_CONNECTED\s*&&\s*"
        r"millis\(\)\s*-\s*\w+\s*<\s*WIFI_ASSOCIATION_TIMEOUT_MS\s*\)",
        helper,
    )
    assert "delay(250)" in helper
    assert re.search(r"return\s+finalStatus\s*==\s*WL_CONNECTED\s*;", helper)
    assert connect.count("waitForWiFiAssociation(") == 2
    assert connect.count("while") == 1  # bounded STA-start preflight only
    assert "while (true)" not in connect
    assert "connectWiFi()" not in connect.removeprefix("static bool connectWiFi()")


def test_sta_preflight_and_credential_begin_remain_single_and_ordered() -> None:
    source = _source()
    connect = _function(source, "static bool connectWiFi()")

    mode = connect.index("WiFi.mode(WIFI_STA)")
    sleep = connect.index("WiFi.setSleep(false)")
    started = [match.start() for match in re.finditer(r"WiFi\.STA\.started\(\)", connect)]
    rf = connect.index("applyC3RfWorkaround()")
    begin = connect.index("WiFi.begin(ssid, pass)")
    first_wait = connect.index('waitForWiFiAssociation("first")')

    assert connect.count("WiFi.mode(WIFI_STA)") == 1
    assert connect.count("WiFi.setSleep(false)") == 1
    assert len(started) >= 2
    assert connect.count("applyC3RfWorkaround()") == 1
    assert source.count("WiFi.begin(ssid, pass)") == 1
    assert mode < sleep < min(started) < max(started) < rf < begin < first_wait
    assert re.search(
        r"WiFi\.begin\(ssid, pass\);\s*clearSensitiveString\(pw\);\s*"
        r"if\s*\(\s*waitForWiFiAssociation\(\"first\"\)\s*\)",
        connect,
    )


def test_retry_is_one_checked_disconnect_reconnect_cycle() -> None:
    source = _source()
    connect = _function(source, "static bool connectWiFi()")

    disconnect_calls = list(
        re.finditer(
            r"WiFi\.disconnect\(false, false, WIFI_DISCONNECT_TIMEOUT_MS\)",
            connect,
        )
    )
    reconnect_calls = list(re.finditer(r"WiFi\.reconnect\(\)", connect))
    waits = list(re.finditer(r"waitForWiFiAssociation\(", connect))
    settles = list(re.finditer(r"delay\(WIFI_RETRY_SETTLE_MS\)", connect))

    assert len(disconnect_calls) == 2
    assert len(reconnect_calls) == 1
    assert len(waits) == 2
    assert len(settles) == 3
    assert (
        waits[0].start()
        < disconnect_calls[0].start()
        < settles[0].start()
        < settles[1].start()
        < reconnect_calls[0].start()
        < waits[1].start()
        < disconnect_calls[1].start()
        < settles[2].start()
    )

    first_retry_region = connect[waits[0].end() : reconnect_calls[0].start()]
    assert re.search(
        r"(?:const\s+)?bool\s+(?P<result>\w+)\s*=\s*WiFi\.disconnect\("
        r"false, false, WIFI_DISCONNECT_TIMEOUT_MS\);.*?"
        r"if\s*\(\s*!\s*(?P=result)\s*\)\s*\{.*?"
        r"delay\(WIFI_RETRY_SETTLE_MS\);\s*return false;\s*\}",
        first_retry_region,
        re.DOTALL,
    )

    reconnect_region = connect[disconnect_calls[0].end() : waits[1].start()]
    assert re.search(
        r"const\s+bool\s+reconnectRequested\s*=\s*WiFi\.reconnect\(\);.*?"
        r"if\s*\(\s*!reconnectRequested\s*\)\s*"
        r"\{.*?return false;\s*\}",
        reconnect_region,
        re.DOTALL,
    )

    final_region = connect[waits[1].end() :]
    assert re.search(
        r"(?:const\s+)?bool\s+(?P<result>\w+)\s*=\s*WiFi\.disconnect\("
        r"false, false, WIFI_DISCONNECT_TIMEOUT_MS\);.*?"
        r"if\s*\(\s*!\s*(?P=result)\s*\)\s*\{.*?\}",
        final_region,
        re.DOTALL,
    )


def test_success_and_failure_paths_preserve_bounded_fallback() -> None:
    source = _source()
    connect = _function(source, "static bool connectWiFi()")
    setup = _function(source, "void setup()")

    waits = list(re.finditer(r"waitForWiFiAssociation\(", connect))
    reconnect = connect.index("WiFi.reconnect()")
    final_disconnect = connect.rindex(
        "WiFi.disconnect(false, false, WIFI_DISCONNECT_TIMEOUT_MS)"
    )

    for wait in waits:
        assert re.match(
            r"waitForWiFiAssociation\([^)]*\)\s*\)\s*"
            r"(?:\{\s*)?return true;",
            connect[wait.start() :],
            re.DOTALL,
        )
    assert waits[0].start() < reconnect < waits[1].start()
    assert final_disconnect > waits[1].start()
    assert re.search(
        r"delay\(WIFI_RETRY_SETTLE_MS\);\s*return false;\s*\}", connect
    )
    assert "const bool setupWifiConnected = connectWiFi()" in setup
    assert "runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED" in setup


def test_preflight_failures_and_missing_credentials_cannot_enter_retry() -> None:
    connect = _function(_source(), "static bool connectWiFi()")
    begin = connect.index("WiFi.begin(ssid, pass)")
    reconnect = connect.index("WiFi.reconnect()")

    missing_credentials = re.search(
        r"if\s*\(\s*!ssid.*?YOUR_WIFI_SSID.*?"
        r"return false;[^\r\n]*(?:\r?\n)\s*\}",
        connect,
        re.DOTALL,
    )
    sta_guard = re.search(
        r"if\s*\(\s*!staModeOk\s*\|\|\s*!WiFi\.STA\.started\(\)\s*\)\s*"
        r"\{.*?return false;\s*\}",
        connect,
        re.DOTALL,
    )
    rf_guard = re.search(
        r"const\s+bool\s+staRfWorkaroundOk\s*=\s*applyC3RfWorkaround\(\);.*?"
        r"if\s*\(\s*!staRfWorkaroundOk\s*\)\s*"
        r"\{.*?return false;\s*\}",
        connect,
        re.DOTALL,
    )

    assert missing_credentials is not None
    assert sta_guard is not None
    assert rf_guard is not None
    assert missing_credentials.end() < sta_guard.start() < sta_guard.end()
    assert sta_guard.end() < rf_guard.start() < rf_guard.end() < begin < reconnect


def test_wifi_driver_persistence_is_disabled_before_every_initial_path() -> None:
    source = _source()
    setup = _function(source, "void setup()")

    assert source.count("WiFi.persistent(false)") == 1
    assert "WiFi.persistent(true)" not in source
    persistent = setup.index("WiFi.persistent(false)")
    admin_gate = setup.index("if (!hasAdminVerifier())")
    connect_gate = setup.index("const bool setupWifiConnected = connectWiFi()")
    assert persistent < admin_gate < connect_gate


def test_retry_adds_no_persistent_writes_callbacks_or_secret_logging() -> None:
    source = _source()
    connect = _function(source, "static bool connectWiFi()")

    assert 'prefs.begin("wifi", true)' in connect
    assert not re.search(r"prefs\.(?:put|clear|remove)", connect)
    assert "WiFi.onEvent(" not in connect
    assert "ESP.restart(" not in connect
    assert "WiFi.mode(WIFI_OFF)" not in connect
    assert connect.count("WiFi.mode(WIFI_STA)") == 1
    assert not re.search(r"Serial\.printf\([^;\n]*pw\.c_str\(\)", connect)
    assert not re.search(r"Serial\.printf\([^;\n]*pass\s*=%s[^;\n]*pw", connect)
