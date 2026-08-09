from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = tuple(
    sorted(
        path
        for path in (REPO_ROOT / "src").rglob("*")
        if path.suffix.lower()
        in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".ino"}
    )
)
INSTALLER_ROOTS = (REPO_ROOT / "docs", REPO_ROOT / "netshield-mini")
# Canonical bytes of Git blob af008e244e0b9cf4c77620742fb165fb9a82af97,
# approved at the P5.1 baseline a282e56.
PARTITIONS_CANONICAL_SHA256 = (
    "085d06a258ab0c39018d973bf9d4fca5f4fb365f773a69200ba71eed8cdc8ee5"
)
LEGACY_ARTIFACT_SHA256 = {
    "bootloader.bin": "e6397e68487ada6e81a273c4b24966418ef6cbf389bae7801363c97ddcbdaeb9",
    "partitions.bin": "d847f381bacdd34ee76954807dda999f1e92d83df521f8afc9561e445562b17e",
    "boot_app0.bin": "f94c5d786a7a8fab06ac5d10e33bf37711a6697636dc037559ea19cc410a17f0",
    "firmware.bin": "25ff30d749091a77ea44c6a7c8a36d76bee83e11a9de23a4385416dff10f1e90",
    "littlefs.bin": "88b84406092cd994662f6ccf008076ac88e99c56a5481b22ae0f0c7f2e6a2d4e",
}


def source_text() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in SOURCE_FILES)


@pytest.mark.parametrize(
    ("pattern", "description"),
    [
        (r'#\s*include\s*[<"]ArduinoOTA\.h[>"]', "ArduinoOTA header"),
        (r"ArduinoOTA", "ArduinoOTA API"),
        (r'#\s*include\s*[<"]Update\.h[>"]', "firmware Update header"),
        (
            r"\bUpdate\s*\.\s*(?:begin|write|end|abort|hasError|printError)\s*\(",
            "firmware Update API",
        ),
        (r"\bhandleFw(?:UpdateDone|Upload)\b", "firmware upload handler"),
        (r"\b(?:ESPhttpUpdate|HTTPUpdate)[A-Za-z0-9_]*\b", "alternate HTTP updater"),
        (r"\besp_(?:https_)?ota(?:_[A-Za-z0-9_]*)?\b", "ESP-IDF OTA API"),
        (r"\[fw-ota\]", "firmware OTA log marker"),
        (r'["\']/update["\']', "exact firmware update route literal"),
    ],
)
def test_firmware_source_has_no_network_firmware_ota(
    pattern: str, description: str
) -> None:
    assert re.search(pattern, source_text()) is None, description


def test_http_firmware_update_route_is_absent_but_blocklist_routes_remain() -> None:
    source = source_text()
    routes = set(re.findall(r'web\.on\(\s*"([^"]+)"', source))

    assert "/update" not in routes
    assert 'BLOCKLIST_UPLOAD_ROUTE = "/upload"' in source
    assert "web.addHandler(new BlocklistUploadRequestHandler())" in source
    assert {"/fetchnow", "/setupdate"}.isdisjoint(routes)


def test_dashboard_has_no_firmware_ota_controls() -> None:
    page = (REPO_ROOT / "src" / "page.h").read_text(encoding="utf-8").casefold()
    forbidden_patterns = (
        r"id\s*=\s*[\"']?fw(?:f|b|msg)\b",
        r"firmware\s*&mdash;\s*ota\s*update",
        r"flash\s+firmware",
        r"fetch\s*\(\s*[\"']/update[\"']",
        r"\.pio/build/c3/firmware\.bin",
    )

    assert not [pattern for pattern in forbidden_patterns if re.search(pattern, page)]


def test_readme_does_not_advertise_removed_firmware_update_paths() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8").casefold()

    assert "firmware updates over the network are disabled" in readme
    assert "legacy browser installers are disabled" in readme
    assert "--upload-protocol espota" not in readme
    assert "firmware → ota update" not in readme
    assert "one-click browser web-installer" not in readme


@pytest.mark.parametrize("installer_root", INSTALLER_ROOTS, ids=lambda path: path.name)
def test_legacy_web_installer_is_fail_closed(installer_root: Path) -> None:
    page = (installer_root / "index.html").read_text(encoding="utf-8").casefold()
    manifest = json.loads(
        (installer_root / "manifest.json").read_text(encoding="utf-8")
    )
    serialized_manifest = json.dumps(manifest).casefold()

    assert all(
        marker in page
        for marker in ("legacy", "deshabilitado", "inseguro", "no instalar")
    )
    assert not any(
        marker in page
        for marker in (
            "<script",
            "<button",
            "<esp-web-install-button",
            "manifest=",
            "esp-web-tools",
            "unpkg.com",
            ".bin",
        )
    )
    assert manifest.get("status") == "legacy-disabled"
    assert manifest.get("builds") == []
    assert '"path"' not in serialized_manifest
    assert ".bin" not in serialized_manifest
    assert "new_install_prompt_erase" not in manifest


@pytest.mark.parametrize("installer_root", INSTALLER_ROOTS, ids=lambda path: path.name)
def test_legacy_binary_artifacts_are_preserved_unmodified(
    installer_root: Path,
) -> None:
    actual = {
        name: hashlib.sha256((installer_root / name).read_bytes()).hexdigest()
        for name in LEGACY_ARTIFACT_SHA256
    }

    assert actual == LEGACY_ARTIFACT_SHA256


def test_partitions_csv_is_byte_for_byte_p5_1_baseline() -> None:
    blob = subprocess.run(
        ["git", "cat-file", "blob", "HEAD:partitions.csv"],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    digest = hashlib.sha256(blob).hexdigest()

    assert digest == PARTITIONS_CANONICAL_SHA256


def test_c3_rf_workaround_is_minimal_and_has_two_call_sites() -> None:
    source = (REPO_ROOT / "src" / "main.cpp").read_text(encoding="utf-8")
    helper = re.search(
        r"static bool applyC3RfWorkaround\(\)\s*\{\s*"
        r"return WiFi\.setTxPower\(WIFI_POWER_8_5dBm\);\s*\}",
        source,
    )

    assert helper is not None
    calls = list(re.finditer(r"\bapplyC3RfWorkaround\(\)", source))
    call_sites = [match for match in calls if not helper.start() <= match.start() < helper.end()]
    assert len(call_sites) == 2
    assert source.count("WiFi.setTxPower(") == 1
    assert source.count("WiFi.getTxPower(") == 0
    assert source.count("esp_wifi_get_max_tx_power(") == 0
    assert source.count("WiFi.setSleep(false)") == 1

    forbidden_rf_changes = (
        "esp_wifi_set_max_tx_power(",
        "esp_wifi_set_protocol(",
        "esp_wifi_set_bandwidth(",
        "esp_wifi_set_country(",
        "esp_wifi_set_ps(",
        "esp_wifi_set_config(",
        "esp_wifi_set_channel(",
        "WiFi.setProtocol(",
        "WiFi.setBandwidth(",
        "WiFi.setBandWidth(",
        "WiFi.setCountry(",
        "WiFi.setChannel(",
        "WiFi.softAPConfig(",
        "pmf_cfg",
        "ampdu",
    )
    assert not [change for change in forbidden_rf_changes if change in source]


def test_sta_rf_workaround_precedes_the_only_credential_bearing_begin() -> None:
    source = (REPO_ROOT / "src" / "main.cpp").read_text(encoding="utf-8")
    connect = source.split("static bool connectWiFi()", 1)[1].split(
        "static void handlePortalRoot", 1
    )[0]

    mode_index = connect.index("WiFi.mode(WIFI_STA)")
    started_checks = [
        match.start() for match in re.finditer(r"WiFi\.STA\.started\(\)", connect)
    ]
    helper_index = connect.index("applyC3RfWorkaround()")
    begin_index = connect.index("WiFi.begin(ssid, pass)")

    assert len(started_checks) >= 2
    assert mode_index < min(started_checks) < max(started_checks)
    assert max(started_checks) < helper_index < begin_index
    start_guard = re.search(
        r"if\s*\(\s*!staModeOk\s*\|\|\s*!WiFi\.STA\.started\(\)\s*\)\s*"
        r"\{.*?return false;\s*\}",
        connect,
        re.DOTALL,
    )
    power_guard = re.search(
        r"if\s*\(\s*!applyC3RfWorkaround\(\)\s*\)\s*"
        r"\{.*?return false;\s*\}",
        connect,
        re.DOTALL,
    )
    assert start_guard is not None
    assert power_guard is not None
    assert start_guard.end() < power_guard.start() < power_guard.end() < begin_index
    assert source.count("WiFi.begin(") == 1
    assert "esp_wifi_connect(" not in source
    assert connect.count("applyC3RfWorkaround()") == 1


def test_ap_rf_workaround_follows_successful_normal_open_softap() -> None:
    source = (REPO_ROOT / "src" / "main.cpp").read_text(encoding="utf-8")
    portal = source.split("static void startConfigPortal", 1)[1].split(
        "void setup()", 1
    )[0]
    softap = re.search(
        r"(?:const\s+)?bool\s+(?P<result>[A-Za-z_]\w*)\s*=\s*"
        r"WiFi\.softAP\(ap\);",
        portal,
    )

    assert softap is not None
    assert '"C3-AdBlock-%02X%02X"' in portal
    assert portal.index("WiFi.mode(WIFI_AP)") < softap.start()
    guarded_helper = re.search(
        rf"if\s*\(\s*{re.escape(softap.group('result'))}\s*&&\s*"
        r"!applyC3RfWorkaround\(\)\s*\)",
        portal[softap.end() :],
    )
    assert guarded_helper is not None
    assert portal.count("WiFi.softAP(") == 1
    assert portal.count("applyC3RfWorkaround()") == 1
