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
    routes = set(re.findall(r'web\.on\(\s*"([^"]+)"', source_text()))

    assert "/update" not in routes
    assert {"/upload", "/fetchnow", "/setupdate"} <= routes


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
