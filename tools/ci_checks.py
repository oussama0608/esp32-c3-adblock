#!/usr/bin/env python3
"""Dependency-free repository and firmware checks used by CI."""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

APP_SLOT_BYTES = 1_376_256
EXPECTED_GIT_BLOBS = {
    "partitions.csv": "af008e244e0b9cf4c77620742fb165fb9a82af97",
    "LICENSE": "48f037bee127a92fbbc38a98fff7737ae0f2b8f0",
}
EXPECTED_ACTIONS = {
    "actions/checkout": "de0fac2e4500dabe0009e67214ff5f5447ce83dd",
    "actions/setup-python": "a309ff8b426b58ec0e2a45f0f869d46889d02405",
}
ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = Path(".github/workflows/ci.yml")

ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b(?:
        WIFI_(?:SSID|PASS(?:WORD)?)
        |SSID|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY
        |CLIENT[_-]?SECRET|AUTH[_-]?TOKEN|ACCESS[_-]?TOKEN|TOKEN|SECRET
    )\b
    [\"']?\s*[:=]\s*
    (?P<quote>[\"'])(?P<value>[^\"'\r\n]*)(?P=quote)
    """
)


class CheckError(RuntimeError):
    """Raised when a CI invariant does not hold."""


def _git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise CheckError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout


def _tracked_files(root: Path) -> list[str]:
    output = _git(root, "ls-files", "-z")
    return [item.decode("utf-8") for item in output.split(b"\0") if item]


def _git_blob(root: Path, relative_path: str) -> str:
    output = _git(
        root,
        "hash-object",
        f"--path={relative_path}",
        relative_path,
    )
    return output.decode("ascii").strip()


def _partition_sizes(root: Path) -> dict[str, int]:
    path = root / "partitions.csv"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise CheckError(f"cannot read partitions.csv: {error}") from error

    rows = csv.reader(line for line in lines if not line.lstrip().startswith("#"))
    sizes: dict[str, int] = {}
    for row in rows:
        if len(row) < 5:
            continue
        name = row[0].strip()
        if name not in {"app0", "app1"}:
            continue
        try:
            sizes[name] = int(row[4].strip(), 0)
        except ValueError as error:
            raise CheckError(f"invalid size for {name} in partitions.csv") from error

    if set(sizes) != {"app0", "app1"}:
        raise CheckError("partitions.csv must define app0 and app1")
    for name, size in sizes.items():
        if size != APP_SLOT_BYTES:
            raise CheckError(
                f"{name} is {size:,} bytes; expected {APP_SLOT_BYTES:,} bytes"
            )
    return sizes


def _secret_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    return (
        (
            "private key",
            re.compile(
                "-----BEGIN "
                + r"(?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            ),
        ),
        (
            "GitHub token",
            re.compile(
                r"\b(?:gh"
                + r"[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
            ),
        ),
        ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
        ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
        ("Stripe live key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
        ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[0-9A-Za-z_-]{20,}\b")),
    )


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().upper()
    if not normalized:
        return True
    if normalized.startswith(("YOUR_", "EXAMPLE_", "PLACEHOLDER", "REPLACE_")):
        return True
    return (
        (value.startswith("${") and value.endswith("}"))
        or (value.startswith("{{") and value.endswith("}}"))
        or (value.startswith("<") and value.endswith(">"))
    )


def _scan_tracked_secrets(root: Path, tracked_files: Sequence[str]) -> list[str]:
    findings: list[str] = []
    token_patterns = _secret_patterns()
    for relative_path in tracked_files:
        path = root / relative_path
        try:
            data = path.read_bytes()
        except OSError as error:
            raise CheckError(f"cannot read tracked file {relative_path}: {error}") from error
        if b"\0" in data:
            continue

        text = data.decode("utf-8", "replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            for name, pattern in token_patterns:
                if pattern.search(line):
                    findings.append(f"{relative_path}:{line_number}: possible {name}")

            for match in ASSIGNMENT_PATTERN.finditer(line):
                if not _is_placeholder(match.group("value")):
                    findings.append(
                        f"{relative_path}:{line_number}: possible literal secret assignment"
                    )
    return findings


def check_repository(root: Path = ROOT) -> None:
    """Check protected files and scan tracked text without printing values."""
    tracked_files = _tracked_files(root)
    tracked_casefold = {path.casefold() for path in tracked_files}

    for relative_path, expected_blob in EXPECTED_GIT_BLOBS.items():
        if relative_path not in tracked_files:
            raise CheckError(f"required tracked file is missing: {relative_path}")
        actual_blob = _git_blob(root, relative_path)
        if actual_blob != expected_blob:
            raise CheckError(
                f"unexpected content in {relative_path}: "
                f"Git blob {actual_blob}, expected {expected_blob}"
            )
        print(f"{relative_path} Git blob: {actual_blob}")

    license_path = root / "LICENSE"
    if not license_path.is_file() or license_path.stat().st_size == 0:
        raise CheckError("LICENSE must exist and be non-empty")
    if "src/secrets.h" in tracked_casefold:
        raise CheckError("src/secrets.h must never be tracked")

    sizes = _partition_sizes(root)
    print(f"app0 slot: {sizes['app0']:,} bytes")
    print(f"app1 slot: {sizes['app1']:,} bytes")
    print("src/secrets.h tracked: no")

    findings = _scan_tracked_secrets(root, tracked_files)
    if findings:
        detail = "\n".join(findings)
        raise CheckError(f"possible secrets found:\n{detail}")
    print(f"tracked secret scan: OK ({len(tracked_files)} files)")

    _git(root, "diff", "--exit-code", "--", "partitions.csv", "LICENSE")
    print("protected working-tree files: unchanged")


def check_workflow(root: Path = ROOT) -> None:
    """Inspect the committed workflow policy without a YAML dependency."""
    path = root / WORKFLOW_PATH
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise CheckError(f"cannot read {WORKFLOW_PATH}: {error}") from error

    if "\t" in text:
        raise CheckError("workflow YAML must not contain tab characters")
    trigger_block = """on:
  push:
    branches:
      - main
      - develop
  pull_request:
    branches:
      - main
      - develop
  workflow_dispatch:
"""
    if trigger_block not in text:
        raise CheckError("workflow triggers differ from the approved branch policy")
    if text.count("permissions:") != 1 or "permissions:\n  contents: read\n" not in text:
        raise CheckError("workflow must grant only top-level contents: read")
    if re.search(r"(?m)^\s+[a-z-]+:\s+write\s*$", text):
        raise CheckError("workflow must not grant write permissions")

    raw_uses = re.findall(r"(?m)^\s*uses:\s*(\S+)", text)
    parsed_uses: list[tuple[str, str]] = []
    for reference in raw_uses:
        match = re.fullmatch(r"([^@\s]+)@([0-9a-f]{40})", reference)
        if match is None:
            raise CheckError(f"Action is not pinned to a full SHA: {reference}")
        parsed_uses.append((match.group(1), match.group(2)))

    if not parsed_uses:
        raise CheckError("workflow contains no Actions")
    for action, revision in parsed_uses:
        expected_revision = EXPECTED_ACTIONS.get(action)
        if expected_revision is None:
            raise CheckError(f"unapproved Action: {action}")
        if revision != expected_revision:
            raise CheckError(
                f"unexpected revision for {action}: {revision}; "
                f"expected {expected_revision}"
            )

    required_fragments = (
        "  python-quality:\n",
        "  firmware-build:\n",
        "runs-on: windows-2022",
        'python-version: "3.13.12"',
        "pytest==9.1.1",
        "ruff==0.16.0",
        "platformio==6.1.19",
        "PLATFORMIO_CORE_DIR:",
        "tests/fixtures/domains.txt",
        "tests/fixtures/hosts.txt",
        "pio run",
        "tools/ci_checks.py firmware",
        "persist-credentials: false",
    )
    for fragment in required_fragments:
        if fragment not in text:
            raise CheckError(f"workflow is missing required fragment: {fragment}")

    forbidden_fragments = (
        "pull_request_target",
        "actions/cache@",
        "upload-artifact",
        "download-artifact",
        "pio run --target upload",
        "pio device monitor",
        "secrets" + ".",
    )
    for fragment in forbidden_fragments:
        if fragment in text:
            raise CheckError(f"workflow contains forbidden fragment: {fragment}")

    print(f"workflow structure: OK ({len(parsed_uses)} pinned Action references)")
    for action, revision in sorted(set(parsed_uses)):
        print(f"{action}@{revision}")


def check_firmware(firmware: Path, root: Path = ROOT) -> None:
    """Fail when the real firmware binary is larger than either app slot."""
    path = firmware if firmware.is_absolute() else root / firmware
    if not path.is_file():
        raise CheckError(f"firmware binary is missing: {firmware}")

    _partition_sizes(root)
    used = path.stat().st_size
    free = APP_SLOT_BYTES - used
    percent = used / APP_SLOT_BYTES * 100
    print(f"firmware.bin used: {used:,} bytes")
    print(f"app slot size    : {APP_SLOT_BYTES:,} bytes")
    print(f"app slot free    : {free:,} bytes ({free / 1024:.2f} KiB)")
    print(f"app slot usage   : {percent:.2f}%")
    if used > APP_SLOT_BYTES:
        raise CheckError(
            f"firmware.bin exceeds the physical app slot by {-free:,} bytes"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("repository", help="check repository invariants")
    subparsers.add_parser("workflow", help="inspect the CI workflow policy")
    firmware = subparsers.add_parser("firmware", help="check firmware.bin size")
    firmware.add_argument("path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the selected CI check and return its process status."""
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "repository":
            check_repository()
        elif arguments.command == "workflow":
            check_workflow()
        else:
            check_firmware(arguments.path)
    except CheckError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
