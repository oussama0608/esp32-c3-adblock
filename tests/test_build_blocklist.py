from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from tools import build_blocklist


def test_parse_simple_domain_fixture(fixtures_dir: Path) -> None:
    data = (fixtures_dir / "domains.txt").read_text(encoding="utf-8")

    assert build_blocklist.parse_domains(data) == {
        "duplicate.example",
        "edge.example",
        "example.com",
        "tracker.example",
        "wild.example",
    }


def test_parse_hosts_fixture(fixtures_dir: Path) -> None:
    data = (fixtures_dir / "hosts.txt").read_text(encoding="utf-8")

    assert build_blocklist.parse_domains(data) == {
        "ads.example",
        "duplicate.example",
        "telemetry.example",
    }


def test_parse_ignores_comments_and_blank_lines() -> None:
    data = "\n# comment\n! adblock comment\n/regexp/\nvalid.example # inline\n"

    assert build_blocklist.parse_domains(data) == {"valid.example"}


@pytest.mark.parametrize(
    ("raw_domain", "expected"),
    [
        ("Example.COM", "example.com"),
        (" .Edge.Example. ", "edge.example"),
        ("www.Tracker.Example", "tracker.example"),
        ("*.Wild.Example.", "wild.example"),
    ],
)
def test_normalization_policy(raw_domain: str, expected: str) -> None:
    assert build_blocklist.norm(raw_domain) == expected


def test_parse_deduplicates_after_normalization() -> None:
    data = "Duplicate.Example\nduplicate.example.\nwww.duplicate.example\n"

    assert build_blocklist.parse_domains(data) == {"duplicate.example"}


def test_invalid_fixture_is_rejected(fixtures_dir: Path) -> None:
    data = (fixtures_dir / "invalid_domains.txt").read_text(encoding="utf-8")

    assert build_blocklist.parse_domains(data) == set()


@pytest.mark.parametrize(
    "entry",
    [
        "localhost",
        "bad_label.example",
        "-leading.example",
        "trailing-.example",
        "double..dot.example",
        "café.example",
        "example.com unexpected-token",
        ".",
    ],
)
def test_invalid_domain_syntax_is_rejected(entry: str) -> None:
    assert build_blocklist.parse_domains(entry) == set()


def test_domain_length_boundary() -> None:
    valid = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
    too_long = f"{valid}e"

    assert len(valid) == 253
    assert len(too_long) == 254
    assert build_blocklist.is_valid_domain(valid)
    assert not build_blocklist.is_valid_domain(too_long)


def test_label_length_boundary() -> None:
    assert build_blocklist.is_valid_domain(f"{'a' * 63}.example")
    assert not build_blocklist.is_valid_domain(f"{'a' * 64}.example")


@pytest.mark.parametrize(
    "entry",
    [
        "0.0.0.0",
        "127.0.0.1",
        "192.0.2.1",
        "2001:db8::1",
        "0.0.0.0 127.0.0.1",
        "127.0.0.1 ::1",
    ],
)
def test_ip_literals_are_rejected(entry: str) -> None:
    assert build_blocklist.parse_domains(entry) == set()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"", 0xE484222325),
        (b"a", 0x4C8601EC8C),
        (b"foobar", 0x71F73967E8),
        (b"example.com", 0x634E2714C6),
    ],
)
def test_fnv40_known_vectors(value: bytes, expected: int) -> None:
    assert build_blocklist.fnv(value) == expected


def test_serialization_is_five_byte_little_endian() -> None:
    assert build_blocklist.serialize_hashes([0x0123456789]) == bytes.fromhex(
        "8967452301"
    )


def test_serialization_sorts_numerically() -> None:
    blob = build_blocklist.serialize_hashes([256, 1])
    values = [
        int.from_bytes(blob[offset : offset + build_blocklist.HASH_BYTES], "little")
        for offset in range(0, len(blob), build_blocklist.HASH_BYTES)
    ]

    assert values == [1, 256]


def test_duplicate_hashes_are_written_once() -> None:
    blob = build_blocklist.serialize_hashes([7, 7, 7])

    assert blob == b"\x07\x00\x00\x00\x00"


def test_duplicate_domains_are_not_reported_as_collisions() -> None:
    hashes, collisions = build_blocklist.hash_domains(
        ["same.example", "same.example"], hash_function=lambda _value: 9
    )

    assert hashes == [9]
    assert collisions == 0


def test_distinct_domain_hash_collision_is_detected() -> None:
    hashes, collisions = build_blocklist.hash_domains(
        ["first.example", "second.example"], hash_function=lambda _value: 9
    )

    assert hashes == [9]
    assert collisions == 1


def test_collision_is_reported_by_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "blocklist.bin"
    monkeypatch.setattr(
        build_blocklist,
        "read_source",
        lambda _source: "first.example\nsecond.example\n",
    )
    monkeypatch.setattr(build_blocklist, "fnv", lambda _value: 9)

    status = build_blocklist.main([str(output), "fixture"])

    assert status == 0
    assert output.read_bytes() == b"\x09\x00\x00\x00\x00"
    assert "collisions       : 1" in capsys.readouterr().out


def test_output_file_size_is_a_multiple_of_five(tmp_path: Path) -> None:
    output = tmp_path / "blocklist.bin"
    values = {
        b"first.example": 3,
        b"second.example": 1,
        b"third.example": 2,
    }

    result = build_blocklist.build_blocklist(
        output,
        ["fixture"],
        reader=lambda _source: "\n".join(value.decode() for value in values),
        hash_function=values.__getitem__,
    )

    assert result.size == 3 * build_blocklist.HASH_BYTES
    assert output.stat().st_size % build_blocklist.HASH_BYTES == 0


def test_validation_rejects_non_record_aligned_blob() -> None:
    with pytest.raises(build_blocklist.BlocklistError, match="multiple of 5"):
        build_blocklist.validate_blob(b"123456", 100)


def test_url_download_is_simulated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_urlopen(url: str, timeout: int) -> io.BytesIO:
        seen.update(url=url, timeout=timeout)
        return io.BytesIO(b"Downloaded.Example\n")

    monkeypatch.setattr(build_blocklist.urllib.request, "urlopen", fake_urlopen)

    data = build_blocklist.read_source("https://fixture.invalid/domains")

    assert data == "Downloaded.Example\n"
    assert seen == {"url": "https://fixture.invalid/domains", "timeout": 180}


def test_local_source_uses_fixture(fixtures_dir: Path) -> None:
    data = build_blocklist.read_source(str(fixtures_dir / "domains.txt"))

    assert "Example.COM" in data


def test_partial_source_failure_uses_successful_source(tmp_path: Path) -> None:
    output = tmp_path / "blocklist.bin"

    def reader(source: str) -> str:
        if source == "failed":
            raise OSError("fixture failure")
        return "valid.example\n"

    result = build_blocklist.build_blocklist(
        output,
        ["failed", "valid"],
        reader=reader,
    )

    assert result.source_domains == 1
    assert output.stat().st_size == build_blocklist.HASH_BYTES


@pytest.mark.parametrize("previous", [None, b"previous-valid-blocklist"])
def test_all_sources_failure_does_not_replace_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    previous: bytes | None,
) -> None:
    output = tmp_path / "blocklist.bin"
    if previous is not None:
        output.write_bytes(previous)

    def fail_source(_source: str) -> str:
        raise OSError("fixture source failed")

    monkeypatch.setattr(build_blocklist, "read_source", fail_source)

    status = build_blocklist.main([str(output), "first", "second"])

    assert status == 1
    assert output.exists() is (previous is not None)
    if previous is not None:
        assert output.read_bytes() == previous
    captured = capsys.readouterr()
    assert "all 2 blocklist sources failed" in captured.err
    assert not list(tmp_path.glob("*.tmp"))


def test_no_valid_domains_does_not_replace_output(tmp_path: Path) -> None:
    output = tmp_path / "blocklist.bin"
    previous = b"previous-valid-blocklist"
    output.write_bytes(previous)

    with pytest.raises(build_blocklist.BlocklistError, match="no valid domains"):
        build_blocklist.build_blocklist(
            output,
            ["empty"],
            reader=lambda _source: "# comments only\nlocalhost\n",
        )

    assert output.read_bytes() == previous
    assert not list(tmp_path.glob("*.tmp"))


def test_atomic_replace_uses_complete_same_directory_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "blocklist.bin"
    previous = b"previous"
    blob = build_blocklist.serialize_hashes([1, 2])
    output.write_bytes(previous)
    real_replace = os.replace
    observed: dict[str, Path] = {}

    def inspect_replace(source: str | Path, destination: str | Path) -> None:
        source_path = Path(source)
        destination_path = Path(destination)
        assert destination_path.read_bytes() == previous
        assert source_path.parent == destination_path.parent
        assert source_path.read_bytes() == blob
        observed.update(source=source_path, destination=destination_path)
        real_replace(source_path, destination_path)

    monkeypatch.setattr(build_blocklist.os, "replace", inspect_replace)

    build_blocklist.atomic_write(output, blob)

    assert output.read_bytes() == blob
    assert observed["destination"] == output
    assert not observed["source"].exists()


def test_replace_failure_preserves_output_and_removes_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "blocklist.bin"
    previous = b"previous"
    output.write_bytes(previous)

    def fail_replace(_source: str | Path, _destination: str | Path) -> None:
        raise PermissionError("fixture replace failure")

    monkeypatch.setattr(build_blocklist.os, "replace", fail_replace)

    with pytest.raises(PermissionError, match="fixture replace failure"):
        build_blocklist.atomic_write(output, build_blocklist.serialize_hashes([1]))

    assert output.read_bytes() == previous
    assert not list(tmp_path.glob("*.tmp"))


def test_output_limit_rejects_oversize_and_preserves_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "blocklist.bin"
    previous = b"previous"
    output.write_bytes(previous)
    monkeypatch.setattr(
        build_blocklist,
        "read_source",
        lambda _source: "first.example\nsecond.example\n",
    )

    status = build_blocklist.main(
        ["--max-bytes", "9", str(output), "fixture"]
    )

    assert status == 1
    assert output.read_bytes() == previous
    assert "limit is 9 bytes" in capsys.readouterr().err
    assert not list(tmp_path.glob("*.tmp"))


def test_output_limit_accepts_exact_boundary(tmp_path: Path) -> None:
    output = tmp_path / "blocklist.bin"

    result = build_blocklist.build_blocklist(
        output,
        ["fixture"],
        reader=lambda _source: "first.example\nsecond.example\n",
        hash_function=lambda value: {b"first.example": 1, b"second.example": 2}[
            value
        ],
        max_output_bytes=10,
    )

    assert result.size == 10
    assert output.stat().st_size == 10
