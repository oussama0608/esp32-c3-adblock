#!/usr/bin/env python3
"""Build the firmware's sorted five-byte DNS blocklist.

The binary format is shared with ``src/main.cpp``: FNV-1a-64 hashes truncated
to 40 bits, serialized little-endian and sorted numerically. Keep
``HASH_BYTES`` synchronized with the firmware.
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import os
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

HASH_BYTES = 5
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
U64 = (1 << 64) - 1

# 250,000 hashes fit the existing LittleFS budget documented for dual OTA.
DEFAULT_MAX_OUTPUT_BYTES = 250_000 * HASH_BYTES
HOSTS_SINK_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1", "::1", "::"})

# Daily driver that fits alongside the existing dual-OTA firmware slots.
DEFAULT_SOURCES = (
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
)


class BlocklistError(Exception):
    """Raised when a blocklist cannot be built safely."""


@dataclass(frozen=True)
class BuildResult:
    """Summary of a completed blocklist build."""

    source_domains: int
    hash_entries: int
    collisions: int
    size: int
    output: Path


def fnv(data: bytes) -> int:
    """Return the firmware-compatible 40-bit FNV-1a hash."""
    value = FNV_OFFSET
    for byte in data:
        value = ((value ^ byte) * FNV_PRIME) & U64
    return value & MASK


def norm(domain: str) -> str:
    """Apply the generator's existing domain normalization policy."""
    domain = domain.strip().lower().lstrip("*").lstrip(".").rstrip(".")
    return domain.removeprefix("www.")


def is_valid_domain(domain: str) -> bool:
    """Validate an ASCII DNS name without changing its binary representation."""
    if not domain or "." not in domain or len(domain) > 253:
        return False

    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return False

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return False

    for label in domain.split("."):
        if not 1 <= len(label) <= 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not all(character.isascii() and (character.isalnum() or character == "-") for character in label):
            return False
    return True


def parse_domains(data: str) -> set[str]:
    """Parse domain-per-line and supported hosts-file records."""
    domains: set[str] = set()
    for raw_line in data.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line[0] in "!/":
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[0] in HOSTS_SINK_ADDRESSES:
            candidate = parts[1]
        elif len(parts) == 1:
            candidate = parts[0]
        else:
            continue

        candidate = norm(candidate)
        if is_valid_domain(candidate):
            domains.add(candidate)
    return domains


def read_source(source: str) -> str:
    """Read a local UTF-8-ish list or download an HTTP(S) source."""
    if source.startswith(("http://", "https://")):
        print(f"  downloading {source} ...", file=sys.stderr)
        with urllib.request.urlopen(source, timeout=180) as response:
            return response.read().decode("utf-8", "ignore")
    return Path(source).read_text(encoding="utf-8", errors="ignore")


def collect_domains(
    sources: Iterable[str],
    reader: Callable[[str], str] | None = None,
) -> tuple[set[str], int]:
    """Read all usable sources and return domains plus the successful count."""
    source_reader = read_source if reader is None else reader
    domains: set[str] = set()
    successful_sources = 0

    for source in sources:
        try:
            data = source_reader(source)
        except (OSError, UnicodeError, ValueError) as error:
            print(f"  !! skipped {source}: {error}", file=sys.stderr)
            continue
        successful_sources += 1
        domains.update(parse_domains(data))

    return domains, successful_sources


def hash_domains(
    domains: Iterable[str],
    hash_function: Callable[[bytes], int] | None = None,
) -> tuple[list[int], int]:
    """Hash distinct domains and report distinct-domain hash collisions."""
    selected_hash = fnv if hash_function is None else hash_function
    unique_domains = set(domains)
    values = [selected_hash(domain.encode("ascii")) for domain in unique_domains]
    unique_hashes = sorted(set(values))
    collisions = len(unique_domains) - len(unique_hashes)
    return unique_hashes, collisions


def serialize_hashes(hashes: Iterable[int]) -> bytes:
    """Serialize unique hashes in ascending numeric order."""
    ordered_hashes = sorted(set(hashes))
    try:
        return b"".join(
            value.to_bytes(HASH_BYTES, "little") for value in ordered_hashes
        )
    except (AttributeError, OverflowError) as error:
        raise BlocklistError("hash outside the 40-bit unsigned range") from error


def validate_blob(blob: bytes, max_output_bytes: int) -> None:
    """Validate the complete blob before it is allowed to replace the output."""
    if max_output_bytes <= 0:
        raise BlocklistError("maximum output size must be greater than zero")
    if not blob:
        raise BlocklistError("refusing to write an empty blocklist")
    if len(blob) % HASH_BYTES:
        raise BlocklistError(f"blocklist size is not a multiple of {HASH_BYTES}")
    if len(blob) > max_output_bytes:
        raise BlocklistError(
            f"blocklist is {len(blob):,} bytes; limit is {max_output_bytes:,} bytes"
        )

    values = [
        int.from_bytes(blob[offset : offset + HASH_BYTES], "little")
        for offset in range(0, len(blob), HASH_BYTES)
    ]
    if values != sorted(set(values)):
        raise BlocklistError("blocklist hashes are not strictly increasing")


def atomic_write(destination: str | Path, blob: bytes) -> None:
    """Replace destination with a fully written same-directory temporary file."""
    output = Path(destination)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            written = temporary.write(blob)
            if written != len(blob):
                raise OSError(f"short write: wrote {written} of {len(blob)} bytes")
            temporary.flush()
            os.fsync(temporary.fileno())

        if temporary_path.stat().st_size != len(blob):
            raise BlocklistError("temporary blocklist size changed after writing")
        os.replace(temporary_path, output)
        temporary_path = None
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def build_blocklist(
    output: str | Path,
    sources: Iterable[str],
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    reader: Callable[[str], str] | None = None,
    hash_function: Callable[[bytes], int] | None = None,
) -> BuildResult:
    """Build, validate and atomically install a blocklist."""
    source_list = list(sources)
    domains, successful_sources = collect_domains(source_list, reader)
    if successful_sources == 0:
        raise BlocklistError(f"all {len(source_list)} blocklist sources failed")
    if not domains:
        raise BlocklistError("blocklist sources contained no valid domains")

    hashes, collisions = hash_domains(domains, hash_function)
    blob = serialize_hashes(hashes)
    validate_blob(blob, max_output_bytes)
    atomic_write(output, blob)

    return BuildResult(
        source_domains=len(domains),
        hash_entries=len(hashes),
        collisions=collisions,
        size=len(blob),
        output=Path(output),
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="blocklist.bin")
    parser.add_argument("sources", nargs="*")
    parser.add_argument(
        "--max-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_OUTPUT_BYTES,
        help=f"maximum output size (default: {DEFAULT_MAX_OUTPUT_BYTES} bytes)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line generator and return its process status."""
    arguments = _parser().parse_args(argv)
    sources = arguments.sources or DEFAULT_SOURCES

    try:
        result = build_blocklist(
            arguments.output,
            sources,
            max_output_bytes=arguments.max_bytes,
        )
    except (BlocklistError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"source domains   : {result.source_domains:,}")
    print(
        f"hash entries     : {result.hash_entries:,}  "
        f"({HASH_BYTES}-byte / {HASH_BYTES * 8}-bit)"
    )
    print(
        f"collisions       : {result.collisions}  "
        "(domains sharing a hash -> over-block)"
    )
    print(
        f"flash blob       : {result.size:,} bytes  "
        f"({result.size / 1024 / 1024:.2f} MB)  -> {result.output}"
    )
    reads = math.ceil(math.log2(max(result.hash_entries, 2)))
    print(f"lookup           : ~{reads} reads/query")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
