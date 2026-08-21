#!/usr/bin/env python3
"""Create a fixed-format detached proof for a validated DNS blocklist."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .build_blocklist import (
        DEFAULT_MAX_OUTPUT_BYTES,
        HASH_BYTES,
        BlocklistError,
        atomic_write,
        validate_blob,
    )
else:
    from build_blocklist import (  # type: ignore[import-not-found]
        DEFAULT_MAX_OUTPUT_BYTES,
        HASH_BYTES,
        BlocklistError,
        atomic_write,
        validate_blob,
    )

MANIFEST_MAGIC = b"NSBM"
SIGNATURE_DOMAIN = b"NSM-BLOCKLIST-V1"
MANIFEST_VERSION = 1
BLOCKLIST_FORMAT_VERSION = 1
SIGNATURE_ALGORITHM = 1
MANIFEST_FLAGS = 0
MANIFEST_SIZE = 64
RAW_SIGNATURE_SIZE = 64
PROOF_SIZE = MANIFEST_SIZE + RAW_SIGNATURE_SIZE
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1

MANIFEST_STRUCT = struct.Struct("<4sBBBBIIQII32s")
P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072A8648CE3D020106082A8648CE3D030107034200"
)
P256_GROUP_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


class SignerError(Exception):
    """Raised when a blocklist proof cannot be created safely."""


@dataclass(frozen=True)
class SignResult:
    """Summary of an atomically installed blocklist proof."""

    input: Path
    output: Path
    payload_bytes: int
    record_count: int
    list_id: int
    sequence: int
    key_id: int


def _positive_bounded_int(value: str, maximum: int) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a decimal integer") from error
    if not 1 <= parsed <= maximum:
        raise argparse.ArgumentTypeError(f"must be between 1 and {maximum}")
    return parsed


def _uint32(value: str) -> int:
    return _positive_bounded_int(value, UINT32_MAX)


def _uint64(value: str) -> int:
    return _positive_bounded_int(value, UINT64_MAX)


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _find_openssl() -> Path:
    configured = os.environ.get("OPENSSL")
    if configured:
        candidate = Path(configured)
        if candidate.is_file():
            return candidate
        raise SignerError("OPENSSL does not identify an executable file")

    discovered = shutil.which("openssl")
    if discovered:
        return Path(discovered)

    candidates: list[Path] = []
    program_files = os.environ.get("PROGRAMFILES")
    if program_files:
        git_root = Path(program_files) / "Git"
        candidates.extend(
            (
                git_root / "usr" / "bin" / "openssl.exe",
                git_root / "mingw64" / "bin" / "openssl.exe",
            )
        )
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        git_root = Path(local_app_data) / "Programs" / "Git"
        candidates.extend(
            (
                git_root / "usr" / "bin" / "openssl.exe",
                git_root / "mingw64" / "bin" / "openssl.exe",
            )
        )

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise SignerError("OpenSSL CLI was not found; set OPENSSL to its executable")


def _run_openssl(executable: Path, arguments: list[str]) -> bytes:
    try:
        completed = subprocess.run(
            [str(executable), *arguments],
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SignerError("OpenSSL execution failed") from error

    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip()
        if detail:
            raise SignerError(f"OpenSSL rejected the operation: {detail}")
        raise SignerError("OpenSSL rejected the operation")
    return completed.stdout


def _extract_p256_public_key(public_key_der: bytes) -> bytes:
    if len(public_key_der) != len(P256_SPKI_PREFIX) + 65:
        raise SignerError("private key is not an uncompressed P-256 key")
    if not public_key_der.startswith(P256_SPKI_PREFIX):
        raise SignerError("private key is not a named-curve P-256 key")
    public_key = public_key_der[len(P256_SPKI_PREFIX) :]
    if public_key[0] != 0x04:
        raise SignerError("P-256 public key is not SEC1 uncompressed form")
    return public_key


def _read_der_integer(encoded: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(encoded) or encoded[offset] != 0x02:
        raise SignerError("OpenSSL returned a malformed ECDSA signature")
    length = encoded[offset + 1]
    start = offset + 2
    end = start + length
    if length == 0 or length > 33 or end > len(encoded):
        raise SignerError("OpenSSL returned an invalid ECDSA integer")

    value = encoded[start:end]
    if value[0] & 0x80:
        raise SignerError("OpenSSL returned a negative ECDSA integer")
    if len(value) > 1 and value[0] == 0:
        if not value[1] & 0x80:
            raise SignerError("OpenSSL returned a non-canonical ECDSA integer")
        value = value[1:]
    if len(value) > 32 or not any(value):
        raise SignerError("OpenSSL returned an out-of-range ECDSA integer")
    return value.rjust(32, b"\0"), end


def _der_signature_to_raw(signature: bytes) -> bytes:
    if len(signature) < 8 or signature[0] != 0x30:
        raise SignerError("OpenSSL returned a malformed ECDSA signature")
    if signature[1] & 0x80 or signature[1] != len(signature) - 2:
        raise SignerError("OpenSSL returned a non-canonical ECDSA sequence")

    r, offset = _read_der_integer(signature, 2)
    s, offset = _read_der_integer(signature, offset)
    if offset != len(signature):
        raise SignerError("OpenSSL returned trailing ECDSA signature data")

    r_value = int.from_bytes(r, "big")
    s_value = int.from_bytes(s, "big")
    if not 1 <= r_value < P256_GROUP_ORDER:
        raise SignerError("OpenSSL returned an out-of-range ECDSA r value")
    if not 1 <= s_value < P256_GROUP_ORDER:
        raise SignerError("OpenSSL returned an out-of-range ECDSA s value")
    if s_value > P256_GROUP_ORDER // 2:
        s_value = P256_GROUP_ORDER - s_value

    raw = r + s_value.to_bytes(32, "big")
    if len(raw) != RAW_SIGNATURE_SIZE:
        raise SignerError("raw ECDSA signature has an unexpected size")
    return raw


def _build_manifest(
    payload: bytes,
    *,
    key_id: int,
    list_id: int,
    sequence: int,
) -> bytes:
    payload_digest = hashlib.sha256(payload).digest()
    manifest = MANIFEST_STRUCT.pack(
        MANIFEST_MAGIC,
        MANIFEST_VERSION,
        BLOCKLIST_FORMAT_VERSION,
        SIGNATURE_ALGORITHM,
        MANIFEST_FLAGS,
        key_id,
        list_id,
        sequence,
        len(payload),
        len(payload) // HASH_BYTES,
        payload_digest,
    )
    if len(manifest) != MANIFEST_SIZE:
        raise SignerError("internal manifest size mismatch")
    return manifest


def _sign_manifest(
    executable: Path,
    private_key: Path,
    manifest: bytes,
    passphrase_file: Path | None,
) -> bytes:
    message_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as message_file:
            message_path = Path(message_file.name)
            message = SIGNATURE_DOMAIN + manifest
            written = message_file.write(message)
            if written != len(message):
                raise OSError(f"short write: wrote {written} of {len(message)} bytes")
            message_file.flush()
            os.fsync(message_file.fileno())

        arguments = ["dgst", "-sha256", "-sign", str(private_key)]
        if passphrase_file is not None:
            arguments.extend(["-passin", f"file:{passphrase_file}"])
        arguments.append(str(message_path))
        der_signature = _run_openssl(executable, arguments)
        return _der_signature_to_raw(der_signature)
    finally:
        if message_path is not None:
            try:
                message_path.unlink()
            except FileNotFoundError:
                pass


def sign_blocklist(
    input_path: str | Path,
    output_path: str | Path,
    private_key_path: str | Path,
    *,
    list_id: int,
    sequence: int,
    openssl: str | Path | None = None,
    passphrase_file_path: str | Path | None = None,
) -> SignResult:
    """Validate, sign, and atomically install a fixed 128-byte proof."""
    input_file = Path(input_path)
    output_file = Path(output_path)
    private_key = Path(private_key_path)
    passphrase_file = (
        Path(passphrase_file_path) if passphrase_file_path is not None else None
    )

    if _same_path(input_file, output_file):
        raise SignerError("proof output must not overwrite the input blocklist")
    if _same_path(private_key, output_file):
        raise SignerError("proof output must not overwrite the private key")
    if passphrase_file is not None and _same_path(passphrase_file, output_file):
        raise SignerError("proof output must not overwrite the passphrase file")
    if not 1 <= list_id <= UINT32_MAX:
        raise SignerError("list ID is outside the uint32 range")
    if not 1 <= sequence <= UINT64_MAX:
        raise SignerError("release sequence is outside the uint64 range")

    payload = input_file.read_bytes()
    validate_blob(payload, DEFAULT_MAX_OUTPUT_BYTES)

    executable = Path(openssl) if openssl is not None else _find_openssl()
    public_key_arguments = ["pkey", "-in", str(private_key)]
    if passphrase_file is not None:
        public_key_arguments.extend(["-passin", f"file:{passphrase_file}"])
    public_key_arguments.extend(["-pubout", "-outform", "DER"])
    public_key_der = _run_openssl(executable, public_key_arguments)
    public_key = _extract_p256_public_key(public_key_der)
    key_id = int.from_bytes(hashlib.sha256(public_key).digest()[:4], "little")

    manifest = _build_manifest(
        payload,
        key_id=key_id,
        list_id=list_id,
        sequence=sequence,
    )
    proof = manifest + _sign_manifest(
        executable, private_key, manifest, passphrase_file
    )
    if len(proof) != PROOF_SIZE:
        raise SignerError("internal proof size mismatch")
    atomic_write(output_file, proof)

    return SignResult(
        input=input_file,
        output=output_file,
        payload_bytes=len(payload),
        record_count=len(payload) // HASH_BYTES,
        list_id=list_id,
        sequence=sequence,
        key_id=key_id,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-id", required=True, type=_uint32)
    parser.add_argument("--sequence", required=True, type=_uint64)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--passphrase-file", type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the signer and return its process status."""
    arguments = _parser().parse_args(argv)
    try:
        result = sign_blocklist(
            arguments.input,
            arguments.output,
            arguments.private_key,
            list_id=arguments.list_id,
            sequence=arguments.sequence,
            passphrase_file_path=arguments.passphrase_file,
        )
    except (BlocklistError, OSError, SignerError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(f"payload bytes : {result.payload_bytes:,}")
    print(f"record count  : {result.record_count:,}")
    print(f"list ID       : {result.list_id}")
    print(f"sequence      : {result.sequence}")
    print(f"key ID        : {result.key_id}")
    print(f"proof bytes   : {PROOF_SIZE} -> {result.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
