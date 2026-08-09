from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from itertools import pairwise
from pathlib import Path

import pytest

from tools import ci_checks, sign_blocklist

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = REPO_ROOT / "src" / "main.cpp"
PAGE_PATH = REPO_ROOT / "src" / "page.h"
TRUST_PATH = REPO_ROOT / "src" / "blocklist_trust.h"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p5_5_crypto"

MANIFEST = struct.Struct("<4sBBBBIIQII32s")
DOMAIN = b"NSM-BLOCKLIST-V1"
MAX_RECORDS = 104_857
MAX_BYTES = MAX_RECORDS * 5
PRODUCTION_KEY_ID = 2_173_599_637
PRODUCTION_LIST_ID = 1
PRODUCTION_PUBLIC_KEY = bytes.fromhex(
    "04C642B500A5378CD0A4FDD3FC1028FBF3E3E908BD7F7A855485C97473050571762"
    "EAED935008E0A4F32EB0FA66B51D43E3F8F849FFA3299355A32C39433BEC765"
)

P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072A8648CE3D020106082A8648CE3D030107034200"
)


class ProofStatus(Enum):
    VALID = "valid"
    BAD_SIZE = "bad_size"
    BAD_ENCODING = "bad_encoding"
    BAD_MANIFEST = "bad_manifest"
    UNKNOWN_KEY = "unknown_key"
    INVALID_SIGNATURE = "invalid_signature"
    PAYLOAD_INVALID = "payload_invalid"
    PAYLOAD_MISMATCH = "payload_mismatch"


def load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def read_main() -> str:
    return MAIN_PATH.read_text(encoding="utf-8")


def cpp_function(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.DOTALL)
    assert match is not None, f"missing C++ function {name}"
    start = match.start()
    opening = source.index("{", match.start())
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated C++ function {name}")


@lru_cache(maxsize=1)
def find_openssl() -> Path:
    configured = os.environ.get("OPENSSL")
    if configured and Path(configured).is_file():
        return Path(configured)
    discovered = shutil.which("openssl")
    if discovered:
        return Path(discovered)
    candidates = (
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files"))
        / "Git/usr/bin/openssl.exe",
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files"))
        / "Git/mingw64/bin/openssl.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise AssertionError("OpenSSL is required for independent public-vector verification")


def raw_signature_to_der(signature: bytes) -> bytes:
    assert len(signature) == 64

    def integer(value: bytes) -> bytes:
        value = value.lstrip(b"\0") or b"\0"
        if value[0] & 0x80:
            value = b"\0" + value
        return b"\x02" + bytes([len(value)]) + value

    body = integer(signature[:32]) + integer(signature[32:])
    return b"\x30" + bytes([len(body)]) + body


def openssl_ecdsa_p256_sha256_verify(
    public_key: bytes, message: bytes, signature: bytes
) -> bool:
    if len(public_key) != 65 or public_key[0] != 0x04 or len(signature) != 64:
        return False
    with tempfile.TemporaryDirectory(prefix="netshield-p55-public-verify-") as temp:
        directory = Path(temp)
        public_path = directory / "public.der"
        signature_path = directory / "signature.der"
        public_path.write_bytes(P256_SPKI_PREFIX + public_key)
        signature_path.write_bytes(raw_signature_to_der(signature))
        completed = subprocess.run(
            [
                str(find_openssl()),
                "dgst",
                "-sha256",
                "-keyform",
                "DER",
                "-verify",
                str(public_path),
                "-signature",
                str(signature_path),
            ],
            input=message,
            capture_output=True,
            check=False,
            timeout=30,
        )
    return completed.returncode == 0


def decode_proof_hex(encoded: str) -> tuple[ProofStatus, bytes | None]:
    if len(encoded) != 256:
        return ProofStatus.BAD_SIZE, None
    if re.fullmatch(r"[0-9A-Fa-f]{256}", encoded) is None:
        return ProofStatus.BAD_ENCODING, None
    return ProofStatus.VALID, bytes.fromhex(encoded)


def structurally_valid(payload: bytes) -> bool:
    if not payload or len(payload) > MAX_BYTES or len(payload) % 5:
        return False
    values = [
        int.from_bytes(payload[index : index + 5], "little")
        for index in range(0, len(payload), 5)
    ]
    return len(values) <= MAX_RECORDS and all(
        left < right for left, right in pairwise(values)
    )


def authenticate(
    payload: bytes, proof: bytes, trusted_keys: dict[int, bytes]
) -> ProofStatus:
    if len(proof) != 128:
        return ProofStatus.BAD_SIZE
    fields = MANIFEST.unpack(proof[:64])
    magic, manifest_version, format_version, algorithm, flags = fields[:5]
    key_id, list_id, sequence, payload_size, record_count, payload_digest = fields[5:]
    if (magic, manifest_version, format_version, algorithm, flags) != (
        b"NSBM",
        1,
        1,
        1,
        0,
    ):
        return ProofStatus.BAD_MANIFEST
    public_key = trusted_keys.get(key_id)
    if public_key is None:
        return ProofStatus.UNKNOWN_KEY
    if list_id != PRODUCTION_LIST_ID or sequence == 0:
        return ProofStatus.BAD_MANIFEST
    if (
        payload_size == 0
        or payload_size > MAX_BYTES
        or payload_size % 5
        or record_count == 0
        or record_count > MAX_RECORDS
        or record_count != payload_size // 5
    ):
        return ProofStatus.BAD_MANIFEST
    if not openssl_ecdsa_p256_sha256_verify(
        public_key, DOMAIN + proof[:64], proof[64:]
    ):
        return ProofStatus.INVALID_SIGNATURE
    if not structurally_valid(payload):
        return ProofStatus.PAYLOAD_INVALID
    if (
        len(payload) != payload_size
        or len(payload) // 5 != record_count
        or hashlib.sha256(payload).digest() != payload_digest
    ):
        return ProofStatus.PAYLOAD_MISMATCH
    return ProofStatus.VALID


def mutate(proof: bytes, offset: int, replacement: bytes) -> bytes:
    changed = bytearray(proof)
    changed[offset : offset + len(replacement)] = replacement
    return bytes(changed)


@dataclass
class ProvenanceLifecycleModel:
    """Small A/O/N/P filesystem model for the approved P5.5 transaction."""

    files: dict[str, bytes]
    trusted_keys: dict[int, bytes]
    failed_renames: set[tuple[str, str]] = field(default_factory=set)
    operations: list[str] = field(default_factory=list)

    def valid(self, path: str) -> bool:
        payload = self.files.get(path)
        return payload is not None and structurally_valid(payload)

    def authenticated(self, path: str) -> bool:
        payload = self.files.get(path)
        proof = self.files.get("P")
        return (
            payload is not None
            and proof is not None
            and authenticate(payload, proof, self.trusted_keys) is ProofStatus.VALID
        )

    def remove(self, path: str) -> bool:
        self.operations.append(f"remove:{path}")
        self.files.pop(path, None)
        return path not in self.files

    def rename(self, source: str, destination: str) -> bool:
        self.operations.append(f"rename:{source}->{destination}")
        if (
            (source, destination) in self.failed_renames
            or source not in self.files
            or destination in self.files
        ):
            return False
        self.files[destination] = self.files.pop(source)
        return True

    def discard_candidate_pair(self) -> bool:
        return self.remove("P") and self.remove("N")

    def restore_old_with_candidate_proof(self) -> bool:
        self.remove("A")
        return self.discard_candidate_pair() and self.rename("O", "A") and self.valid("A")

    def promote(self, cut_after: str | None = None) -> str:
        if not self.authenticated("N") or not self.valid("A"):
            return "rejected"
        self.remove("O")
        if not self.rename("A", "O"):
            return "rejected"
        if cut_after == "active_to_old":
            return "power_cut"
        if not self.rename("N", "A"):
            return "rollback" if self.restore_old_with_candidate_proof() else "fail_closed"
        if cut_after == "new_to_active":
            return "power_cut"
        if not self.authenticated("A"):
            return "rollback" if self.restore_old_with_candidate_proof() else "fail_closed"
        if cut_after == "active_verification":
            return "power_cut"
        if not self.remove("P"):
            return "rollback" if self.restore_old_with_candidate_proof() else "fail_closed"
        if cut_after == "proof_cleanup":
            return "power_cut"
        if not self.remove("O"):
            return "rollback"
        return "success"

    def recover(self) -> str:
        active_valid = self.valid("A")
        old_valid = self.valid("O")
        candidate_valid = self.valid("N")

        if active_valid:
            candidate_exists = "N" in self.files
            proof_exists = "P" in self.files
            if not candidate_exists and proof_exists:
                if self.authenticated("A"):
                    return (
                        "finish_promoted"
                        if self.remove("P") and self.remove("O")
                        else "fail_closed"
                    )
                if not old_valid:
                    return "fail_closed"
                self.remove("A")
                if not self.discard_candidate_pair() or not self.rename("O", "A"):
                    return "fail_closed"
                return "restore_old" if self.valid("A") else "fail_closed"
            if not self.discard_candidate_pair() or not self.remove("O"):
                return "fail_closed"
            return "use_active"

        if old_valid:
            self.remove("A")
            if not self.discard_candidate_pair() or not self.rename("O", "A"):
                return "fail_closed"
            return "restore_old" if self.valid("A") else "fail_closed"

        if candidate_valid and self.authenticated("N"):
            self.remove("A")
            if not self.rename("N", "A") or not self.authenticated("A"):
                return "fail_closed"
            if not self.remove("P") or not self.remove("O"):
                return "fail_closed"
            return "promote_candidate"

        return "fail_closed"


def lifecycle_material() -> tuple[bytes, bytes, bytes, dict[int, bytes]]:
    vector = load_fixture("netshield_protocol_test_vector.json")
    legacy = (1).to_bytes(5, "little")
    candidate = bytes.fromhex(str(vector["payload_hex"]))
    proof = bytes.fromhex(str(vector["proof_hex"]))
    key_id = int(vector["test_key_id"])
    public_key = bytes.fromhex(str(vector["public_key_sec1_hex"]))
    return legacy, candidate, proof, {key_id: public_key}


def test_reviewed_nist_p256_sha256_vector_verifies() -> None:
    vector = load_fixture("nist_p256_sha256_sigver.json")
    public_key = b"\x04" + bytes.fromhex(str(vector["public_qx_hex"])) + bytes.fromhex(
        str(vector["public_qy_hex"])
    )
    signature = bytes.fromhex(str(vector["signature_r_hex"])) + bytes.fromhex(
        str(vector["signature_s_hex"])
    )

    assert vector["result"] == "P (valid signature)"
    assert openssl_ecdsa_p256_sha256_verify(
        public_key, bytes.fromhex(str(vector["message_hex"])), signature
    )


def test_nist_fixture_records_exact_reviewed_provenance() -> None:
    provenance = (FIXTURE_DIR / "README.md").read_text(encoding="utf-8")

    assert "186-4ecdsatestvectors.zip" in provenance
    assert "FE47CC92B4CEE418236125C9FFBCD9BB01C8C34E74A4BA195D954BCB72824752" in provenance
    assert "1,144,603 bytes" in provenance
    assert "SigVer.rsp" in provenance


def test_disposable_protocol_vector_is_public_only_and_valid() -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    payload = bytes.fromhex(str(vector["payload_hex"]))
    proof = bytes.fromhex(str(vector["proof_hex"]))
    public_key = bytes.fromhex(str(vector["public_key_sec1_hex"]))

    assert vector["classification"] == "TEST ONLY — NOT TRUSTED BY FIRMWARE"
    assert hashlib.sha256(public_key).hexdigest().upper() == vector["public_key_sha256_hex"]
    assert int.from_bytes(hashlib.sha256(public_key).digest()[:4], "little") == vector["test_key_id"]
    assert proof[:64].hex().upper() == vector["manifest_hex"]
    assert proof[64:96].hex().upper() == vector["signature_r_hex"]
    assert proof[96:].hex().upper() == vector["signature_s_hex"]
    assert authenticate(payload, proof, {int(vector["test_key_id"]): public_key}) is ProofStatus.VALID


def test_valid_signature_fails_for_wrong_payload_and_different_list() -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    payload = bytes.fromhex(str(vector["payload_hex"]))
    proof = bytes.fromhex(str(vector["proof_hex"]))
    public_key = bytes.fromhex(str(vector["public_key_sec1_hex"]))
    keys = {int(vector["test_key_id"]): public_key}
    different = payload[:-5] + (int.from_bytes(payload[-5:], "little") + 1).to_bytes(5, "little")

    assert structurally_valid(different)
    assert authenticate(different, proof, keys) is ProofStatus.PAYLOAD_MISMATCH
    assert authenticate(payload + b"\xff" * 5, proof, keys) is ProofStatus.PAYLOAD_MISMATCH


def test_corrupted_payload_and_invalid_signature_fail() -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    payload = bytes.fromhex(str(vector["payload_hex"]))
    proof = bytes.fromhex(str(vector["proof_hex"]))
    public_key = bytes.fromhex(str(vector["public_key_sec1_hex"]))
    keys = {int(vector["test_key_id"]): public_key}
    corrupted = bytearray(payload)
    corrupted[-1] ^= 1
    bad_signature = proof[:-1] + bytes([proof[-1] ^ 1])

    assert authenticate(bytes(corrupted), proof, keys) is ProofStatus.PAYLOAD_MISMATCH
    assert authenticate(payload, bad_signature, keys) is ProofStatus.INVALID_SIGNATURE
    assert authenticate(payload, proof[:64] + bytes(64), keys) is ProofStatus.INVALID_SIGNATURE


@pytest.mark.parametrize("length", [0, 1, 63, 64, 127, 129])
def test_truncated_or_wrong_sized_proof_is_rejected(length: int) -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    proof = bytes.fromhex(str(vector["proof_hex"]))
    candidate = proof[:length] if length <= len(proof) else proof + b"\0"

    assert authenticate(b"\x01\0\0\0\0", candidate, {}) is ProofStatus.BAD_SIZE


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        ("", ProofStatus.BAD_SIZE),
        ("00" * 127, ProofStatus.BAD_SIZE),
        ("00" * 129, ProofStatus.BAD_SIZE),
        ("00" * 127 + "0G", ProofStatus.BAD_ENCODING),
        ("z" * 256, ProofStatus.BAD_ENCODING),
    ],
)
def test_strict_proof_hex_decoder(encoded: str, expected: ProofStatus) -> None:
    status, decoded = decode_proof_hex(encoded)

    assert status is expected
    assert decoded is None


@pytest.mark.parametrize(
    ("offset", "replacement", "expected"),
    [
        (0, b"FAIL", ProofStatus.BAD_MANIFEST),
        (4, b"\x02", ProofStatus.BAD_MANIFEST),
        (5, b"\x02", ProofStatus.BAD_MANIFEST),
        (6, b"\x02", ProofStatus.BAD_MANIFEST),
        (7, b"\x01", ProofStatus.BAD_MANIFEST),
        (8, (99).to_bytes(4, "little"), ProofStatus.UNKNOWN_KEY),
        (12, (2).to_bytes(4, "little"), ProofStatus.BAD_MANIFEST),
        (16, bytes(8), ProofStatus.BAD_MANIFEST),
        (24, (0).to_bytes(4, "little"), ProofStatus.BAD_MANIFEST),
        (24, (6).to_bytes(4, "little"), ProofStatus.BAD_MANIFEST),
        (28, (8).to_bytes(4, "little"), ProofStatus.BAD_MANIFEST),
    ],
)
def test_manifest_policy_fields_are_rejected_before_payload_use(
    offset: int, replacement: bytes, expected: ProofStatus
) -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    proof = bytes.fromhex(str(vector["proof_hex"]))
    payload = bytes.fromhex(str(vector["payload_hex"]))
    public_key = bytes.fromhex(str(vector["public_key_sec1_hex"]))

    assert authenticate(
        payload,
        mutate(proof, offset, replacement),
        {int(vector["test_key_id"]): public_key},
    ) is expected


def test_structurally_valid_list_signed_by_test_key_is_unauthorized_in_firmware() -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    payload = bytes.fromhex(str(vector["payload_hex"]))
    proof = bytes.fromhex(str(vector["proof_hex"]))

    assert structurally_valid(payload)
    assert authenticate(payload, proof, {PRODUCTION_KEY_ID: PRODUCTION_PUBLIC_KEY}) is ProofStatus.UNKNOWN_KEY


def test_signer_constructs_the_exact_fixed_manifest() -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    payload = bytes.fromhex(str(vector["payload_hex"]))

    manifest = sign_blocklist._build_manifest(
        payload,
        key_id=int(vector["test_key_id"]),
        list_id=int(vector["list_id"]),
        sequence=int(vector["sequence"]),
    )

    assert len(manifest) == 64
    assert manifest.hex().upper() == vector["manifest_hex"]
    assert hashlib.sha256(DOMAIN + manifest).digest_size == 32


def test_signer_normalizes_der_signature_to_fixed_width_raw() -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    r = bytes.fromhex(str(vector["signature_r_hex"]))
    s = bytes.fromhex(str(vector["signature_s_hex"]))

    def der_integer(value: bytes) -> bytes:
        encoded = b"\0" + value if value[0] & 0x80 else value
        return b"\x02" + bytes([len(encoded)]) + encoded

    body = der_integer(r) + der_integer(s)
    der = b"\x30" + bytes([len(body)]) + body

    assert sign_blocklist._der_signature_to_raw(der) == r + s

    high_s = (P256_N - int.from_bytes(s, "big")).to_bytes(32, "big")
    high_body = der_integer(r) + der_integer(high_s)
    high_der = b"\x30" + bytes([len(high_body)]) + high_body
    assert sign_blocklist._der_signature_to_raw(high_der) == r + s


def test_signer_writes_exact_public_fixture_proof_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    payload = bytes.fromhex(str(vector["payload_hex"]))
    public_key = bytes.fromhex(str(vector["public_key_sec1_hex"]))
    raw_signature = bytes.fromhex(str(vector["proof_hex"]))[64:]
    input_path = tmp_path / "blocklist.bin"
    output_path = tmp_path / "blocklist.sig"
    key_reference = tmp_path / "offline-key-reference"
    input_path.write_bytes(payload)
    calls: list[list[str]] = []

    def fake_openssl(executable: Path, arguments: list[str]) -> bytes:
        del executable
        calls.append(arguments)
        if arguments[0] == "pkey":
            return sign_blocklist.P256_SPKI_PREFIX + public_key
        assert arguments[:3] == ["dgst", "-sha256", "-sign"]
        return raw_signature_to_der(raw_signature)

    monkeypatch.setattr(sign_blocklist, "_run_openssl", fake_openssl)

    result = sign_blocklist.sign_blocklist(
        input_path,
        output_path,
        key_reference,
        list_id=1,
        sequence=42,
        openssl=tmp_path / "mock-openssl",
    )

    assert output_path.read_bytes().hex().upper() == vector["proof_hex"]
    assert output_path.stat().st_size == 128
    assert result.key_id == vector["test_key_id"]
    assert [call[0] for call in calls] == ["pkey", "dgst"]


def test_signer_failure_preserves_previous_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    payload = bytes.fromhex(str(vector["payload_hex"]))
    public_key = bytes.fromhex(str(vector["public_key_sec1_hex"]))
    input_path = tmp_path / "blocklist.bin"
    output_path = tmp_path / "blocklist.sig"
    input_path.write_bytes(payload)
    output_path.write_bytes(b"previous-valid-output")

    def failing_openssl(executable: Path, arguments: list[str]) -> bytes:
        del executable
        if arguments[0] == "pkey":
            return sign_blocklist.P256_SPKI_PREFIX + public_key
        raise sign_blocklist.SignerError("simulated signing failure")

    monkeypatch.setattr(sign_blocklist, "_run_openssl", failing_openssl)

    with pytest.raises(sign_blocklist.SignerError, match="simulated signing failure"):
        sign_blocklist.sign_blocklist(
            input_path,
            output_path,
            tmp_path / "offline-key-reference",
            list_id=1,
            sequence=42,
            openssl=tmp_path / "mock-openssl",
        )

    assert output_path.read_bytes() == b"previous-valid-output"


def test_signer_is_generic_atomic_and_contains_no_embedded_key() -> None:
    source = (REPO_ROOT / "tools" / "sign_blocklist.py").read_text(encoding="utf-8")

    for option in ("--list-id", "--sequence", "--private-key", "--input", "--output"):
        assert option in source
    assert "validate_blob(payload" in source
    assert "atomic_write(output_file, proof)" in source
    assert "P5_5_PRODUCTION_PUBLIC_KEY_HEX" not in source
    assert PRODUCTION_PUBLIC_KEY.hex().upper() not in source.replace(" ", "").upper()


def test_production_trust_table_contains_exactly_the_approved_public_key() -> None:
    source = TRUST_PATH.read_text(encoding="utf-8")
    byte_stream = bytes(int(value, 16) for value in re.findall(r"0x([0-9A-Fa-f]{2})", source))

    assert "struct TrustedBlocklistKey" in source
    assert "kBlocklistProductionKeyId = 2173599637u" in source
    assert "kBlocklistAcceptedListId = 1u" in source
    assert byte_stream.count(PRODUCTION_PUBLIC_KEY) == 1
    assert "kTrustedBlocklistKeyCount == 1" in source
    assert "trustedBlocklistKeyIdsAreUnique" in source
    assert "sec1PublicKey[0] == 0x04" in source


def test_disposable_test_key_is_not_firmware_trusted() -> None:
    vector = load_fixture("netshield_protocol_test_vector.json")
    trust = TRUST_PATH.read_text(encoding="utf-8")
    trust_hex = "".join(re.findall(r"0x([0-9A-Fa-f]{2})", trust)).upper()

    assert str(vector["test_key_id"]) not in trust
    assert str(vector["public_key_sec1_hex"]) not in trust_hex
    repository_files = sorted(
        set(ci_checks._tracked_files(REPO_ROOT))
        | set(ci_checks._untracked_files(REPO_ROOT))
    )
    ci_checks._check_p5_5_key_material(REPO_ROOT, repository_files)


def test_private_key_material_is_absent_from_repository_candidates() -> None:
    files = sorted(
        set(ci_checks._tracked_files(REPO_ROOT))
        | set(ci_checks._untracked_files(REPO_ROOT))
    )

    assert not ci_checks._scan_tracked_secrets(REPO_ROOT, files)
    fixture_documents = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in FIXTURE_DIR.glob("*.json")
    ]
    assert not [
        field
        for document in fixture_documents
        for field in ci_checks._find_private_fixture_fields(document)
    ]


def test_ui_requires_bin_and_128_byte_sig_and_sends_hex_header() -> None:
    page = PAGE_PATH.read_text(encoding="utf-8")

    assert 'id="blf" accept=".bin"' in page
    assert 'id="sigf" accept=".sig"' in page
    assert "BLOCKLIST_PROOF_BYTES=128" in page
    assert "sf.size!==BLOCKLIST_PROOF_BYTES" in page
    assert "new Uint8Array(await sf.arrayBuffer())" in page
    assert 'padStart(2,"0")' in page
    assert 'options.headers["X-Blocklist-Proof"]=proofHex' in page
    upload = page.split('request("/upload",', 1)[1].split("if(!r.ok)", 1)[0]
    assert "withBlocklistProof(" in upload
    assert "headers:csrfHeaders()" in upload
    assert 'fd.append("f",f)' in page
    assert "fd.append(\"f\",sf)" not in page
    assert "innerHTML" not in page


def test_upload_authenticates_proof_before_candidate_creation() -> None:
    source = read_main()
    upload = cpp_function(source, "handleUpload")
    start = upload.split("case UPLOAD_FILE_START:", 1)[1].split(
        "case UPLOAD_FILE_WRITE:", 1
    )[0]

    authorize = start.index("requireAdminMutation(false)")
    header = start.index("web.header(BLOCKLIST_PROOF_HEADER)", authorize)
    decode = start.index("decodeBlocklistProofHex", header)
    verify = start.index("validateBlocklistProofEnvelope", decode)
    discard = start.index("removeBlocklistCandidateFiles", verify)
    candidate = start.index("LittleFS.open(BLOCKLIST_NEW_PATH", discard)
    assert authorize < header < decode < verify < discard < candidate
    assert 'BLOCKLIST_PROOF_HEADER = "X-Blocklist-Proof"' in source
    assert "BLOCKLIST_PROOF_HEADER" in source[source.index("REQUEST_HEADERS"):]


def test_upload_authenticates_complete_payload_before_promotion() -> None:
    source = read_main()
    upload = cpp_function(source, "handleUpload")
    end = upload.split("case UPLOAD_FILE_END:", 1)[1].split(
        "case UPLOAD_FILE_ABORTED:", 1
    )[0]
    done = cpp_function(source, "handleUploadDone")

    structural = end.index("validateBlocklistFile")
    stored_proof = end.index("writeBlocklistCandidateProof", structural)
    authenticated = end.index("authenticateBlocklistWithStoredProof", stored_proof)
    ready = end.index("BlocklistUploadStatus::CANDIDATE_READY", authenticated)
    assert structural < stored_proof < authenticated < ready
    assert done.index("requireAdminMutation()") < done.index("promoteBlocklistCandidate()")
    assert 'message = "signed blocklist proof required"' in done
    assert 'message = "invalid signed blocklist"' in done


def test_candidate_pair_cleanup_is_proof_first() -> None:
    cleanup = cpp_function(read_main(), "removeBlocklistCandidateFiles")

    proof = cleanup.index("removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)")
    candidate = cleanup.index("removeBlocklistFile(BLOCKLIST_NEW_PATH)")
    assert proof < candidate


def test_signed_promotion_keeps_proof_through_reload_then_removes_old_last() -> None:
    promotion = cpp_function(read_main(), "promoteBlocklistCandidate")

    authenticate_candidate = promotion.index("authenticateBlocklistWithStoredProof")
    active_to_old = promotion.index("LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_OLD_PATH)")
    new_to_active = promotion.index("LittleFS.rename(BLOCKLIST_NEW_PATH, BLOCKLIST_PATH)")
    authenticate_active = promotion.index("authenticateBlocklistWithStoredProof", new_to_active)
    reopen = promotion.index("reopenBlocklist()", authenticate_active)
    remove_proof = promotion.index("removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)", reopen)
    remove_old = promotion.index("LittleFS.remove(BLOCKLIST_OLD_PATH)", remove_proof)
    assert authenticate_candidate < active_to_old < new_to_active
    assert new_to_active < authenticate_active < reopen < remove_proof < remove_old


def test_boot_recovery_keeps_legacy_active_but_requires_proof_for_candidate() -> None:
    recovery = cpp_function(read_main(), "recoverBlocklistFiles")

    active_branch = recovery.index("if (activeStatus == BlocklistValidationStatus::VALID)")
    old_branch = recovery.index("if (oldStatus == BlocklistValidationStatus::VALID)")
    candidate_auth = recovery.index("authenticateBlocklistWithStoredProof(BLOCKLIST_NEW_PATH)")
    fail_closed = recovery.rindex("return false;")
    assert active_branch < old_branch < candidate_auth < fail_closed
    active_path = recovery[active_branch:old_branch]
    assert "removeBlocklistCandidateFiles()" in active_path
    assert "authenticateBlocklistWithStoredProof(BLOCKLIST_PATH)" in active_path
    assert "candidateProofStatus == BlocklistProofStatus::VALID" in recovery


def test_lifecycle_model_promotes_signed_candidate_and_cleans_old_last() -> None:
    legacy, candidate, proof, keys = lifecycle_material()
    model = ProvenanceLifecycleModel(
        {"A": legacy, "N": candidate, "P": proof}, keys
    )

    assert model.promote() == "success"
    assert model.files == {"A": candidate}
    assert model.operations.index("rename:A->O") < model.operations.index("rename:N->A")
    assert model.operations.index("rename:N->A") < model.operations.index("remove:P")
    assert model.operations.index("remove:P") < len(model.operations) - 1
    assert model.operations[-1] == "remove:O"


def test_lifecycle_model_promotion_failure_restores_old_and_discards_pair() -> None:
    legacy, candidate, proof, keys = lifecycle_material()
    model = ProvenanceLifecycleModel(
        {"A": legacy, "N": candidate, "P": proof},
        keys,
        failed_renames={("N", "A")},
    )

    assert model.promote() == "rollback"
    assert model.files == {"A": legacy}
    failed_promotion = model.operations.index("rename:N->A")
    assert failed_promotion < model.operations.index("remove:P")
    assert model.operations.index("remove:P") < model.operations.index("remove:N")
    assert model.operations[-1] == "rename:O->A"


def test_lifecycle_model_boot_migration_and_candidate_only_policy() -> None:
    legacy, candidate, proof, keys = lifecycle_material()
    legacy_boot = ProvenanceLifecycleModel({"A": legacy}, keys)
    signed_candidate = ProvenanceLifecycleModel({"N": candidate, "P": proof}, keys)
    unsigned_candidate = ProvenanceLifecycleModel({"N": candidate}, keys)
    invalid_proof = ProvenanceLifecycleModel(
        {"N": candidate, "P": proof[:-1] + bytes([proof[-1] ^ 1])}, keys
    )

    assert legacy_boot.recover() == "use_active"
    assert legacy_boot.files == {"A": legacy}
    assert signed_candidate.recover() == "promote_candidate"
    assert signed_candidate.files == {"A": candidate}
    assert unsigned_candidate.recover() == "fail_closed"
    assert unsigned_candidate.files == {"N": candidate}
    assert invalid_proof.recover() == "fail_closed"
    assert invalid_proof.files == {
        "N": candidate,
        "P": proof[:-1] + bytes([proof[-1] ^ 1]),
    }


@pytest.mark.parametrize(
    ("frontier", "initial", "expected_action", "expected_active"),
    [
        ("during-upload", "partial_candidate", "use_active", "legacy"),
        ("after-candidate-close", "candidate_no_proof", "use_active", "legacy"),
        ("after-proof-close", "candidate_with_proof", "use_active", "legacy"),
        ("after-candidate-validation", "candidate_with_proof", "use_active", "legacy"),
        ("after-active-to-old", "cut_active_to_old", "restore_old", "legacy"),
        ("after-new-to-active", "cut_new_to_active", "finish_promoted", "candidate"),
        (
            "after-active-verification",
            "cut_active_verification",
            "finish_promoted",
            "candidate",
        ),
        ("after-proof-cleanup", "cut_proof_cleanup", "use_active", "candidate"),
        ("after-old-cleanup", "promoted", "use_active", "candidate"),
    ],
)
def test_lifecycle_model_recovers_every_persisted_power_cut_frontier(
    frontier: str,
    initial: str,
    expected_action: str,
    expected_active: str,
) -> None:
    del frontier
    legacy, candidate, proof, keys = lifecycle_material()
    if initial == "partial_candidate":
        model = ProvenanceLifecycleModel({"A": legacy, "N": b"partial"}, keys)
    elif initial == "candidate_no_proof":
        model = ProvenanceLifecycleModel({"A": legacy, "N": candidate}, keys)
    elif initial == "candidate_with_proof":
        model = ProvenanceLifecycleModel(
            {"A": legacy, "N": candidate, "P": proof}, keys
        )
    else:
        model = ProvenanceLifecycleModel(
            {"A": legacy, "N": candidate, "P": proof}, keys
        )
        cut = {
            "cut_active_to_old": "active_to_old",
            "cut_new_to_active": "new_to_active",
            "cut_active_verification": "active_verification",
            "cut_proof_cleanup": "proof_cleanup",
        }.get(initial)
        if cut is None:
            assert initial == "promoted"
            assert model.promote() == "success"
        else:
            assert model.promote(cut_after=cut) == "power_cut"

    assert model.recover() == expected_action
    expected_payload = legacy if expected_active == "legacy" else candidate
    assert model.files == {"A": expected_payload}


def test_lifecycle_model_discards_proof_before_candidate_at_pre_promotion_cuts() -> None:
    legacy, candidate, proof, keys = lifecycle_material()
    model = ProvenanceLifecycleModel(
        {"A": legacy, "N": candidate, "P": proof}, keys
    )

    assert model.recover() == "use_active"
    assert model.files == {"A": legacy}
    assert model.operations.index("remove:P") < model.operations.index("remove:N")


def test_no_permanent_active_proof_sidecar_or_nvs_provenance_is_added() -> None:
    source = read_main()
    provenance_functions = "\n".join(
        cpp_function(source, name)
        for name in (
            "authenticateBlocklistFile",
            "recoverBlocklistFiles",
            "promoteBlocklistCandidate",
            "handleUpload",
            "handleUploadDone",
        )
    )

    assert 'BLOCKLIST_NEW_AUTH_PATH = "/blocklist.new.auth"' in source
    assert "/blocklist.bin.auth" not in source
    assert "/blocklist.old.auth" not in source
    assert "Preferences" not in provenance_functions


def test_remote_fetch_and_firmware_ota_remain_absent() -> None:
    production = "\n".join(
        path.read_text(encoding="utf-8") for path in (MAIN_PATH, PAGE_PATH, TRUST_PATH)
    )
    routes = set(re.findall(r'web\.on\(\s*"([^"]+)"', production))

    for token in (
        "setInsecure",
        "/fetchnow",
        "/setupdate",
        "HTTPClient",
        "NetworkClientSecure",
        "ArduinoOTA",
    ):
        assert token not in production
    assert "/update" not in routes
    assert re.search(r'#\s*include\s*[<"]Update\.h[>"]', production) is None


def test_p5_4_wifi_retry_and_rf_workaround_are_unchanged() -> None:
    source = read_main()
    connect = cpp_function(source, "connectWiFi")

    assert source.count("WiFi.begin(ssid, pass)") == 1
    assert source.count("WiFi.reconnect()") == 1
    assert connect.count("applyC3RfWorkaround()") == 1
    assert "WIFI_ASSOCIATION_TIMEOUT_MS = 20000" in source
    assert "WIFI_RETRY_SETTLE_MS = 250" in source
    assert "WiFi.disconnect(false, false, WIFI_DISCONNECT_TIMEOUT_MS)" in connect
