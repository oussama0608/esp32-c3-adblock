from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

import pytest

from tools import build_blocklist

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = REPO_ROOT / "src" / "main.cpp"
PAGE_PATH = REPO_ROOT / "src" / "page.h"

HASH_BYTES = 5
MAX_RECORDS = 104_857
MAX_BYTES = MAX_RECORDS * HASH_BYTES
LEGACY_MAX_BYTES = 250_000 * HASH_BYTES


def read_main() -> str:
    return MAIN_PATH.read_text(encoding="utf-8")


def read_page() -> str:
    return PAGE_PATH.read_text(encoding="utf-8")


def read_production_sources() -> str:
    paths = sorted(
        path
        for path in (REPO_ROOT / "src").rglob("*")
        if path.suffix.casefold() in {".c", ".cc", ".cpp", ".h", ".hpp"}
    )
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def cpp_function(source: str, name: str) -> str:
    """Return one C++ function while ignoring braces in strings/comments."""
    signature = re.search(
        rf"\b{re.escape(name)}\s*\([^;{{]*?\)\s*\{{",
        source,
        re.DOTALL,
    )
    assert signature is not None, f"missing function: {name}"
    start = signature.end() - 1
    depth = 0
    index = start
    while index < len(source):
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            assert end >= 0, "unterminated C++ block comment"
            index = end + 2
            continue
        if source.startswith('R"', index):
            delimiter_end = source.find("(", index + 2)
            assert delimiter_end >= 0, "unterminated C++ raw-string delimiter"
            delimiter = source[index + 2 : delimiter_end]
            terminator = ")" + delimiter + '"'
            end = source.find(terminator, delimiter_end + 1)
            assert end >= 0, "unterminated C++ raw string"
            index = end + len(terminator)
            continue
        if source[index] in {'"', "'"}:
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            continue
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[signature.start() : index + 1]
        index += 1
    raise AssertionError(f"unterminated function: {name}")


def record(value: int) -> bytes:
    return value.to_bytes(HASH_BYTES, "little")


class FileState(Enum):
    ABSENT = auto()
    INVALID = auto()
    VALID = auto()


class RecoveryAction(Enum):
    USE_ACTIVE = auto()
    RESTORE_OLD = auto()
    PROMOTE_NEW = auto()
    FAIL_CLOSED = auto()


def recovery_oracle(
    active: FileState,
    old: FileState,
    new: FileState,
) -> RecoveryAction:
    """Reference the approved P5.3a recovery precedence."""
    if active is FileState.VALID:
        return RecoveryAction.USE_ACTIVE
    if old is FileState.VALID:
        return RecoveryAction.RESTORE_OLD
    if new is FileState.VALID:
        return RecoveryAction.PROMOTE_NEW
    return RecoveryAction.FAIL_CLOSED


@dataclass
class FakeBlocklistFs:
    """Small fault-injection model for the approved three-file protocol."""

    files: dict[str, bytes]
    failed_renames: set[tuple[str, str]] = field(default_factory=set)
    failed_removes: set[str] = field(default_factory=set)
    short_write: bool = False

    def remove(self, path: str) -> bool:
        if path in self.failed_removes:
            return False
        self.files.pop(path, None)
        return True

    def rename(self, source: str, destination: str) -> bool:
        if (
            (source, destination) in self.failed_renames
            or source not in self.files
            or destination in self.files
        ):
            return False
        self.files[destination] = self.files.pop(source)
        return True

    def write_candidate(self, data: bytes) -> int:
        written = len(data) - 1 if self.short_write and data else len(data)
        self.files["new"] = self.files.get("new", b"") + data[:written]
        return written


@dataclass
class ManualUploadOracle:
    """Model only the safety invariants exercised by host fault tests."""

    fs: FakeBlocklistFs
    transaction_active: bool = False
    bytes_written: int = 0

    def start(self, *, authorized: bool = True) -> str:
        if not authorized:
            return "forbidden"
        if self.transaction_active:
            return "busy"
        self.transaction_active = True
        self.bytes_written = 0
        self.fs.remove("new")
        return "receiving"

    def write(self, data: bytes) -> str:
        if len(data) > MAX_BYTES - self.bytes_written:
            return self._fail("too_large")
        written = self.fs.write_candidate(data)
        if written != len(data):
            return self._fail("write_error")
        self.bytes_written += written
        return "receiving"

    def abort(self) -> str:
        return self._fail("aborted")

    def finish(
        self,
        *,
        candidate_valid: bool = True,
        interrupt_after: str | None = None,
    ) -> str:
        if not candidate_valid:
            return self._fail("invalid")
        if not self.fs.remove("old"):
            return self._fail("promotion_error")
        if not self.fs.rename("active", "old"):
            return self._fail("promotion_error")
        if interrupt_after == "active_to_old":
            return "power_loss"
        if not self.fs.rename("new", "active"):
            restored = self.fs.rename("old", "active")
            self.fs.remove("new")
            self.transaction_active = False
            return "promotion_error" if restored else "fail_closed"
        if interrupt_after == "new_to_active":
            return "power_loss"
        if not self.fs.remove("old"):
            removed_new = self.fs.remove("active")
            restored = removed_new and self.fs.rename("old", "active")
            self.transaction_active = False
            return "promotion_error" if restored else "fail_closed"
        self.transaction_active = False
        return "success"

    def _fail(self, status: str) -> str:
        self.fs.remove("new")
        self.transaction_active = False
        return status


def test_generator_and_firmware_share_the_exact_candidate_policy() -> None:
    source = read_main()

    assert build_blocklist.HASH_BYTES == HASH_BYTES
    assert build_blocklist.MAX_RECORDS == MAX_RECORDS
    assert build_blocklist.DEFAULT_MAX_OUTPUT_BYTES == MAX_BYTES == 524_285
    assert re.search(
        r"\bBLOCKLIST_MAX_RECORDS\s*=\s*104_?857(?:U|UL|ULL)?\s*;",
        source,
    )
    assert re.search(
        r"\bBLOCKLIST_MAX_BYTES\s*=\s*"
        r"BLOCKLIST_MAX_RECORDS\s*\*\s*HASH_BYTES\s*;",
        source,
    )


def test_generator_cannot_raise_the_firmware_candidate_maximum(tmp_path: Path) -> None:
    with pytest.raises(build_blocklist.BlocklistError, match="firmware candidate"):
        build_blocklist.build_blocklist(
            tmp_path / "blocklist.bin",
            ["fixture"],
            reader=lambda _source: "one.example\n",
            max_output_bytes=MAX_BYTES + HASH_BYTES,
        )


def test_five_byte_little_endian_decode_known_vector() -> None:
    encoded = bytes.fromhex("8967452301")

    assert int.from_bytes(encoded, "little", signed=False) == 0x0123456789
    assert build_blocklist.serialize_hashes([0x0123456789]) == encoded


def test_empty_candidate_is_rejected() -> None:
    with pytest.raises(build_blocklist.BlocklistError, match="empty"):
        build_blocklist.validate_blob(b"", MAX_BYTES)


def test_one_record_candidate_is_accepted() -> None:
    build_blocklist.validate_blob(record(0x0123456789), MAX_BYTES)


def test_exact_maximum_record_count_is_accepted() -> None:
    candidate = b"".join(record(value) for value in range(MAX_RECORDS))

    assert len(candidate) == MAX_BYTES
    build_blocklist.validate_blob(candidate, MAX_BYTES)


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(record(1) * MAX_RECORDS + b"\x00", id="max-plus-one-byte"),
        pytest.param(
            b"".join(record(value) for value in range(MAX_RECORDS + 1)),
            id="max-plus-one-record",
        ),
    ],
)
def test_candidate_above_maximum_is_rejected(candidate: bytes) -> None:
    with pytest.raises(build_blocklist.BlocklistError):
        build_blocklist.validate_blob(candidate, MAX_BYTES)


def test_valid_oversized_legacy_active_can_remain_readable() -> None:
    legacy = b"".join(record(value) for value in range(MAX_RECORDS + 1))

    with pytest.raises(build_blocklist.BlocklistError):
        build_blocklist.validate_blob(legacy, MAX_BYTES)
    build_blocklist.validate_blob(legacy, LEGACY_MAX_BYTES)

    source = read_main()
    recovery = cpp_function(source, "recoverBlocklistFiles")
    assert "BLOCKLIST_LEGACY_MAX_BYTES" in source
    assert "validateBlocklistFile(BLOCKLIST_PATH, false)" in recovery
    assert "validateBlocklistFile(BLOCKLIST_OLD_PATH, false)" in recovery
    assert "validateBlocklistFile(BLOCKLIST_NEW_PATH, true)" in recovery


def test_non_multiple_of_five_is_rejected() -> None:
    with pytest.raises(build_blocklist.BlocklistError, match="multiple of 5"):
        build_blocklist.validate_blob(record(1) + b"\x02", MAX_BYTES)


def test_truncated_record_is_rejected() -> None:
    with pytest.raises(build_blocklist.BlocklistError, match="multiple of 5"):
        build_blocklist.validate_blob(record(1) + record(2)[:-1], MAX_BYTES)


def test_strictly_ascending_records_are_accepted() -> None:
    build_blocklist.validate_blob(record(1) + record(256) + record(1 << 39), MAX_BYTES)


@pytest.mark.parametrize(
    "candidate",
    [
        pytest.param(record(7) + record(7), id="duplicate"),
        pytest.param(record(8) + record(7), id="descending"),
    ],
)
def test_non_increasing_records_are_rejected(candidate: bytes) -> None:
    with pytest.raises(build_blocklist.BlocklistError, match="strictly increasing"):
        build_blocklist.validate_blob(candidate, MAX_BYTES)


def test_firmware_validator_is_explicit_streaming_and_bounded() -> None:
    source = read_main()
    validator = cpp_function(source, "validateBlocklistFile")
    decoder = cpp_function(source, "decodeBlocklistHash")

    assert re.search(
        r"enum\s+class\s+BlocklistValidationStatus\b[^}]*}",
        source,
        re.DOTALL,
    )
    assert re.search(
        r"BlocklistValidationStatus\s+validateBlocklistFile\s*\(", source
    )
    assert "HASH_BYTES" in validator
    assert "BLOCKLIST_MAX_BYTES" in validator
    assert ".size()" in validator
    assert "size == 0" in validator
    assert "size % HASH_BYTES != 0" in validator
    assert "recordCount = size / HASH_BYTES" in validator
    assert "recordCount > maxRecords" in validator
    assert ".read(" in validator
    assert re.search(
        r"\.read\([^;]+\)\s*!=\s*(?:HASH_BYTES|batchBytes)", validator
    )
    assert ".available() != 0" in validator
    assert "current == previous" in validator
    assert "<= previous" in validator
    assert re.search(
        r"static_cast<uint64_t>\(record\[i\]\)\s*<<\s*\(8\s*\*\s*i\)",
        decoder,
    )
    for whole_file_allocation in ("malloc(", "calloc(", "std::vector", "readString("):
        assert whole_file_allocation not in validator


@pytest.mark.parametrize(
    ("active", "old", "new", "expected"),
    [
        (FileState.VALID, FileState.ABSENT, FileState.ABSENT, RecoveryAction.USE_ACTIVE),
        (FileState.VALID, FileState.ABSENT, FileState.INVALID, RecoveryAction.USE_ACTIVE),
        (FileState.VALID, FileState.VALID, FileState.ABSENT, RecoveryAction.USE_ACTIVE),
        (FileState.ABSENT, FileState.VALID, FileState.ABSENT, RecoveryAction.RESTORE_OLD),
        (FileState.INVALID, FileState.VALID, FileState.INVALID, RecoveryAction.RESTORE_OLD),
        (FileState.ABSENT, FileState.ABSENT, FileState.VALID, RecoveryAction.PROMOTE_NEW),
        (FileState.INVALID, FileState.INVALID, FileState.INVALID, RecoveryAction.FAIL_CLOSED),
    ],
)
def test_recovery_state_policy(
    active: FileState,
    old: FileState,
    new: FileState,
    expected: RecoveryAction,
) -> None:
    assert recovery_oracle(active, old, new) is expected


@pytest.mark.parametrize(
    ("interruption", "active", "old", "new", "expected"),
    [
        (
            "during-upload",
            FileState.VALID,
            FileState.ABSENT,
            FileState.INVALID,
            RecoveryAction.USE_ACTIVE,
        ),
        (
            "after-candidate-close",
            FileState.VALID,
            FileState.ABSENT,
            FileState.VALID,
            RecoveryAction.USE_ACTIVE,
        ),
        (
            "after-candidate-validation",
            FileState.VALID,
            FileState.ABSENT,
            FileState.VALID,
            RecoveryAction.USE_ACTIVE,
        ),
        (
            "after-active-to-old",
            FileState.ABSENT,
            FileState.VALID,
            FileState.VALID,
            RecoveryAction.RESTORE_OLD,
        ),
        (
            "after-new-to-active",
            FileState.VALID,
            FileState.VALID,
            FileState.ABSENT,
            RecoveryAction.USE_ACTIVE,
        ),
        (
            "before-old-cleanup",
            FileState.VALID,
            FileState.VALID,
            FileState.ABSENT,
            RecoveryAction.USE_ACTIVE,
        ),
    ],
)
def test_power_loss_states_recover_deterministically(
    interruption: str,
    active: FileState,
    old: FileState,
    new: FileState,
    expected: RecoveryAction,
) -> None:
    expected_file_states = {
        "during-upload": (FileState.VALID, FileState.ABSENT, FileState.INVALID),
        "after-candidate-close": (
            FileState.VALID,
            FileState.ABSENT,
            FileState.VALID,
        ),
        "after-candidate-validation": (
            FileState.VALID,
            FileState.ABSENT,
            FileState.VALID,
        ),
        "after-active-to-old": (
            FileState.ABSENT,
            FileState.VALID,
            FileState.VALID,
        ),
        "after-new-to-active": (
            FileState.VALID,
            FileState.VALID,
            FileState.ABSENT,
        ),
        "before-old-cleanup": (
            FileState.VALID,
            FileState.VALID,
            FileState.ABSENT,
        ),
    }
    assert (active, old, new) == expected_file_states[interruption]
    assert recovery_oracle(active, old, new) is expected


def test_fault_model_rejects_unauthorized_and_concurrent_uploads() -> None:
    original = record(1)
    upload = ManualUploadOracle(FakeBlocklistFs({"active": original}))

    assert upload.start(authorized=False) == "forbidden"
    assert upload.fs.files == {"active": original}
    assert upload.start() == "receiving"
    assert upload.start() == "busy"
    assert upload.fs.files["active"] == original


def test_fault_model_overflow_keeps_active_and_removes_candidate() -> None:
    original = record(1)
    upload = ManualUploadOracle(FakeBlocklistFs({"active": original}))
    upload.start()
    upload.bytes_written = MAX_BYTES

    assert upload.write(b"x") == "too_large"
    assert upload.fs.files == {"active": original}
    assert not upload.transaction_active


def test_fault_model_accepts_the_exact_stream_boundary() -> None:
    original = record(1)
    upload = ManualUploadOracle(FakeBlocklistFs({"active": original}))
    upload.start()
    upload.bytes_written = MAX_BYTES - HASH_BYTES

    assert upload.write(record(2)) == "receiving"
    assert upload.bytes_written == MAX_BYTES
    assert upload.transaction_active


def test_fault_model_short_write_keeps_active_and_removes_candidate() -> None:
    original = record(1)
    filesystem = FakeBlocklistFs({"active": original}, short_write=True)
    upload = ManualUploadOracle(filesystem)
    upload.start()

    assert upload.write(record(2)) == "write_error"
    assert filesystem.files == {"active": original}
    assert not upload.transaction_active


def test_fault_model_abort_and_invalid_candidate_keep_active() -> None:
    original = record(1)
    for finish in (lambda upload: upload.abort(), lambda upload: upload.finish(candidate_valid=False)):
        upload = ManualUploadOracle(FakeBlocklistFs({"active": original}))
        upload.start()
        assert upload.write(record(2)) == "receiving"

        assert finish(upload) in {"aborted", "invalid"}
        assert upload.fs.files == {"active": original}
        assert not upload.transaction_active


def test_fault_model_valid_candidate_promotes_and_cleans_backup() -> None:
    original = record(1)
    replacement = record(2)
    upload = ManualUploadOracle(FakeBlocklistFs({"active": original}))
    upload.start()
    upload.write(replacement)

    assert upload.finish() == "success"
    assert upload.fs.files == {"active": replacement}
    assert not upload.transaction_active


def test_fault_model_failed_candidate_rename_restores_old_active() -> None:
    original = record(1)
    replacement = record(2)
    filesystem = FakeBlocklistFs(
        {"active": original},
        failed_renames={("new", "active")},
    )
    upload = ManualUploadOracle(filesystem)
    upload.start()
    upload.write(replacement)

    assert upload.finish() == "promotion_error"
    assert filesystem.files == {"active": original}
    assert not upload.transaction_active


def test_fault_model_failed_active_to_old_rename_keeps_active() -> None:
    original = record(1)
    filesystem = FakeBlocklistFs(
        {"active": original},
        failed_renames={("active", "old")},
    )
    upload = ManualUploadOracle(filesystem)
    upload.start()
    upload.write(record(2))

    assert upload.finish() == "promotion_error"
    assert filesystem.files == {"active": original}
    assert not upload.transaction_active


def test_fault_model_never_relies_on_rename_over_existing_backup() -> None:
    original = record(1)
    stale_backup = record(9)
    replacement = record(2)
    filesystem = FakeBlocklistFs({"active": original, "old": stale_backup})
    upload = ManualUploadOracle(filesystem)
    upload.start()
    upload.write(replacement)

    assert upload.finish() == "success"
    assert filesystem.files == {"active": replacement}


def test_fault_model_stale_backup_remove_failure_keeps_active() -> None:
    original = record(1)
    replacement = record(2)
    filesystem = FakeBlocklistFs(
        {"active": original, "old": record(9)},
        failed_removes={"old"},
    )
    upload = ManualUploadOracle(filesystem)
    upload.start()
    upload.write(replacement)

    assert upload.finish() == "promotion_error"
    assert filesystem.files["active"] == original
    assert filesystem.files["old"] == record(9)
    assert not upload.transaction_active


@pytest.mark.parametrize(
    ("frontier", "expected"),
    [
        ("active_to_old", RecoveryAction.RESTORE_OLD),
        ("new_to_active", RecoveryAction.USE_ACTIVE),
    ],
)
def test_fault_model_simulated_promotion_power_loss_recovers(
    frontier: str,
    expected: RecoveryAction,
) -> None:
    upload = ManualUploadOracle(FakeBlocklistFs({"active": record(1)}))
    upload.start()
    upload.write(record(2))

    assert upload.finish(interrupt_after=frontier) == "power_loss"
    states = tuple(
        FileState.VALID if path in upload.fs.files else FileState.ABSENT
        for path in ("active", "old", "new")
    )
    assert recovery_oracle(*states) is expected


def test_recovery_and_promotion_use_active_candidate_and_backup_paths() -> None:
    source = read_main()
    recovery = cpp_function(source, "recoverBlocklistFiles")
    promotion = cpp_function(source, "promoteBlocklistCandidate")

    for declaration in (
        'BLOCKLIST_PATH = "/blocklist.bin"',
        'BLOCKLIST_NEW_PATH = "/blocklist.new"',
        'BLOCKLIST_OLD_PATH = "/blocklist.old"',
    ):
        assert declaration in source
    for path_name in ("BLOCKLIST_PATH", "BLOCKLIST_NEW_PATH", "BLOCKLIST_OLD_PATH"):
        assert path_name in recovery
        assert path_name in promotion
    assert "validateBlocklistFile" in recovery
    assert "validateBlocklistFile" in promotion
    assert "LittleFS.rename" in recovery
    assert "LittleFS.rename" in promotion

    active_branch = recovery.index(
        "if (activeStatus == BlocklistValidationStatus::VALID)"
    )
    old_branch = recovery.index(
        "if (oldStatus == BlocklistValidationStatus::VALID)", active_branch
    )
    new_branch = recovery.index(
        "if (newStatus == BlocklistValidationStatus::VALID)", old_branch
    )
    fail_closed = recovery.rindex("return false;")
    assert active_branch < old_branch < new_branch < fail_closed
    assert "cleanupOrphanedBlocklistUpload()" in recovery[active_branch:old_branch]
    assert "LittleFS.rename(BLOCKLIST_OLD_PATH, BLOCKLIST_PATH)" in recovery[
        old_branch:new_branch
    ]
    assert "LittleFS.rename(BLOCKLIST_NEW_PATH, BLOCKLIST_PATH)" in recovery[
        new_branch:fail_closed
    ]


def test_promotion_validates_before_touching_active_and_checks_rollback() -> None:
    source = read_main()
    promotion = cpp_function(source, "promoteBlocklistCandidate")
    restore = cpp_function(source, "restoreOldBlocklist")
    reopen = cpp_function(source, "reopenBlocklist")

    candidate_validation = promotion.index("validateBlocklistFile")
    close_active = promotion.index("blocklist.close()")
    active_to_old = promotion.index(
        "LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_OLD_PATH)"
    )
    new_to_active = promotion.index(
        "LittleFS.rename(BLOCKLIST_NEW_PATH, BLOCKLIST_PATH)"
    )
    reload_active = promotion.index("reopenBlocklist()", new_to_active)
    remove_old = promotion.index("LittleFS.remove(BLOCKLIST_OLD_PATH)", reload_active)

    assert candidate_validation < close_active < active_to_old < new_to_active
    assert new_to_active < reload_active < remove_old
    failed_promotion = promotion[new_to_active:reload_active]
    assert "restoreOldBlocklist()" in failed_promotion
    assert "LittleFS.rename(BLOCKLIST_OLD_PATH, BLOCKLIST_PATH)" in restore
    assert "reopenBlocklist()" in restore
    assert "validateBlocklistFile(BLOCKLIST_PATH, false" in reopen


def test_upload_keeps_p5_2_authorization_before_candidate_open() -> None:
    source = read_main()
    envelope = cpp_function(source, "handleFixedEnvelopeUpload")
    upload = cpp_function(source, "handleUpload")
    start = upload.split("case UPLOAD_FILE_START:", 1)[1].split(
        "case UPLOAD_FILE_WRITE:", 1
    )[0]

    authorize = envelope.index("requireAdminMutation()")
    proof = envelope.index("reader.readExact(uploadProof, sizeof(uploadProof))", authorize)
    signed_length = envelope.index("expectedPayloadLength != reader.remaining", proof)
    start_upload = envelope.index("handleUpload(start)", signed_length)
    transaction = start.index("blocklistTransactionActive")
    candidate = start.index("BLOCKLIST_NEW_PATH", transaction)
    assert authorize < proof < signed_length < start_upload
    assert transaction < candidate
    assert "BLOCKLIST_PATH" not in start
    assert re.search(
        r"BLOCKLIST_UPLOAD_REQUEST_MAX\s*=\s*"
        r"BLOCKLIST_PROOF_BYTES\s*\+\s*BLOCKLIST_MAX_BYTES\s*;",
        source,
    )


def test_upload_enforces_stream_limit_and_checks_every_write() -> None:
    upload = cpp_function(read_main(), "handleUpload")
    write = upload.split("case UPLOAD_FILE_WRITE:", 1)[1].split(
        "case UPLOAD_FILE_END:", 1
    )[0]

    assert "BLOCKLIST_MAX_BYTES" in write
    assert "u.currentSize" in write
    assert re.search(r"\.write\s*\(\s*u\.buf\s*,\s*u\.currentSize\s*\)", write)
    assert re.search(r"(?:written|bytesWritten)\s*!=\s*u\.currentSize", write)


def test_upload_abort_and_failure_remove_only_candidate_and_reset_state() -> None:
    upload = cpp_function(read_main(), "handleUpload")
    aborted = upload.split("case UPLOAD_FILE_ABORTED:", 1)[1]

    assert "BLOCKLIST_NEW_PATH" in aborted
    assert "LittleFS.remove" in aborted
    assert "blocklistTransactionActive = false" in aborted
    assert "BLOCKLIST_PATH" not in aborted


def test_upload_completion_reports_too_large_and_resets_concurrency_flag() -> None:
    source = read_main()
    upload = cpp_function(source, "handleUpload")
    done = cpp_function(source, "handleUploadDone")

    assert "413" in done
    assert "blocklistTransactionActive" in upload
    assert "blocklistTransactionActive = false" in done
    assert "promoteBlocklistCandidate" not in upload
    second_authorization = done.index("requireAdminMutation()")
    promotion = done.index("promoteBlocklistCandidate(uploadDeadlineReached)", second_authorization)
    assert second_authorization < promotion
    assert "validateBlocklistFile" in source


def test_upload_rechecks_authorization_before_promotion_and_discards_on_failure() -> None:
    done = cpp_function(read_main(), "handleUploadDone")

    final_authorization = done.index("requireAdminMutation()")
    authorization_failure = done.index("failBlocklistUpload", final_authorization)
    promotion = done.index("promoteBlocklistCandidate(uploadDeadlineReached)")
    assert final_authorization < authorization_failure < promotion
    assert "BlocklistUploadStatus::ABORTED" in done[
        final_authorization:promotion
    ]


def test_signed_envelope_length_mismatch_is_rejected_before_staging() -> None:
    envelope = cpp_function(read_main(), "handleFixedEnvelopeUpload")

    proof = envelope.index("reader.readExact(uploadProof, sizeof(uploadProof))")
    signed_length = envelope.index("expectedPayloadLength != reader.remaining", proof)
    start = envelope.index("handleUpload(start)", signed_length)
    assert proof < signed_length < start
    assert "BlocklistUploadStatus::AUTH_INVALID" in envelope[signed_length:start]


def test_second_upload_is_rejected_while_transaction_is_active() -> None:
    upload = cpp_function(read_main(), "handleUpload")
    start = upload.split("case UPLOAD_FILE_START:", 1)[1].split(
        "case UPLOAD_FILE_WRITE:", 1
    )[0]

    guard = start.index("blocklistTransactionActive")
    set_active = start.index("blocklistTransactionActive = true", guard)
    assert guard < set_active
    assert "409" in read_main()


def test_second_envelope_cannot_restart_a_completed_or_failed_transaction() -> None:
    upload = cpp_function(read_main(), "handleUpload")
    start = upload.split("case UPLOAD_FILE_START:", 1)[1].split(
        "case UPLOAD_FILE_WRITE:", 1
    )[0]

    terminal_state_guard = start.index(
        "blocklistUploadStatus != BlocklistUploadStatus::IDLE"
    )
    reset_bytes = start.index("uploadBytesWritten = 0")
    open_candidate = start.index("LittleFS.open(BLOCKLIST_NEW_PATH", reset_bytes)
    assert terminal_state_guard < reset_bytes < open_candidate
    assert "failBlocklistUpload(BlocklistUploadStatus::BUSY)" in start[
        terminal_state_guard:reset_bytes
    ]


def test_failed_envelope_receive_aborts_the_real_candidate_path() -> None:
    source = read_main()
    envelope = cpp_function(source, "handleFixedEnvelopeUpload")
    upload = cpp_function(source, "handleUpload")

    abort = envelope.index("HTTPUpload aborted")
    complete = envelope.index("handleUploadDone()", abort)
    assert abort < complete
    aborted = upload.split("case UPLOAD_FILE_ABORTED:", 1)[1]
    assert "removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)" in aborted
    assert "LittleFS.remove(BLOCKLIST_NEW_PATH)" in aborted
    assert "blocklistTransactionActive = false" in aborted
    cleanup = cpp_function(source, "cleanupOrphanedBlocklistUpload")
    assert cleanup.index("BLOCKLIST_NEW_AUTH_PATH") < cleanup.index("BLOCKLIST_NEW_PATH")


def test_non_binary_upload_body_is_rejected_without_opening_staging() -> None:
    source = read_main()
    handler = cpp_function(source, "handleFixedEnvelopeUpload")

    content_type = handler.index("requestHasOctetStreamContentType()")
    candidate = handler.index("handleUpload(start)")
    assert content_type < candidate
    assert '"binary signed blocklist upload required"' in handler
    assert "rejectRequestWithPendingBody" in handler
    assert "multipart/form-data" not in source
    assert 'BLOCKLIST_UPLOAD_ROUTE = "/upload"' in source
    assert "handleFixedEnvelopeUpload(request)" in source


def test_littlefs_mount_and_recovery_fail_closed_before_normal_load() -> None:
    source = read_main()
    setup = cpp_function(source, "setup")

    assert "LittleFS.begin(true)" not in source
    mount_call = re.search(r"LittleFS\.begin\(\s*(?:false)?\s*\)", setup)
    assert mount_call is not None
    mount = mount_call.start()
    recovery = setup.index("recoverBlocklistFiles()", mount)
    active_load = setup.index("reopenBlocklist()", recovery)
    assert mount < recovery < active_load
    mount_guard = re.search(
        r"if\s*\(\s*!LittleFS\.begin\(\s*(?:false)?\s*\)\s*\)", setup
    )
    recovery_guard = re.search(
        r"if\s*\(\s*!recoverBlocklistFiles\(\s*\)\s*\)", setup
    )
    assert mount_guard is not None
    assert recovery_guard is not None
    dns_start = setup.index("startDnsServices()", active_load)
    assert mount_guard.start() < dns_start
    assert recovery_guard.start() < dns_start


def test_runtime_blocklist_seek_and_read_failures_mark_storage_unhealthy() -> None:
    lookup = cpp_function(read_main(), "inFlash")

    assert "!blocklist.seek" in lookup
    assert re.search(r"blocklist\.read\([^;]+\)\s*!=\s*HASH_BYTES", lookup)
    assert "blocklistHealthy = false" in lookup


def test_runtime_blocklist_failure_stops_network_instead_of_forwarding() -> None:
    source = read_main()
    dns = cpp_function(source, "handleDns")
    fail_closed = cpp_function(source, "enterStorageFailClosed")

    entry_guard = dns.index('enterStorageFailClosed("runtime blocklist unavailable")')
    parse = dns.index("dnsServer.parsePacket()")
    lookup = dns.index("isBlocked(domain)")
    read_guard = dns.index(
        'enterStorageFailClosed("runtime blocklist read failed")', lookup
    )
    upstream = dns.index("forwardUpstream(qlen)", read_guard)
    assert entry_guard < parse < lookup < read_guard < upstream
    for stopped_service in ("dnsServer.stop()", "upstreamCli.stop()"):
        assert stopped_service in fail_closed
    assert "#include <WebServer" not in source


def test_remote_blocklist_fetching_is_absent_from_production() -> None:
    source = read_main()
    production = read_production_sources()
    forbidden = (
        "setInsecure",
        "/fetchnow",
        "/setupdate",
        "HTTPC_STRICT_FOLLOW_REDIRECTS",
        "HTTPC_FORCE_FOLLOW_REDIRECTS",
        "update.cfg",
        "HTTPClient",
        "NetworkClientSecure",
        "WiFiClientSecure",
        "fetchBlocklist",
        "loadUpdateCfg",
        "saveUpdateCfg",
        "updateUrl",
        "updateIntervalH",
        "beginBlocklistSwap",
        "commitNewBlocklist",
    )

    assert not [token for token in forbidden if token in production]
    assert 'BLOCKLIST_UPLOAD_ROUTE = "/upload"' in source
    assert "handleFixedEnvelopeUpload(request)" in source
    assert "esp_http_server.h" in source
    assert '"/update"' not in source


def test_dashboard_keeps_only_manual_validated_blocklist_upload() -> None:
    page = read_page()
    folded = page.casefold()

    assert 'request("/upload",' in page
    assert "MAX_BLOCKLIST_BYTES=524285" in page
    assert "new Blob([sf,f]" in page
    assert "FormData" not in page
    assert "actualizaciones remotas de listas" in folded
    assert "desactivadas" in folded
    assert "blocklist validados" in folded
    for obsolete_id in ('id="uurl"', 'id="uiv"', 'id="fetch"', 'id="save"'):
        assert obsolete_id not in page


def test_network_firmware_ota_remains_absent() -> None:
    production = read_production_sources()
    routes = set(re.findall(r'web\.on\(\s*"([^"]+)"', production))

    assert "/update" not in routes
    assert "ArduinoOTA" not in production
    assert re.search(r'#\s*include\s*[<"]Update\.h[>"]', production) is None
    assert re.search(r"\bUpdate\s*\.\s*(?:begin|write|end|abort)\s*\(", production) is None
