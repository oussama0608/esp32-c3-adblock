from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_CPP = REPO_ROOT / "src" / "main.cpp"
DNS_PROTOCOL_H = REPO_ROOT / "src" / "dns_protocol.h"
DNS_PROTOCOL_CPP = REPO_ROOT / "src" / "dns_protocol.cpp"
DNS_NATIVE_TEST = REPO_ROOT / "tests" / "native" / "test_dns_protocol.cpp"
NATIVE_FUZZ_ITERATIONS = 100_000
NATIVE_FUZZ_SEED = "0x4E534D"


def _main_source() -> str:
    return MAIN_CPP.read_text(encoding="utf-8")


def _protocol_header_source() -> str:
    return DNS_PROTOCOL_H.read_text(encoding="utf-8")


def _static_function(source: str, name: str) -> str:
    signature = re.search(
        rf"static\s+[\w:<>&*\s]+\b{re.escape(name)}\s*"
        r"\([^;{}]*\)\s*\{",
        source,
    )
    if signature is None:
        raise AssertionError(f"static function not found: {name}")

    opening_brace = source.index("{", signature.start())
    depth = 0
    for index in range(opening_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[signature.start() : index + 1]
    raise AssertionError(f"unterminated function: {name}")


def _function_from_signature(source: str, signature: str) -> str:
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


def _find_vswhere() -> Path:
    candidates: list[Path] = []
    discovered = shutil.which("vswhere.exe")
    if discovered:
        candidates.append(Path(discovered))

    for variable in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(variable)
        if base:
            candidates.append(
                Path(base) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
            )

    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise AssertionError(
        "Visual Studio Build Tools are required for the permanent DNS parser gate; "
        "vswhere.exe was not found"
    )


def _find_vsdevcmd() -> Path:
    vswhere = _find_vswhere()
    completed = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    installations = [line.strip() for line in completed.stdout.splitlines() if line]
    assert completed.returncode == 0 and installations, (
        "Visual Studio C++ x64 Build Tools were not found\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )

    vsdevcmd = Path(installations[-1]) / "Common7" / "Tools" / "VsDevCmd.bat"
    assert vsdevcmd.is_file(), f"VsDevCmd.bat was not found at {vsdevcmd}"
    return vsdevcmd


def _run_in_vs_environment(
    vsdevcmd: Path,
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    extra_environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    comspec = os.environ.get("COMSPEC", "cmd.exe")
    child_command = subprocess.list2cmdline(command)
    command_script = cwd / "run-in-vs-environment.cmd"
    command_script.write_text(
        "@echo off\n"
        f'call "{vsdevcmd}" -no_logo -arch=x64 -host_arch=x64\n'
        "if errorlevel 1 exit /b %errorlevel%\n"
        f"{child_command}\n"
        "exit /b %errorlevel%\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    if extra_environment:
        environment.update(extra_environment)
    return subprocess.run(
        [comspec, "/d", "/c", str(command_script)],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _assert_success(
    completed: subprocess.CompletedProcess[str], operation: str
) -> None:
    assert completed.returncode == 0, (
        f"{operation} failed with exit code {completed.returncode}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )


def test_real_dns_protocol_code_passes_native_asan_corpus(tmp_path: Path) -> None:
    assert DNS_PROTOCOL_CPP.is_file(), f"missing production parser: {DNS_PROTOCOL_CPP}"
    assert DNS_NATIVE_TEST.is_file(), f"missing native harness: {DNS_NATIVE_TEST}"

    vsdevcmd = _find_vsdevcmd()
    executable = tmp_path / "dns_protocol_tests.exe"
    compile_result = _run_in_vs_environment(
        vsdevcmd,
        [
            "cl.exe",
            "/nologo",
            "/std:c++17",
            "/EHsc",
            "/W4",
            "/WX",
            "/Od",
            "/Zi",
            "/fsanitize=address",
            f"/I{REPO_ROOT / 'src'}",
            str(DNS_PROTOCOL_CPP),
            str(DNS_NATIVE_TEST),
            f"/Fe:{executable}",
        ],
        cwd=tmp_path,
        timeout=120,
    )
    _assert_success(compile_result, "native DNS protocol ASan build")
    assert executable.is_file(), "MSVC succeeded without creating the test executable"

    fuzz_result = _run_in_vs_environment(
        vsdevcmd,
        [
            str(executable),
            "--iterations",
            str(NATIVE_FUZZ_ITERATIONS),
            "--seed",
            NATIVE_FUZZ_SEED,
        ],
        cwd=tmp_path,
        timeout=120,
        extra_environment={
            "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=1:detect_leaks=0"
        },
    )
    _assert_success(fuzz_result, "native DNS protocol deterministic fuzz corpus")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DNS_PACKET_MAX_BYTES", 600),
        ("DNS_UPSTREAM_TIMEOUT_MS", 1000),
        ("DNS_STALE_DRAIN_MAX", 8),
        ("DNS_RESPONSE_CANDIDATE_MAX", 8),
    ],
)
def test_dns_resource_and_wait_limits_are_explicit(name: str, value: int) -> None:
    source = _protocol_header_source()
    declarations = re.findall(
        rf"\b{re.escape(name)}\s*=\s*{value}(?:[uUlL]*)\s*;",
        source,
    )
    assert len(declarations) == 1


def test_upstream_path_has_a_separate_bounded_receive_buffer() -> None:
    source = _main_source()

    assert re.search(
        r"\bupstreamBuf\s*\[\s*DNS_PACKET_MAX_BYTES\s*\]",
        source,
    )
    assert "uint8_t buf[600]" not in source
    assert re.search(r"\bbuf\s*\[\s*DNS_PACKET_MAX_BYTES\s*\]", source)


def test_upstream_send_and_reply_attributes_are_checked() -> None:
    source = _main_source()
    forward = _static_function(source, "forwardUpstream")

    assert len(re.findall(r"\besp_random\s*\(", source)) == 1
    for token in (
        "upstreamCli.clear()",
        "upstreamCli.remoteIP()",
        "upstreamCli.remotePort()",
        "UPSTREAM",
        "DNS_PORT",
        "DNS_UPSTREAM_TIMEOUT_MS",
        "DNS_STALE_DRAIN_MAX",
        "DNS_RESPONSE_CANDIDATE_MAX",
    ):
        assert token in forward

    for method in ("beginPacket", "write", "endPacket"):
        assert re.search(
            rf"(?:if\s*\([^;]*|=\s*[^;]*)upstreamCli\.{method}\s*\(",
            forward,
        ), f"upstreamCli.{method}() return value must be checked"
        assert not re.search(
            rf"^\s*upstreamCli\.{method}\s*\([^;]*\)\s*;\s*$",
            forward,
            re.MULTILINE,
        )

    assert re.search(
        r"(?:const\s+)?IPAddress\s+\w+\s*=\s*upstreamCli\.remoteIP\(\)",
        forward,
    )
    assert re.search(
        r"(?:const\s+)?uint16_t\s+\w+\s*=\s*upstreamCli\.remotePort\(\)",
        forward,
    )
    wait_start = forward.index("const uint32_t deadline")
    candidate = forward.index("upstreamCli.parsePacket()", wait_start)
    source_ip = forward.index("upstreamCli.remoteIP()", candidate)
    source_port = forward.index("upstreamCli.remotePort()", source_ip)
    packet_limit = forward.index("DNS_PACKET_MAX_BYTES", source_port)
    assert candidate < source_ip < source_port < packet_limit

    deadline = re.search(
        r"(?:const\s+)?uint32_t\s+(?P<name>\w+)\s*=\s*"
        r"millis\(\)\s*\+\s*DNS_UPSTREAM_TIMEOUT_MS",
        forward,
    )
    assert deadline is not None
    assert re.search(
        rf"static_cast<int32_t>\(\s*{deadline.group('name')}\s*-\s*"
        r"millis\(\)\s*\)\s*>\s*0",
        forward,
    )


def test_client_and_upstream_datagrams_are_never_read_partially() -> None:
    source = _main_source()
    handle = _static_function(source, "handleDns")
    forward = _static_function(source, "forwardUpstream")

    assert "DNS_PACKET_MAX_BYTES" in handle
    assert "dnsServer.clear()" in handle
    assert re.search(
        r"\bsz\s*>\s*static_cast<int>\(DNS_PACKET_MAX_BYTES\)",
        handle,
    )

    assert "DNS_PACKET_MAX_BYTES" in forward
    assert "upstreamCli.clear()" in forward
    assert re.search(r"upstreamCli\.read\(\s*upstreamBuf", forward)
    assert re.search(
        r"(?:if\s*\([^;]*|=\s*[^;]*)"
        r"upstreamCli\.read\(\s*upstreamBuf,",
        forward,
    )
    assert not re.search(
        r"^\s*upstreamCli\.read\(\s*upstreamBuf,[^;]+\)\s*;\s*$",
        forward,
        re.MULTILINE,
    )


def test_dns_forwarding_remains_single_and_synchronous_per_loop_turn() -> None:
    source = _main_source()
    handle = _static_function(source, "handleDns")
    forward = _static_function(source, "forwardUpstream")

    assert handle.count("forwardUpstream(") == 1
    assert source.count("forwardUpstream(") == 2
    assert "DNS_RESPONSE_CANDIDATE_MAX" in forward
    assert len(re.findall(r"while\s*\(", forward)) <= 1

    call = handle.index("forwardUpstream(")
    after_call = handle[call:]
    assert re.search(
        r"\b(?:break|return)\b",
        after_call,
    ), "an allowed query must yield the loop after its single upstream wait"


def test_parse_and_block_decision_precede_any_upstream_send() -> None:
    source = _main_source()
    handle = _static_function(source, "handleDns")

    parse = re.search(r"\bparseClientQuery\s*\(", handle)
    blocked = re.search(r"\bblocked\s*=", handle)
    forward = re.search(r"\bforwardUpstream\s*\(", handle)

    assert parse is not None
    assert blocked is not None
    assert forward is not None
    assert parse.start() < blocked.start() < forward.start()

    blocked_branch = handle[blocked.start() : forward.start()]
    assert "buildBlocked" in blocked_branch


def test_dns_socket_startup_failure_is_remembered_without_false_success() -> None:
    setup = _function_from_signature(_main_source(), "void setup()")

    assert re.search(
        r"upstreamSocketReady\s*=\s*upstreamCli\.begin\(0\)\s*!=\s*0\s*;",
        setup,
    )


def test_query_error_rcodes_and_upstream_servfail_are_explicit() -> None:
    handle = _static_function(_main_source(), "handleDns")

    drop = handle.index("dns_protocol::QueryStatus::DROP")
    invalid = handle.index("queryStatus != dns_protocol::QueryStatus::VALID")
    mapped_code = handle.index("dns_protocol::responseCodeFor(queryStatus)")
    forward = handle.index("forwardUpstream(qlen)")
    server_failure = handle.index("dns_protocol::ResponseCode::SERVER_FAILURE")

    assert drop < invalid < mapped_code < forward < server_failure
    assert handle.count("buildDnsError(") == 2
    assert "continue;" in handle[mapped_code:forward]


def test_allowed_counters_only_advance_after_a_correlated_reply() -> None:
    handle = _static_function(_main_source(), "handleDns")
    forward = handle.index("rlen = forwardUpstream(qlen)")
    success = handle.index("if (rlen > 0)", forward)
    allowed = handle.index("totalAllowed++", success)
    failure = handle.index("dns_protocol::ResponseCode::SERVER_FAILURE", success)

    assert forward < success < allowed < failure
    assert handle.count("totalAllowed++") == 1


def test_root_query_is_valid_but_never_looked_up_in_the_blocklist() -> None:
    handle = _static_function(_main_source(), "handleDns")

    assert re.search(
        r"blocked\s*=\s*ban\s*\|\|\s*\(\s*!query\.root\s*&&\s*"
        r"query\.blocklistNameLength\s*&&.*?isBlocked\(domain\)\s*\)",
        handle,
        re.DOTALL,
    )
    assert re.search(
        r"if\s*\(blocked\)\s*\{.*?buildBlocked\(qlen, query\);.*?\}"
        r"\s*else\s*\{\s*rlen\s*=\s*forwardUpstream\(qlen\);",
        handle,
        re.DOTALL,
    )


def test_upstream_id_is_device_generated_validated_and_restored() -> None:
    forward = _static_function(_main_source(), "forwardUpstream")

    generated = forward.index("esp_random()")
    outbound_id = forward.index("dns_protocol::setTransactionId(", generated)
    write = forward.index("upstreamCli.write(", outbound_id)
    restore_query = forward.index("dns_protocol::setTransactionId(", write)
    validate = forward.index("dns_protocol::validateUpstreamResponse(", restore_query)
    restore_reply = forward.index("dns_protocol::setTransactionId(", validate)

    assert generated < outbound_id < write < restore_query < validate < restore_reply
    assert forward.count("dns_protocol::setTransactionId(") == 3
    assert "dns_protocol::endpointMatches(actualEndpoint, expectedEndpoint)" in forward
