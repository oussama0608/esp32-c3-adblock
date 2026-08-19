from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = REPO_ROOT / "src" / "main.cpp"
PAGE_PATH = REPO_ROOT / "src" / "page.h"
CI_CHECKS_PATH = REPO_ROOT / "tools" / "ci_checks.py"
PLATFORMIO_PATH = REPO_ROOT / "platformio.ini"
README_PATH = REPO_ROOT / "README.md"
DECISIONS_PATH = REPO_ROOT / "docs" / "DECISIONS.md"
PLATFORMIO_GIT_BLOB = "93675edbde6e33d082f6e9325f53aca7f1059ee2"


def read_main() -> str:
    return MAIN_PATH.read_text(encoding="utf-8")


def read_page() -> str:
    return PAGE_PATH.read_text(encoding="utf-8")


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


def test_platformio_configuration_is_canonical_and_ci_protected() -> None:
    actual_blob = subprocess.run(
        [
            "git",
            "hash-object",
            "--path=platformio.ini",
            str(PLATFORMIO_PATH),
        ],
        cwd=REPO_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout.decode("ascii").strip()
    ci_checks = CI_CHECKS_PATH.read_text(encoding="utf-8")

    assert actual_blob == PLATFORMIO_GIT_BLOB
    assert (
        f'"platformio.ini": "{PLATFORMIO_GIT_BLOB}"'
        in ci_checks
    )
    assert ci_checks.count('"platformio.ini"') >= 2


def test_dashboard_uses_external_script_without_inline_event_handlers() -> None:
    page = read_page()

    assert '<script src="/app.js" defer></script>' in page
    assert re.search(r"<script\b(?![^>]*\bsrc\s*=)", page, re.IGNORECASE) is None
    assert re.search(r"\son[a-z]+\s*=", page, re.IGNORECASE) is None
    assert ".innerHTML" not in page


def test_dashboard_builds_untrusted_content_with_dom_text_apis() -> None:
    page = read_page()

    required_dom_apis = (
        "document.createElement",
        ".textContent",
        ".replaceChildren",
        ".addEventListener",
    )
    assert all(api in page for api in required_dom_apis)
    assert "eval(" not in page
    assert "document.write(" not in page
    assert "insertAdjacentHTML(" not in page


def test_dashboard_mutations_are_posted_with_session_csrf_header() -> None:
    page = read_page()
    csrf_helper = page.split("function csrfHeaders()", 1)[1].split(
        "async function post", 1
    )[0]
    post_helper = page.split("async function post(path,fields)", 1)[1].split(
        "async function action", 1
    )[0]

    assert '"X-CSRF-Token":csrf' in csrf_helper
    assert "csrfHeaders()" in post_helper
    assert 'method:"POST"' in post_helper
    assert 'post("/logout"' in page
    for removed_route in ("/ban", "/addblock", "/unblock", "/forgetwifi"):
        assert removed_route not in page

    upload = page.split("upf.addEventListener", 1)[1]
    assert 'method:"POST"' in upload
    assert "const headers=csrfHeaders()" in upload


def test_dashboard_redirects_unauthenticated_requests_to_login() -> None:
    page = read_page()

    assert "r.status===401" in page
    assert 'location.assign("/login")' in page


def test_admin_verifier_uses_fixed_pbkdf2_sha256_parameters() -> None:
    source = read_main()
    derive = cpp_function(source, "deriveAdminVerifier")

    expected_constants = {
        "ADMIN_PASSWORD_MIN_LENGTH": "12",
        "ADMIN_PASSWORD_MAX_LENGTH": "128",
        "ADMIN_PBKDF2_ITERATIONS": "50000",
        "ADMIN_SALT_BYTES": "16",
        "ADMIN_VERIFIER_BYTES": "32",
    }
    for name, value in expected_constants.items():
        assert re.search(rf"\b{re.escape(name)}\s*=\s*{value}\s*;", source)

    assert "mbedtls_pkcs5_pbkdf2_hmac_ext(" in derive
    assert "MBEDTLS_MD_SHA256" in derive
    assert "ADMIN_SALT_BYTES" in derive
    assert "ADMIN_VERIFIER_BYTES" in derive


def test_admin_verifier_uses_random_salt_constant_time_compare_and_zeroing() -> None:
    source = read_main()
    create = cpp_function(source, "createAdminVerifier")
    verify = cpp_function(source, "verifyAdminPassword")
    zero = cpp_function(source, "secureZero")

    assert "esp_fill_random(record.salt, sizeof(record.salt))" in create
    assert "mbedtls_ct_memcmp(" in verify
    assert "memcmp(" not in verify.replace("mbedtls_ct_memcmp(", "")
    assert verify.count("secureZero(") >= 2
    assert "#include <mbedtls/platform_util.h>" in source
    assert "mbedtls_platform_zeroize(data, length)" in zero


def test_admin_nvs_stores_only_versioned_salt_and_verifier() -> None:
    source = read_main()
    create = cpp_function(source, "createAdminVerifier")
    load = cpp_function(source, "loadAdminVerifier")

    assert 'ADMIN_NAMESPACE = "admin"' in source
    assert 'putUChar("version"' in create
    assert 'putUInt("iterations"' in create
    assert 'putBytes("salt"' in create
    assert 'putBytes("verifier"' in create
    assert "putString(" not in create
    assert 'getBytes("salt"' in load
    assert 'getBytes("verifier"' in load
    assert re.search(
        r"(?i)put(?:string|bytes)\([^;\n]*(?:session|csrf)", source
    ) is None


def test_no_admin_password_or_active_token_is_hard_coded_or_persisted() -> None:
    source = read_main()
    literal_assignments = re.finditer(
        r"(?im)^\s*(?:static\s+)?(?:constexpr\s+)?(?:const\s+)?"
        r"(?:char\s*\*|String)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*"
        r'"(?P<value>[^"]*)"',
        source,
    )
    sensitive_literals: list[str] = []
    for assignment in literal_assignments:
        name = assignment.group("name").casefold()
        is_admin_password = "admin" in name and "pass" in name
        is_active_token = "token" in name and (
            "session" in name or "csrf" in name
        )
        if (is_admin_password or is_active_token) and assignment.group("value"):
            sensitive_literals.append(name)

    assert sensitive_literals == []
    assert "adminPrefs.putString(" not in source


def test_admin_session_and_csrf_tokens_are_random_ram_only_and_expire() -> None:
    source = read_main()
    start = cpp_function(source, "startAdminSession")
    current = cpp_function(source, "adminSessionIsCurrent")
    clear = cpp_function(source, "clearAdminSession")

    assert re.search(r"\bSESSION_TOKEN_BYTES\s*=\s*32\s*;", source)
    assert re.search(r"\bCSRF_TOKEN_BYTES\s*=\s*32\s*;", source)
    assert re.search(
        r"\bSESSION_LIFETIME_MS\s*=\s*30UL\s*\*\s*60UL\s*\*\s*1000UL\s*;",
        source,
    )
    assert "esp_fill_random(adminSessionToken, sizeof(adminSessionToken))" in start
    assert "esp_fill_random(adminCsrfToken, sizeof(adminCsrfToken))" in start
    assert "SESSION_LIFETIME_MS" in current
    assert "clearAdminSession()" in current
    assert "secureZero(adminSessionToken" in clear
    assert "secureZero(adminCsrfToken" in clear


def test_session_and_csrf_comparisons_are_constant_time() -> None:
    source = read_main()
    session = cpp_function(source, "requestHasAdminSession")
    csrf = cpp_function(source, "requestHasValidCsrf")

    assert 'web.header("Cookie")' in session
    assert "mbedtls_ct_memcmp(" in session
    assert "secureZero(candidate" in session
    assert 'web.header("X-CSRF-Token")' in csrf
    assert "mbedtls_ct_memcmp(" in csrf
    assert "secureZero(candidate" in csrf


def test_login_throttle_is_ram_only_bounded_and_increasing() -> None:
    source = read_main()
    delay = cpp_function(source, "loginDelayMs")
    failure = cpp_function(source, "recordLoginFailure")
    reset = cpp_function(source, "resetLoginThrottle")

    for fragment in (
        "failures < 3",
        "failures == 3",
        "return 5000",
        "failures == 4",
        "return 10000",
        "failures == 5",
        "return 20000",
        "return 30000",
    ):
        assert fragment in delay
    assert "loginFailures++" in failure
    assert "loginBlockedUntilMs" in failure
    assert "loginFailures = 0" in reset
    assert "loginBlockedUntilMs = 0" in reset
    assert re.search(
        r"(?i)put(?:u?int|u?char|bytes|string)\([^;\n]*(?:failure|blockeduntil)",
        source,
    ) is None


def test_host_allowlist_uses_collected_header_and_rejects_other_hosts() -> None:
    source = read_main()
    helper = cpp_function(source, "isAllowedAdminHost")
    authorization = cpp_function(source, "adminAuthorizationStatus")

    assert 'host.endsWith(":80")' in helper
    assert "host.indexOf(':') >= 0" in helper
    assert "host == allowedIp" in helper
    assert "return false" in helper
    assert 'web.header("Host")' in authorization
    assert "WiFi.softAPIP().toString()" in authorization
    assert "hostHeader(" not in source


def test_security_headers_are_local_http_appropriate() -> None:
    source = read_main()
    headers = cpp_function(source, "addSecurityHeaders")

    required = (
        '"Cache-Control", "no-store"',
        '"X-Content-Type-Options", "nosniff"',
        '"Referrer-Policy", "no-referrer"',
        '"Content-Security-Policy"',
        "default-src 'none'",
        "script-src 'self'",
        "img-src 'none'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
    assert all(fragment in headers for fragment in required)
    assert "Strict-Transport-Security" not in source


def test_html_escape_encodes_all_five_html_metacharacters() -> None:
    helper = cpp_function(read_main(), "htmlEscape")

    assert all(
        entity in helper
        for entity in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;")
    )
    assert "case '&'" in helper
    assert "case '<'" in helper
    assert "case '>'" in helper
    assert "case '\"'" in helper
    assert "case '\\''" in helper


def test_json_escape_handles_quotes_backslashes_and_all_control_bytes() -> None:
    helper = cpp_function(read_main(), "jsonEscape")

    for escaped in (r'\"', r"\\", r"\b", r"\f", r"\n", r"\r", r"\t"):
        assert escaped in helper
    assert "ch < 0x20" in helper
    assert r'"\\u00"' in helper


def test_configured_values_are_encoded_at_their_output_contexts() -> None:
    source = read_main()
    stats = cpp_function(source, "handleStats")
    wifi_save = cpp_function(source, "handleWifiSave")

    assert "jsonEscape(customDom[i])" in stats
    assert "WiFi.scanNetworks" not in source
    assert "htmlEscape(ss)" in wifi_save


def test_http_route_inventory_and_methods_are_exact() -> None:
    source = read_main()
    assert 'BLOCKLIST_UPLOAD_ROUTE = "/upload"' in source
    server_source = source[source.index("static bool startBoundedHttpServer(bool provisioning) {") :]
    server = cpp_function(server_source, "startBoundedHttpServer")
    for route in ('registerUri("/", HTTP_GET', 'registerUri("/login", HTTP_GET',
                  'registerUri("/login", HTTP_POST', 'registerUri("/logout", HTTP_POST',
                  'registerUri("/app.js", HTTP_GET', 'registerUri("/stats.json", HTTP_GET',
                  'registerUri(BLOCKLIST_UPLOAD_ROUTE, HTTP_POST',
                  'registerUri("/*", HTTP_GET', 'registerUri("/wifisave", HTTP_POST'):
        assert route in server
    for removed_route in ("/ban", "/addblock", "/unblock", "/forgetwifi"):
        assert f'"{removed_route}"' not in source


def test_all_normal_mode_state_changes_are_post_only() -> None:
    source = read_main()
    server_source = source[source.index("static bool startBoundedHttpServer(bool provisioning) {") :]
    server = cpp_function(server_source, "startBoundedHttpServer")
    assert 'registerUri("/logout", HTTP_POST' in server
    assert 'registerUri(BLOCKLIST_UPLOAD_ROUTE, HTTP_POST' in server
    assert 'registerUri("/wifisave", HTTP_POST' in server
    for removed_route in ("/ban", "/addblock", "/unblock", "/forgetwifi"):
        assert f'"{removed_route}"' not in source


def test_admin_read_routes_require_session_and_host_authorization() -> None:
    source = read_main()

    for handler in ("handleDashboardRoot", "handleAppJs", "handleStats"):
        body = cpp_function(source, handler)
        assert "requireAdminRead(" in body
        assert body.index("requireAdminRead(") < body.index("web.send")

    authorization = cpp_function(source, "adminAuthorizationStatus")
    read_guard = cpp_function(source, "requireAdminRead")
    mutation_guard = cpp_function(source, "requireAdminMutation")
    assert "requestHasAdminSession()" in authorization
    assert "requireCsrf && !requestHasValidCsrf()" in authorization
    assert "return 401" in authorization
    assert "return 403" in authorization
    assert authorization.index("isAllowedAdminHost(") < authorization.index(
        "requestHasAdminSession()"
    ) < authorization.index("requestHasValidCsrf()")
    assert "adminAuthorizationStatus(false)" in read_guard
    assert "adminAuthorizationStatus(true)" in mutation_guard


def test_dashboard_root_redirects_to_fixed_login_path_only_after_host_check() -> None:
    source = read_main()
    root = cpp_function(source, "handleDashboardRoot")
    guard = cpp_function(source, "requireAdminRead")

    assert "requireAdminRead(true)" in root
    assert "status == 401 && redirectUnauthenticated" in guard
    assert 'web.sendHeader("Location", "/login")' in guard
    assert "web.send(303" in guard
    assert guard.index("adminAuthorizationStatus(false)") < guard.index(
        'web.sendHeader("Location", "/login")'
    )


def test_verbose_core_request_logging_is_compile_time_forbidden() -> None:
    source = read_main()

    assert "ARDUHAL_LOG_LEVEL >= ARDUHAL_LOG_LEVEL_VERBOSE" in source
    assert "Verbose Arduino core logging can expose WiFi/admin form values" in source


def test_admin_mutation_guards_precede_each_state_change() -> None:
    source = read_main()
    mutations = {
        "handleLogout": "clearAdminSession()",
        "handleBan": "c->banned = !c->banned",
        "handleAddBlock": 'addCustom(web.arg("d"))',
        "handleUnblock": 'removeCustom(web.arg("d"))',
        "handleForgetWifi": "clearWifiCredentials()",
    }

    for handler, mutation in mutations.items():
        body = cpp_function(source, handler)
        assert "requireAdminMutation()" in body
        assert body.index("requireAdminMutation()") < body.index(mutation)


def test_upload_is_authorized_before_any_blocklist_swap_or_write() -> None:
    source = read_main()
    envelope = cpp_function(source, "handleFixedEnvelopeUpload")
    upload = cpp_function(source, "handleUpload")
    done = cpp_function(source, "handleUploadDone")
    start = upload.split("case UPLOAD_FILE_START:", 1)[1].split(
        "case UPLOAD_FILE_WRITE:", 1
    )[0]
    write = upload.split("case UPLOAD_FILE_WRITE:", 1)[1].split(
        "case UPLOAD_FILE_END:", 1
    )[0]
    end = upload.split("case UPLOAD_FILE_END:", 1)[1].split(
        "case UPLOAD_FILE_ABORTED:", 1
    )[0]

    assert "requireAdminMutation()" in envelope
    assert envelope.index("requireAdminMutation()") < envelope.index("handleUpload(start)")
    assert "!uploadAuthorized || !uploadProofEnvelopeValid" in start
    assert "uploadAuthorized" in write
    assert "upFile" in write
    assert "if (!uploadAuthorized) break" in end
    assert "requireAdminMutation()" in done
    assert done.index("requireAdminMutation()") < done.index(
        "promoteBlocklistCandidate(uploadDeadlineReached)"
    )


def test_session_cookie_flags_lifetime_and_logout_invalidation() -> None:
    source = read_main()
    login = cpp_function(source, "handleLoginPost")
    logout = cpp_function(source, "handleLogout")

    for flag in ("HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=1800"):
        assert flag in login
    assert "; Secure" not in login
    assert "startAdminSession()" in login
    assert "verifyAdminPassword(password)" in login
    assert login.index("verifyAdminPassword(password)") < login.index(
        "startAdminSession()"
    )

    assert "requireAdminMutation()" in logout
    assert "clearAdminSession()" in logout
    assert "Max-Age=0" in logout
    assert logout.index("requireAdminMutation()") < logout.index(
        "clearAdminSession()"
    )


def test_login_routes_validate_host_and_do_not_log_sensitive_values() -> None:
    source = read_main()
    login_get = cpp_function(source, "handleLoginGet")
    login_post = cpp_function(source, "handleLoginPost")

    assert "requireAllowedAdminHost()" in login_get
    assert "requireAllowedAdminHost()" in login_post
    assert "loginIsBlocked()" in login_post
    assert "clearSensitiveString(password)" in login_post
    assert not re.search(r"(?i)Serial\.printf\([^\n;]*password[^\n;]*\.c_str", source)
    assert not re.search(r"(?i)Serial\.printf\([^\n;]*(?:sessiontoken|csrftoken)", source)


def test_setup_does_not_authorize_or_erase_from_early_boot_pin_reads() -> None:
    source = read_main()
    setup = cpp_function(source, "setup")

    assert "pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP)" in setup
    assert "digitalRead(" not in setup
    assert "bootHoldReached(" not in setup
    assert "clearWifiCredentials()" not in setup
    assert "clearAdminVerifier()" not in setup
    assert "physicalProvisioningAllowed =" not in setup
    assert "delay(60)" not in setup
    assert "if (!hasAdminVerifier())" in setup
    assert "startConfigPortal(false)" not in setup
    assert "runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED" in setup


def test_boot_hold_state_requires_release_and_a_continuous_timed_press() -> None:
    source = read_main()
    hold = cpp_function(source, "bootHoldReached")
    stable_release = cpp_function(source, "bootReleasedStable")

    assert "PORTAL_BOOT_HOLD_MS = 3000" in source
    assert "RUNTIME_BOOT_HOLD_MS = 5000" in source
    assert "digitalRead(BOOT_BUTTON_PIN) == LOW" in hold
    assert "delay(" not in hold
    assert "while (" not in hold

    release = hold.index("if (!pressed)")
    armed = hold.index("state.releaseObserved = true", release)
    tracking_reset = hold.index("state.tracking = false", armed)
    handled_reset = hold.index("state.handled = false", tracking_reset)
    timestamp_reset = hold.index("state.pressedSinceMs = 0", handled_reset)
    release_return = hold.index("return false", timestamp_reset)
    assert release < armed < tracking_reset < handled_reset < timestamp_reset
    assert timestamp_reset < release_return

    require_release = hold.index("if (!state.releaseObserved || state.handled)")
    start_tracking = hold.index("if (!state.tracking)", require_release)
    start_time = hold.index("state.pressedSinceMs = millis()", start_tracking)
    short_press_return = hold.index("return false", start_time)
    threshold = hold.index(
        "if (millis() - state.pressedSinceMs < thresholdMs) return false;",
        short_press_return,
    )
    handled = hold.index("state.handled = true", threshold)
    assert require_release < start_tracking < start_time < short_press_return
    assert short_press_return < threshold < handled

    assert "digitalRead(BOOT_BUTTON_PIN) == LOW" in stable_release
    assert "state.tracking = false" in stable_release
    assert "state.releasedSinceMs = 0" in stable_release
    assert "state.releasedSinceMs = millis()" in stable_release
    assert "millis() - state.releasedSinceMs >= BOOT_RELEASE_STABLE_MS" in stable_release
    assert "delay(" not in stable_release


def test_provisioning_requires_recovery_and_rotates_csrf() -> None:
    source = read_main()
    portal_root = cpp_function(source, "handlePortalRoot")
    wifi_save = cpp_function(source, "handleWifiSave")
    start_portal = cpp_function(source, "startConfigPortal")
    refresh_csrf = cpp_function(source, "refreshProvisioningCsrf")
    csrf = cpp_function(source, "validProvisioningCsrf")

    assert "if (!physicalProvisioningAllowed)" in portal_root
    assert "action=/wifisave" in portal_root
    assert "if (!physicalProvisioningAllowed)" in wifi_save
    assert "validProvisioningCsrf()" in wifi_save
    assert "pendingProvisioningAdminPassword = adminPassword" in wifi_save
    assert "secureZero(provisioningCsrf" in refresh_csrf
    assert "esp_fill_random(provisioningCsrf" in refresh_csrf
    assert refresh_csrf.index("secureZero(") < refresh_csrf.index("esp_fill_random(")
    assert "if (!authorized)" in start_portal
    assert start_portal.index("if (!authorized)") < start_portal.index(
        "WiFi.softAP(ap, psk.c_str(), 1, false, 1)"
    )
    assert start_portal.index("WiFi.softAP(ap, psk.c_str(), 1, false, 1)") < start_portal.index("refreshProvisioningCsrf()")
    assert "mbedtls_ct_memcmp(" in csrf


def test_provisioning_save_defers_persistence_until_candidate_validation() -> None:
    source = read_main()
    wifi_save = cpp_function(source, "handleWifiSave")
    lock = wifi_save.index("physicalProvisioningAllowed = false")
    clear_csrf = wifi_save.index("secureZero(provisioningCsrf", lock)
    pending = wifi_save.index("provisioningCandidatePending = true")
    response = wifi_save.index("web.send(200", pending)
    assert pending < lock < clear_csrf < response
    assert "ESP.restart()" not in wifi_save
    supervisor = cpp_function(source, "processProvisioningCandidate")
    assert supervisor.index("validateProvisioningCandidateSta()") < supervisor.index("commitProvisioningCandidate(")


def test_runtime_recovery_requires_five_seconds_then_release_before_restart() -> None:
    source = read_main()
    recovery = cpp_function(source, "handleRuntimeBootRecovery")
    loop = cpp_function(source, "loop")
    clear_session = cpp_function(source, "clearAdminSession")

    pending_branch, hold_branch = recovery.split(
        "if (!bootHoldReached(runtimeBootHold, RUNTIME_BOOT_HOLD_MS)) return;",
        1,
    )
    assert "if (runtimeRecoveryPending)" in pending_branch
    assert "bootReleasedStable(runtimeRecoveryRelease)" in pending_branch
    assert pending_branch.index("BOOT released") < pending_branch.index("ESP.restart()")

    clear_wifi = hold_branch.index("clearWifiCredentials()")
    clear_admin = hold_branch.index("clearAdminVerifier()", clear_wifi)
    clear_runtime_session = hold_branch.index("clearAdminSession()", clear_admin)
    set_pending = hold_branch.index("runtimeRecoveryPending = true", clear_runtime_session)
    assert clear_wifi < clear_admin < clear_runtime_session < set_pending
    assert "ESP.restart()" not in hold_branch
    assert "bootGesture.update" in loop
    assert "adminSessionActive = false" in clear_session
    assert "secureZero(adminSessionToken" in clear_session
    assert "secureZero(adminCsrfToken" in clear_session


def test_application_recovery_instructions_never_require_boot_during_reset() -> None:
    source = read_main()
    readme = README_PATH.read_text(encoding="utf-8")
    decisions = DECISIONS_PATH.read_text(encoding="utf-8")
    application_docs = f"{source}\n{readme}\n{decisions}"

    forbidden = (
        re.compile(r"Reinicia\s+manteniendo BOOT", re.IGNORECASE),
        re.compile(r"hold the \*\*BOOT\*\* button while\s+powering on", re.IGNORECASE),
        re.compile(r"mediante BOOT\s+al arrancar", re.IGNORECASE),
        re.compile(r"BOOT held ->\s+cleared saved WiFi", re.IGNORECASE),
    )
    assert not [pattern.pattern for pattern in forbidden if pattern.search(application_docs)]
    assert "Con el dispositivo ya encendido" in source
    assert "durante 3 segundos" in source


def test_softap_failure_is_checked_before_portal_services_or_success_message() -> None:
    portal = cpp_function(read_main(), "startConfigPortal")

    mode = portal.index("const bool apModeOk = WiFi.mode(WIFI_AP)")
    softap = portal.index("const bool softApOk = apConfigOk && WiFi.softAP", mode)
    failure = portal.index("if (!softApOk || !applyC3RfWorkaround() || !startBoundedHttpServer(true))", softap)
    csrf = portal.index("refreshProvisioningCsrf()", failure)
    dns = portal.index("dnsPortal.start", csrf)
    assert mode < softap < failure < csrf < dns
    failed_path = portal[failure:csrf]
    assert "runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED" in failed_path
    assert "ESP.restart()" not in failed_path


def test_provisioning_inputs_have_wifi_and_admin_length_bounds() -> None:
    wifi_save = cpp_function(read_main(), "handleWifiSave")

    assert "ss.length() > 32" in wifi_save
    assert "pw.length() > 63" in wifi_save
    assert "validAdminPasswordLength(adminPassword)" in wifi_save


def test_normal_mode_not_found_handler_also_rejects_untrusted_host() -> None:
    not_found = cpp_function(read_main(), "handleNotFound")

    assert "requireAllowedAdminHost()" in not_found
    assert not_found.index("requireAllowedAdminHost()") < not_found.index("web.send")


def test_required_request_headers_are_collected_explicitly() -> None:
    source = read_main()
    server_source = source[source.index("static bool startBoundedHttpServer(bool provisioning) {") :]
    server = cpp_function(server_source, "startBoundedHttpServer")

    for header in ('"Host"', '"Cookie"', '"X-CSRF-Token"'):
        assert header in read_main()
    assert "httpd_req_get_hdr_value" in read_main()
    assert "max_req_hdr_len = HTTP_MAX_HEADER_BYTES" in server


def test_successful_admin_pages_and_json_receive_security_headers() -> None:
    source = read_main()

    for handler in (
        "sendLoginPage",
        "handleDashboardRoot",
        "handleAppJs",
        "handleStats",
    ):
        body = cpp_function(source, handler)
        assert "addSecurityHeaders()" in body
        assert body.index("addSecurityHeaders()") < body.index("web.send")


def test_network_firmware_update_surface_remains_absent() -> None:
    source = read_main() + "\n" + read_page()
    routes = set(re.findall(r'web\.on\(\s*"([^"]+)"', source))

    assert "/update" not in routes
    assert "ArduinoOTA" not in source
    assert re.search(r'#\s*include\s*[<"]Update\.h[>"]', source) is None
    assert re.search(r"\bUpdate\s*\.\s*(?:begin|write|end|abort)\s*\(", source) is None
