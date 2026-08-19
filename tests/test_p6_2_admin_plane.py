from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src" / "main.cpp").read_text(encoding="utf-8")


def _function(name: str) -> str:
    start = SOURCE.index(name)
    opening = SOURCE.index("{", start)
    depth = 0
    for index in range(opening, len(SOURCE)):
        depth += SOURCE[index] == "{"
        depth -= SOURCE[index] == "}"
        if depth == 0:
            return SOURCE[start : index + 1]
    raise AssertionError(name)


def test_normal_mode_has_no_http_listener_or_mdns() -> None:
    setup = _function("void setup()")
    assert "startBoundedHttpServer" not in setup
    assert "MDNS" not in SOURCE and "ESPmDNS" not in SOURCE
    assert "runtimeState = RuntimeState::DNS_ONLY" in setup


def test_admin_ap_requires_stored_wpa2_psk_and_is_single_client() -> None:
    portal = _function("static bool startConfigPortal")
    admin = _function("static bool startAdminApWindow")
    for body in (portal, admin):
        assert "loadAdminApPsk(psk)" in body
        assert "WiFi.softAP(ap, psk.c_str(), 1, false, 1)" in body
        assert "WIFI_AP" in body


def test_provisioning_candidate_is_not_persisted_by_form_handler() -> None:
    handler = _function("static void handleWifiSave")
    assert "pendingProvisioningSsid = ss" in handler
    assert "provisioningCandidatePending = true" in handler
    assert "createAdminVerifier" not in handler
    assert 'prefs.putString("ssid"' not in handler
    assert "commitProvisioningCandidate" not in handler


def test_candidate_is_validated_before_complete_ab_commit() -> None:
    supervisor = _function("static void processProvisioningCandidate")
    assert supervisor.index("validateProvisioningCandidateSta()") < supervisor.index("commitProvisioningCandidate(")
    assert "startConfigPortal(true)" in supervisor
    commit = _function("static bool commitProvisioningCandidate")
    assert "config.putBytes(inactive" in commit
    assert "memcmp(&readback, &next" in commit
    assert "validConfigRecord(readback)" in commit


def test_fixed_envelope_requires_authenticated_signed_length_before_staging() -> None:
    upload = _function("static esp_err_t handleFixedEnvelopeUpload")
    assert "requestHasOctetStreamContentType()" in upload
    assert "parseStrictContentLength" in upload
    assert "requestHasTransferEncoding()" in upload
    assert "const bool hasTransferEncoding" in upload
    assert "request->content_len != 0" in upload
    assert "declared > BLOCKLIST_PROOF_BYTES" in upload
    assert "declared <= BLOCKLIST_UPLOAD_REQUEST_MAX" in upload
    transfer_encoding = upload.index("requestHasTransferEncoding()")
    framing_rejection = upload.index("if (!trustedFraming)")
    upload_start = upload.index("uploadWindowBudget.recordUploadStart()")
    proof = upload.index("reader.readExact(uploadProof, sizeof(uploadProof))")
    verified = upload.index("validateBlocklistProofEnvelope(uploadProof)", proof)
    expected = upload.index("readLittleEndian32(uploadProof + kBlocklistPayloadSizeOffset)", verified)
    length_matches = upload.index("fixed_envelope::hasAllowedPayloadLength", expected)
    start = upload.index("handleUpload(start)", length_matches)
    assert transfer_encoding < framing_rejection < upload_start < proof < start
    assert proof < verified < expected < length_matches < start
    assert "streamAuthenticatedBlocklistPayload(" in upload
    assert "reader, expectedPayloadLength, &payloadReceiveStatus" in upload
    assert "uploadWindowBudget.recordUploadStart()" in upload
    assert "uploadRequestInFlight = true" in upload
    done = _function("static bool handleUploadDone")
    assert "const bool promotionSucceeded = handleUploadDone();" in upload
    assert "uploadWindowBudget.recordPromotion(true)" in done


def test_p6_2_fixed_size_buffers_have_matching_input_bounds() -> None:
    form = _function("static admin_http_policy::FormReadOutcome readRequiredForm")
    reader = (ROOT / "src" / "fixed_envelope.h").read_text(encoding="utf-8")
    upload = _function("static esp_err_t handleFixedEnvelopeUpload")

    assert "HTTP_FORM_MAX_BYTES = 2048" in SOURCE
    assert "requestLength > HTTP_FORM_MAX_BYTES" in form
    assert "static char body[HTTP_FORM_MAX_BYTES + 1]" in form
    assert "char buffer_[512]" in reader
    assert "readExact(uint8_t* output, size_t outputLength)" in reader
    assert "uint8_t output[256]" in SOURCE
    assert "BLOCKLIST_PROOF_BYTES = kBlocklistProofSize" in SOURCE
    assert "BLOCKLIST_UPLOAD_REQUEST_MAX" in upload


def test_signed_upload_transport_has_no_header_or_multipart_proof_source() -> None:
    page = (ROOT / "src" / "page.h").read_text(encoding="utf-8")
    assert "X-Blocklist-Proof" not in SOURCE
    assert "X-Blocklist-Proof" not in page
    assert "multipart/form-data" not in SOURCE
    assert "FormData" not in page
    assert "application/octet-stream" in SOURCE
    assert "new Blob([sf,f]" in page
    assert "f.size<1" in page


def test_p6_2_production_sources_contain_no_temporary_hil_residue() -> None:
    production = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in ("src/main.cpp", "src/admin_state.h", "src/admin_state.cpp")
    )

    for token in ("P62_HIL", "p62Hil", "[p62-hil]", "[p62-wifi]", "armedForRuntimeGesture"):
        assert token not in production


def test_admin_window_uses_exact_normal_and_hard_deadlines() -> None:
    state_header = (ROOT / "src" / "admin_state.h").read_text(encoding="utf-8")
    state_source = (ROOT / "src" / "admin_state.cpp").read_text(encoding="utf-8")
    loop = _function("void loop()")
    upload = _function("static esp_err_t handleFixedEnvelopeUpload")
    done = _function("static bool handleUploadDone")

    assert "acceptsNewAdminWork" in state_header
    assert "mustCloseAdminWindow" in state_header
    assert "kAdminHardCeilingMs" in state_source
    assert "uploadInFlight" in state_source
    assert "!admin_state::acceptsNewAdminWork" in upload
    assert "uploadDeadlineReached()" in done
    assert "admin_state::mustCloseAdminWindow" in loop


def test_receive_failures_are_distinguished_and_close_the_handler() -> None:
    upload = _function("static esp_err_t handleFixedEnvelopeUpload")
    adapter = _function("static fixed_envelope::ReceiveResult receiveEnvelopeBytes")
    reader = (ROOT / "src" / "fixed_envelope.h").read_text(encoding="utf-8")

    assert "HTTPD_SOCK_ERR_TIMEOUT" in adapter
    assert "ReceiveStatus::TIMEOUT" in adapter
    assert "ReceiveStatus::END_OF_BODY" in adapter
    assert "ReceiveStatus::ERROR" in adapter
    assert "receiveFailureRequiresClose" in upload
    assert "return receiveFailureRequiresClose(proofRead) ? ESP_FAIL : ESP_OK;" in upload
    assert "return status != fixed_envelope::ReceiveStatus::OK;" in SOURCE
    assert "ReceiveStatus::DEADLINE" in reader


def test_upload_deadline_covers_the_admin_hard_ceiling_and_promotion() -> None:
    upload = _function("static esp_err_t handleFixedEnvelopeUpload")
    done = _function("static bool handleUploadDone")
    state = (ROOT / "src" / "admin_state.cpp").read_text(encoding="utf-8")

    assert "uploadDeadlineDuration(adminWindowStartedMs, uploadStartedMs)" in upload
    assert "uploadDeadlineReached(millis(), adminWindowStartedMs, uploadStartedMs)" in SOURCE
    assert "if (uploadDeadlineReached())" in done
    assert done.index("requireAdminMutation()") < done.index(
        "promoteBlocklistCandidate(uploadDeadlineReached)"
    )
    assert "kAdminHardCeilingMs" in state


def test_orphan_cleanup_runs_only_from_boot_recovery_and_preserves_active() -> None:
    recovery = _function("static bool recoverBlocklistFiles")
    cleanup = _function("static bool cleanupOrphanedBlocklistUpload")

    assert "removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)" in cleanup
    assert "removeBlocklistFile(BLOCKLIST_NEW_PATH)" in cleanup
    assert cleanup.index("BLOCKLIST_NEW_AUTH_PATH") < cleanup.index("BLOCKLIST_NEW_PATH")
    assert recovery.count("cleanupOrphanedBlocklistUpload()") >= 2
    assert "removeBlocklistFile(BLOCKLIST_PATH)" not in cleanup


def test_p6_2_config_record_lengths_are_bounded_before_fixed_buffer_copy() -> None:
    valid = _function("static bool validConfigRecord")
    commit = _function("static bool commitProvisioningCandidate")

    assert "char ssid[33]" in SOURCE
    assert "char password[64]" in SOURCE
    assert "record.ssidLength > 0 && record.ssidLength <= 32" in valid
    assert "record.passwordLength <= 63" in valid
    assert "record.ssid[record.ssidLength] == '\\0'" in valid
    assert "record.password[record.passwordLength] == '\\0'" in valid
    assert "next.ssid[next.ssidLength] = '\\0'" in commit
    assert "next.password[next.passwordLength] = '\\0'" in commit


def test_commercial_mutation_routes_are_absent() -> None:
    page = (ROOT / "src" / "page.h").read_text(encoding="utf-8")
    for route in ("/ban", "/addblock", "/unblock", "/forgetwifi"):
        assert f'"{route}"' not in SOURCE
        assert route not in page


def test_provisioning_is_recovery_only_not_an_ordinary_boot_or_admin_action() -> None:
    setup = _function("void setup()")
    loop = _function("void loop()")
    portal = _function("static bool startConfigPortal")

    assert "startConfigPortal(false)" not in setup
    assert "OFFLINE_RECOVERY_REQUIRED" in setup
    assert "if (!authorized)" in portal
    assert portal.index("if (!authorized)") < portal.index("loadAdminApPsk(psk)")
    assert "admin_state::bootActionFor(runtimeState, gesture)" in loop
    assert "BootAction::OPEN_PROVISIONING" in loop
    assert "BootAction::OPEN_ADMIN" in loop
    provisioning = loop.split("if (runtimeState == RuntimeState::PROVISIONING_AP)", 1)[1]
    assert "BootGesture::ADMIN_WINDOW" not in provisioning
    assert "BootGesture::RECOVERY" not in provisioning


def test_form_parser_and_transport_failure_close_policy_are_production_helpers() -> None:
    policy = (ROOT / "src" / "admin_http_policy.h").read_text(encoding="utf-8")
    form = _function("static admin_http_policy::FormReadOutcome readRequiredForm")
    admin_post = _function("static esp_err_t dispatchAdminPost")
    provisioning_post = _function("static esp_err_t dispatchProvisioningPost")

    assert "parseStrictDecimal" in policy
    assert "byte < '0' || byte > '9'" in policy
    assert "maximum / 10" in policy
    assert "FormReadStatus::TIMEOUT" in form
    assert "formFramingOutcome" in form
    assert "formReceiveStatus" in form
    assert "mustCloseConnection(form) ? ESP_FAIL" in admin_post
    assert "mustCloseConnection(form) ? ESP_FAIL" in provisioning_post


def test_upload_rejections_close_when_declared_body_is_pending() -> None:
    upload = _function("static esp_err_t handleFixedEnvelopeUpload")
    assert "rejectRequestWithPendingBody" in upload
    assert "hasTransferEncoding" in upload
    assert upload.index("hasTransferEncoding") < upload.index("uploadWindowBudget.recordUploadStart()")
    assert "mustCloseRequestBody({true, reader.remaining()}) ? ESP_FAIL" in upload
    assert "receiveFailureRequiresClose(payloadReceiveStatus) ||" in upload


def test_promotion_deadline_uses_the_shared_transaction_decision() -> None:
    promotion = _function("static bool promoteBlocklistCandidate")
    policy = (ROOT / "src" / "admin_http_policy.h").read_text(encoding="utf-8")

    assert "bool (*deadlineExpired)()" in promotion
    assert promotion.count("deadlineExpired()") >= 6
    assert "AFTER_ACTIVE_TO_OLD" in promotion
    assert "AFTER_NEW_TO_ACTIVE" in promotion
    assert "AFTER_CLEANUP" in promotion
    assert "RESTORE_OLD" in policy
    assert "FAIL_CLOSED" in policy
