// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include <esp_random.h>
#include <esp_http_server.h>
extern "C" {
#include <mbedtls/constant_time.h>
}
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include "blocklist_trust.h"
#include "admin_http_policy.h"
#include "admin_state.h"
#include "dns_protocol.h"
#include "fixed_envelope.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"

#if ARDUHAL_LOG_LEVEL >= ARDUHAL_LOG_LEVEL_VERBOSE
#error "Verbose Arduino core logging can expose WiFi/admin form values"
#endif
#if __has_include("secrets.h")
#include "secrets.h"   // Optional local WIFI_SSID / WIFI_PASS fallback.
#else
static constexpr const char* WIFI_SSID = "";
static constexpr const char* WIFI_PASS = "";
#endif

// ---- config ----
static const IPAddress UPSTREAM(9, 9, 9, 9);     // Quad9
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const char* BLOCKLIST_NEW_PATH = "/blocklist.new";
static const char* BLOCKLIST_NEW_AUTH_PATH = "/blocklist.new.auth";
static const char* BLOCKLIST_OLD_PATH = "/blocklist.old";
static const char* BLOCKLIST_UPLOAD_ROUTE = "/upload";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const uint32_t BLOCKLIST_MAX_RECORDS = 104857;
static const size_t BLOCKLIST_MAX_BYTES = BLOCKLIST_MAX_RECORDS * HASH_BYTES;
// Existing P1/P2 blocklists may be larger than the transactional upload limit.
// Validate and keep those live, but never accept a new upload above the new cap.
static const uint32_t BLOCKLIST_LEGACY_MAX_RECORDS = 250000;
static const size_t BLOCKLIST_LEGACY_MAX_BYTES = BLOCKLIST_LEGACY_MAX_RECORDS * HASH_BYTES;
static const size_t BLOCKLIST_PROOF_BYTES = kBlocklistProofSize;
static const size_t BLOCKLIST_UPLOAD_REQUEST_MAX =
  BLOCKLIST_PROOF_BYTES + BLOCKLIST_MAX_BYTES;
static const size_t ADMIN_PASSWORD_MIN_LENGTH = 12;
static const size_t ADMIN_PASSWORD_MAX_LENGTH = 128;
static const uint8_t ADMIN_VERIFIER_VERSION = 1;
static const uint32_t ADMIN_PBKDF2_ITERATIONS = 50000;
static const size_t ADMIN_SALT_BYTES = 16;
static const size_t ADMIN_VERIFIER_BYTES = 32;
static const size_t SESSION_TOKEN_BYTES = 32;
static const size_t CSRF_TOKEN_BYTES = 32;
static const uint32_t SESSION_LIFETIME_MS = 30UL * 60UL * 1000UL;
static const char* ADMIN_NAMESPACE = "admin";
static const char* ADMIN_SESSION_COOKIE = "NSSESSION";
static const uint8_t BOOT_BUTTON_PIN = 9;
static const uint32_t PORTAL_BOOT_HOLD_MS = 3000;
static const uint32_t RUNTIME_BOOT_HOLD_MS = 5000;
static const uint32_t BOOT_RELEASE_STABLE_MS = 60;
static const uint32_t WIFI_ASSOCIATION_TIMEOUT_MS = 20000;
static const uint32_t WIFI_DISCONNECT_TIMEOUT_MS = 100;
static const uint32_t WIFI_RETRY_SETTLE_MS = 250;
static const size_t HTTP_MAX_URI_LEN = 512;
static const size_t HTTP_MAX_HEADER_BYTES = 1024;
static const size_t HTTP_FORM_MAX_BYTES = 2048;
static const uint32_t HTTP_IO_TIMEOUT_SECONDS = 2;
static const uint16_t HTTP_SERVER_MAX_OPEN_SOCKETS = 4;  // Three are internal; one client remains.

enum HTTPUploadStatus { UPLOAD_FILE_START, UPLOAD_FILE_WRITE, UPLOAD_FILE_END, UPLOAD_FILE_ABORTED };
struct HTTPUpload {
  HTTPUploadStatus status;
  size_t totalSize;
  size_t currentSize;
  uint8_t* buf;
};

// Small compatibility surface for the existing response/auth handlers.  It is
// intentionally not an Arduino WebServer wrapper: every request is supplied by
// esp_http_server and request bodies are parsed by the bounded helpers below.
class BoundedHttpRequest {
 public:
  void begin(httpd_req_t* request) { request_ = request; argCount_ = 0; }
  void end() { request_ = nullptr; argCount_ = 0; }
  bool active() const { return request_ != nullptr; }
  httpd_req_t* request() const { return request_; }
  int clientContentLength() const { return request_ ? request_->content_len : -1; }
  String header(const char* name) const {
    if (!request_ || !name) return "";
    const size_t length = httpd_req_get_hdr_value_len(request_, name);
    if (length == 0 || length >= HTTP_MAX_HEADER_BYTES) return "";
    static char value[HTTP_MAX_HEADER_BYTES];
    if (httpd_req_get_hdr_value_str(request_, name, value, length + 1) != ESP_OK) return "";
    return String(value);
  }
  String arg(const char* name) const {
    for (size_t index = 0; index < argCount_; ++index) {
      if (strcmp(args_[index].name, name) == 0) return String(args_[index].value);
    }
    return "";
  }
  bool addArg(const char* name, const char* value) {
    if (!name || !value || argCount_ >= kMaxArgs || strlen(name) >= sizeof(args_[0].name) ||
        strlen(value) >= sizeof(args_[0].value)) return false;
    strlcpy(args_[argCount_].name, name, sizeof(args_[0].name));
    strlcpy(args_[argCount_].value, value, sizeof(args_[0].value));
    ++argCount_;
    return true;
  }
  void sendHeader(const String& name, const String& value) const {
    if (request_) httpd_resp_set_hdr(request_, name.c_str(), value.c_str());
  }
  void send(int status, const char* type, const String& body) const {
    sendBytes(status, type, body.c_str(), body.length());
  }
  void send(int status, const char* type, const char* body) const {
    sendBytes(status, type, body, body ? strlen(body) : 0);
  }
  void send_P(int status, const char* type, const char* body) const {
    sendBytes(status, type, body, body ? strlen(body) : 0);
  }

 private:
  struct Arg { char name[16]; char value[129]; };
  static constexpr size_t kMaxArgs = 6;
  httpd_req_t* request_ = nullptr;
  Arg args_[kMaxArgs]{};
  size_t argCount_ = 0;
  void sendBytes(int status, const char* type, const char* body, size_t length) const {
    if (!request_) return;
    char statusText[20];
    snprintf(statusText, sizeof(statusText), "%d %s", status,
             status == 200 ? "OK" : status == 303 ? "See Other" : status == 400 ? "Bad Request" :
             status == 401 ? "Unauthorized" : status == 403 ? "Forbidden" : status == 404 ? "Not Found" :
             status == 409 ? "Conflict" : status == 413 ? "Payload Too Large" :
             status == 415 ? "Unsupported Media Type" : status == 429 ? "Too Many Requests" :
             status == 500 ? "Internal Server Error" : "Error");
    httpd_resp_set_status(request_, statusText);
    httpd_resp_set_type(request_, type);
    httpd_resp_send(request_, body, length);
  }
};

using dns_protocol::DNS_PACKET_MAX_BYTES;
using dns_protocol::DNS_RESPONSE_CANDIDATE_MAX;
using dns_protocol::DNS_STALE_DRAIN_MAX;
using dns_protocol::DNS_UPSTREAM_TIMEOUT_MS;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
BoundedHttpRequest web;
httpd_handle_t adminHttpServer = nullptr;
bool adminHttpAccepting = false;
int adminHttpSocket = -1;
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[DNS_PACKET_MAX_BYTES];
uint8_t upstreamBuf[DNS_PACKET_MAX_BYTES];
bool networkServicesStarted = false;
bool blocklistHealthy = false;
bool upstreamSocketReady = false;

[[noreturn]] static void enterStorageFailClosed(const char* reason);

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start
bool        physicalProvisioningAllowed = false;
uint8_t     provisioningCsrf[CSRF_TOKEN_BYTES];

// One authenticated admin session. Tokens remain in RAM and disappear on reboot.
bool     adminSessionActive = false;
uint8_t  adminSessionToken[SESSION_TOKEN_BYTES];
uint8_t  adminCsrfToken[CSRF_TOKEN_BYTES];
uint32_t adminSessionStartedMs = 0;
uint8_t  loginFailures = 0;
uint32_t loginBlockedUntilMs = 0;
bool adminWindowCloseRequested = false;
using RuntimeState = admin_state::RuntimeState;
RuntimeState runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED;
admin_state::BootGestureTracker bootGesture;
uint32_t adminWindowStartedMs = 0, provisioningStartedMs = 0, uploadStartedMs = 0;
admin_state::WindowBudget uploadWindowBudget;
bool uploadRequestInFlight = false;
bool provisioningCandidatePending = false;
String pendingProvisioningSsid, pendingProvisioningPassword, pendingProvisioningAdminPassword;

struct BootHoldState {
  bool releaseObserved = false;
  bool tracking = false;
  bool handled = false;
  uint32_t pressedSinceMs = 0;
};

struct BootReleaseState {
  bool tracking = false;
  uint32_t releasedSinceMs = 0;
};

BootHoldState portalBootHold;
BootHoldState runtimeBootHold;
BootReleaseState portalRestartRelease;
BootReleaseState runtimeRecoveryRelease;
bool portalRestartPending = false;
bool runtimeRecoveryPending = false;

static void secureZero(void* data, size_t length);

struct AdminVerifierRecord {
  uint8_t version;
  uint32_t iterations;
  uint8_t salt[ADMIN_SALT_BYTES];
  uint8_t verifier[ADMIN_VERIFIER_BYTES];
};

// Versioned A/B configuration.  A complete valid record is selected by its
// generation; legacy "wifi" + "admin" namespaces are read-only fallbacks.
struct ConfigRecord {
  uint32_t magic;
  uint16_t version;
  uint16_t generation;
  uint8_t ssidLength;
  uint8_t passwordLength;
  char ssid[33];
  char password[64];
  AdminVerifierRecord admin;
  uint32_t checksum;
};
static constexpr uint32_t CONFIG_MAGIC = 0x32474643;  // CFG2
static constexpr uint16_t CONFIG_VERSION = 1;
static const char* CONFIG_NAMESPACE = "cfgv2";
static const char* CONFIG_SLOT_A = "a";
static const char* CONFIG_SLOT_B = "b";

static uint32_t configChecksum(const ConfigRecord& record) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&record);
  uint32_t hash = 2166136261UL;
  for (size_t i = 0; i < offsetof(ConfigRecord, checksum); ++i) {
    hash ^= bytes[i]; hash *= 16777619UL;
  }
  return hash;
}

static bool validConfigRecord(const ConfigRecord& record) {
  return record.magic == CONFIG_MAGIC && record.version == CONFIG_VERSION &&
         record.ssidLength > 0 && record.ssidLength <= 32 && record.passwordLength <= 63 &&
         record.ssid[record.ssidLength] == '\0' && record.password[record.passwordLength] == '\0' &&
         record.admin.version == ADMIN_VERIFIER_VERSION && record.admin.iterations == ADMIN_PBKDF2_ITERATIONS &&
         record.checksum == configChecksum(record);
}

static bool readConfigSlot(const char* key, ConfigRecord& record) {
  secureZero(&record, sizeof(record));
  Preferences config;
  if (!config.begin(CONFIG_NAMESPACE, true)) return false;
  const bool read = config.getBytesLength(key) == sizeof(record) &&
                    config.getBytes(key, &record, sizeof(record)) == sizeof(record);
  config.end();
  if (!read || !validConfigRecord(record)) { secureZero(&record, sizeof(record)); return false; }
  return true;
}

static bool loadActiveConfig(ConfigRecord& record) {
  ConfigRecord a, b;
  const bool validA = readConfigSlot(CONFIG_SLOT_A, a);
  const bool validB = readConfigSlot(CONFIG_SLOT_B, b);
  if (!validA && !validB) return false;
  const bool selectA = validA && (!validB || static_cast<int16_t>(a.generation - b.generation) >= 0);
  record = selectA ? a : b;
  secureZero(&a, sizeof(a)); secureZero(&b, sizeof(b));
  return true;
}

// ESP32-C3 SuperMini HIL showed unstable Wi-Fi association at default TX power.
// Limit TX power to 8.5 dBm for stable AP/STA operation.
static bool applyC3RfWorkaround() {
  return WiFi.setTxPower(WIFI_POWER_8_5dBm);
}

static bool waitForWiFiAssociation(const char* window) {
  const uint32_t startedAtMs = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - startedAtMs < WIFI_ASSOCIATION_TIMEOUT_MS) {
    delay(250);
    Serial.print(".");
  }
  Serial.println();
  const wl_status_t finalStatus = WiFi.status();
  return finalStatus == WL_CONNECTED;
}

static bool bootHoldReached(BootHoldState& state, uint32_t thresholdMs) {
  const bool pressed = digitalRead(BOOT_BUTTON_PIN) == LOW;
  if (!pressed) {
    state.releaseObserved = true;
    state.tracking = false;
    state.handled = false;
    state.pressedSinceMs = 0;
    return false;
  }
  if (!state.releaseObserved || state.handled) return false;
  if (!state.tracking) {
    state.tracking = true;
    state.pressedSinceMs = millis();
    return false;
  }
  if (millis() - state.pressedSinceMs < thresholdMs) return false;
  state.handled = true;
  return true;
}

static bool bootReleasedStable(BootReleaseState& state) {
  if (digitalRead(BOOT_BUTTON_PIN) == LOW) {
    state.tracking = false;
    state.releasedSinceMs = 0;
    return false;
  }
  if (!state.tracking) {
    state.tracking = true;
    state.releasedSinceMs = millis();
    return false;
  }
  return millis() - state.releasedSinceMs >= BOOT_RELEASE_STABLE_MS;
}

// ---------- local admin security ----------
static void secureZero(void* data, size_t length) {
  mbedtls_platform_zeroize(data, length);
}

static void clearSensitiveString(String& value) {
  for (size_t i = 0; i < value.length(); i++) value.setCharAt(i, '\0');
  value = "";
}

static bool validAdminPasswordLength(const String& password) {
  return password.length() >= ADMIN_PASSWORD_MIN_LENGTH &&
         password.length() <= ADMIN_PASSWORD_MAX_LENGTH;
}

static bool deriveAdminVerifier(const String& password, const uint8_t* salt,
                                uint32_t iterations, uint8_t* verifier) {
  return mbedtls_pkcs5_pbkdf2_hmac_ext(
           MBEDTLS_MD_SHA256,
           reinterpret_cast<const unsigned char*>(password.c_str()), password.length(),
           salt, ADMIN_SALT_BYTES, iterations, ADMIN_VERIFIER_BYTES, verifier) == 0;
}

static void clearAdminVerifier() {
  Preferences adminPrefs;
  if (adminPrefs.begin(ADMIN_NAMESPACE, false)) {
    adminPrefs.clear();
    adminPrefs.end();
  }
}

static bool loadAdminVerifier(AdminVerifierRecord& record) {
  secureZero(&record, sizeof(record));
  ConfigRecord configRecord;
  if (loadActiveConfig(configRecord)) {
    record = configRecord.admin;
    secureZero(&configRecord, sizeof(configRecord));
    return true;
  }
  Preferences adminPrefs;
  if (!adminPrefs.begin(ADMIN_NAMESPACE, true)) return false;
  record.version = adminPrefs.getUChar("version", 0);
  record.iterations = adminPrefs.getUInt("iterations", 0);
  const bool sizesOk = adminPrefs.getBytesLength("salt") == ADMIN_SALT_BYTES &&
                       adminPrefs.getBytesLength("verifier") == ADMIN_VERIFIER_BYTES;
  const bool readsOk = sizesOk &&
                       adminPrefs.getBytes("salt", record.salt, sizeof(record.salt)) == sizeof(record.salt) &&
                       adminPrefs.getBytes("verifier", record.verifier, sizeof(record.verifier)) == sizeof(record.verifier);
  adminPrefs.end();
  const bool valid = readsOk && record.version == ADMIN_VERIFIER_VERSION &&
                     record.iterations == ADMIN_PBKDF2_ITERATIONS;
  if (!valid) secureZero(&record, sizeof(record));
  return valid;
}

static bool hasAdminVerifier() {
  AdminVerifierRecord record;
  const bool present = loadAdminVerifier(record);
  secureZero(&record, sizeof(record));
  return present;
}

static bool createAdminVerifier(const String& password) {
  if (!validAdminPasswordLength(password)) return false;

  AdminVerifierRecord record;
  secureZero(&record, sizeof(record));
  record.version = ADMIN_VERIFIER_VERSION;
  record.iterations = ADMIN_PBKDF2_ITERATIONS;
  esp_fill_random(record.salt, sizeof(record.salt));
  if (!deriveAdminVerifier(password, record.salt, record.iterations, record.verifier)) {
    secureZero(&record, sizeof(record));
    return false;
  }

  Preferences adminPrefs;
  bool stored = adminPrefs.begin(ADMIN_NAMESPACE, false);
  if (stored) {
    stored = adminPrefs.clear() &&
             adminPrefs.putUChar("version", record.version) == sizeof(record.version) &&
             adminPrefs.putUInt("iterations", record.iterations) == sizeof(record.iterations) &&
             adminPrefs.putBytes("salt", record.salt, sizeof(record.salt)) == sizeof(record.salt) &&
             adminPrefs.putBytes("verifier", record.verifier, sizeof(record.verifier)) == sizeof(record.verifier);
    adminPrefs.end();
  }
  secureZero(&record, sizeof(record));
  if (!stored) clearAdminVerifier();
  return stored;
}

static bool commitProvisioningCandidate(const String& ssid, const String& password,
                                        const String& adminPassword) {
  if (!ssid.length() || ssid.length() > 32 || password.length() > 63 ||
      !validAdminPasswordLength(adminPassword)) return false;
  ConfigRecord current, next;
  const bool haveCurrent = loadActiveConfig(current);
  secureZero(&next, sizeof(next));
  next.magic = CONFIG_MAGIC; next.version = CONFIG_VERSION;
  next.generation = haveCurrent ? static_cast<uint16_t>(current.generation + 1) : 1;
  next.ssidLength = static_cast<uint8_t>(ssid.length());
  next.passwordLength = static_cast<uint8_t>(password.length());
  memcpy(next.ssid, ssid.c_str(), next.ssidLength); next.ssid[next.ssidLength] = '\0';
  memcpy(next.password, password.c_str(), next.passwordLength); next.password[next.passwordLength] = '\0';
  next.admin.version = ADMIN_VERIFIER_VERSION;
  next.admin.iterations = ADMIN_PBKDF2_ITERATIONS;
  esp_fill_random(next.admin.salt, sizeof(next.admin.salt));
  if (!deriveAdminVerifier(adminPassword, next.admin.salt, next.admin.iterations, next.admin.verifier)) {
    secureZero(&current, sizeof(current)); secureZero(&next, sizeof(next)); return false;
  }
  next.checksum = configChecksum(next);
  const char* inactive = haveCurrent && (current.generation & 1U) ? CONFIG_SLOT_B : CONFIG_SLOT_A;
  Preferences config;
  bool stored = config.begin(CONFIG_NAMESPACE, false) &&
                config.putBytes(inactive, &next, sizeof(next)) == sizeof(next);
  ConfigRecord readback;
  if (stored) stored = config.getBytes(inactive, &readback, sizeof(readback)) == sizeof(readback) &&
                       memcmp(&readback, &next, sizeof(next)) == 0 && validConfigRecord(readback);
  config.end();
  secureZero(&readback, sizeof(readback)); secureZero(&current, sizeof(current)); secureZero(&next, sizeof(next));
  return stored;
}

static bool verifyAdminPassword(const String& password) {
  AdminVerifierRecord record;
  uint8_t candidate[ADMIN_VERIFIER_BYTES];
  secureZero(candidate, sizeof(candidate));
  bool verified = false;
  if (validAdminPasswordLength(password) && loadAdminVerifier(record) &&
      deriveAdminVerifier(password, record.salt, record.iterations, candidate)) {
    verified = mbedtls_ct_memcmp(candidate, record.verifier, sizeof(candidate)) == 0;
  }
  secureZero(candidate, sizeof(candidate));
  secureZero(&record, sizeof(record));
  return verified;
}

static char hexDigit(uint8_t value) {
  return value < 10 ? static_cast<char>('0' + value) : static_cast<char>('a' + value - 10);
}

static String encodeHex(const uint8_t* data, size_t length) {
  String encoded;
  if (!encoded.reserve(length * 2)) return "";
  for (size_t i = 0; i < length; i++) {
    encoded += hexDigit(data[i] >> 4);
    encoded += hexDigit(data[i] & 0x0f);
  }
  return encoded;
}

static int hexValue(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

static bool decodeHex(const String& encoded, uint8_t* output, size_t outputLength) {
  if (encoded.length() != outputLength * 2) return false;
  for (size_t i = 0; i < outputLength; i++) {
    const int high = hexValue(encoded[i * 2]);
    const int low = hexValue(encoded[i * 2 + 1]);
    if (high < 0 || low < 0) {
      secureZero(output, outputLength);
      return false;
    }
    output[i] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

static String cookieValue(const String& cookieHeader, const String& name) {
  int start = 0;
  while (start < static_cast<int>(cookieHeader.length())) {
    int end = cookieHeader.indexOf(';', start);
    if (end < 0) end = cookieHeader.length();
    String part = cookieHeader.substring(start, end);
    part.trim();
    const String prefix = name + "=";
    if (part.startsWith(prefix)) return part.substring(prefix.length());
    start = end + 1;
  }
  return "";
}

static void clearAdminSession() {
  secureZero(adminSessionToken, sizeof(adminSessionToken));
  secureZero(adminCsrfToken, sizeof(adminCsrfToken));
  adminSessionStartedMs = 0;
  adminSessionActive = false;
}

static void startAdminSession() {
  clearAdminSession();
  esp_fill_random(adminSessionToken, sizeof(adminSessionToken));
  esp_fill_random(adminCsrfToken, sizeof(adminCsrfToken));
  adminSessionStartedMs = millis();
  adminSessionActive = true;
}

static bool adminSessionIsCurrent() {
  if (!adminSessionActive) return false;
  if (millis() - adminSessionStartedMs >= SESSION_LIFETIME_MS) {
    clearAdminSession();
    return false;
  }
  return true;
}

static bool requestHasAdminSession() {
  if (!adminSessionIsCurrent()) return false;
  String encoded = cookieValue(web.header("Cookie"), ADMIN_SESSION_COOKIE);
  uint8_t candidate[SESSION_TOKEN_BYTES];
  secureZero(candidate, sizeof(candidate));
  const bool decoded = decodeHex(encoded, candidate, sizeof(candidate));
  const bool matches = decoded &&
                       mbedtls_ct_memcmp(candidate, adminSessionToken, sizeof(candidate)) == 0;
  secureZero(candidate, sizeof(candidate));
  clearSensitiveString(encoded);
  return matches;
}

static bool requestHasValidCsrf() {
  String encoded = web.header("X-CSRF-Token");
  uint8_t candidate[CSRF_TOKEN_BYTES];
  secureZero(candidate, sizeof(candidate));
  const bool decoded = decodeHex(encoded, candidate, sizeof(candidate));
  const bool matches = decoded &&
                       mbedtls_ct_memcmp(candidate, adminCsrfToken, sizeof(candidate)) == 0;
  secureZero(candidate, sizeof(candidate));
  clearSensitiveString(encoded);
  return matches;
}

static bool isAllowedAdminHost(const String& rawHost, const String& localIp) {
  if (runtimeState != RuntimeState::ADMIN_AP_WINDOW || !rawHost.length() ||
      !localIp.length() || localIp == "0.0.0.0") return false;
  String host = rawHost;
  for (size_t i = 0; i < host.length(); i++) {
    const uint8_t ch = static_cast<uint8_t>(host[i]);
    if (ch <= 0x20 || ch == 0x7f) return false;
  }
  host.toLowerCase();
  if (host.endsWith(":80")) host.remove(host.length() - 3);
  if (!host.length() || host.indexOf(':') >= 0) return false;
  String allowedIp = localIp;
  allowedIp.toLowerCase();
  return host == allowedIp;
}

static void addSecurityHeaders() {
  web.sendHeader("Cache-Control", "no-store");
  web.sendHeader("X-Content-Type-Options", "nosniff");
  web.sendHeader("Referrer-Policy", "no-referrer");
  web.sendHeader("Content-Security-Policy",
                 "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                 "img-src 'none'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                 "frame-ancestors 'none'; form-action 'self'");
}

static int adminAuthorizationStatus(bool requireCsrf) {
  if (!isAllowedAdminHost(web.header("Host"), WiFi.softAPIP().toString())) return 403;
  if (!requestHasAdminSession()) return 401;
  if (requireCsrf && !requestHasValidCsrf()) return 403;
  return 200;
}

static void sendAuthorizationError(int status) {
  addSecurityHeaders();
  if (status == 401) web.sendHeader("Location", "/login");
  web.send(status, "text/plain", status == 401 ? "authentication required" : "forbidden");
}

static bool requireAdminRead(bool redirectUnauthenticated = false) {
  const int status = adminAuthorizationStatus(false);
  if (status == 200) return true;
  if (status == 401 && redirectUnauthenticated) {
    addSecurityHeaders();
    web.sendHeader("Location", "/login");
    web.send(303, "text/plain", "sign-in required");
    return false;
  }
  sendAuthorizationError(status);
  return false;
}

static bool requireAdminMutation(bool sendResponse = true) {
  const int status = adminAuthorizationStatus(true);
  if (status == 200) return true;
  if (sendResponse) sendAuthorizationError(status);
  return false;
}

static uint32_t loginDelayMs(uint8_t failures) {
  if (failures < 3) return 0;
  if (failures == 3) return 5000;
  if (failures == 4) return 10000;
  if (failures == 5) return 20000;
  return 30000;
}

static bool loginIsBlocked() {
  return loginBlockedUntilMs != 0 &&
         static_cast<int32_t>(loginBlockedUntilMs - millis()) > 0;
}

static void recordLoginFailure() {
  if (loginFailures < UINT8_MAX) loginFailures++;
  const uint32_t delayMs = loginDelayMs(loginFailures);
  loginBlockedUntilMs = delayMs ? millis() + delayMs : 0;
}

static void resetLoginThrottle() {
  loginFailures = 0;
  loginBlockedUntilMs = 0;
}

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static bool inFlash(uint64_t h) {
  int32_t lo = 0, hi = (int32_t)numHashes - 1; uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    if (!blocklist.seek((uint32_t)mid * HASH_BYTES) ||
        blocklist.read(b, HASH_BYTES) != HASH_BYTES) {
      blocklistHealthy = false;
      return false;
    }
    uint64_t v = 0; for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    if (v < h) lo = mid + 1; else if (v > h) hi = mid - 1; else return true;
  }
  return false;
}
static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inFlash(h) || inCustom(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static int buildBlocked(int qlen, const dns_protocol::QueryInfo& query) {
  return static_cast<int>(dns_protocol::buildBlockedResponse(
      buf, static_cast<size_t>(qlen), query, buf, sizeof(buf)));
}

static int buildDnsError(int qlen, const dns_protocol::QueryInfo* query,
                         dns_protocol::ResponseCode code) {
  return static_cast<int>(dns_protocol::buildErrorResponse(
      buf, static_cast<size_t>(qlen), query, code, buf, sizeof(buf)));
}

static int forwardUpstream(int qlen) {
  dns_protocol::QueryInfo query = {};
  if (!upstreamSocketReady ||
      dns_protocol::parseClientQuery(buf, static_cast<size_t>(qlen), &query) !=
          dns_protocol::QueryStatus::VALID) {
    return 0;
  }

  // NetworkUDP refuses to parse a new datagram while a partially-read RX
  // buffer exists. Clear that state, then require an observed empty queue
  // within the bounded stale-packet budget before sending a new transaction.
  upstreamCli.clear();
  bool queueObservedEmpty = false;
  for (uint8_t drained = 0; drained < DNS_STALE_DRAIN_MAX; ++drained) {
    const int staleSize = upstreamCli.parsePacket();
    if (staleSize <= 0) {
      queueObservedEmpty = true;
      break;
    }
    upstreamCli.clear();
  }
  if (!queueObservedEmpty) return 0;

  const uint16_t upstreamId = static_cast<uint16_t>(esp_random());
  if (upstreamCli.beginPacket(UPSTREAM, DNS_PORT) != 1) return 0;
  if (!dns_protocol::setTransactionId(
          buf, static_cast<size_t>(qlen), upstreamId)) {
    return 0;
  }
  const size_t bytesWritten = upstreamCli.write(buf, static_cast<size_t>(qlen));
  const bool idRestored = dns_protocol::setTransactionId(
      buf, static_cast<size_t>(qlen), query.clientId);
  if (!idRestored || bytesWritten != static_cast<size_t>(qlen) ||
      upstreamCli.endPacket() != 1) {
    return 0;
  }

  const uint32_t deadline = millis() + DNS_UPSTREAM_TIMEOUT_MS;
  uint8_t candidates = 0;
  while (static_cast<int32_t>(deadline - millis()) > 0 &&
         candidates < DNS_RESPONSE_CANDIDATE_MAX) {
    const int packetSize = upstreamCli.parsePacket();
    if (packetSize <= 0) {
      delay(1);
      continue;
    }
    ++candidates;

    // Capture peer metadata before any later beginPacket() can overwrite it.
    const IPAddress sourceIp = upstreamCli.remoteIP();
    const uint16_t sourcePort = upstreamCli.remotePort();
    if (packetSize > static_cast<int>(DNS_PACKET_MAX_BYTES)) {
      upstreamCli.clear();
      continue;
    }

    dns_protocol::Ipv4Endpoint actualEndpoint = {
        {sourceIp[0], sourceIp[1], sourceIp[2], sourceIp[3]}, sourcePort};
    const dns_protocol::Ipv4Endpoint expectedEndpoint = {
        {UPSTREAM[0], UPSTREAM[1], UPSTREAM[2], UPSTREAM[3]}, DNS_PORT};
    if (!dns_protocol::endpointMatches(actualEndpoint, expectedEndpoint)) {
      upstreamCli.clear();
      continue;
    }

    const int received = upstreamCli.read(
        upstreamBuf, static_cast<size_t>(packetSize));
    if (received != packetSize) {
      upstreamCli.clear();
      continue;
    }
    if (dns_protocol::validateUpstreamResponse(
            buf, static_cast<size_t>(qlen), query, upstreamBuf,
            static_cast<size_t>(received), upstreamId) !=
        dns_protocol::ResponseStatus::VALID) {
      continue;
    }

    memcpy(buf, upstreamBuf, static_cast<size_t>(received));
    if (!dns_protocol::setTransactionId(
            buf, static_cast<size_t>(received), query.clientId)) {
      return 0;
    }
    return received;
  }
  return 0;
}
// Drain a whole RX burst per call (capped, so the web server still gets a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  if (!blocklistHealthy) enterStorageFailClosed("runtime blocklist unavailable");
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    const int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    if (sz > static_cast<int>(DNS_PACKET_MAX_BYTES)) {
      dnsServer.clear();
      continue;
    }
    const int qlen = dnsServer.read(buf, static_cast<size_t>(sz));
    if (qlen != sz) {
      dnsServer.clear();
      continue;
    }

    dns_protocol::QueryInfo query = {};
    const dns_protocol::QueryStatus queryStatus =
        dns_protocol::parseClientQuery(
            buf, static_cast<size_t>(qlen), &query);
    if (queryStatus == dns_protocol::QueryStatus::DROP) continue;
    if (queryStatus != dns_protocol::QueryStatus::VALID) {
      const dns_protocol::QueryInfo* completeQuestion =
          query.questionEnd >= dns_protocol::DNS_HEADER_BYTES &&
                  query.questionEnd <= static_cast<size_t>(qlen)
              ? &query
              : nullptr;
      const int errorLength = buildDnsError(
          qlen, completeQuestion,
          dns_protocol::responseCodeFor(queryStatus));
      if (errorLength > 0) {
        dnsServer.beginPacket(cip, cport);
        dnsServer.write(buf, static_cast<size_t>(errorLength));
        dnsServer.endPacket();
      }
      continue;
    }

    const char* domain = query.blocklistName;
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    bool blocked = ban || (!query.root && query.blocklistNameLength &&
                           numHashes && isBlocked(domain));
    if (!blocklistHealthy) enterStorageFailClosed("runtime blocklist read failed");
    int rlen = 0;
    if (blocked) {
      rlen = buildBlocked(qlen, query);
      totalBlocked++;
      if (c) c->blocked++;
    } else {
      rlen = forwardUpstream(qlen);
      if (rlen > 0) {
        totalAllowed++;
        if (c) c->allowed++;
      } else {
        rlen = buildDnsError(
            qlen, &query, dns_protocol::ResponseCode::SERVER_FAILURE);
      }
    }
    if (rlen > 0) {
      dnsServer.beginPacket(cip, cport);
      dnsServer.write(buf, static_cast<size_t>(rlen));
      dnsServer.endPacket();
    }
    if (!blocked) break;  // At most one synchronous upstream wait per loop turn.
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String htmlEscape(const String& input) {
  String output;
  output.reserve(input.length() + 16);
  for (char ch : input) {
    switch (ch) {
      case '&': output += "&amp;"; break;
      case '<': output += "&lt;"; break;
      case '>': output += "&gt;"; break;
      case '"': output += "&quot;"; break;
      case '\'': output += "&#39;"; break;
      default: output += ch; break;
    }
  }
  return output;
}

static String jsonEscape(const String& input) {
  static const char HEX_DIGITS[] = "0123456789abcdef";
  String output;
  output.reserve(input.length() + 16);
  for (char raw : input) {
    const uint8_t ch = static_cast<uint8_t>(raw);
    switch (ch) {
      case '"': output += "\\\""; break;
      case '\\': output += "\\\\"; break;
      case '\b': output += "\\b"; break;
      case '\f': output += "\\f"; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (ch < 0x20) {
          output += "\\u00";
          output += HEX_DIGITS[ch >> 4];
          output += HEX_DIGITS[ch & 0x0f];
        } else {
          output += static_cast<char>(ch);
        }
        break;
    }
  }
  return output;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static bool requireAllowedAdminHost() {
  if (isAllowedAdminHost(web.header("Host"), WiFi.softAPIP().toString())) return true;
  sendAuthorizationError(403);
  return false;
}

static void sendLoginPage(int status, bool failed) {
  addSecurityHeaders();
  String page =
    "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Acceso a NetShield Mini</title><style>body{font:16px system-ui,sans-serif;max-width:420px;margin:48px auto;"
    "padding:0 16px;background:#0d1117;color:#c9d1d9}input,button{width:100%;box-sizing:border-box;padding:11px;"
    "margin:7px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9}button{background:#3fb950;"
    "color:#000;font-weight:600}</style></head><body><h2>Administraci&oacute;n de NetShield Mini</h2>";
  if (failed) page += "<p>No se pudo iniciar sesi&oacute;n. Comprueba la contrase&ntilde;a o int&eacute;ntalo m&aacute;s tarde.</p>";
  page += "<form method=POST action=/login><label>Contrase&ntilde;a de administraci&oacute;n<input name=password type=password minlength=12 maxlength=128 "
          "autocomplete=current-password required></label><button type=submit>Entrar</button></form></body></html>";
  web.send(status, "text/html; charset=utf-8", page);
}

static void handleLoginGet() {
  if (!requireAllowedAdminHost()) return;
  sendLoginPage(200, false);
}

static void handleLoginPost() {
  if (!requireAllowedAdminHost()) return;
  if (loginIsBlocked()) {
    sendLoginPage(429, true);
    return;
  }

  String password = web.arg("password");
  const bool verified = verifyAdminPassword(password);
  clearSensitiveString(password);
  if (!verified) {
    recordLoginFailure();
    if (loginFailures >= 10) adminWindowCloseRequested = true;
    sendLoginPage(401, true);
    return;
  }

  resetLoginThrottle();
  startAdminSession();
  String encodedToken = encodeHex(adminSessionToken, sizeof(adminSessionToken));
  if (encodedToken.length() != SESSION_TOKEN_BYTES * 2) {
    clearAdminSession();
    addSecurityHeaders();
    web.send(500, "text/plain", "sign-in unavailable");
    return;
  }
  String cookie = String(ADMIN_SESSION_COOKIE) + "=" + encodedToken +
                  // Intentionally no Secure flag while the local UI is HTTP-only.
                  "; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800";
  addSecurityHeaders();
  web.sendHeader("Set-Cookie", cookie);
  web.sendHeader("Location", "/");
  web.send(303, "text/plain", "signed in");
  clearSensitiveString(encodedToken);
  clearSensitiveString(cookie);
}

static void handleLogout() {
  if (!requireAdminMutation()) return;
  clearAdminSession();
  addSecurityHeaders();
  web.sendHeader("Set-Cookie", "NSSESSION=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
  web.send(200, "text/plain", "signed out");
  adminWindowCloseRequested = true;
}

static void handleDashboardRoot() {
  if (!requireAdminRead(true)) return;
  addSecurityHeaders();
  web.send_P(200, "text/html; charset=utf-8", PAGE);
}

static void handleAppJs() {
  if (!requireAdminRead()) return;
  addSecurityHeaders();
  web.send_P(200, "application/javascript; charset=utf-8", APP_JS);
}

static void handleStats() {
  if (!requireAdminRead()) return;
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String csrf = encodeHex(adminCsrfToken, sizeof(adminCsrfToken));
  String j = "{\"csrf\":\"" + csrf + "\",\"ip\":\"" + WiFi.softAPIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jsonEscape(customDom[i]) + "\""; }
  j += "]}";
  addSecurityHeaders();
  web.send(200, "application/json", j);
  clearSensitiveString(csrf);
}
static void handleBan() {
  if (!requireAdminMutation()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  addSecurityHeaders();
  web.send(200, "text/plain", "ok");
}

// ---------- validated, transactional manual blocklist upload ----------
enum class BlocklistValidationStatus : uint8_t {
  VALID,
  MISSING,
  OPEN_FAILED,
  EMPTY,
  TOO_LARGE,
  BAD_SIZE,
  READ_FAILED,
  DUPLICATE,
  UNSORTED,
};

enum class BlocklistProofStatus : uint8_t {
  VALID,
  MISSING,
  BAD_SIZE,
  BAD_ENCODING,
  BAD_MANIFEST,
  UNKNOWN_KEY,
  INVALID_SIGNATURE,
  PAYLOAD_INVALID,
  PAYLOAD_MISMATCH,
  STORAGE_ERROR,
  CRYPTO_ERROR,
};

static const char* blocklistValidationToken(BlocklistValidationStatus status) {
  switch (status) {
    case BlocklistValidationStatus::VALID: return "valid";
    case BlocklistValidationStatus::MISSING: return "missing";
    case BlocklistValidationStatus::OPEN_FAILED: return "open_failed";
    case BlocklistValidationStatus::EMPTY: return "empty";
    case BlocklistValidationStatus::TOO_LARGE: return "too_large";
    case BlocklistValidationStatus::BAD_SIZE: return "bad_size";
    case BlocklistValidationStatus::READ_FAILED: return "read_failed";
    case BlocklistValidationStatus::DUPLICATE: return "duplicate";
    case BlocklistValidationStatus::UNSORTED: return "unsorted";
  }
  return "unknown";
}

static const char* blocklistProofToken(BlocklistProofStatus status) {
  switch (status) {
    case BlocklistProofStatus::VALID: return "valid";
    case BlocklistProofStatus::MISSING: return "missing";
    case BlocklistProofStatus::BAD_SIZE: return "bad_size";
    case BlocklistProofStatus::BAD_ENCODING: return "bad_encoding";
    case BlocklistProofStatus::BAD_MANIFEST: return "bad_manifest";
    case BlocklistProofStatus::UNKNOWN_KEY: return "unknown_key";
    case BlocklistProofStatus::INVALID_SIGNATURE: return "invalid_signature";
    case BlocklistProofStatus::PAYLOAD_INVALID: return "payload_invalid";
    case BlocklistProofStatus::PAYLOAD_MISMATCH: return "payload_mismatch";
    case BlocklistProofStatus::STORAGE_ERROR: return "storage_error";
    case BlocklistProofStatus::CRYPTO_ERROR: return "crypto_error";
  }
  return "unknown";
}

static uint64_t decodeBlocklistHash(const uint8_t record[HASH_BYTES]) {
  uint64_t value = 0;
  for (int i = 0; i < HASH_BYTES; i++) value |= static_cast<uint64_t>(record[i]) << (8 * i);
  return value;
}

static BlocklistValidationStatus validateBlocklistFile(
    const char* path, bool candidateLimits, uint32_t* validatedRecords = nullptr) {
  if (validatedRecords) *validatedRecords = 0;
  if (!LittleFS.exists(path)) return BlocklistValidationStatus::MISSING;

  File candidate = LittleFS.open(path, "r");
  if (!candidate) return BlocklistValidationStatus::OPEN_FAILED;
  const size_t size = candidate.size();
  const size_t maxBytes = candidateLimits ? BLOCKLIST_MAX_BYTES : BLOCKLIST_LEGACY_MAX_BYTES;
  const uint32_t maxRecords = candidateLimits ? BLOCKLIST_MAX_RECORDS : BLOCKLIST_LEGACY_MAX_RECORDS;
  if (size == 0) {
    candidate.close();
    return BlocklistValidationStatus::EMPTY;
  }
  if (size > maxBytes) {
    candidate.close();
    return BlocklistValidationStatus::TOO_LARGE;
  }
  if (size % HASH_BYTES != 0) {
    candidate.close();
    return BlocklistValidationStatus::BAD_SIZE;
  }

  const size_t recordCount = size / HASH_BYTES;
  if (recordCount == 0 || recordCount > maxRecords) {
    candidate.close();
    return BlocklistValidationStatus::TOO_LARGE;
  }

  static const size_t VALIDATION_RECORDS_PER_READ = 64;
  uint8_t recordsBuffer[HASH_BYTES * VALIDATION_RECORDS_PER_READ];
  uint64_t previous = 0;
  bool havePrevious = false;
  size_t recordsRead = 0;
  while (recordsRead < recordCount) {
    const size_t batchRecords =
      min(VALIDATION_RECORDS_PER_READ, recordCount - recordsRead);
    const size_t batchBytes = batchRecords * HASH_BYTES;
    if (candidate.read(recordsBuffer, batchBytes) != batchBytes) {
      candidate.close();
      return BlocklistValidationStatus::READ_FAILED;
    }
    for (size_t batchIndex = 0; batchIndex < batchRecords; batchIndex++) {
      const uint8_t* record = recordsBuffer + batchIndex * HASH_BYTES;
      const uint64_t current = decodeBlocklistHash(record);
      if (havePrevious && current == previous) {
        candidate.close();
        return BlocklistValidationStatus::DUPLICATE;
      }
      if (havePrevious && current <= previous) {
        candidate.close();
        return BlocklistValidationStatus::UNSORTED;
      }
      previous = current;
      havePrevious = true;
    }
    recordsRead += batchRecords;
  }
  if (candidate.available() != 0) {
    candidate.close();
    return BlocklistValidationStatus::BAD_SIZE;
  }
  candidate.close();
  if (validatedRecords) *validatedRecords = static_cast<uint32_t>(recordCount);
  return BlocklistValidationStatus::VALID;
}

static uint32_t readLittleEndian32(const uint8_t* input) {
  return static_cast<uint32_t>(input[0]) |
         static_cast<uint32_t>(input[1]) << 8 |
         static_cast<uint32_t>(input[2]) << 16 |
         static_cast<uint32_t>(input[3]) << 24;
}

static uint64_t readLittleEndian64(const uint8_t* input) {
  uint64_t value = 0;
  for (size_t index = 0; index < 8; index++) {
    value |= static_cast<uint64_t>(input[index]) << (8 * index);
  }
  return value;
}

static BlocklistProofStatus validateBlocklistProofEnvelope(
    const uint8_t proof[kBlocklistProofSize]) {
  if (memcmp(proof + kBlocklistMagicOffset, kBlocklistManifestMagic,
             sizeof(kBlocklistManifestMagic)) != 0 ||
      proof[kBlocklistManifestVersionOffset] != kBlocklistManifestVersion ||
      proof[kBlocklistFormatVersionOffset] != kBlocklistFormatVersion ||
      proof[kBlocklistAlgorithmOffset] != kBlocklistSignatureAlgorithm ||
      proof[kBlocklistFlagsOffset] != kBlocklistManifestFlags) {
    return BlocklistProofStatus::BAD_MANIFEST;
  }

  const uint32_t keyId = readLittleEndian32(proof + kBlocklistKeyIdOffset);
  const TrustedBlocklistKey* trustedKey = findTrustedBlocklistKey(keyId);
  if (!trustedKey) return BlocklistProofStatus::UNKNOWN_KEY;
  if (readLittleEndian32(proof + kBlocklistListIdOffset) !=
          kBlocklistAcceptedListId ||
      readLittleEndian64(proof + kBlocklistSequenceOffset) == 0) {
    return BlocklistProofStatus::BAD_MANIFEST;
  }

  const uint32_t payloadSize =
    readLittleEndian32(proof + kBlocklistPayloadSizeOffset);
  const uint32_t recordCount =
    readLittleEndian32(proof + kBlocklistRecordCountOffset);
  if (payloadSize == 0 || payloadSize > BLOCKLIST_MAX_BYTES ||
      payloadSize % HASH_BYTES != 0 || recordCount == 0 ||
      recordCount > BLOCKLIST_MAX_RECORDS ||
      recordCount != payloadSize / HASH_BYTES) {
    return BlocklistProofStatus::BAD_MANIFEST;
  }

  uint8_t signedDigest[32];
  secureZero(signedDigest, sizeof(signedDigest));
  mbedtls_sha256_context shaContext;
  mbedtls_sha256_init(&shaContext);
  int result = mbedtls_sha256_starts(&shaContext, 0);
  if (result == 0) {
    result = mbedtls_sha256_update(
      &shaContext, kBlocklistSignatureDomain,
      sizeof(kBlocklistSignatureDomain));
  }
  if (result == 0) {
    result = mbedtls_sha256_update(&shaContext, proof, kBlocklistManifestSize);
  }
  if (result == 0) result = mbedtls_sha256_finish(&shaContext, signedDigest);
  mbedtls_sha256_free(&shaContext);
  if (result != 0) {
    secureZero(signedDigest, sizeof(signedDigest));
    return BlocklistProofStatus::CRYPTO_ERROR;
  }

  mbedtls_ecp_group group;
  mbedtls_ecp_point publicPoint;
  mbedtls_mpi signatureR;
  mbedtls_mpi signatureS;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&publicPoint);
  mbedtls_mpi_init(&signatureR);
  mbedtls_mpi_init(&signatureS);

  int setupResult = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
  if (setupResult == 0) {
    setupResult = mbedtls_ecp_point_read_binary(
      &group, &publicPoint, trustedKey->sec1PublicKey, kBlocklistSec1PublicKeySize);
  }
  if (setupResult == 0) {
    setupResult = mbedtls_ecp_check_pubkey(&group, &publicPoint);
  }
  if (setupResult == 0) {
    setupResult = mbedtls_mpi_read_binary(
      &signatureR, proof + kBlocklistSignatureROffset,
      kBlocklistSignatureSize / 2);
  }
  if (setupResult == 0) {
    setupResult = mbedtls_mpi_read_binary(
      &signatureS, proof + kBlocklistSignatureSOffset,
      kBlocklistSignatureSize / 2);
  }
  if (setupResult == 0) {
    result = mbedtls_ecdsa_verify(
      &group, signedDigest, sizeof(signedDigest), &publicPoint,
      &signatureR, &signatureS);
  }

  mbedtls_mpi_free(&signatureS);
  mbedtls_mpi_free(&signatureR);
  mbedtls_ecp_point_free(&publicPoint);
  mbedtls_ecp_group_free(&group);
  secureZero(signedDigest, sizeof(signedDigest));
  if (setupResult != 0) return BlocklistProofStatus::CRYPTO_ERROR;
  if (result == 0) return BlocklistProofStatus::VALID;
  if (result == MBEDTLS_ERR_ECP_VERIFY_FAILED ||
      result == MBEDTLS_ERR_ECP_BAD_INPUT_DATA ||
      result == MBEDTLS_ERR_MPI_BAD_INPUT_DATA) {
    return BlocklistProofStatus::INVALID_SIGNATURE;
  }
  return BlocklistProofStatus::CRYPTO_ERROR;
}

static BlocklistProofStatus calculateBlocklistSha256(
    const char* path, uint8_t digest[32]) {
  secureZero(digest, 32);
  if (!LittleFS.exists(path)) return BlocklistProofStatus::MISSING;
  File file = LittleFS.open(path, "r");
  if (!file) return BlocklistProofStatus::STORAGE_ERROR;

  mbedtls_sha256_context shaContext;
  mbedtls_sha256_init(&shaContext);
  int result = mbedtls_sha256_starts(&shaContext, 0);
  uint8_t readBuffer[320];
  size_t remaining = file.size();
  while (result == 0 && remaining > 0) {
    const size_t wanted = min(remaining, sizeof(readBuffer));
    if (file.read(readBuffer, wanted) != wanted) {
      file.close();
      mbedtls_sha256_free(&shaContext);
      secureZero(readBuffer, sizeof(readBuffer));
      return BlocklistProofStatus::STORAGE_ERROR;
    }
    result = mbedtls_sha256_update(&shaContext, readBuffer, wanted);
    remaining -= wanted;
  }
  if (result == 0) result = mbedtls_sha256_finish(&shaContext, digest);
  mbedtls_sha256_free(&shaContext);
  file.close();
  secureZero(readBuffer, sizeof(readBuffer));
  if (result != 0) {
    secureZero(digest, 32);
    return BlocklistProofStatus::CRYPTO_ERROR;
  }
  return BlocklistProofStatus::VALID;
}

static BlocklistProofStatus authenticateBlocklistFile(
    const char* path, const uint8_t proof[kBlocklistProofSize],
    uint32_t* validatedRecords = nullptr) {
  if (validatedRecords) *validatedRecords = 0;
  const BlocklistProofStatus envelopeStatus = validateBlocklistProofEnvelope(proof);
  if (envelopeStatus != BlocklistProofStatus::VALID) return envelopeStatus;

  uint32_t records = 0;
  if (validateBlocklistFile(path, true, &records) !=
      BlocklistValidationStatus::VALID) {
    return BlocklistProofStatus::PAYLOAD_INVALID;
  }
  File file = LittleFS.open(path, "r");
  if (!file) return BlocklistProofStatus::STORAGE_ERROR;
  const size_t payloadSize = file.size();
  file.close();
  if (payloadSize != readLittleEndian32(proof + kBlocklistPayloadSizeOffset) ||
      records != readLittleEndian32(proof + kBlocklistRecordCountOffset)) {
    return BlocklistProofStatus::PAYLOAD_MISMATCH;
  }

  uint8_t digest[32];
  const BlocklistProofStatus digestStatus = calculateBlocklistSha256(path, digest);
  if (digestStatus != BlocklistProofStatus::VALID) {
    secureZero(digest, sizeof(digest));
    return digestStatus;
  }
  const bool digestMatches =
    mbedtls_ct_memcmp(digest, proof + kBlocklistPayloadSha256Offset,
                      sizeof(digest)) == 0;
  secureZero(digest, sizeof(digest));
  if (!digestMatches) return BlocklistProofStatus::PAYLOAD_MISMATCH;
  if (validatedRecords) *validatedRecords = records;
  return BlocklistProofStatus::VALID;
}

static BlocklistProofStatus readBlocklistProofFile(
    uint8_t proof[kBlocklistProofSize]) {
  secureZero(proof, kBlocklistProofSize);
  if (!LittleFS.exists(BLOCKLIST_NEW_AUTH_PATH)) return BlocklistProofStatus::MISSING;
  File proofFile = LittleFS.open(BLOCKLIST_NEW_AUTH_PATH, "r");
  if (!proofFile) return BlocklistProofStatus::STORAGE_ERROR;
  if (proofFile.size() != kBlocklistProofSize ||
      proofFile.read(proof, kBlocklistProofSize) != kBlocklistProofSize ||
      proofFile.available() != 0) {
    proofFile.close();
    secureZero(proof, kBlocklistProofSize);
    return BlocklistProofStatus::BAD_SIZE;
  }
  proofFile.close();
  return BlocklistProofStatus::VALID;
}

static BlocklistProofStatus authenticateBlocklistWithStoredProof(
    const char* path, uint32_t* validatedRecords = nullptr) {
  uint8_t proof[kBlocklistProofSize];
  const BlocklistProofStatus readStatus = readBlocklistProofFile(proof);
  if (readStatus != BlocklistProofStatus::VALID) {
    secureZero(proof, sizeof(proof));
    return readStatus;
  }
  const BlocklistProofStatus status =
    authenticateBlocklistFile(path, proof, validatedRecords);
  secureZero(proof, sizeof(proof));
  return status;
}

static bool removeBlocklistFile(const char* path) {
  if (LittleFS.remove(path)) return !LittleFS.exists(path);
  return !LittleFS.exists(path);
}

static bool removeBlocklistCandidateFiles() {
  // Proof-first cleanup reserves auth-without-candidate as the interrupted
  // new-to-active promotion marker used by boot recovery.
  if (!removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)) return false;
  return removeBlocklistFile(BLOCKLIST_NEW_PATH);
}

// Called only by boot recovery after the active/rollback state has been
// classified.  Never removes the active list; proof-first preserves the
// interrupted-promotion marker until it has been resolved.
static bool cleanupOrphanedBlocklistUpload() {
  if (!removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)) return false;
  return removeBlocklistFile(BLOCKLIST_NEW_PATH);
}

static bool reopenBlocklist() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  blocklistHealthy = false;
  uint32_t records = 0;
  if (validateBlocklistFile(BLOCKLIST_PATH, false, &records) !=
      BlocklistValidationStatus::VALID) return false;
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (!blocklist || !blocklist.seek(0)) {
    if (blocklist) blocklist.close();
    return false;
  }
  numHashes = records;
  blocklistHealthy = true;
  return true;
}

static bool restoreOldBlocklist();

static bool recoverBlocklistFiles() {
  const BlocklistValidationStatus activeStatus =
    validateBlocklistFile(BLOCKLIST_PATH, false);
  const BlocklistValidationStatus oldStatus =
    validateBlocklistFile(BLOCKLIST_OLD_PATH, false);
  const BlocklistValidationStatus newStatus =
    validateBlocklistFile(BLOCKLIST_NEW_PATH, true);
  Serial.printf("[blocklist] recovery active=%s old=%s candidate=%s\n",
                blocklistValidationToken(activeStatus),
                blocklistValidationToken(oldStatus),
                blocklistValidationToken(newStatus));

  if (activeStatus == BlocklistValidationStatus::VALID) {
    const bool candidateExists = LittleFS.exists(BLOCKLIST_NEW_PATH);
    const bool proofExists = LittleFS.exists(BLOCKLIST_NEW_AUTH_PATH);
    if (!candidateExists && proofExists) {
      // The proof deliberately remains while new is renamed to active. This is
      // the only state in which auth may exist without a candidate.
      const BlocklistProofStatus promotedStatus =
        authenticateBlocklistWithStoredProof(BLOCKLIST_PATH);
      Serial.printf("[blocklist] recovery promoted proof=%s\n",
                    blocklistProofToken(promotedStatus));
      if (promotedStatus == BlocklistProofStatus::VALID) {
        return removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH) &&
               removeBlocklistFile(BLOCKLIST_OLD_PATH);
      }
      if (oldStatus != BlocklistValidationStatus::VALID) return false;
      if (!removeBlocklistFile(BLOCKLIST_PATH)) return false;
      if (!removeBlocklistCandidateFiles()) return false;
      if (!LittleFS.rename(BLOCKLIST_OLD_PATH, BLOCKLIST_PATH)) return false;
      return validateBlocklistFile(BLOCKLIST_PATH, false) ==
             BlocklistValidationStatus::VALID;
    }
    if (!cleanupOrphanedBlocklistUpload()) return false;
    return removeBlocklistFile(BLOCKLIST_OLD_PATH);
  }

  if (oldStatus == BlocklistValidationStatus::VALID) {
    if (!removeBlocklistFile(BLOCKLIST_PATH)) return false;
    if (!cleanupOrphanedBlocklistUpload()) return false;
    if (!LittleFS.rename(BLOCKLIST_OLD_PATH, BLOCKLIST_PATH)) return false;
    if (validateBlocklistFile(BLOCKLIST_PATH, false) !=
        BlocklistValidationStatus::VALID) {
      if (LittleFS.exists(BLOCKLIST_PATH) &&
          !LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_OLD_PATH)) {
        Serial.println("[blocklist] rollback recovery rename failed");
      }
      return false;
    }
    return true;
  }

  BlocklistProofStatus candidateProofStatus = BlocklistProofStatus::MISSING;
  if (newStatus == BlocklistValidationStatus::VALID) {
    candidateProofStatus = authenticateBlocklistWithStoredProof(BLOCKLIST_NEW_PATH);
  }
  Serial.printf("[blocklist] recovery candidate proof=%s\n",
                blocklistProofToken(candidateProofStatus));
  if (candidateProofStatus == BlocklistProofStatus::VALID) {
    if (!removeBlocklistFile(BLOCKLIST_PATH)) return false;
    if (!LittleFS.rename(BLOCKLIST_NEW_PATH, BLOCKLIST_PATH)) return false;
    if (authenticateBlocklistWithStoredProof(BLOCKLIST_PATH) !=
        BlocklistProofStatus::VALID) return false;
    if (!removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)) return false;
    return removeBlocklistFile(BLOCKLIST_OLD_PATH);
  }

  return false;
}

[[noreturn]] static void enterStorageFailClosed(const char* reason) {
  if (blocklist) blocklist.close();
  numHashes = 0;
  blocklistHealthy = false;
  if (networkServicesStarted) {
    dnsServer.stop();
    upstreamCli.stop();
    networkServicesStarted = false;
  }
  Serial.printf("[fs] %s\n", reason);
  Serial.println("[fs] DNS/dashboard disabled; USB filesystem recovery required");
  while (true) delay(1000);
}

static bool restoreOldBlocklist() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  blocklistHealthy = false;
  if (validateBlocklistFile(BLOCKLIST_OLD_PATH, false) !=
      BlocklistValidationStatus::VALID) return false;
  if (!removeBlocklistFile(BLOCKLIST_PATH)) return false;
  // Keep old at its rollback path until proof and candidate are both gone. A
  // reset at any intermediate point therefore re-enters the old-first branch.
  if (!removeBlocklistCandidateFiles()) return false;
  if (!LittleFS.rename(BLOCKLIST_OLD_PATH, BLOCKLIST_PATH)) return false;
  return reopenBlocklist();
}

static bool uploadDeadlineReached();

static bool promoteBlocklistCandidate(bool (*deadlineExpired)()) {
  if (!deadlineExpired || deadlineExpired()) return false;
  uint32_t candidateRecords = 0;
  if (authenticateBlocklistWithStoredProof(BLOCKLIST_NEW_PATH,
                                            &candidateRecords) !=
      BlocklistProofStatus::VALID) return false;
  if (deadlineExpired()) return false;
  if (validateBlocklistFile(BLOCKLIST_PATH, false) !=
      BlocklistValidationStatus::VALID) {
    enterStorageFailClosed("active blocklist validation failed");
  }
  if (admin_http_policy::promotionDeadlineAction(
          admin_http_policy::PromotionPhase::BEFORE_ACTIVE_TO_OLD,
          deadlineExpired()) != admin_http_policy::PromotionDeadlineAction::CONTINUE) {
    return false;
  }
  if (!removeBlocklistFile(BLOCKLIST_OLD_PATH)) return false;
  if (admin_http_policy::promotionDeadlineAction(
          admin_http_policy::PromotionPhase::BEFORE_ACTIVE_TO_OLD,
          deadlineExpired()) != admin_http_policy::PromotionDeadlineAction::CONTINUE) {
    return false;
  }

  if (blocklist) blocklist.close();
  numHashes = 0;
  if (!LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_OLD_PATH)) {
    if (!reopenBlocklist() && !restoreOldBlocklist()) {
      enterStorageFailClosed("active blocklist reopen failed");
    }
    return false;
  }
  if (admin_http_policy::promotionDeadlineAction(
          admin_http_policy::PromotionPhase::AFTER_ACTIVE_TO_OLD,
          deadlineExpired()) != admin_http_policy::PromotionDeadlineAction::CONTINUE) {
    if (!restoreOldBlocklist()) enterStorageFailClosed("blocklist deadline rollback failed");
    return false;
  }
  if (!LittleFS.rename(BLOCKLIST_NEW_PATH, BLOCKLIST_PATH)) {
    const bool restored = restoreOldBlocklist();
    if (!restored) enterStorageFailClosed("blocklist rollback failed");
    return false;
  }
  if (admin_http_policy::promotionDeadlineAction(
          admin_http_policy::PromotionPhase::AFTER_NEW_TO_ACTIVE,
          deadlineExpired()) != admin_http_policy::PromotionDeadlineAction::CONTINUE) {
    if (!restoreOldBlocklist()) enterStorageFailClosed("blocklist deadline rollback failed");
    return false;
  }
  uint32_t promotedRecords = 0;
  if (authenticateBlocklistWithStoredProof(BLOCKLIST_PATH, &promotedRecords) !=
        BlocklistProofStatus::VALID ||
      promotedRecords != candidateRecords || !reopenBlocklist() ||
      numHashes != candidateRecords) {
    if (!restoreOldBlocklist()) {
      enterStorageFailClosed("blocklist rollback failed");
    }
    return false;
  }
  if (deadlineExpired()) {
    if (!restoreOldBlocklist()) enterStorageFailClosed("blocklist deadline rollback failed");
    return false;
  }
  if (!removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)) {
    if (!restoreOldBlocklist()) {
      enterStorageFailClosed("blocklist rollback failed");
    }
    return false;
  }
  if (deadlineExpired()) {
    if (!restoreOldBlocklist()) enterStorageFailClosed("blocklist deadline rollback failed");
    return false;
  }
  if (!LittleFS.remove(BLOCKLIST_OLD_PATH)) {
    if (!restoreOldBlocklist()) enterStorageFailClosed("blocklist rollback failed");
    return false;
  }
  if (admin_http_policy::promotionDeadlineAction(
          admin_http_policy::PromotionPhase::AFTER_CLEANUP,
          deadlineExpired()) == admin_http_policy::PromotionDeadlineAction::FAIL_CLOSED) {
    enterStorageFailClosed("blocklist deadline after promotion cleanup");
  }
  return true;
}

enum class BlocklistUploadStatus : uint8_t {
  IDLE,
  RECEIVING,
  CANDIDATE_READY,
  SUCCESS,
  BUSY,
  TOO_LARGE,
  STORAGE_ERROR,
  WRITE_ERROR,
  INVALID,
  PROOF_REQUIRED,
  AUTH_INVALID,
  CRYPTO_ERROR,
  ABORTED,
  PROMOTION_ERROR,
};

static bool uploadAuthorized = false;
static bool blocklistTransactionActive = false;
static bool uploadOwnsTransaction = false;
static size_t uploadBytesWritten = 0;
static BlocklistUploadStatus blocklistUploadStatus = BlocklistUploadStatus::IDLE;
static File upFile;
static uint8_t uploadProof[kBlocklistProofSize];
static bool uploadProofEnvelopeValid = false;

static bool discardBlocklistCandidate() {
  if (upFile) upFile.close();
  return removeBlocklistCandidateFiles();
}

static bool writeBlocklistCandidateProof() {
  if (!removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH)) return false;
  File proofFile = LittleFS.open(BLOCKLIST_NEW_AUTH_PATH, "w");
  if (!proofFile) return false;
  const size_t written = proofFile.write(uploadProof, kBlocklistProofSize);
  proofFile.flush();
  proofFile.close();
  if (written != kBlocklistProofSize) return false;

  uint8_t storedProof[kBlocklistProofSize];
  const BlocklistProofStatus readStatus = readBlocklistProofFile(storedProof);
  const bool matches = readStatus == BlocklistProofStatus::VALID &&
                       mbedtls_ct_memcmp(storedProof, uploadProof,
                                         sizeof(storedProof)) == 0;
  secureZero(storedProof, sizeof(storedProof));
  return matches;
}

static void resetBlocklistUploadRequestState() {
  uploadAuthorized = false;
  uploadRequestInFlight = false;
  uploadBytesWritten = 0;
  blocklistUploadStatus = BlocklistUploadStatus::IDLE;
  uploadProofEnvelopeValid = false;
  secureZero(uploadProof, sizeof(uploadProof));
}

static bool uploadDeadlineReached() {
  return uploadRequestInFlight &&
         admin_state::uploadDeadlineReached(millis(), adminWindowStartedMs, uploadStartedMs);
}

static void failBlocklistUpload(BlocklistUploadStatus status) {
  if (!uploadOwnsTransaction) {
    blocklistUploadStatus = status;
    return;
  }
  const bool cleaned = discardBlocklistCandidate();
  blocklistUploadStatus = cleaned ? status : BlocklistUploadStatus::STORAGE_ERROR;
  blocklistTransactionActive = false;
  uploadOwnsTransaction = false;
}

static bool handleUploadDone() {
  if (uploadDeadlineReached()) {
    if (uploadOwnsTransaction) failBlocklistUpload(BlocklistUploadStatus::ABORTED);
    addSecurityHeaders();
    web.send(400, "text/plain", "blocklist upload deadline exceeded");
    resetBlocklistUploadRequestState();
    return false;
  }
  if (!requireAdminMutation()) {
    if (uploadOwnsTransaction) failBlocklistUpload(BlocklistUploadStatus::ABORTED);
    resetBlocklistUploadRequestState();
    return false;
  }
  if (!uploadAuthorized) {
    if (uploadOwnsTransaction) failBlocklistUpload(BlocklistUploadStatus::ABORTED);
    addSecurityHeaders();
    web.send(400, "text/plain", "incomplete blocklist upload");
    resetBlocklistUploadRequestState();
    return false;
  }

  if (blocklistUploadStatus == BlocklistUploadStatus::CANDIDATE_READY) {
    if (uploadDeadlineReached()) {
      failBlocklistUpload(BlocklistUploadStatus::ABORTED);
    } else {
      blocklistUploadStatus = promoteBlocklistCandidate(uploadDeadlineReached)
        ? BlocklistUploadStatus::SUCCESS
        : BlocklistUploadStatus::PROMOTION_ERROR;
    }
    if (blocklistUploadStatus != BlocklistUploadStatus::SUCCESS &&
        !discardBlocklistCandidate()) {
      blocklistUploadStatus = BlocklistUploadStatus::STORAGE_ERROR;
    }
  }
  if (blocklistUploadStatus == BlocklistUploadStatus::SUCCESS && uploadDeadlineReached()) {
    // Cleanup has already made the new list active.  Do not falsely report a
    // transaction that crossed its absolute deadline; preserve safety by
    // entering the existing storage fail-closed state.
    enterStorageFailClosed("blocklist deadline before success response");
  }
  if (uploadOwnsTransaction) {
    blocklistTransactionActive = false;
    uploadOwnsTransaction = false;
  }

  int status = 500;
  const char* message = "blocklist update failed";
  switch (blocklistUploadStatus) {
    case BlocklistUploadStatus::SUCCESS:
      status = 200; message = "ok"; break;
    case BlocklistUploadStatus::BUSY:
      status = 409; message = "blocklist upload busy"; break;
    case BlocklistUploadStatus::TOO_LARGE:
      status = 413; message = "blocklist too large"; break;
    case BlocklistUploadStatus::INVALID:
      status = 400; message = "invalid blocklist"; break;
    case BlocklistUploadStatus::PROOF_REQUIRED:
      status = 400; message = "signed blocklist proof required"; break;
    case BlocklistUploadStatus::AUTH_INVALID:
      status = 400; message = "invalid signed blocklist"; break;
    case BlocklistUploadStatus::CRYPTO_ERROR:
      status = 500; message = "blocklist verification unavailable"; break;
    case BlocklistUploadStatus::ABORTED:
      status = 400; message = "blocklist upload aborted"; break;
    case BlocklistUploadStatus::STORAGE_ERROR:
    case BlocklistUploadStatus::WRITE_ERROR:
      status = 507; message = "blocklist storage failure"; break;
    case BlocklistUploadStatus::PROMOTION_ERROR:
      status = 500; message = "blocklist promotion failed; active retained"; break;
    case BlocklistUploadStatus::IDLE:
    case BlocklistUploadStatus::RECEIVING:
    case BlocklistUploadStatus::CANDIDATE_READY:
      status = 400; message = "incomplete blocklist upload"; break;
  }
  Serial.printf("[blocklist] upload result=%d bytes=%u records=%u\n",
                status, static_cast<unsigned>(uploadBytesWritten), numHashes);
  addSecurityHeaders();
  const bool success = blocklistUploadStatus == BlocklistUploadStatus::SUCCESS;
  if (success && uploadDeadlineReached()) {
    enterStorageFailClosed("blocklist deadline before success response");
  }
  if (success) (void)uploadWindowBudget.recordPromotion(true);
  web.send(status, "text/plain", message);
  resetBlocklistUploadRequestState();
  return success;
}

static void handleUpload(HTTPUpload& u) {
  switch (u.status) {
    case UPLOAD_FILE_START: {
      if (!uploadAuthorized || !uploadProofEnvelopeValid) {
        if (uploadAuthorized) blocklistUploadStatus = BlocklistUploadStatus::PROOF_REQUIRED;
        if (uploadOwnsTransaction) failBlocklistUpload(BlocklistUploadStatus::ABORTED);
        break;
      }
      // Preserve the first terminal result and never let another request part
      // restart the transaction after the fixed envelope has been validated.
      if (blocklistUploadStatus != BlocklistUploadStatus::IDLE) {
        if (uploadOwnsTransaction) failBlocklistUpload(BlocklistUploadStatus::BUSY);
        break;
      }
      if (blocklistTransactionActive) {
        if (uploadOwnsTransaction) {
          failBlocklistUpload(BlocklistUploadStatus::BUSY);
        } else {
          blocklistUploadStatus = BlocklistUploadStatus::BUSY;
        }
        break;
      }
      uploadBytesWritten = 0;
      uploadOwnsTransaction = false;
      blocklistTransactionActive = true;
      uploadOwnsTransaction = true;
      const int contentLength = web.clientContentLength();
      if (contentLength > 0 &&
          static_cast<size_t>(contentLength) > BLOCKLIST_UPLOAD_REQUEST_MAX) {
        failBlocklistUpload(BlocklistUploadStatus::TOO_LARGE);
        break;
      }
      if (!removeBlocklistCandidateFiles()) {
        failBlocklistUpload(BlocklistUploadStatus::STORAGE_ERROR);
        break;
      }
      upFile = LittleFS.open(BLOCKLIST_NEW_PATH, "w");
      if (!upFile) {
        failBlocklistUpload(BlocklistUploadStatus::STORAGE_ERROR);
        break;
      }
      blocklistUploadStatus = BlocklistUploadStatus::RECEIVING;
      Serial.println("[blocklist] receiving manual upload");
      break;
    }
    case UPLOAD_FILE_WRITE: {
      if (!uploadAuthorized ||
          blocklistUploadStatus != BlocklistUploadStatus::RECEIVING || !upFile) break;
      if (u.currentSize > BLOCKLIST_MAX_BYTES - uploadBytesWritten) {
        failBlocklistUpload(BlocklistUploadStatus::TOO_LARGE);
        break;
      }
      const size_t bytesWritten = upFile.write(u.buf, u.currentSize);
      if (bytesWritten != u.currentSize) {
        failBlocklistUpload(BlocklistUploadStatus::WRITE_ERROR);
        break;
      }
      uploadBytesWritten += bytesWritten;
      break;
    }
    case UPLOAD_FILE_END: {
      if (!uploadAuthorized) break;
      if (blocklistUploadStatus != BlocklistUploadStatus::RECEIVING || !upFile) break;
      if (uploadDeadlineReached()) {
        failBlocklistUpload(BlocklistUploadStatus::ABORTED);
        break;
      }
      upFile.flush();
      upFile.close();
      if (uploadBytesWritten > BLOCKLIST_MAX_BYTES ||
          u.totalSize != uploadBytesWritten) {
        failBlocklistUpload(BlocklistUploadStatus::TOO_LARGE);
        break;
      }
      if (uploadDeadlineReached()) {
        failBlocklistUpload(BlocklistUploadStatus::ABORTED);
        break;
      }
      const BlocklistValidationStatus validation =
        validateBlocklistFile(BLOCKLIST_NEW_PATH, true);
      if (validation != BlocklistValidationStatus::VALID) {
        Serial.printf("[blocklist] candidate rejected=%s\n",
                      blocklistValidationToken(validation));
        failBlocklistUpload(BlocklistUploadStatus::INVALID);
        break;
      }
      if (uploadDeadlineReached()) {
        failBlocklistUpload(BlocklistUploadStatus::ABORTED);
        break;
      }
      if (!writeBlocklistCandidateProof()) {
        failBlocklistUpload(BlocklistUploadStatus::STORAGE_ERROR);
        break;
      }
      if (uploadDeadlineReached()) {
        failBlocklistUpload(BlocklistUploadStatus::ABORTED);
        break;
      }
      const BlocklistProofStatus proofStatus =
        authenticateBlocklistWithStoredProof(BLOCKLIST_NEW_PATH);
      if (proofStatus != BlocklistProofStatus::VALID) {
        Serial.printf("[blocklist] candidate proof rejected=%s\n",
                      blocklistProofToken(proofStatus));
        const BlocklistUploadStatus failureStatus =
          proofStatus == BlocklistProofStatus::CRYPTO_ERROR
            ? BlocklistUploadStatus::CRYPTO_ERROR
            : (proofStatus == BlocklistProofStatus::STORAGE_ERROR
                 ? BlocklistUploadStatus::STORAGE_ERROR
                 : BlocklistUploadStatus::AUTH_INVALID);
        failBlocklistUpload(failureStatus);
        break;
      }
      if (uploadDeadlineReached()) {
        failBlocklistUpload(BlocklistUploadStatus::ABORTED);
        break;
      }
      blocklistUploadStatus = BlocklistUploadStatus::CANDIDATE_READY;
      break;
    }
    case UPLOAD_FILE_ABORTED:
      if (!uploadAuthorized) break;
      if (!uploadOwnsTransaction) break;
      if (upFile) upFile.close();
      bool cleaned = removeBlocklistFile(BLOCKLIST_NEW_AUTH_PATH);
      if (cleaned) {
        cleaned = LittleFS.remove(BLOCKLIST_NEW_PATH) ||
                  !LittleFS.exists(BLOCKLIST_NEW_PATH);
      }
      if (!cleaned) {
        blocklistUploadStatus = BlocklistUploadStatus::STORAGE_ERROR;
      } else {
        blocklistUploadStatus = BlocklistUploadStatus::ABORTED;
      }
      blocklistTransactionActive = false;
      uploadOwnsTransaction = false;
      Serial.println("[blocklist] upload aborted; active retained");
      break;
  }
}

static bool requestStateAllowsAdmin();
static bool headerEqualsPrefix(const String& value, const char* prefix);
static esp_err_t sendBadRequest(httpd_req_t* request, int status, const char* message);

static fixed_envelope::ReceiveResult receiveEnvelopeBytes(
    void* context, char* buffer, size_t length) {
  const int received = httpd_req_recv(static_cast<httpd_req_t*>(context), buffer, length);
  if (received > 0) {
    return {fixed_envelope::ReceiveStatus::OK, static_cast<size_t>(received)};
  }
  if (received == HTTPD_SOCK_ERR_TIMEOUT) {
    return {fixed_envelope::ReceiveStatus::TIMEOUT, 0};
  }
  if (received == 0) {
    return {fixed_envelope::ReceiveStatus::END_OF_BODY, 0};
  }
  return {fixed_envelope::ReceiveStatus::ERROR, 0};
}

static uint32_t envelopeMillis() { return millis(); }

static bool receiveFailureRequiresClose(fixed_envelope::ReceiveStatus status) {
  return status != fixed_envelope::ReceiveStatus::OK;
}

static bool flushUploadBytes(uint8_t* bytes, size_t& count) {
  if (!count) return true;
  HTTPUpload upload{UPLOAD_FILE_WRITE, 0, count, bytes};
  handleUpload(upload);
  count = 0;
  return blocklistUploadStatus == BlocklistUploadStatus::RECEIVING;
}

static bool parseStrictContentLength(const String& value, size_t maximum,
                                     size_t* parsedLength) {
  return admin_http_policy::parseStrictDecimal(value.c_str(), value.length(),
                                                maximum, parsedLength);
}

static esp_err_t rejectRequestWithPendingBody(httpd_req_t* request, int status,
                                              const char* message,
                                              admin_http_policy::RequestBodyFraming framing) {
  const esp_err_t response = sendBadRequest(request, status, message);
  return admin_http_policy::mustCloseRequestBody(framing) ? ESP_FAIL : response;
}

static bool requestHasOctetStreamContentType() {
  String contentType = web.header("Content-Type");
  contentType.trim();
  contentType.toLowerCase();
  const bool matches = contentType == "application/octet-stream";
  clearSensitiveString(contentType);
  return matches;
}

static bool requestHasTransferEncoding() {
  String transferEncoding = web.header("Transfer-Encoding");
  const bool present = transferEncoding.length() != 0;
  clearSensitiveString(transferEncoding);
  return present;
}

static BlocklistUploadStatus blocklistProofFailureStatus(BlocklistProofStatus status) {
  if (status == BlocklistProofStatus::MISSING) return BlocklistUploadStatus::PROOF_REQUIRED;
  if (status == BlocklistProofStatus::CRYPTO_ERROR) return BlocklistUploadStatus::CRYPTO_ERROR;
  return BlocklistUploadStatus::AUTH_INVALID;
}

static bool streamAuthenticatedBlocklistPayload(
    fixed_envelope::Reader& reader, size_t expectedLength,
    fixed_envelope::ReceiveStatus* receiveStatus) {
  if (!receiveStatus) return false;
  *receiveStatus = fixed_envelope::ReceiveStatus::OK;
  uint8_t output[256];
  while (expectedLength) {
    const size_t chunkLength = min(expectedLength, sizeof(output));
    const fixed_envelope::ReceiveStatus status = reader.readExact(output, chunkLength);
    if (status != fixed_envelope::ReceiveStatus::OK) {
      *receiveStatus = status;
      return false;
    }
    size_t pending = chunkLength;
    if (!flushUploadBytes(output, pending)) return false;
    expectedLength -= chunkLength;
  }
  return reader.remaining() == 0;
}

static esp_err_t handleFixedEnvelopeUpload(httpd_req_t* request) {
  if (!requestStateAllowsAdmin()) return ESP_FAIL;
  String declaredLength = web.header("Content-Length");
  size_t declared = 0;
  const bool validDeclaredLength = parseStrictContentLength(
      declaredLength, BLOCKLIST_UPLOAD_REQUEST_MAX, &declared);
  clearSensitiveString(declaredLength);
  const bool hasTransferEncoding = requestHasTransferEncoding();
  const bool trustedFraming = !hasTransferEncoding && validDeclaredLength &&
      request->content_len != 0 && declared == request->content_len &&
      declared > BLOCKLIST_PROOF_BYTES && declared <= BLOCKLIST_UPLOAD_REQUEST_MAX;
  if (!trustedFraming) {
    return rejectRequestWithPendingBody(request, 400, "invalid binary upload length",
                                        {false, request->content_len});
  }

  if (!requestHasOctetStreamContentType()) {
    return rejectRequestWithPendingBody(request, 415,
                                        "binary signed blocklist upload required",
                                        {true, request->content_len});
  }

  if (!admin_state::acceptsNewAdminWork(millis(), adminWindowStartedMs) ||
      !uploadWindowBudget.allowUploadStart() || uploadRequestInFlight) {
    return rejectRequestWithPendingBody(request, 403, "upload window closed",
                                        {true, request->content_len});
  }

  if (!requireAdminMutation()) return ESP_FAIL;
  uploadAuthorized = true;
  if (blocklistTransactionActive) {
    blocklistUploadStatus = BlocklistUploadStatus::BUSY;
    handleUploadDone();
    return ESP_FAIL;
  }
  if (!uploadWindowBudget.recordUploadStart()) {
    return rejectRequestWithPendingBody(request, 403, "upload window closed",
                                        {true, request->content_len});
  }
  uploadStartedMs = millis();
  uploadRequestInFlight = true;
  fixed_envelope::Reader reader(
      request->content_len, uploadStartedMs,
      admin_state::uploadDeadlineDuration(adminWindowStartedMs, uploadStartedMs),
      request, receiveEnvelopeBytes, envelopeMillis);
  const fixed_envelope::ReceiveStatus proofRead =
      reader.readExact(uploadProof, sizeof(uploadProof));
  if (proofRead != fixed_envelope::ReceiveStatus::OK) {
    blocklistUploadStatus = BlocklistUploadStatus::ABORTED;
    handleUploadDone();
    return receiveFailureRequiresClose(proofRead) ? ESP_FAIL : ESP_OK;
  }
  const BlocklistProofStatus proofStatus = validateBlocklistProofEnvelope(uploadProof);
  if (proofStatus != BlocklistProofStatus::VALID) {
    blocklistUploadStatus = blocklistProofFailureStatus(proofStatus);
    handleUploadDone();
    return admin_http_policy::mustCloseRequestBody({true, reader.remaining()})
      ? ESP_FAIL : ESP_OK;
  }
  const size_t expectedPayloadLength =
    static_cast<size_t>(readLittleEndian32(uploadProof + kBlocklistPayloadSizeOffset));
  if (!fixed_envelope::hasAllowedPayloadLength(
          request->content_len, BLOCKLIST_PROOF_BYTES,
          expectedPayloadLength, BLOCKLIST_MAX_BYTES) ||
      expectedPayloadLength != reader.remaining()) {
    blocklistUploadStatus = BlocklistUploadStatus::AUTH_INVALID;
    handleUploadDone();
    return admin_http_policy::mustCloseRequestBody({true, reader.remaining()})
      ? ESP_FAIL : ESP_OK;
  }
  if (uploadDeadlineReached()) {
    blocklistUploadStatus = BlocklistUploadStatus::ABORTED;
    handleUploadDone();
    return ESP_FAIL;
  }
  uploadProofEnvelopeValid = true;

  HTTPUpload start{UPLOAD_FILE_START, 0, 0, nullptr};
  handleUpload(start);
  if (!uploadAuthorized || blocklistUploadStatus != BlocklistUploadStatus::RECEIVING) {
    handleUploadDone();
    return admin_http_policy::mustCloseRequestBody({true, reader.remaining()})
      ? ESP_FAIL : ESP_OK;
  }

  fixed_envelope::ReceiveStatus payloadReceiveStatus = fixed_envelope::ReceiveStatus::OK;
  const bool payloadComplete = streamAuthenticatedBlocklistPayload(
      reader, expectedPayloadLength, &payloadReceiveStatus) && !uploadDeadlineReached();
  if (!payloadComplete && payloadReceiveStatus == fixed_envelope::ReceiveStatus::OK &&
      uploadDeadlineReached()) {
    payloadReceiveStatus = fixed_envelope::ReceiveStatus::DEADLINE;
  }
  if (!payloadComplete) {
    HTTPUpload aborted{UPLOAD_FILE_ABORTED, 0, 0, nullptr};
    handleUpload(aborted);
  } else {
    HTTPUpload end{UPLOAD_FILE_END, uploadBytesWritten, 0, nullptr};
    handleUpload(end);
  }
  const bool promotionSucceeded = handleUploadDone();
  return receiveFailureRequiresClose(payloadReceiveStatus) ||
         admin_http_policy::mustCloseRequestBody({true, reader.remaining()}) ? ESP_FAIL : ESP_OK;
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static const char* ADMIN_AP_NAMESPACE = "adminap";
static const char* ADMIN_AP_PSK_KEY = "psk";

static bool validAdminApPsk(const String& psk) {
  if (psk.length() < 8 || psk.length() > 63) return false;
  for (size_t index = 0; index < psk.length(); ++index) {
    const uint8_t ch = static_cast<uint8_t>(psk[index]);
    if (ch < 0x20 || ch > 0x7e) return false;
  }
  return true;
}

// Manufacturing/USB tooling owns this value.  The generic firmware never
// creates, derives, prints, or substitutes an AP password.
static bool loadAdminApPsk(String& psk) {
  Preferences apPrefs;
  if (!apPrefs.begin(ADMIN_AP_NAMESPACE, true)) return false;
  psk = apPrefs.getString(ADMIN_AP_PSK_KEY, "");
  apPrefs.end();
  return validAdminApPsk(psk);
}

static void clearWifiCredentials() {
  if (prefs.begin("wifi", false)) {
    prefs.clear();
    prefs.end();
  }
}

static void refreshProvisioningCsrf() {
  secureZero(provisioningCsrf, sizeof(provisioningCsrf));
  esp_fill_random(provisioningCsrf, sizeof(provisioningCsrf));
}

static bool startBoundedHttpServer(bool provisioning);
static void closeAdminWindowAndRestart(const char* reason);

static void handlePortalBootAuthorization() {
  if (physicalProvisioningAllowed ||
      !bootHoldReached(portalBootHold, PORTAL_BOOT_HOLD_MS)) return;

  physicalProvisioningAllowed = true;
  clearWifiCredentials();
  clearAdminVerifier();
  refreshProvisioningCsrf();
  Serial.println("[setup] physical BOOT hold authorized provisioning");
}

static void handlePortalRestart() {
  if (!portalRestartPending || !bootReleasedStable(portalRestartRelease)) return;
  Serial.println("[setup] BOOT released; restarting after provisioning");
  ESP.restart();
}

static void handleRuntimeBootRecovery() {
  if (runtimeRecoveryPending) {
    if (!bootReleasedStable(runtimeRecoveryRelease)) return;
    Serial.println("[setup] BOOT released; restarting into recovery portal");
    ESP.restart();
    return;
  }

  if (!bootHoldReached(runtimeBootHold, RUNTIME_BOOT_HOLD_MS)) return;

  clearWifiCredentials();
  clearAdminVerifier();
  clearAdminSession();
  runtimeRecoveryPending = true;
  Serial.println("[setup] physical BOOT hold cleared WiFi/admin; release BOOT to restart");
}

static bool constantTimeStringsEqual(const String& left, const String& right) {
  if (left.length() != right.length()) return false;
  return mbedtls_ct_memcmp(left.c_str(), right.c_str(), left.length()) == 0;
}

static bool validProvisioningCsrf() {
  String encoded = web.arg("csrf");
  uint8_t candidate[CSRF_TOKEN_BYTES];
  secureZero(candidate, sizeof(candidate));
  const bool decoded = decodeHex(encoded, candidate, sizeof(candidate));
  const bool matches = decoded &&
                       mbedtls_ct_memcmp(candidate, provisioningCsrf, sizeof(candidate)) == 0;
  secureZero(candidate, sizeof(candidate));
  clearSensitiveString(encoded);
  return matches;
}

static bool connectWiFi() {
  ConfigRecord config;
  String ss, pw;
  if (loadActiveConfig(config)) {
    ss = String(config.ssid); pw = String(config.password);
    secureZero(&config, sizeof(config));
  } else {
    prefs.begin("wifi", true);
    ss = prefs.getString("ssid", "");
    pw = prefs.getString("pass", "");
    prefs.end();
  }
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) {
    clearSensitiveString(pw);
    return false;  // unconfigured
  }
  Serial.printf("WiFi: connecting using %s credentials\n", ss.length() ? "provisioned" : "local fallback");
  const bool staModeOk = WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  const uint32_t staStartWaitMs = millis();
  while (staModeOk && !WiFi.STA.started() && millis() - staStartWaitMs < 1000) delay(1);
  if (!staModeOk || !WiFi.STA.started()) {
    Serial.println("[wifi] failed to start STA before applying the TX power limit");
    clearSensitiveString(pw);
    return false;
  }
  const bool staRfWorkaroundOk = applyC3RfWorkaround();
  if (!staRfWorkaroundOk) {
    Serial.println("[wifi] failed to apply the 8.5 dBm STA TX power limit");
    clearSensitiveString(pw);
    return false;
  }
  WiFi.begin(ssid, pass);
  clearSensitiveString(pw);
  if (waitForWiFiAssociation("first")) return true;

  Serial.println("[wifi] first association window timed out; retrying once");
  const bool disconnectedForRetry =
    WiFi.disconnect(false, false, WIFI_DISCONNECT_TIMEOUT_MS);
  if (!disconnectedForRetry) {
    Serial.println("[wifi] disconnect did not settle within retry timeout");
    delay(WIFI_RETRY_SETTLE_MS);
    return false;
  }
  delay(WIFI_RETRY_SETTLE_MS);

  const bool reconnectRequested = WiFi.reconnect();
  if (!reconnectRequested) {
    Serial.println("[wifi] reconnect request failed");
    return false;
  }
  if (waitForWiFiAssociation("second")) return true;

  const bool finalDisconnectOk =
    WiFi.disconnect(false, false, WIFI_DISCONNECT_TIMEOUT_MS);
  if (!finalDisconnectOk) {
    Serial.println("[wifi] failed to quiesce STA after final timeout");
  }
  delay(WIFI_RETRY_SETTLE_MS);
  return false;
}

static bool startDnsServices() {
  bool retryUsed = false;
  while (true) {
    dnsServer.stop();
    const bool dnsBound = dnsServer.begin(DNS_PORT) != 0;
    const admin_state::DnsStartupAction action =
      admin_state::dnsStartupAction(dnsBound, retryUsed);
    if (action == admin_state::DnsStartupAction::STARTED) {
      upstreamCli.stop();
      upstreamSocketReady = upstreamCli.begin(0) != 0;
      networkServicesStarted = true;
      return true;
    }
    if (action == admin_state::DnsStartupAction::FAIL_CLOSED) {
      upstreamCli.stop();
      upstreamSocketReady = false;
      networkServicesStarted = false;
      return false;
    }
    retryUsed = true;
  }
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Configuraci&oacute;n de NetShield Mini</title></head>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; NetShield Mini &mdash; configuraci&oacute;n Wi-Fi</h2>";
  if (!physicalProvisioningAllowed) {
    html += "<p>Los cambios requieren autorizaci&oacute;n f&iacute;sica. Con el dispositivo ya encendido, mant&eacute;n pulsado BOOT durante 5 segundos, su&eacute;ltalo y recarga esta p&aacute;gina. No reinicies ni apagues el dispositivo mientras pulsas BOOT.</p>";
  } else {
    String csrf = encodeHex(provisioningCsrf, sizeof(provisioningCsrf));
    html +=
      "<p style='color:#8b949e'>Elige tu red, crea la contrase&ntilde;a local de administraci&oacute;n y conecta.</p>"
      "<form method=POST action=/wifisave>"
      "<input type=hidden name=csrf value=\"" + htmlEscape(csrf) + "\">"
      "<input list=nets name=s placeholder='Nombre Wi-Fi' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
      "<datalist id=nets>" + portalOpts + "</datalist>"
      "<input name=p type=password placeholder='Contrase&ntilde;a Wi-Fi' autocomplete=new-password style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
      "<input name=a type=password minlength=12 maxlength=128 required autocomplete=new-password placeholder='Contrase&ntilde;a admin (12-128 caracteres)' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
      "<input name=c type=password minlength=12 maxlength=128 required autocomplete=new-password placeholder='Confirma la contrase&ntilde;a admin' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
      "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Conectar</button>"
      "</form>";
    clearSensitiveString(csrf);
  }
  html += "</body></html>";
  addSecurityHeaders();
  web.send(200, "text/html; charset=utf-8", html);
}
static void handleWifiSave() {
  if (!physicalProvisioningAllowed) {
    addSecurityHeaders();
    web.send(403, "text/plain", "physical authorization required");
    return;
  }
  if (!validProvisioningCsrf()) {
    addSecurityHeaders();
    web.send(403, "text/plain", "invalid provisioning request");
    return;
  }

  String ss = web.arg("s");
  String pw = web.arg("p");
  String adminPassword = web.arg("a");
  String adminConfirmation = web.arg("c");
  const bool passwordsValid = validAdminPasswordLength(adminPassword) &&
                              constantTimeStringsEqual(adminPassword, adminConfirmation);
  if (!ss.length() || ss.length() > 32 || pw.length() > 63 || !passwordsValid) {
    clearSensitiveString(pw);
    clearSensitiveString(adminPassword);
    clearSensitiveString(adminConfirmation);
    addSecurityHeaders();
    web.send(400, "text/plain", "invalid setup data");
    return;
  }

  // No candidate byte reaches NVS here.  The provisioning supervisor first
  // proves STA association, then writes one complete inactive A/B record.
  pendingProvisioningSsid = ss;
  pendingProvisioningPassword = pw;
  pendingProvisioningAdminPassword = adminPassword;
  provisioningCandidatePending = true;
  clearSensitiveString(adminConfirmation);
  physicalProvisioningAllowed = false;
  secureZero(provisioningCsrf, sizeof(provisioningCsrf));
  String escapedSsid = htmlEscape(ss);
  addSecurityHeaders();
  web.send(200, "text/html; charset=utf-8", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Probando la red indicada antes de guardarla: <b>" + escapedSsid + "</b>&hellip;</body>");
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static bool startConfigPortal(bool authorized) {
  // Setup HTTP is a recovery-only mutation surface.  A normal boot, an
  // ordinary STA failure, and a 2–<4 second admin gesture must not publish it.
  if (!authorized) {
    runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED;
    return false;
  }
  String psk;
  if (!loadAdminApPsk(psk)) {
    runtimeState = RuntimeState::ADMIN_PSK_REQUIRED;
    Serial.println("[setup] per-device admin AP PSK missing; USB/manufacturing recovery required");
    return false;
  }
  portalOpts = "";  // Do not scan or disclose nearby SSIDs in this window.
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[28]; snprintf(ap, sizeof(ap), "NetShield-Setup-%02X%02X", mac[4], mac[5]);
  const bool apModeOk = WiFi.mode(WIFI_AP);
  const bool apConfigOk = apModeOk && WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  const bool softApOk = apConfigOk && WiFi.softAP(ap, psk.c_str(), 1, false, 1);
  clearSensitiveString(psk);
  if (!softApOk || !applyC3RfWorkaround() || !startBoundedHttpServer(true)) {
    runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED;
    Serial.println("[setup] bounded WPA2 setup AP failed");
    return false;
  }
  refreshProvisioningCsrf();
  physicalProvisioningAllowed = true;
  if (runtimeState != RuntimeState::PROVISIONING_AP) provisioningStartedMs = millis();
  runtimeState = RuntimeState::PROVISIONING_AP;
  dnsPortal.start(53, "*", WiFi.softAPIP());
  Serial.printf("[setup] WPA2 setup AP ready: %s\n", ap);
  return true;
}

static bool startAdminApWindow() {
  String psk;
  if (!loadAdminApPsk(psk)) {
    runtimeState = RuntimeState::ADMIN_PSK_REQUIRED;
    Serial.println("[admin] per-device AP PSK missing; no admin listener started");
    return false;
  }
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[28]; snprintf(ap, sizeof(ap), "NetShield-Admin-%02X%02X", mac[4], mac[5]);
  const bool apModeOk = WiFi.mode(WIFI_AP);
  bool apConfigOk = false;
  if (apModeOk) {
    apConfigOk = WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  }
  bool softApOk = false;
  if (apConfigOk) {
    softApOk = WiFi.softAP(ap, psk.c_str(), 1, false, 1);
  }
  clearSensitiveString(psk);
  bool rfOk = false;
  if (softApOk) {
    rfOk = applyC3RfWorkaround();
  }
  bool httpOk = false;
  if (rfOk) {
    httpOk = startBoundedHttpServer(false);
  }
  if (!softApOk || !rfOk || !httpOk) {
    Serial.println("[admin] WPA2 admin AP failed; rebooting to DNS-only mode");
    ESP.restart();
    return false;
  }
  clearAdminSession(); resetLoginThrottle(); adminHttpSocket = -1;
  adminWindowCloseRequested = false; uploadWindowBudget = admin_state::WindowBudget{};
  adminWindowStartedMs = millis(); runtimeState = RuntimeState::ADMIN_AP_WINDOW;
  Serial.printf("[admin] WPA2 admin window ready: %s\n", ap);
  return true;
}

static bool validateProvisioningCandidateSta() {
  adminHttpAccepting = false;
  dnsPortal.stop();
  if (adminHttpServer) { httpd_stop(adminHttpServer); adminHttpServer = nullptr; }
  WiFi.softAPdisconnect(true);
  const bool modeOk = WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  const uint32_t started = millis();
  while (modeOk && !WiFi.STA.started() && millis() - started < 1000) delay(1);
  if (!modeOk || !WiFi.STA.started() || !applyC3RfWorkaround()) return false;
  WiFi.begin(pendingProvisioningSsid.c_str(), pendingProvisioningPassword.c_str());
  if (waitForWiFiAssociation("candidate-first")) return true;
  if (!WiFi.disconnect(false, false, WIFI_DISCONNECT_TIMEOUT_MS)) return false;
  delay(WIFI_RETRY_SETTLE_MS);
  if (!WiFi.reconnect()) return false;
  if (waitForWiFiAssociation("candidate-second")) return true;
  WiFi.disconnect(false, false, WIFI_DISCONNECT_TIMEOUT_MS);
  delay(WIFI_RETRY_SETTLE_MS);
  return false;
}

static void processProvisioningCandidate() {
  if (!provisioningCandidatePending) return;
  provisioningCandidatePending = false;
  const bool connected = validateProvisioningCandidateSta();
  const bool committed = connected && commitProvisioningCandidate(
    pendingProvisioningSsid, pendingProvisioningPassword, pendingProvisioningAdminPassword);
  clearSensitiveString(pendingProvisioningPassword);
  clearSensitiveString(pendingProvisioningAdminPassword);
  clearSensitiveString(pendingProvisioningSsid);
  if (committed) { ESP.restart(); return; }
  if (!admin_state::deadlineReached(millis(), provisioningStartedMs, admin_state::kProvisioningWindowMs)) {
    startConfigPortal(true);
  } else {
    runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED;
  }
}

static void handleAddBlock() {
  if (!requireAdminMutation()) return;
  addCustom(web.arg("d"));
  addSecurityHeaders();
  web.send(200, "text/plain", "ok");
}

static void handleUnblock() {
  if (!requireAdminMutation()) return;
  removeCustom(web.arg("d"));
  addSecurityHeaders();
  web.send(200, "text/plain", "ok");
}

static void handleForgetWifi() {
  if (!requireAdminMutation()) return;
  addSecurityHeaders();
  web.send(200, "text/plain; charset=utf-8",
           "Wi-Fi borrada. Reiniciando normalmente; no mantengas BOOT durante el reinicio. "
           "Cuando aparezca el portal, mantén BOOT durante 3 segundos y suéltalo.");
  clearWifiCredentials();
  delay(500);
  ESP.restart();
}

static void handleNotFound() {
  if (!requireAllowedAdminHost()) return;
  addSecurityHeaders();
  web.send(404, "text/plain", "not found");
}

static bool headerEqualsPrefix(const String& value, const char* prefix) {
  return value.startsWith(prefix);
}

static admin_http_policy::FormReadOutcome readRequiredForm(httpd_req_t* request) {
  using admin_http_policy::FormReadOutcome;
  using admin_http_policy::FormReadStatus;
  if (!request) return {FormReadStatus::BAD_REQUEST, true};
  const size_t requestLength = request->content_len;
  const bool hasTransferEncoding = requestHasTransferEncoding();
  if (hasTransferEncoding || !requestLength || requestLength > HTTP_FORM_MAX_BYTES) {
    return admin_http_policy::formFramingOutcome(hasTransferEncoding, requestLength);
  }
  String declaredLength = web.header("Content-Length");
  size_t declared = 0;
  const bool validDeclaredLength = parseStrictContentLength(
      declaredLength, HTTP_FORM_MAX_BYTES, &declared);
  clearSensitiveString(declaredLength);
  if (!validDeclaredLength || declared != requestLength) {
    return {FormReadStatus::BAD_REQUEST, false};
  }
  String contentType = web.header("Content-Type");
  const bool formType = headerEqualsPrefix(contentType, "application/x-www-form-urlencoded");
  clearSensitiveString(contentType);
  if (!formType) return {FormReadStatus::BAD_REQUEST, false};

  static char body[HTTP_FORM_MAX_BYTES + 1];
  auto finish = [](FormReadStatus status, bool bodyConsumed) {
    secureZero(body, sizeof(body));
    return FormReadOutcome{status, bodyConsumed};
  };
  size_t received = 0;
  const uint32_t started = millis();
  while (received < requestLength) {
    if (admin_state::deadlineReached(millis(), started, HTTP_IO_TIMEOUT_SECONDS * 1000UL)) {
      return finish(FormReadStatus::TIMEOUT, false);
    }
    const int result = httpd_req_recv(request, body + received,
                                      requestLength - received);
    const FormReadStatus receiveStatus = admin_http_policy::formReceiveStatus(
        result, result == HTTPD_SOCK_ERR_TIMEOUT);
    if (receiveStatus != FormReadStatus::OK) return finish(receiveStatus, false);
    if (static_cast<size_t>(result) > requestLength - received) {
      return finish(FormReadStatus::RECEIVE_ERROR, false);
    }
    received += static_cast<size_t>(result);
  }
  if (admin_state::deadlineReached(millis(), started, HTTP_IO_TIMEOUT_SECONDS * 1000UL)) {
    return finish(FormReadStatus::TIMEOUT, true);
  }
  body[received] = '\0';
  char* pair = body;
  while (pair && *pair) {
    char* next = strchr(pair, '&');
    if (next) *next++ = '\0';
    char* equals = strchr(pair, '=');
    if (!equals) return finish(FormReadStatus::BAD_REQUEST, true);
    *equals++ = '\0';
    auto decode = [](char* text) -> bool {
      char* out = text;
      for (char* in = text; *in; ++in) {
        if (*in == '+') { *out++ = ' '; continue; }
        if (*in == '%') {
          if (!in[1] || !in[2]) return false;
          const int high = hexValue(in[1]);
          const int low = hexValue(in[2]);
          if (high < 0 || low < 0) return false;
          *out++ = static_cast<char>((high << 4) | low);
          in += 2;
          continue;
        }
        *out++ = *in;
      }
      *out = '\0';
      return true;
    };
    if (!decode(pair) || !decode(equals) || !web.addArg(pair, equals)) {
      return finish(FormReadStatus::BAD_REQUEST, true);
    }
    pair = next;
  }
  return finish(FormReadStatus::OK, true);
}

static esp_err_t sendBadRequest(httpd_req_t* request, int status, const char* message) {
  web.begin(request);
  addSecurityHeaders();
  web.send(status, "text/plain", message);
  web.end();
  return ESP_OK;
}

static bool requestStateAllowsAdmin() {
  if (runtimeState != RuntimeState::ADMIN_AP_WINDOW || !adminHttpAccepting) return false;
  if (admin_state::deadlineReached(millis(), adminWindowStartedMs,
                                   admin_state::kAdminHardCeilingMs)) return false;
  return uploadRequestInFlight || admin_state::acceptsNewAdminWork(
      millis(), adminWindowStartedMs);
}

static bool requestStateAllowsProvisioning() {
  return runtimeState == RuntimeState::PROVISIONING_AP && adminHttpAccepting;
}

static esp_err_t handleFixedEnvelopeUpload(httpd_req_t* request);

static esp_err_t dispatchAdminGet(httpd_req_t* request) {
  if (!requestStateAllowsAdmin()) return sendBadRequest(request, 403, "admin window closed");
  web.begin(request); adminHttpSocket = httpd_req_to_sockfd(request);
  if (strcmp(request->uri, "/") == 0) handleDashboardRoot();
  else if (strcmp(request->uri, "/login") == 0) handleLoginGet();
  else if (strcmp(request->uri, "/app.js") == 0) handleAppJs();
  else if (strcmp(request->uri, "/stats.json") == 0) handleStats();
  else handleNotFound();
  web.end();
  return ESP_OK;
}

static esp_err_t dispatchAdminPost(httpd_req_t* request) {
  if (!requestStateAllowsAdmin()) {
    return rejectRequestWithPendingBody(request, 403, "admin window closed",
                                        {false, request->content_len});
  }
  web.begin(request); adminHttpSocket = httpd_req_to_sockfd(request);
  if (strcmp(request->uri, BLOCKLIST_UPLOAD_ROUTE) == 0) {
    const esp_err_t result = handleFixedEnvelopeUpload(request);
    web.end();
    return result;
  }
  if (strcmp(request->uri, "/login") != 0 && strcmp(request->uri, "/logout") != 0) {
    web.end();
    return rejectRequestWithPendingBody(request, 404, "not found",
                                        {false, request->content_len});
  }
  if (strcmp(request->uri, "/login") == 0) {
    const admin_http_policy::FormReadOutcome form = readRequiredForm(request);
    if (form.status != admin_http_policy::FormReadStatus::OK) {
      web.end();
      const esp_err_t response = sendBadRequest(request, 400, "invalid request body");
      return admin_http_policy::mustCloseConnection(form) ? ESP_FAIL : response;
    }
  } else if (requestHasTransferEncoding() || request->content_len != 0) {
    web.end();
    return rejectRequestWithPendingBody(request, 400, "logout request must be empty",
                                        {false, request->content_len});
  }
  if (strcmp(request->uri, "/login") == 0) handleLoginPost(); else handleLogout();
  web.end();
  return ESP_OK;
}

static esp_err_t dispatchProvisioningGet(httpd_req_t* request) {
  if (!requestStateAllowsProvisioning()) return sendBadRequest(request, 403, "setup window closed");
  web.begin(request); adminHttpSocket = httpd_req_to_sockfd(request);
  handlePortalRoot();
  web.end();
  return ESP_OK;
}

static esp_err_t dispatchProvisioningPost(httpd_req_t* request) {
  if (!requestStateAllowsProvisioning()) {
    return rejectRequestWithPendingBody(request, 403, "setup window closed",
                                        {false, request->content_len});
  }
  web.begin(request); adminHttpSocket = httpd_req_to_sockfd(request);
  if (strcmp(request->uri, "/wifisave") != 0) {
    web.end();
    return rejectRequestWithPendingBody(request, 404, "not found",
                                        {false, request->content_len});
  }
  const admin_http_policy::FormReadOutcome form = readRequiredForm(request);
  if (form.status != admin_http_policy::FormReadStatus::OK) {
    web.end();
    const esp_err_t response = sendBadRequest(request, 400, "invalid request body");
    return admin_http_policy::mustCloseConnection(form) ? ESP_FAIL : response;
  }
  handleWifiSave();
  web.end();
  return ESP_OK;
}

static bool registerUri(const char* uri, httpd_method_t method, esp_err_t (*handler)(httpd_req_t*)) {
  httpd_uri_t route{};
  route.uri = uri;
  route.method = method;
  route.handler = handler;
  return httpd_register_uri_handler(adminHttpServer, &route) == ESP_OK;
}

static bool startBoundedHttpServer(bool provisioning) {
  if (adminHttpServer) return false;
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.max_uri_len = HTTP_MAX_URI_LEN;
  config.max_req_hdr_len = HTTP_MAX_HEADER_BYTES;
  config.max_open_sockets = HTTP_SERVER_MAX_OPEN_SOCKETS;
  config.max_uri_handlers = 8;
  config.recv_wait_timeout = HTTP_IO_TIMEOUT_SECONDS;
  config.send_wait_timeout = HTTP_IO_TIMEOUT_SECONDS;
  config.backlog_conn = 1;
  config.uri_match_fn = httpd_uri_match_wildcard;
  if (httpd_start(&adminHttpServer, &config) != ESP_OK) return false;
  const bool registered = provisioning
    ? registerUri("/*", HTTP_GET, dispatchProvisioningGet) &&
      registerUri("/wifisave", HTTP_POST, dispatchProvisioningPost)
    : registerUri("/", HTTP_GET, dispatchAdminGet) &&
      registerUri("/login", HTTP_GET, dispatchAdminGet) &&
      registerUri("/login", HTTP_POST, dispatchAdminPost) &&
      registerUri("/logout", HTTP_POST, dispatchAdminPost) &&
      registerUri("/app.js", HTTP_GET, dispatchAdminGet) &&
      registerUri("/stats.json", HTTP_GET, dispatchAdminGet) &&
      registerUri(BLOCKLIST_UPLOAD_ROUTE, HTTP_POST, dispatchAdminPost);
  if (!registered) {
    httpd_stop(adminHttpServer);
    adminHttpServer = nullptr;
    return false;
  }
  adminHttpAccepting = true;
  return true;
}

static void closeAdminWindowAndRestart(const char* reason) {
  adminHttpAccepting = false;
  clearAdminSession();
  if (adminHttpServer && adminHttpSocket >= 0) {
    httpd_sess_trigger_close(adminHttpServer, adminHttpSocket);
  }
  Serial.printf("[admin] closing window: %s\n", reason);
  ESP.restart();
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");

  // GPIO9 is a strapping pin. Recovery is armed only after the running firmware
  // observes BOOT released, then measures a new continuous hold at runtime.
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);

  if (!LittleFS.begin(false)) enterStorageFailClosed("LittleFS mount failed");
  if (!recoverBlocklistFiles()) enterStorageFailClosed("blocklist recovery failed");
  if (!reopenBlocklist()) enterStorageFailClosed("active blocklist load failed");
  Serial.printf("blocklist: %u domains\n", numHashes);
  loadCustom(); loadBanned();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Keep Arduino driver configuration RAM-only; application Preferences and
  // the optional compile-time fallback remain the only credential sources.
  WiFi.persistent(false);

  // A legacy complete Wi-Fi/admin pair remains boot-compatible without a
  // migration write.  HTTP is deliberately absent in normal DNS-only mode.
  if (!hasAdminVerifier()) {
    runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED;
    Serial.println("[setup] admin verifier missing; hold BOOT for 5 seconds then release for recovery");
    return;
  }
  const bool setupWifiConnected = connectWiFi();
  if (!setupWifiConnected) {
    runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED;
    Serial.println("[wifi] offline; hold BOOT for 5 seconds then release for recovery");
    return;
  }
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());

  if (!startDnsServices()) {
    runtimeState = RuntimeState::OFFLINE_RECOVERY_REQUIRED;
    Serial.println("[dns] UDP/53 bind failed; hold BOOT for 5 seconds then release for recovery");
    return;
  }
  runtimeState = RuntimeState::DNS_ONLY;
  Serial.println("DNS :53 up; HTTP administration requires physical BOOT authorization");
}

void loop() {
  const uint32_t now = millis();
  const bool bootPressed = digitalRead(BOOT_BUTTON_PIN) == LOW;
  const admin_state::BootGesture gesture = bootGesture.update(bootPressed, now);
  const admin_state::BootAction bootAction = admin_state::bootActionFor(runtimeState, gesture);

  if (runtimeState == RuntimeState::DNS_ONLY) {
    if (bootAction == admin_state::BootAction::OPEN_ADMIN) {
      dnsServer.stop();
      upstreamCli.stop();
      networkServicesStarted = false;
      startAdminApWindow();
      return;
    }
    if (bootAction == admin_state::BootAction::OPEN_PROVISIONING) {
      dnsServer.stop(); upstreamCli.stop(); networkServicesStarted = false;
      startConfigPortal(true);  // old known-good configuration remains intact.
      return;
    }
    const bool busy = handleDns();
    if (!busy) delay(1);
    return;
  }

  if (runtimeState == RuntimeState::OFFLINE_RECOVERY_REQUIRED || runtimeState == RuntimeState::ADMIN_PSK_REQUIRED) {
    if (bootAction == admin_state::BootAction::OPEN_PROVISIONING) startConfigPortal(true);
    delay(2);
    return;
  }

  if (runtimeState == RuntimeState::ADMIN_AP_WINDOW) {
    if (adminWindowCloseRequested || admin_state::mustCloseAdminWindow(
        now, adminWindowStartedMs, uploadRequestInFlight)) {
      closeAdminWindowAndRestart("deadline/logout/login budget");
    }
    delay(2);
    return;
  }

  if (runtimeState == RuntimeState::PROVISIONING_AP) {
    dnsPortal.processNextRequest();
    if (admin_state::deadlineReached(now, provisioningStartedMs, admin_state::kProvisioningWindowMs)) {
      closeAdminWindowAndRestart("provisioning deadline");
    }
    if (provisioningCandidatePending) {
      processProvisioningCandidate();
      return;
    }
    delay(2);
  }
}
