// C3 AdBlock — DNS sinkhole + web dashboard for the ESP32-C3 (no PSRAM).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://c3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include <esp_random.h>
extern "C" {
#include <mbedtls/constant_time.h>
}
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform_util.h>
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
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
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

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[600];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

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

struct AdminVerifierRecord {
  uint8_t version;
  uint32_t iterations;
  uint8_t salt[ADMIN_SALT_BYTES];
  uint8_t verifier[ADMIN_VERIFIER_BYTES];
};

// ESP32-C3 SuperMini HIL showed unstable Wi-Fi association at default TX power.
// Limit TX power to 8.5 dBm for stable AP/STA operation.
static bool applyC3RfWorkaround() {
  return WiFi.setTxPower(WIFI_POWER_8_5dBm);
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
  if (!rawHost.length() || !localIp.length() || localIp == "0.0.0.0") return false;
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
  return host == allowedIp || host == "c3adblock.local";
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
  if (!isAllowedAdminHost(web.header("Host"), WiFi.localIP().toString())) return 403;
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
    blocklist.seek((uint32_t)mid * HASH_BYTES); blocklist.read(b, HASH_BYTES);
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
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int forwardUpstream(int qlen) {
  upstreamCli.beginPacket(UPSTREAM, 53); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 1000) { int sz = upstreamCli.parsePacket(); if (sz > 0) return upstreamCli.read(buf, sizeof(buf)); delay(1); }
  return 0;
}
// Drain a whole RX burst per call (capped, so the web server still gets a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    bool blocked = ban || (dl && numHashes && isBlocked(domain));
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
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
  if (isAllowedAdminHost(web.header("Host"), WiFi.localIP().toString())) return true;
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
  String j = "{\"csrf\":\"" + csrf + "\",\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jsonEscape(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jsonEscape(updateStatus) + "\"" +
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

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool uploadAuthorized = false;
static File upFile;
static void handleUploadDone() {
  if (!requireAdminMutation()) {
    uploadAuthorized = false;
    return;
  }
  if (!uploadAuthorized) {
    sendAuthorizationError(403);
    return;
  }
  addSecurityHeaders();
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
  uploadAuthorized = false;
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upOk = false;
      uploadAuthorized = requireAdminMutation(false);
      if (!uploadAuthorized) break;
      beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.println("[ota] receiving blocklist upload");
      break;
    case UPLOAD_FILE_WRITE:
      if (uploadAuthorized && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!uploadAuthorized) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!uploadAuthorized) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      uploadAuthorized = false;
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.println("[remote] GET configured blocklist URL");
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
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
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
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
  if (!applyC3RfWorkaround()) {
    Serial.println("[wifi] failed to apply the 8.5 dBm STA TX power limit");
    clearSensitiveString(pw);
    return false;
  }
  WiFi.begin(ssid, pass);
  clearSensitiveString(pw);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>Configuraci&oacute;n de NetShield Mini</title></head>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; NetShield Mini &mdash; configuraci&oacute;n Wi-Fi</h2>";
  if (!physicalProvisioningAllowed) {
    html += "<p>Los cambios requieren autorizaci&oacute;n f&iacute;sica. Con el dispositivo ya encendido, mant&eacute;n pulsado BOOT durante 3 segundos, su&eacute;ltalo y recarga esta p&aacute;gina. No reinicies ni apagues el dispositivo mientras pulsas BOOT.</p>";
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

  if (!createAdminVerifier(adminPassword)) {
    clearSensitiveString(pw);
    clearSensitiveString(adminPassword);
    clearSensitiveString(adminConfirmation);
    addSecurityHeaders();
    web.send(500, "text/plain", "could not save setup");
    return;
  }

  bool wifiStored = prefs.begin("wifi", false);
  if (wifiStored) {
    const size_t ssidBytes = prefs.putString("ssid", ss);
    const size_t passwordBytes = prefs.putString("pass", pw);
    wifiStored = ssidBytes == ss.length() &&
                 (pw.length() == 0 || passwordBytes == pw.length());
    prefs.end();
  }
  clearSensitiveString(pw);
  clearSensitiveString(adminPassword);
  clearSensitiveString(adminConfirmation);
  if (!wifiStored) {
    clearAdminVerifier();
    addSecurityHeaders();
    web.send(500, "text/plain", "could not save setup");
    return;
  }

  physicalProvisioningAllowed = false;
  secureZero(provisioningCsrf, sizeof(provisioningCsrf));
  portalRestartPending = true;
  String escapedSsid = htmlEscape(ss);
  addSecurityHeaders();
  web.send(200, "text/html; charset=utf-8", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Guardado. Suelta BOOT si sigue pulsado; el dispositivo reiniciar&aacute; para conectar con <b>" + escapedSsid + "</b>&hellip;<br><br>"
                             "Vuelve a conectar el dispositivo cliente a tu Wi-Fi habitual y abre <b>c3adblock.local</b>.</body>");
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) {
    portalOpts += "<option value=\"" + htmlEscape(WiFi.SSID(i)) + "\"></option>";
  }
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  const bool apModeOk = WiFi.mode(WIFI_AP);
  if (!apModeOk) {
    Serial.println("[setup] ERROR: configuration portal AP mode failed; configuration remains locked");
    while (true) delay(1000);
  }
  const bool softApOk = WiFi.softAP(ap);
  if (!softApOk) {
    Serial.println("[setup] ERROR: configuration portal AP failed to start; configuration remains locked");
    while (true) delay(1000);
  }
  if (softApOk && !applyC3RfWorkaround()) {
    Serial.println("[wifi] failed to apply the 8.5 dBm AP TX power limit");
  }
  refreshProvisioningCsrf();
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", HTTP_GET, handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] Configuration portal ready. Join open network \"%s\" and open http://%s\n",
                ap, apIP.toString().c_str());
  while (true) {
    dnsPortal.processNextRequest();
    web.handleClient();
    handlePortalBootAuthorization();
    handlePortalRestart();
    delay(2);
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

static void handleFetchNow() {
  if (!requireAdminMutation()) return;
  fetchBlocklist(updateUrl);
  addSecurityHeaders();
  web.send(200, "text/plain", updateStatus);
}

static void handleSetUpdate() {
  if (!requireAdminMutation()) return;
  if (web.hasArg("u")) updateUrl = web.arg("u");
  if (web.hasArg("h")) {
    updateIntervalH = web.arg("h").toInt();
    if (updateIntervalH < 1) updateIntervalH = 1;
  }
  saveUpdateCfg();
  addSecurityHeaders();
  web.send(200, "text/plain", "ok");
}

static void handleNotFound() {
  if (!requireAllowedAdminHost()) return;
  addSecurityHeaders();
  web.send(404, "text/plain", "not found");
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");

  // GPIO9 is a strapping pin. Recovery is armed only after the running firmware
  // observes BOOT released, then measures a new continuous hold at runtime.
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);

  static const char* REQUEST_HEADERS[] = {"Host", "Cookie", "X-CSRF-Token"};
  web.collectHeaders(REQUEST_HEADERS, sizeof(REQUEST_HEADERS) / sizeof(REQUEST_HEADERS[0]));

  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) { numHashes = blocklist.size() / HASH_BYTES; Serial.printf("blocklist: %u domains\n", numHashes); }
  loadCustom(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // An admin verifier must exist before provisioned or compile-time WiFi can
  // bypass the physically authorized setup portal.
  if (!hasAdminVerifier()) startConfigPortal();
  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  web.on("/login", HTTP_GET, handleLoginGet);
  web.on("/login", HTTP_POST, handleLoginPost);
  web.on("/logout", HTTP_POST, handleLogout);
  web.on("/", HTTP_GET, handleDashboardRoot);
  web.on("/app.js", HTTP_GET, handleAppJs);
  web.on("/stats.json", HTTP_GET, handleStats);
  web.on("/ban", HTTP_POST, handleBan);
  web.on("/addblock", HTTP_POST, handleAddBlock);
  web.on("/unblock", HTTP_POST, handleUnblock);
  web.on("/forgetwifi", HTTP_POST, handleForgetWifi);
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA
  web.on("/fetchnow", HTTP_POST, handleFetchNow);
  web.on("/setupdate", HTTP_POST, handleSetUpdate);
  web.onNotFound(handleNotFound);
  web.begin();
  Serial.println("DNS :53 + dashboard :80 up");
}

void loop() {
  web.handleClient();
  bool busy = handleDns();
  handleRuntimeBootRecovery();
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
