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
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include <esp_system.h>    // esp_reset_reason(): surface why the device rebooted
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
// Upstream resolver. Quad9 used to be the default, but it is overseas: measured from a CN
// network it answers in ~226 ms, versus ~3 ms for the local router and ~27-44 ms for
// domestic public resolvers. Every *allowed* query is forwarded, and a client typically
// asks A and AAAA back to back, so that latency lands on every page load twice over.
// Default is now a domestic resolver; override in secrets.h to use your router or another
// (223.5.5.5 AliDNS, 119.29.29.29 DNSPod, 114.114.114.114).
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 223, 5, 5, 5                  // AliDNS (domestic, ~44 ms from CN)
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// Sanity floor for anything that replaces the live blocklist. The published list is ~134k
// entries (~670 KB); 20k entries (~100 KB) is comfortably below any legitimate build while
// still rejecting a truncated transfer, an HTML error page, or a stray small file.
static const int MIN_BLOCKLIST_ENTRIES = 20000;

// Upper bound on a plausible list: the LittleFS partition is 0x150000. Used to tell a real
// Content-Length apart from the arduino-esp32 sentinels CONTENT_LENGTH_UNKNOWN /
// CONTENT_LENGTH_NOT_SET, which arrive as huge size_t values rather than 0.
static const size_t MAX_BLOCKLIST_BYTES = 0x150000;

// Expected byte length of the pending /blocklist.new, or 0 when the sender didn't declare
// one. Set by the fetcher and the uploader, checked by commitNewBlocklist().
static size_t expectedBlocklistBytes = 0;

// millis() timestamp for the deferred second index rebuild after a swap -- see
// reopenBlocklist(): the first build can sample the previous blob through an unsettled
// cache layer and still look monotonic, so loop() reopens once more after 3 s.
static uint32_t indexRebuildDue = 0;

// Any write to LittleFS (config saves, custom list edits) can leave the blocklist
// file's read path serving stale bytes -- the field-verified whole-table-forwarding
// wedge. Config writes are rare, so after one, loop() reopens the blocklist file
// (fresh handle = fresh read cache) and rebuilds the index. Cheap insurance.
static bool blocklistRefreshDue = false;

// Canary for runtime index health: the LAST index sample is by construction always in
// the blob, so inFlash() over it must succeed forever. Field data shows this board can
// start failing lookups minutes after boot while the file stays byte-perfect on flash
// (reads through the lookup path go bad) -- the probe exposes that, and loop() rebuilds
// instead of quietly forwarding every ad.
// Canary for runtime index health: probe permanent members of EVERY build (Hagezi
// carries these unconditionally). The probe must be INDEPENDENT of the index and of
// littlefs -- a canary derived from the index or the file would "hit" the stale bytes
// the wedge serves and stay silent while every real lookup fails (field-verified).
static const char* const CANARY_DOMAINS[] = {
    "doubleclick.net", "googlesyndication.com", "tanx.com",
};
static uint32_t canaryNextAt = 0;
static uint8_t canaryFails = 0;       // consecutive confident canary misses

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// ---------- upstream answer cache ----------
// Every allowed query used to be forwarded, and forwarding blocks inside handleDns() for up
// to 1 s, so a page load (browser opens several connections, each asking A then AAAA) paid
// the upstream round trip over and over. A small cache makes repeats instant and removes
// them from the serialized forwarding path entirely.
//
// Keyed on the full question section (qname+qtype+qclass) rather than just the name, so an
// A and an AAAA for the same host are distinct entries. Only the response body AFTER the
// 12-byte header is stored: the transaction id must be per-request, so it is patched back
// in when answering. TTL comes from the upstream record, capped so a long TTL cannot pin a
// stale address, with a floor so a 0-TTL answer is not effectively uncached.
// Sized to fit the classic ESP32 too: 64 entries x ~650 B overflowed its DRAM by 13.8 KB
// (`dram0_0_seg`), which only surfaced because CI compiles both boards. 24 entries still
// covers the hot set for ordinary browsing (a page load touches a handful of hosts, and
// repeats are what the cache is for) while costing ~15 KB instead of ~41 KB.
static const int DNS_CACHE_SIZE = 32;              // power of 2
static const uint32_t DNS_TTL_MIN_MS = 5UL * 1000;
static const uint32_t DNS_TTL_MAX_MS = 10UL * 60 * 1000;
// Classic ESP32 DRAM cannot fit the roomier body: a cache bump once overflowed
// dram0_0_seg by 13.8 KB and only surfaced because CI compiles both boards. C3/S3
// boards have the headroom for 512 B answers (bigger CDN record sets cache).
#ifdef CONFIG_IDF_TARGET_ESP32
static const uint16_t DNS_BODY_MAX = 320;
#else
static const uint16_t DNS_BODY_MAX = 512;
#endif
struct DnsCacheEntry {
  bool     used;
  uint32_t expires;
  uint16_t bodyLen;                                // bytes of the cached response body
  uint8_t  key[128 + 4];                           // question section (<=128 B name + qtype/qclass)
  uint8_t  keyLen;
  uint8_t  body[DNS_BODY_MAX];                     // response minus its 12-byte header
};
static DnsCacheEntry dnsCache[DNS_CACHE_SIZE];
static uint32_t dnsCacheHits = 0, dnsCacheMiss = 0;   // surfaced in /stats.json

// Look up a cached answer for this question; patches the caller's transaction id into buf.
// Returns the full response length, or 0 on miss.
static int dnsCacheGet(const uint8_t* key, size_t keyLen) {
  if (keyLen == 0 || keyLen > sizeof(dnsCache[0].key)) return 0;
  const uint32_t now = millis();
  // Direct-mapped: hash the question bytes so the same name+type always lands in one slot.
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < keyLen; i++) { h ^= key[i]; h *= 16777619u; }
  DnsCacheEntry& e = dnsCache[h & (DNS_CACHE_SIZE - 1)];
  if (!e.used || (int32_t)(now - e.expires) >= 0) { dnsCacheMiss++; return 0; }
  if (e.keyLen != keyLen || memcmp(e.key, key, keyLen) != 0) { dnsCacheMiss++; return 0; }
  memcpy(buf + 12, e.body, e.bodyLen);
  dnsCacheHits++;
  return 12 + e.bodyLen;
}

// Store a response (buf[0..n)) under the given question key, if it fits.
static void dnsCachePut(const uint8_t* key, size_t keyLen, int n) {
  if (keyLen == 0 || keyLen > sizeof(dnsCache[0].key)) return;
  if (n <= 12 || n > 12 + (int)sizeof(dnsCache[0].body)) return;
  // Cache ordinary successes and NXDOMAIN. NXDOMAIN negative-caching matters because
  // Windows alone burns a burst of guaranteed-miss probes (UPnP, WS-Discovery) and each
  // uncached one pays the up-to-1 s blocking forward; 30 s is well inside client retry
  // windows. Other rcodes are treated as transient and skipped.
  const uint8_t flags = buf[3];
  if (flags & 0x02) return;                        // TC: truncated, retry over TCP wasn't done
  const uint8_t rcode = flags & 0x0F;
  uint32_t ttl;
  if (rcode == 3) {
    ttl = 30000;                                   // fixed negative TTL
  } else if (rcode != 0) {
    return;                                        // SERVFAIL etc: retry against upstream soon
  } else {
    if (buf[6] || buf[7]) { /* ancount>0: normal */ } else if (buf[8] || buf[9]) { return; }

    // Shortest TTL across the answer records, so we never outlive the upstream's own bound.
    ttl = DNS_TTL_MAX_MS;
    int i = 12 + keyLen;                           // skip header + question
    const int ancount = (buf[6] << 8) | buf[7];
    for (int a = 0; a < ancount && i + 12 <= n; a++) {
      // Walk (and skip) the owner name. A compression pointer occupies exactly 2 bytes with
      // no terminator; only the inline-label form ends with a NUL byte. Consuming a terminator
      // after a pointer would shift every field by one and mis-read the type/TTL -- which is
      // exactly what an earlier version did.
      if (buf[i] & 0xC0) i += 2;
      else { while (i < n && buf[i] != 0) i += buf[i] + 1; i += 1; }   // +1 for the terminator
      if (i + 10 > n) break;
      const uint16_t rtype  = (buf[i] << 8) | buf[i + 1];
      const uint16_t rclass = (buf[i + 2] << 8) | buf[i + 3];
      const uint32_t rttl   = ((uint32_t)buf[i + 4] << 24) | ((uint32_t)buf[i + 5] << 16) |
                              ((uint32_t)buf[i + 6] << 8) | buf[i + 7];
      const uint16_t rdlen  = (buf[i + 8] << 8) | buf[i + 9];
      i += 10 + rdlen;
      if (rtype == 1 && rclass == 1) { const uint32_t ms = rttl * 1000UL;
        if (ms < ttl) ttl = ms; }
    }
  }
  if (ttl < DNS_TTL_MIN_MS) ttl = DNS_TTL_MIN_MS;
  if (ttl > DNS_TTL_MAX_MS) ttl = DNS_TTL_MAX_MS;

  uint32_t h = 2166136261u;
  for (size_t k = 0; k < keyLen; k++) { h ^= key[k]; h *= 16777619u; }
  DnsCacheEntry& e = dnsCache[h & (DNS_CACHE_SIZE - 1)];
  memcpy(e.key, key, keyLen); e.keyLen = (uint8_t)keyLen;
  memcpy(e.body, buf + 12, n - 12); e.bodyLen = (uint16_t)(n - 12);
  e.expires = millis() + ttl;
  e.used = true;
}

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// ---------- DNS query capture ----------
// Records every query the device sees, so "this ad still gets through" can be turned into
// concrete hostnames instead of guesswork: start capture, reproduce the ad in the app,
// then read the list to see exactly what was asked for and whether it was blocked.
//
// RAM-backed on purpose: a flash write per query would wear the device and block the DNS
// loop.
//
// Grouped by ROOT domain, not by full hostname. Two earlier designs both failed the same
// way: a 96-slot raw ring, then a table keyed on the full hostname. Either way one chatty
// app filled it and pushed out every other platform -- Douyin live alone emits hundreds of
// DISTINCT pull-<codec>-<node>.douyincdn.com names, so a 96-row export was 96 unique
// hostnames of a single app and the Tencent/Mango/Youku traffic was gone. Keying on the
// registrable domain collapses those hundreds into one row per platform, so a multi-app
// session keeps every app visible.
//
// Pass a filter (e.g. qq.com) to switch the key back to the full hostname: that is the
// drill-down mode used to copy exact ad domains into data/custom-domains.txt.
//
// Sized per target: the table is static (.bss) and the classic ESP32 has far less usable
// DRAM than the C3 -- 256 full-hostname entries overflowed dram0_0_seg on esp32dev.
#if CONFIG_IDF_TARGET_ESP32C3
static const int CAPTURE_SIZE = 192;        // C3: roomier SRAM
#else
static const int CAPTURE_SIZE = 128;        // classic ESP32: DRAM constrained
#endif
static const int CAPTURE_DOMAIN_MAX = 80;   // longest full name kept (as an example)
static const int CAPTURE_ROOT_MAX = 48;     // longest root domain

// Multi-part public suffixes we must not split, or "douyin.com.cn" would group as "com.cn".
static const char* const MULTI_TLD[] = {
  "com.cn","net.cn","org.cn","gov.cn","edu.cn","ac.cn","co.uk","org.uk","ac.uk",
  "com.br","co.jp","or.kr","co.kr","com.au","net.au","co.in","com.tw","com.hk",NULL };

// Start offset of the label `back` positions from the right (0 = last label, 1 = the one
// before it, ...). Returns 0 when the name has no more labels to skip.
static int capLabelStart(const char* d, int back) {
  int n = strlen(d), seen = 0;
  for (int i = n; i >= 0; i--)
    if (i == 0 || d[i - 1] == '.') { if (seen == back) return i; seen++; }
  return 0;
}
static int capLabelCount(const char* d) {
  int c = 1; for (const char* p = d; *p; p++) if (*p == '.') c++; return c;
}

// Offset of the registrable domain within d: last two labels, or three when the tail is a
// known multi-part public suffix.
static int capRootOffset(const char* d) {
  if (capLabelCount(d) < 2) return 0;
  int n = strlen(d), prev = capLabelStart(d, 1);
  // Match the TWO-LABEL tail (d+prev, e.g. "com.cn"). Matching only the last label ("cn")
  // can never hit a multi-char entry, so every *.com.cn tenant merged into one "com.cn"
  // row -- seen in real capture data as 31 hits for "com.cn" with example
  // sdktmp.hubcloud.com.cn, where the group should be hubcloud.com.cn.
  for (int k = 0; MULTI_TLD[k]; k++) {
    int len = strlen(MULTI_TLD[k]);
    if (n - prev == len && strcmp(d + prev, MULTI_TLD[k]) == 0)
      return capLabelCount(d) >= 3 ? capLabelStart(d, 2) : prev;
  }
  return prev;
}

struct CapEntry {
  char     root[CAPTURE_ROOT_MAX];      // grouping key (or full name while filtering)
  char     example[CAPTURE_DOMAIN_MAX]; // an ALLOWED full hostname under this root, if any
  uint32_t ip;
  uint32_t firstMs, lastMs;
  uint16_t hits, blockedHits;           // total, and how many of those were blocked
  uint8_t  qtype;
  bool     used;
};
static CapEntry capBuf[CAPTURE_SIZE];
static uint32_t capQueries = 0;            // total queries recorded since the last clear
static bool     capOverflow = false;       // set when a new group had nowhere to go
static bool     capOn = false;
static String   capFilter;                 // substring filter; empty records everything
// Precise mode groups by FULL hostname instead of the root domain. Costs table
// capacity (more distinct keys -> overflows sooner) and truncates names over 47
// chars, but it is the only way to see WHICH subdomain carries an ad leak -- the
// root grouping is exactly what hid v3.gdt.qq.com inside qq.com's 134 hits.
static bool     capPrecise = false;

// Capture settings live in RAM, so any reboot -- crash, brownout, watchdog, OTA -- silently
// switched capture off and emptied the table, which looked like "the capture stopped on its
// own". Persisting just the two settings costs one tiny flash write per user action (not per
// query, so no wear concern) and capture resumes itself after a reboot. The table itself is
// still RAM-only by design; the reset reason below makes the lost data explainable.
static void saveCaptureCfg() {
  File f = LittleFS.open("/cap.cfg", "w"); if (!f) return;
  // Explicit \n only: println() writes \r\n, and the \r used to end up INSIDE the
  // reloaded filter ("qq.com\r") -- which then matched nothing, so capture looked armed
  // but silently recorded zero queries after every reboot (field-observed).
  f.print(capOn ? "1\n" : "0\n"); f.print(capFilter); f.print("\n");
  f.print(capPrecise ? "1\n" : "0\n"); f.close();
  blocklistRefreshDue = true;
}
static void loadCaptureCfg() {
  File f = LittleFS.open("/cap.cfg", "r"); if (!f) return;
  String on = f.readStringUntil('\n'); on.trim();
  capFilter = f.readStringUntil('\n'); capFilter.trim();   // also heals old \r\n files
  String pr = f.readStringUntil('\n'); pr.trim();          // absent in old files -> false
  capPrecise = (pr == "1");
  f.close();
  capOn = (on == "1");
  if (capOn) Serial.println("[capture] resumed from saved settings after reboot");
}

// Why did the last boot happen? Without this a reboot is invisible and the emptied capture
// looks like a software bug rather than a restart.
static const char* resetReason() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "power-on";
    case ESP_RST_BROWNOUT: return "brownout (weak USB supply)";
    case ESP_RST_PANIC:    return "crash";
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT: return "watchdog";
    case ESP_RST_SW:       return "software restart";
    case ESP_RST_DEEPSLEEP:return "deep-sleep";
    default:               return "other/unknown";
  }
}

// ---------- raw query log (ring) ----------
// The grouped table answers "which domains", but ad-hunting also needs "WHEN, and in
// what order" -- a splash ad correlates with a burst of lookups right now. This is a
// fixed ring of the last N queries, unfiltered, newest shown first. DNS-level capture
// only ever has domains: HTTP request paths flow client->router->internet and never
// touch this device, so a path column is physically impossible here.
struct RecentQuery {
  uint32_t ms;
  char     d[48];
  uint32_t ip;
  bool     blocked;
  uint8_t  qtype;
};
static const int RECENT_LOG_SIZE = 48;
static RecentQuery recentLog[RECENT_LOG_SIZE];
static int      recentHead = 0;      // next write slot
static uint16_t recentCount = 0;

static void recentLogAdd(const char* domain, uint32_t ip, uint8_t qtype, bool blocked) {
  RecentQuery& r = recentLog[recentHead];
  r.ms = millis(); r.ip = ip; r.blocked = blocked; r.qtype = qtype;
  strncpy(r.d, domain, sizeof(r.d) - 1); r.d[sizeof(r.d) - 1] = 0;
  recentHead = (recentHead + 1) % RECENT_LOG_SIZE;
  if (recentCount < RECENT_LOG_SIZE) recentCount++;
}

static void capRecord(const char* domain, uint32_t ip, uint8_t qtype, bool blocked) {
  if (!capOn) return;
  recentLogAdd(domain, ip, qtype, blocked);   // raw log: EVERY query, unfiltered by design
  if (capFilter.length() && !strstr(domain, capFilter.c_str())) return;   // no String here: this runs per query
  capQueries++;
  // Filtering means the user is drilling into one platform and wants exact names; precise
  // mode is the same idea with a toggle. Only an empty filter + non-precise groups by root
  // to stay inside the table.
  const char* key = (capPrecise || capFilter.length()) ? domain : domain + capRootOffset(domain);
  for (int i = 0; i < CAPTURE_SIZE; i++) {
    CapEntry& e = capBuf[i];
    if (e.used && strcmp(e.root, key) == 0) {
      if (e.hits < 0xFFFF) e.hits++;
      if (blocked && e.blockedHits < 0xFFFF) e.blockedHits++;
      e.ip = ip; e.qtype = qtype; e.lastMs = millis();
      // Keep an *allowed* hostname as the example: that is the actionable one when hunting
      // for leaks. Recording any name made the CSV claim e.g. stun.hitv.com was allowed
      // while the group's blocked flag actually came from a different subdomain.
      if (!blocked) strncpy(e.example, domain, CAPTURE_DOMAIN_MAX - 1);
      e.example[CAPTURE_DOMAIN_MAX - 1] = 0;
      return;
    }
  }
  for (int i = 0; i < CAPTURE_SIZE; i++) {
    CapEntry& e = capBuf[i];
    if (e.used) continue;
    e.used = true;
    strncpy(e.root, key, CAPTURE_ROOT_MAX - 1);      e.root[CAPTURE_ROOT_MAX - 1] = 0;
    strncpy(e.example, domain, CAPTURE_DOMAIN_MAX - 1); e.example[CAPTURE_DOMAIN_MAX - 1] = 0;
    e.ip = ip; e.qtype = qtype;
    e.hits = 1; e.blockedHits = blocked ? 1 : 0; e.firstMs = e.lastMs = millis();
    return;
  }
  // Table full: evict the least-recently-updated entry instead of dropping the newcomer.
  // Dropping meant a long session filled the table once and then EVERY later domain --
  // including the ad leak being hunted -- was invisible. Hot domains keep refreshing
  // lastMs, so they survive; stale ones make room. capOverflow now means "recycling".
  int victim = 0;
  for (int i = 1; i < CAPTURE_SIZE; i++)
    if ((int32_t)(capBuf[i].lastMs - capBuf[victim].lastMs) < 0) victim = i;
  CapEntry& e = capBuf[victim];
  capOverflow = true;
  strncpy(e.root, key, CAPTURE_ROOT_MAX - 1);      e.root[CAPTURE_ROOT_MAX - 1] = 0;
  strncpy(e.example, domain, CAPTURE_DOMAIN_MAX - 1); e.example[CAPTURE_DOMAIN_MAX - 1] = 0;
  e.ip = ip; e.qtype = qtype;
  e.hits = 1; e.blockedHits = blocked ? 1 : 0; e.firstMs = e.lastMs = millis();
}

// remote blocklist auto-update
//
// A compiled-in default subscription, so a freshly flashed device keeps itself current
// without anyone having to discover and paste a URL. Previously updateUrl started empty
// and nothing fetched until the user filled the field by hand, which left a new unit on
// whatever blocklist was baked into flash -- silently going stale over time.
//
// This is the fork's own daily release (see .github/workflows/blocklist.yml): GitHub
// rebuilds blocklist.bin every day at 03:00 Beijing from Hagezi + anti-AD + 217heidai +
// home-dns-adblock. Override with -D DEFAULT_UPDATE_URL=... at build time, or by editing
// the field in the dashboard. Set it to "" to ship with auto-update off.
#define BLOCKLIST_ASSET_PATH "0079123/c3-adblock/releases/download/blocklist/blocklist.bin"

// Mainland-China reachability: github.com is frequently slow or unreachable from CN ISPs
// (release assets are served from objects.githubusercontent.com, which is commonly
// blocked), so a GitHub-only default would leave the device unable to update at all.
// These are the well-known GitHub mirrors; each is tried in order until one returns a
// complete file, and the reachable direct URL is tried first so non-CN users never take
// the proxy detour. All three were verified to return a byte-identical blocklist.bin
// (same SHA-256 as the direct download), so proxying does not alter the payload.
//
// Mirrors do go down or get rate-limited, which is why this is a list rather than a
// single hardcoded host: one failing proxy just moves to the next.
#ifndef DEFAULT_UPDATE_URL
#define DEFAULT_UPDATE_URL "https://github.com/" BLOCKLIST_ASSET_PATH
#endif
// Comma-separated candidates used only when updateUrl is still the compiled-in default;
// a user-entered URL is always used verbatim.
#ifndef DEFAULT_UPDATE_MIRRORS
#define DEFAULT_UPDATE_MIRRORS \
  "https://github.com/" BLOCKLIST_ASSET_PATH "," \
  "https://ghfast.top/https://github.com/" BLOCKLIST_ASSET_PATH "," \
  "https://gh-proxy.com/https://github.com/" BLOCKLIST_ASSET_PATH "," \
  "https://ghproxy.net/https://github.com/" BLOCKLIST_ASSET_PATH
#endif
#ifndef DEFAULT_UPDATE_INTERVAL_H
#define DEFAULT_UPDATE_INTERVAL_H 24
#endif

String updateUrl = DEFAULT_UPDATE_URL;   // prebuilt blocklist.bin to pull on a schedule
uint32_t updateIntervalH = DEFAULT_UPDATE_INTERVAL_H;  // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";
// Idle timeout while reading the body. Shortened while walking mirrors so a dead host
// does not stall the whole cycle (4 mirrors x 15 s would be a minute of nothing).
static const uint32_t FETCH_IDLE_MS = 15000;
static const uint32_t FETCH_IDLE_MIRROR_MS = 6000;
static uint32_t fetchIdleMs = FETCH_IDLE_MS;
// Wait this long after boot before the first subscription fetch (WiFi + DNS settle first).
static const uint32_t BOOT_FETCH_DELAY_MS = 20000;
bool updateUrlCustom = false;       // true once the user sets/clears it themselves

// Split a comma-separated candidate list, trimming each entry.
static void splitUrls(const String& csv, String* out, int maxOut) {
  int n = 0; unsigned start = 0;
  while (start <= csv.length() && n < maxOut) {
    int comma = csv.indexOf(',', start);
    String part = (comma < 0) ? csv.substring(start) : csv.substring(start, comma);
    part.trim();
    if (part.length()) out[n++] = part;
    if (comma < 0) break;
    start = comma + 1;
  }
  while (n < maxOut) out[n++] = String();     // clear the remainder
}

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalNets;             // JSON array of scanned networks, refreshed on demand

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  int shortReads = 0;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    if (!blocklist.seek((uint32_t)pos * HASH_BYTES) ||
        blocklist.read(blIndex[i], HASH_BYTES) != HASH_BYTES) {
      // A half-written index entry makes every lookup in that bucket miss, and the entry
      // stays wrong for the life of the list. Retry once, then count it so the dashboard
      // is not silently under-blocking.
      memset(blIndex[i], 0, HASH_BYTES);
      if (!blocklist.seek((uint32_t)pos * HASH_BYTES) ||
          blocklist.read(blIndex[i], HASH_BYTES) != HASH_BYTES) shortReads++;
    }
  }
  if (shortReads) Serial.printf("[blocklist] WARNING: %d index entries unreadable\n", shortReads);
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

// `reliable` is set false when the lookup could not be completed (file handle gone, short
// read). A failed read otherwise looks exactly like "not on the list", and isBlockedHash
// used to cache that negative permanently: one transient short read while LittleFS was
// busy writing a fresh blocklist silently un-blocked that domain until the next list
// reload. Cold boot blocked correctly, long-running sessions leaked -- which is what the
// field data showed.
static bool inFlash(uint64_t h, bool* reliable = nullptr) {
  auto bad = [&]{ if (reliable) *reliable = false; };
  if (reliable) *reliable = true;
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  if (!blocklist.seek((uint32_t)startPos * HASH_BYTES)) { bad(); return false; }
  if (blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES) != (int)(rangeCount * HASH_BYTES)) {
    bad(); return false;                 // short read: unknown, must not be cached as "allowed"
  }
  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool reliable = true;
  bool res = inFlash(h, &reliable);
  if (!reliable) return res;            // never poison the cache with an unknown result
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    p = dot + 1;
    // No early break at the TLD level: pseudo-TLD parents like the wmz beacon family
    // are blocked AT the "wmz" label, so the walk must reach single-label ancestors.
    // Bare "com"/"cn" can never be in the blob -- the build tool rejects dotless
    // entries outside the hand-curated custom list.
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
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); blocklistRefreshDue = true; }
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
  blocklistRefreshDue = true;
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
// Reuse a slot rather than refusing to track the client. clients[] used to only ever grow,
// so after MAX_CLIENTS distinct IPs (guest devices, phones rotating their MAC, DHCP lease
// churn) every later client returned nullptr -- invisible in the dashboard and impossible
// to ban, since /ban needs a non-null Dev*. Evict the least-recently-seen *unbanned* entry
// so a ban can never be silently dropped; if every slot is banned, keep the newest ban
// instead of clobbering it.
static Dev* allocClientSlot() {
  if (numClients < MAX_CLIENTS) return &clients[numClients++];
  int victim = -1;
  for (int i = 0; i < numClients; i++) {
    if (clients[i].banned) continue;
    if (victim < 0 || (int32_t)(clients[i].lastSeen - clients[victim].lastSeen) < 0) victim = i;
  }
  if (victim < 0) return nullptr;                   // all slots banned -> leave them alone
  return &clients[victim];
}

static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  Dev* c = allocClientSlot();
  if (!c) return nullptr;
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
  getMac(ip, c->mac); return c;
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
// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int forwardUpstream(int qlen, int qend) {
  upstreamCli.flush();                                   // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < 1000) {                         // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
}
// ---------- async upstream forwarding ----------
// A cache miss used to forward synchronously and park this loop for up to a second;
// bursts of client queries queued behind it and their replies were dropped (field
// observed, and the cause of the dashboard stalling during DNS-heavy moments). A miss
// now goes into a small pending table and pollUpstream() delivers the reply on a later
// loop pass -- the client's own retry window is >= 1 s, which is plenty. The blocking
// forwardUpstream() above stays as the fallback for when the table is full.
static const int PENDING_Q = 6;
static const uint32_t PENDING_TIMEOUT_MS = 1000;
struct PendingQ {
  bool     used;
  uint16_t txidUp;                  // txid we sent upstream with
  uint16_t clientTxid;              // txid the client sent, restored on the way back
  uint32_t clientIp;
  uint16_t clientPort;
  uint8_t  q[128 + 4];              // question section: reply matching + cache key
  uint8_t  qLen;
  uint32_t sentAt;
};
static PendingQ pendingQ[PENDING_Q];

static void purgePending() {
  const uint32_t now = millis();
  for (int i = 0; i < PENDING_Q; i++)
    if (pendingQ[i].used && now - pendingQ[i].sentAt > PENDING_TIMEOUT_MS) pendingQ[i].used = false;
}

// Deliver upstream replies to the clients that asked for them. Matching is by our own
// txid plus the full question section, so a late reply for an already-purged query is
// dropped instead of being relayed to the next client (issue #10's off-by-one relay).
static int pollUpstream() {
  int served = 0;
  for (;;) {
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) break;
    IPAddress rip = upstreamCli.remoteIP(); uint16_t rport = upstreamCli.remotePort();
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (n < 12 || rip != UPSTREAM || rport != UPSTREAM_PORT) continue;
    const uint16_t wid = (buf[0] << 8) | buf[1];
    PendingQ* p = nullptr;
    for (int i = 0; i < PENDING_Q && !p; i++)
      if (pendingQ[i].used && pendingQ[i].txidUp == wid &&
          (int)(12 + pendingQ[i].qLen) <= n &&
          memcmp(buf + 12, pendingQ[i].q, pendingQ[i].qLen) == 0) p = &pendingQ[i];
    if (!p) continue;
    dnsCachePut(p->q, p->qLen, n);                 // before the txid rewrite: body unaffected
    buf[0] = p->clientTxid >> 8; buf[1] = p->clientTxid & 0xFF;
    dnsServer.beginPacket(p->clientIp, p->clientPort); dnsServer.write(buf, n); dnsServer.endPacket();
    p->used = false; served++;
  }
  return served;
}

// Send a cache miss upstream without waiting for the answer: record it in the table and
// let pollUpstream() deliver the reply later. Returns false when the table is full or the
// random txid collides with an entry still in flight -- the caller then takes the
// synchronous path so the client never loses the query.
static bool sendUpstreamAsync(int qlen, int qend, uint32_t clientIp, uint16_t clientPort) {
  PendingQ* p = nullptr;
  for (int i = 0; i < PENDING_Q && !p; i++) if (!pendingQ[i].used) p = &pendingQ[i];
  if (!p) return false;
  int ql = qend - 12;
  if (ql <= 0 || ql > (int)sizeof(p->q) || qend > qlen) return false;
  const uint16_t wid = (uint16_t)esp_random();
  for (int i = 0; i < PENDING_Q; i++)
    if (pendingQ[i].used && pendingQ[i].txidUp == wid) return false;   // rare: sync fallback
  p->used = true; p->txidUp = wid;
  p->clientTxid = (buf[0] << 8) | buf[1];
  p->clientIp = clientIp; p->clientPort = clientPort;
  p->qLen = (uint8_t)ql; memcpy(p->q, buf + 12, ql);
  p->sentAt = millis();
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  return true;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Also delivers upstream replies for earlier async
// misses. Returns true if any DNS work happened this call.
static bool handleDns() {
  purgePending();                     // free expired misses before serving anything new
  bool busy = pollUpstream() > 0;
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c ? c->banned : isBannedIP((uint32_t)cip);   // slots can be full: don't lose the ban
    bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
    // Record before acting, so the capture shows what arrived and how it was classified.
    if (dl) capRecord(domain, (uint32_t)cip, (uint8_t)qtype, blocked);
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else {
      // Cache key = the question section (qname+qtype+qclass), so A and AAAA differ. A
      // hit answers without touching the network. A miss goes upstream ASYNC -- the
      // reply is delivered by pollUpstream() on a later pass -- so this loop no longer
      // parks for up to 1 s behind a slow upstream.
      const uint8_t* qkey = buf + 12;
      const size_t qkeyLen = (qend > 12) ? (size_t)(qend - 12) : 0;
      const uint8_t cid0 = buf[0], cid1 = buf[1];
      rlen = dnsCacheGet(qkey, qkeyLen);
      if (rlen > 0) { buf[0] = cid0; buf[1] = cid1; }     // restore the client's txid
      else if (sendUpstreamAsync(qlen, qend, (uint32_t)cip, cport)) {
        rlen = 0;                                          // reply lands via pollUpstream()
      } else {
        rlen = forwardUpstream(qlen, qend);                // table full: blocking fallback
        if (rlen > 0) { dnsCachePut(qkey, qkeyLen, rlen); }
      }
      totalAllowed++; if (c) c->allowed++;
    }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return busy || did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) {
  String o; o.reserve(s.length() + 8);
  for (char ch : s) {
    if ((uint8_t)ch < 0x20) { o += ' '; continue; }   // a raw control byte breaks the JSON frame
    if (ch == '"' || ch == '\\') o += '\\';
    o += ch;
  }
  return o;
}
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6
#include "page_gz.h" // same page, precompressed (generated from page.h at build time)

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j; j.reserve(1024);                        // this runs on every dashboard poll: no realloc ratchet
  j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"heapmin\":" + ESP.getMinFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\""
             + ",\"upcustom\":" + (updateUrlCustom ? "true" : "false")
             + ",\"resetreason\":\"" + jesc(String(resetReason())) + "\""
             + ",\"cachehits\":" + dnsCacheHits + ",\"cachemiss\":" + dnsCacheMiss +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "102030Zz") == 0 || strcmp(OTA_PASS, "102030Zz") == 0 ||
                                  strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// c3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "c3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition only holds one list, so the live file is removed before /blocklist.new
// is renamed into place. Call order matters: fetch/upload into /blocklist.new FIRST,
// then commit. An aborted transfer therefore leaves the existing list untouched --
// fail-safe (keep blocking with the old list) instead of fail-open (block nothing).
static void reopenBlocklist(bool afterSwap = false) {
  // LittleFS can still be flushing a freshly swapped blob, and buildFlashIndex then
  // zeroes unreadable samples -- a zeroed LAST entry makes `h > last` short-circuit
  // every lookup, silently disabling the whole list while the dashboard keeps showing
  // the domain count (observed in the field). Rebuild until the index is sane: the
  // blob is sorted, so first <= last must hold for any usable index.
  for (int attempt = 0; attempt < 5; attempt++) {
    blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
    numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
    buildFlashIndex();
    if (numHashes == 0) return;
    // Strict: ANY out-of-order sample (a zeroed entry anywhere) wedges its bucket's
    // lookups, so require full non-decreasing order, not just first <= last.
    bool sane = true;
    for (int i = 1; sane && i < INDEX_ENTRIES; i++)
      if (unpackHash(blIndex[i]) < unpackHash(blIndex[i - 1])) sane = false;
    if (sane) {
      // A stale-but-monotonic index (built against the previous blob through a not
      // yet settled cache layer) also passes this check -- field-verified: after a
      // swap the whole table can still forward until the file settles. One delayed
      // rebuild settles it; loop() runs it and re-clears the hash cache.
      if (afterSwap) indexRebuildDue = millis() + 3000;
      canaryNextAt = millis() + 30000;
      return;
    }
    if (attempt < 4) delay(200);
  }
  Serial.println("[blocklist] FATAL: flash index unusable after retries -- refetch or reboot");
}
static void discardPendingBlocklist() {             // aborted transfer -> drop the partial
  if (blocklist) blocklist.close();
  LittleFS.remove("/blocklist.new");
  reopenBlocklist(true);                            // keep serving the live list
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  // A truncated download is still a multiple of 5 roughly 20% of the time, so the old
  // check (sz % 5 == 0) happily installed a half-length list -- sorted-hash lookups kept
  // working, so the missing tail failed silently. Callers also pass the expected size
  // (HTTP Content-Length, or the multipart upload length) and we require an exact match,
  // plus a floor so a tiny/garbage file can never replace a real list.
  bool ok = sz >= (size_t)HASH_BYTES * MIN_BLOCKLIST_ENTRIES && (sz % HASH_BYTES) == 0;
  if (ok && expectedBlocklistBytes && sz != expectedBlocklistBytes) {
    Serial.printf("[blocklist] size mismatch: got %u, expected %u\n",
                  (unsigned)sz, (unsigned)expectedBlocklistBytes);
    ok = false;
  }
  if (ok) {
    // Rename straight over the live file -- do NOT delete it first. littlefs's lfs_rename
    // accepts an existing target and replaces it in ONE atomic dir commit (it emits
    // LFS_TYPE_DELETE(newid) + LFS_TYPE_CREATE(newid) together), so the old list keeps
    // serving right up to the swap and survives if the rename fails. Deleting first (the
    // previous behaviour) left a window with NO list at all and turned any rename failure
    // into a permanently empty blocklist. It also avoids needing a second full copy: the
    // partition is 0x150000 and holding old+new simultaneously would need ~98% of it.
    if (blocklist) blocklist.close();
    if (!LittleFS.rename("/blocklist.new", BLOCKLIST_PATH)) {
      Serial.println("[blocklist] rename failed -- keeping existing list");
      reopenBlocklist(true);                        // live file untouched -> still serving
      return false;
    }
  } else {
    LittleFS.remove("/blocklist.new");
  }
  reopenBlocklist(true);
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: not a valid blocklist.bin (too small, wrong size, or not a multiple of 5)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false;
      // Write to /blocklist.new only; the live list is swapped in at UPLOAD_FILE_END once
      // validation passes, so an aborted upload leaves the current blocklist serving.
      LittleFS.remove("/blocklist.new");
      // totalSize is CONTENT_LENGTH_UNKNOWN/NOT_SET (huge, not 0) when the browser sends no
      // length; treat anything implausible as "unknown" so a valid upload is never rejected.
      expectedBlocklistBytes = (u.totalSize > 0 && u.totalSize <= MAX_BLOCKLIST_BYTES) ? u.totalSize : 0;
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      expectedBlocklistBytes = 0;
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist(true);
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
// Absent /update.cfg means "never configured" -> keep the compiled-in defaults so
// auto-update is on out of the box. Only a file the user actually saved overrides them,
// which is why an empty URL is only honoured when updateUrlCustom is set (otherwise a
// blank line would silently disable the default subscription).
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r");
  if (!f) { Serial.printf("[update] no cfg -> default %s every %uh\n",
                          updateUrl.c_str(), (unsigned)updateIntervalH); return; }
  String u = f.readStringUntil('\n'); u.trim();
  String iv = f.readStringUntil('\n'); iv.trim();
  f.close();
  updateUrl = u;
  updateUrlCustom = true;                        // a saved file means the user chose this
  if (iv.length()) updateIntervalH = iv.toInt();
  if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
  blocklistRefreshDue = true;
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  int len = http.getSize();                         // -1 when chunked/unknown
  // Reject an absurd Content-Length before downloading a single byte. Without this a server
  // advertising e.g. 100 MB would keep us reading until the 15 s idle deadline and only then
  // fail; the largest list that can possibly fit is the partition itself.
  if (len > (int)MAX_BLOCKLIST_BYTES) {
    http.end();
    updateStatus = "implausible size (" + String(len) + "B)";
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  // Download into /blocklist.new WITHOUT touching the live list. The old code removed
  // BLOCKLIST_PATH up front, so any failure below (network drop, full FS, short read) left
  // the device with no blocklist at all until the next successful update.
  LittleFS.remove("/blocklist.new");                // drop any stale partial from a prior run
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; return false; }
  WiFiClient* stream = http.getStreamPtr();
  uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  // Yield to DNS and the dashboard every few chunks.
  //
  // This loop used to run to completion without ever returning to loop(), so a 672 KB
  // download froze the device: no DNS replies and no web responses for the whole transfer
  // (measured: the box stopped answering ping-adjacent HTTP and DNS until it finished).
  // Because the blocklist fetch runs ~20 s after every boot, the device appeared to "hang
  // for a minute then recover" -- it was blocking, not crashing.
  //
  // handleDns() is called directly rather than loop(), since we are already inside it.
  uint32_t yielded = 0;
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) {
      int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) { f.write(b, n); total += n; idle = millis(); }
      // Every ~8 KB written, service pending DNS queries once. Small enough that the
      // socket stays busy, frequent enough that clients aren't stalled. NOTE: only DNS
      // is serviced, never web.handleClient() -- this runs inside the /fetchnow handler
      // and WebServer is not re-entrant; nested requests would clobber its connection
      // state. Dashboard requests made during a fetch wait in the backlog instead.
      if ((total - yielded) >= 8192) {
        yielded = total;
        handleDns();
        delay(1);
      }
    } else {
      // No data ready: instead of a bare delay(2), process DNS first so an idle wait
      // does not also become a stall.
      handleDns();
      if (millis() - idle > fetchIdleMs) break;
      delay(2);
    }
  }
  f.close(); http.end();
  // Reject a short transfer here rather than letting commitNewBlocklist decide: a severed
  // connection can end at any byte count, and the reader above exits its loop on either
  // the deadline or the socket closing, so `total < len` means the body is incomplete.
  if (len > 0 && (int)total != len) {
    updateStatus = "short read (" + String((unsigned)total) + "/" + String(len) + "B)";
    discardPendingBlocklist();
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }
  expectedBlocklistBytes = (len > 0) ? (size_t)len : 0;
  bool ok = commitNewBlocklist();
  expectedBlocklistBytes = 0;
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// Fetch the subscription, trying the compiled-in mirror list in order.
//
// Only used while the URL is still the built-in default -- a URL the user typed is honoured
// exactly (no silent substitution), so a private/intranet source can't be "helpfully"
// rerouted. Whichever candidate succeeds becomes updateUrl, so later polls retry the mirror
// that actually worked instead of re-walking a dead list every time.
static bool fetchDefaultBlocklist() {
  String cands[6];
  splitUrls(DEFAULT_UPDATE_MIRRORS, cands, 6);
  bool any = false;
  for (int i = 0; i < 6 && cands[i].length(); i++) {
    if (i) Serial.printf("[remote] trying mirror %d/%d\n", i + 1, 6);
    fetchIdleMs = i ? FETCH_IDLE_MIRROR_MS : FETCH_IDLE_MS;
    bool got = fetchBlocklist(cands[i]);
    fetchIdleMs = FETCH_IDLE_MS;
    if (got) {
      if (updateUrl != cands[i]) { updateUrl = cands[i]; saveUpdateCfg(); }
      return true;
    }
    any = true;
  }
  updateStatus = any ? "all mirrors failed" : "no url set";
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return false;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 30000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  // Bilingual (中文 / English) setup page. Networks are scanned at portal start and rendered
  // as a tappable list with signal strength -- the previous <datalist> needed the user to
  // tap the field and often showed no dropdown on phones, so it read as "type it yourself".
  // A manual-entry field stays available for hidden SSIDs.
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock 设置 / setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:460px;margin:24px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<div style='display:flex;justify-content:space-between;align-items:center'>"
    "<h2 style='margin:0'>&#128737; C3 AdBlock</h2>"
    "<button id=lang onclick=toggleLang() style='background:#21262d;color:#c9d1d9;border:1px solid #30363d;"
    "border-radius:5px;padding:5px 10px;cursor:pointer;font-size:13px'>English</button></div>"
    "<p id=sub style='color:#8b949e;margin:8px 0 14px'></p>"
    "<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>"
    "<b id=netsTitle></b>"
    "<button type=button id=rescan onclick=rescan() style='background:#21262d;color:#c9d1d9;border:1px solid "
    "#30363d;border-radius:5px;padding:4px 9px;cursor:pointer;font-size:13px'></button></div>"
    "<div id=netlist style='border:1px solid #30363d;border-radius:8px;overflow:hidden;margin-bottom:6px'></div>"
    "<p id=noNets style='color:#8b949e;font-size:13px;display:none'></p>"
    "<p><button type=button id=manualBtn onclick=toggleManual() style='background:none;border:0;color:#58a6ff;"
    "cursor:pointer;padding:0;font-size:13px'></button></p>"
    "<div id=manualBox style='display:none'>"
    "<input id=ssidIn placeholder='SSID' style='width:100%;box-sizing:border-box;padding:11px;margin:4px 0;"
    "border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "</div>"
    "<form method=POST action=/wifisave id=pwForm>"
    "<input type=hidden name=s id=ssidVal>"
    "<input name=p id=pw type=password style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;"
    "border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button id=go style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;"
    "color:#000;font-weight:600;cursor:pointer'></button>"
    "</form>"
    "<p id=hint style='color:#8b949e;font-size:13px;margin-top:16px'></p>"
    "<script>"
    "var NETS=" + portalNets + ";"
    "var chosen=null;"
    "var T={zh:{sub:'选择一个 WiFi，输入密码后设备会重启并接入。',nets:'扫描到的网络',rescan:'重新扫描',"
    "scanning:'扫描中…',none:'没有扫描到网络 —— 请靠近路由器后点「重新扫描」，或用下方手动输入。',"
    "manual:'SSID 隐藏了？手动输入',manualHide:'收起手动输入',ssid:'WiFi 名称 (SSID)',pw:'WiFi 密码',go:'连接',"
    "pick:'请先选择一个 WiFi',nopw:'请输入密码（或留空如果是开放网络）',open:'开放',"
    "hint:'连上后，在浏览器打开 http://c3adblock.local 进入管理面板 (Dashboard)。',btn:'English'},"
    "en:{sub:'Pick a WiFi network and enter its password. The device will reboot and join it.',nets:'Networks found',rescan:'Rescan',"
    "scanning:'Scanning...',none:'No networks found -- move closer to the router and tap Rescan, or enter it manually below.',"
    "manual:'SSID hidden? Enter manually',manualHide:'Hide manual entry',ssid:'WiFi name (SSID)',pw:'WiFi password',go:'Connect',"
    "pick:'Pick a network first',nopw:'Enter the password (leave empty if open)',open:'Open',"
    "hint:'Once connected, open http://c3adblock.local in a browser for the dashboard.',btn:'中文'}};"
    "function bars(r){var n=r>=-55?4:r>=-67?3:r>=-75?2:1;return '▮'.repeat(n)+'▯'.repeat(4-n)}"
    "function render(){"
    "netlist.innerHTML=NETS.map(function(w,i){"
    "return '<div class=net data-i='+i+' style=\"padding:11px 13px;border-bottom:1px solid #21262d;cursor:pointer;"
    "display:flex;justify-content:space-between;align-items:center\">'+"
    "'<span>'+esc(w.s)+(w.o?' <span style=\"color:#8b949e;font-size:12px\">'+T[LANG].open+'</span>':' &#128274;')+"
    "'</span><span style=\"color:#8b949e;font-size:12px\">'+bars(w.r)+'</span></div>'}).join('');"
    "noNets.style.display=NETS.length?'none':'block';}"
    "function esc(s){return String(s).replace(/[&<>\"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]})}"
    "function pick(i){chosen=NETS[i].s;ssidVal.value=chosen;ssidIn.value=chosen;"
    "Array.prototype.forEach.call(netlist.children,function(el){"
    "el.style.background=(+el.dataset.i===i)?'#1f6feb33':''});"
    "pw.focus();}"
    "netlist.addEventListener('click',function(e){var el=e.target.closest('.net');if(el)pick(+el.dataset.i)});"
    "ssidIn.addEventListener('input',function(){ssidVal.value=ssidIn.value;chosen=ssidIn.value});"
    "function toggleManual(){var b=manualBox.style.display==='none';manualBox.style.display=b?'block':'none';"
    "manualBtn.textContent=b?T[LANG].manualHide:T[LANG].manual;if(b)ssidIn.focus()}"
    "function rescan(){netsTitle.textContent=T[LANG].scanning;"
    "fetch('/rescan').then(function(r){return r.json()}).then(function(j){NETS=j;render();apply(LANG)})"
    ".catch(function(){apply(LANG)})}"
    "var LANG='en';"
    "function apply(l){LANG=l;var t=T[l];sub.textContent=t.sub;netsTitle.textContent=t.nets;"
    "document.getElementById('rescan').textContent=t.rescan;noNets.textContent=t.none;pw.placeholder=t.pw;ssidIn.placeholder=t.ssid;"
    "go.textContent=t.go;hint.textContent=t.hint;manualBtn.textContent=manualBox.style.display==='none'?t.manual:t.manualHide;"
    "document.getElementById('lang').textContent=t.btn;"
    "document.documentElement.lang=(l==='zh'?'zh-CN':'en');try{localStorage.setItem('c3lang',l)}catch(e){}render();}"
    "function cur(){try{return localStorage.getItem('c3lang')}catch(e){return null}}"
    "function toggleLang(){apply(cur()==='zh'?'en':'zh')}"
    "document.getElementById('pwForm').addEventListener('submit',function(e){"
    "ssidVal.value=chosen||ssidIn.value.trim();"
    "if(!ssidVal.value){e.preventDefault();alert(T[LANG].pick);return}});"
    "apply(cur()||((navigator.language||'en').toLowerCase().indexOf('zh')===0?'zh':'en'));"
    "</script></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name / 缺少 WiFi 名称"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  // Bilingual confirmation. The language choice isn't cached anywhere server-side, so show
  // both rather than guessing; the saved SSID is HTML-escaped (attacker-controllable input).
  const String esc = htmlEscape(ss);
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8>"
    "<body style='font:16px system-ui;text-align:center;margin-top:60px;padding:0 16px'>"
    "<p style='font-size:20px'>&#9989; 已保存，正在重启并连接 <b>" + esc + "</b>&hellip;</p>"
    "<p style='color:#57606a'>Saved. Restarting and joining <b>" + esc + "</b>&hellip;</p>"
    "<p>请把手机/电脑重新连回你原来的 WiFi，然后访问 <b>c3adblock.local</b></p>"
    "<p style='color:#57606a'>Reconnect to your normal WiFi, then open <b>c3adblock.local</b>.</p>"
    "</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
// Scan results are captured as JSON once, while still in STA mode: ESP32 switches channel
// to scan, which briefly drops AP clients, so re-scanning on demand is avoided by default
// (the page has an explicit "rescan" button for when a network was missed).
static void scanNetworksToJson() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalNets = "[";
  for (int i = 0; i < n && i < 20; i++) {
    if (i) portalNets += ",";
    portalNets += "{\"s\":\"" + jesc(WiFi.SSID(i)) + "\"";
    portalNets += ",\"r\":" + String(WiFi.RSSI(i));
    // WIFI_AUTH_OPEN == 0; anything else needs a password (WEP/WPA/WPA2/WPA3/enterprise)
    portalNets += ",\"o\":" + String(WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? 1 : 0);
    portalNets += "}";
  }
  portalNets += "]";
}
static void startConfigPortal() {
  scanNetworksToJson();
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "C3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  // Re-scan on demand. Accepted trade-off: scanning switches channel, so AP clients may see
  // a brief blip; the page warns and reloads afterwards.
  web.on("/rescan", []() { scanNetworksToJson(); web.send(200, "application/json", portalNets); });
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[c3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadBanned(); loadUpdateCfg(); loadCaptureCfg();
  Serial.printf("[boot] reset reason: %s\n", resetReason());
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // classic ESP32 BOOT button (GPIO9 is a flash pin there)
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (MDNS.begin("c3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://c3adblock.local"); }

  if (strcmp(WEB_PASS, "102030Zz") == 0 || strcmp(OTA_PASS, "102030Zz") == 0 ||
      strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h WEB_PASS/OTA_PASS are a PUBLIC default — anyone who has seen the repo knows it. "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  { const char* hdrs[] = { CSRF_HEADER, "Accept-Encoding" }; web.collectHeaders(hdrs, 2); }  // CSRF for requireAuth(); AE for the gzipped page
  // Pages must NOT call web.requestAuthentication() (requireAuthPage), because browsers
  // handle that prompt inconsistently -- some never show it, leaving users staring at a
  // blank/401 page. Being public keeps the dashboard always reachable; the password
  // question is moved into the page itself (see the login bar in src/page.h), which then
  // supplies credentials to the mutating endpoints. CSRF protection is unchanged there:
  // only state-changing endpoints require it, and they keep requireAuth().
  web.on("/", []() {
    // Browsers always offer gzip -- serve the precompressed page and let the client
    // decompress. Cheaper on both sides over a weak link than streaming 34 KB raw;
    // non-gzip clients (curl, tools) still get the plaintext PROGMEM page.
    if (PAGE_GZ_LEN && web.header("Accept-Encoding").indexOf("gzip") >= 0) {
      web.sendHeader("Content-Encoding", "gzip");
      web.send_P(200, "text/html", (const char*)PAGE_GZ, PAGE_GZ_LEN);
      return;
    }
    web.send_P(200, "text/html", PAGE);
  });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() { if (!requireAuth()) return; addCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return;
    if (updateUrlCustom) fetchBlocklist(updateUrl); else fetchDefaultBlocklist();
    web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) { updateUrl = web.arg("u"); updateUrl.trim(); updateUrlCustom = true; }
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    updateStatus = updateUrl.length() ? "scheduled" : "auto-update off";
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  // Restore the built-in subscription after the user cleared it.
  web.on("/resetupdate", []() {
    if (!requireAuth()) return;
    updateUrl = DEFAULT_UPDATE_URL;
    updateIntervalH = DEFAULT_UPDATE_INTERVAL_H;
    updateUrlCustom = false;
    updateStatus = "reset to default";
    LittleFS.remove("/update.cfg");                 // fall back to the compiled-in defaults
    lastCheckMs = millis() - (BOOT_FETCH_DELAY_MS ? BOOT_FETCH_DELAY_MS : 0);  // fetch soon
    web.send(200, "text/plain", updateUrl.length() ? updateUrl : "(no default compiled in)");
  });

  // ---------- DNS capture ----------
  // /capture?on=1|0[&f=substr][&clear=1] controls it; /capture.json and /capture.csv read
  // it. Reads are unauthenticated like /stats.json (they are only as sensitive as the
  // client list already exposed there), but starting/clearing requires auth.
  web.on("/capture", []() {
    if (!requireAuth()) return;
    if (web.hasArg("clear")) {
      capQueries = 0; capOn = false; capOverflow = false;
      memset(capBuf, 0, sizeof(capBuf));
      recentHead = 0; recentCount = 0;
    }
    // Starting a capture resets the filter unless one was given in the same request: a
    // leftover filter silently narrows the log, so the next capture looks like "this app
    // only asks for these domains" when it actually asks for far more. Default = record all.
    if (web.hasArg("on") && web.arg("on") != "0" && !web.hasArg("f")) capFilter = "";
    if (web.hasArg("f")) {
      capFilter = "";
      for (char ch : web.arg("f"))
        if ((uint8_t)ch >= 0x20) capFilter += ch;   // a control byte (stray \r) poisons indexOf matching
    }
    if (web.hasArg("p")) capPrecise = web.arg("p") != "0";
    if (web.hasArg("on")) capOn = web.arg("on") != "0";
    saveCaptureCfg();
    web.send(200, "application/json", String("{\"on\":") + (capOn ? "true" : "false") +
              ",\"precise\":" + (capPrecise ? "true" : "false") +
              ",\"filter\":\"" + jesc(capFilter) + "\"}");
  });
  // Distinct domains ordered by hit count, most-queried first: that ordering is what
  // makes a capture readable when one chatty app dominates the raw query stream.
  auto capSorted = [](const int **out) -> int {
    static int order[CAPTURE_SIZE];
    int n = 0;
    for (int i = 0; i < CAPTURE_SIZE; i++) if (capBuf[i].used) order[n++] = i;
    for (int a = 1; a < n; a++) {                 // insertion sort: n <= 256, mostly stable
      int key = order[a], b = a - 1;
      while (b >= 0 && (capBuf[order[b]].hits < capBuf[key].hits ||
                        (capBuf[order[b]].hits == capBuf[key].hits &&
                         capBuf[order[b]].lastMs < capBuf[key].lastMs))) { order[b + 1] = order[b]; b--; }
      order[b + 1] = key;
    }
    *out = order;
    return n;
  };
  const int *capOrder = nullptr;
  web.on("/capture.json", [&capSorted, &capOrder]() {
    int n = capSorted(&capOrder);
    String j; j.reserve(256 + n * 160 + recentCount * 110);
    j += "{\"on\":" + String(capOn ? "true" : "false") +
               ",\"precise\":" + String(capPrecise ? "true" : "false") +
               ",\"queries\":" + String(capQueries) +
               ",\"distinct\":" + String(n) +
               ",\"overflow\":" + String(capOverflow ? "true" : "false") +
               ",\"filter\":\"" + jesc(capFilter) + "\",\"entries\":[";
    for (int k = 0; k < n; k++) {
      const CapEntry& e = capBuf[capOrder[k]];
      if (k) j += ",";
      IPAddress ip(e.ip);
      j += "{\"d\":\"" + jesc(String(e.root)) + "\",\"ex\":\"" + jesc(String(e.example)) +
           "\",\"hits\":" + String(e.hits) + ",\"bh\":" + String(e.blockedHits) +
           ",\"ah\":" + String(e.hits - e.blockedHits) +
           ",\"ip\":\"" + ip.toString() + "\",\"q\":" + String(e.qtype) +
           ",\"b\":" + String(e.blockedHits == e.hits ? "true" : "false") +
           ",\"first\":" + String(e.firstMs) + ",\"last\":" + String(e.lastMs) + "}";
    }
    j += "],\"recent\":[";
    for (int k = 0; k < recentCount; k++) {
      int idx = (recentHead - 1 - k + RECENT_LOG_SIZE) % RECENT_LOG_SIZE;   // newest first
      const RecentQuery& r = recentLog[idx];
      if (k) j += ",";
      IPAddress rip(r.ip);
      j += "{\"t\":" + String(r.ms) + ",\"d\":\"" + jesc(String(r.d)) +
           "\",\"ip\":\"" + rip.toString() + "\",\"b\":" + String(r.blocked ? "true" : "false") +
           ",\"q\":" + String(r.qtype) + "}";
    }
    j += "]}";
    web.send(200, "application/json", j);
  });
  web.on("/capture.csv", [&capSorted, &capOrder]() {
    // One row per group (root domain, or full hostname while filtering), most-queried first.
    int n = capSorted(&capOrder);
    String csv = "rank,domain,example_allowed,hits,blocked,allowed,client,qtype,first_ms,last_ms\r\n";
    for (int k = 0; k < n; k++) {
      const CapEntry& e = capBuf[capOrder[k]];
      IPAddress ip(e.ip);
      csv += String(k + 1) + ",\"" + String(e.root) + "\",\"" + String(e.example) +
             "\"," + String(e.hits) + "," +
             String(e.blockedHits) + "," + String(e.hits - e.blockedHits) + "," + ip.toString() + "," + String(e.qtype) +
             "," + String(e.firstMs) + "," + String(e.lastMs) + "\r\n";
    }
    web.sendHeader("Content-Disposition", "attachment; filename=c3-dns-capture.csv");
    web.send(200, "text/csv", csv);
  });
  web.begin();
  ArduinoOTA.setHostname("c3adblock");   // pio run -t upload --upload-port c3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (blocklistRefreshDue) {
    blocklistRefreshDue = false;
    reopenBlocklist();          // fresh handle after a LittleFS write -- see the flag's comment
  }
  if (indexRebuildDue && (int32_t)(millis() - indexRebuildDue) >= 0) {
    indexRebuildDue = 0;
    reopenBlocklist();          // second pass once the swap's flush has settled
  }
  if ((int32_t)(millis() - canaryNextAt) >= 0) {
    canaryNextAt = millis() + 30000;
    // Canary v3: probe PERMANENT list members instead of an index-derived hash. The
    // index itself can be built from stale bytes (the swap-time wedge) and then passes
    // every self-referential check while real lookups forward -- probing fixed ad
    // domains reads the wedged layer too, but the STALE content no longer contains
    // anything guaranteeing a hit, so a miss actually means broken. Any hit = healthy.
    bool anyHit = false, anyReliable = false;
    for (auto* cdom : CANARY_DOMAINS) {
      bool rel = true;
      if (inFlash(fnv40(cdom, strlen(cdom)), &rel)) { anyHit = true; break; }
      if (rel) anyReliable = true;
    }
    if (anyHit) {
      canaryFails++;
      // Rebuild first; if the read path stays wedged (littlefs caches keep serving the
      // previous blob), the restart below clears it -- guarded so a genuinely broken
      // flash cannot trap the device in a reboot loop.
      Serial.printf("[blocklist] canary %s x%d -- matching broken\n",
                    anyReliable ? "miss" : "unreliable", canaryFails);
      if (canaryFails == 3) {
        // The field-verified healer: a refetch rewrites the file through fresh
        // littlefs blocks, so even the read-path wedge clears without a reboot.
        Serial.println("[blocklist] refetching -- fresh download rewrites the file blocks");
        fetchDefaultBlocklist();
      } else if (canaryFails >= 5) {
        prefs.begin("blk", false);
        uint8_t restarts = prefs.getUChar("restarts", 0);
        if (restarts >= 3) {
          prefs.end();
          Serial.println("[blocklist] restart guard tripped -- staying up, refetch manually");
        } else {
          prefs.putUChar("restarts", restarts + 1);
          prefs.end();
          Serial.println("[blocklist] restarting to clear the wedged filesystem");
          delay(100);
          ESP.restart();
        }
      } else {
        reopenBlocklist(true);
      }
    } else {
      // Healthy probe: decay toward re-arming restarts; 10 healthy minutes clears the guard.
      if (canaryFails) canaryFails--;
      if (millis() > 600000 && canaryFails == 0) {
        prefs.begin("blk", false); prefs.putUChar("restarts", 0); prefs.end();
      }
    }
  }
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    // Fetch shortly after boot instead of waiting a full interval: a freshly flashed unit
    // carries a snapshot from build time, and the previous "skip the first check" behaviour
    // meant it stayed on that snapshot for the first interval (24 h) after every reboot.
    // Deferred by BOOT_FETCH_DELAY_MS so WiFi/DNS have settled and the dashboard is up.
    // Use the mirror list only while the URL is still the built-in default; a URL the user
    // typed is used as-is.
    if (lastCheckMs == 0) {
      if (now >= BOOT_FETCH_DELAY_MS) {
        lastCheckMs = now;
        Serial.println("[update] first fetch after boot");
        if (updateUrlCustom) fetchBlocklist(updateUrl); else fetchDefaultBlocklist();
      }
    }
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) {
      lastCheckMs = now;
      if (updateUrlCustom) fetchBlocklist(updateUrl); else fetchDefaultBlocklist();
    }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
