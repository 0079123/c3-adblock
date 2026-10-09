#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [src ...] [flags]
  src = local file or URL. With none given, downloads the default CN-curated set
  (Hagezi Light + anti-AD) ~= 150k entries once home-dns-adblock is folded in:
  ads/trackers across web, App and video surfaces, tuned for CN networks.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt

Flags:
  --with-hda          append home-dns-adblock (CN app ad/tracker domains) to the sources.
                      With no src args this means the defaults + HDA; with src args it
                      appends HDA to those. Refuses to write if HDA yields < HDA_MIN_DOMAINS.
  --protect-file F    read extra playback-protect domains from file F (one per line,
                      '#' comments allowed) and use them INSTEAD of DEFAULT_PROTECT.
  --no-protect        skip protect filtering entirely (not recommended).
  --no-prune          keep subdomains whose parent is already blocked. They are dead
                      weight -- the firmware's parent-matching never reaches them -- but
                      this restores the pre-prune blob for A/B comparison.
  --allow-missing     continue when a source cannot be downloaded (default: fail).

Protect (DEFAULT_PROTECT) removes domains that must never be blocked because the firmware
also blocks every subdomain: a wildcard parent for a CN video app would take the real
stream down with the ads, and blocking a public DoH resolver takes the LAN offline. See
the DEFAULT_PROTECT comment.
"""
import re
import sys, os, math, socket, ipaddress, tempfile, pathlib, urllib.request, urllib.parse

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget).
#
# Curated for CN networks with video/app ads as the primary target. StevenBlack was
# DROPPED: on a video-app probe it contributed 83 matching domains (mostly overlapping
# Hagezi) while costing ~268 KB of the 1.31 MB filesystem. Removing it buys the headroom
# anti-AD needs, and anti-AD covers the web/app-ad surface StevenBlack was carrying.
#
# Measured on this source set (5-byte hashes, protect applied, parent-pruning on):
#   Hagezi Light + anti-AD + 217heidai lite + home-dns-adblock
#     -> ~136k entries / ~682 KB / ~50% of the 0x150000 (1,376,256 B) LittleFS partition
# Coverage gains vs the old StevenBlack+Hagezi set (video): iQiyi 19->61, Youku 21->88,
# MangoTV 3->55, Douyin 305->377, Kuaishou 71->101; (web/app) Baidu 99->329, Taobao 63->130.
HAGEZI_DOMAINS = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt'
ANTIAD_DOMAINS = 'https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt'
# 217heidai's *domain* variant (not the default adblockfilters.txt, which is URL-level
# filtering: paths, wildcards and $modifiers that a DNS hash list cannot express -- only
# ~520 of its 106k lines are usable here). The lite domain list adds ~1.2k entries after
# dedup, incl. Youku/iQiyi/MangoTV ad hosts and dns.weixin.qq.com (see DEFAULT_PROTECT).
ADBLOCKFILTERS_DOMAINS = 'https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdomainlite.txt'
# jdlingyu/ad-wars: CN-focused hosts list. Against the current published blob it adds only
# 16 domains (1,622 of its 1,638 are already covered), but 6 of those are genuinely missing
# -- notably tanx.com, the Alimama ad exchange that none of the other sources carried. Kept
# as a live source so future additions flow in automatically; the entries that break
# login/push/app resources are neutralised in DEFAULT_PROTECT rather than by dropping the
# source, so the annotations there explain each exception.
ADWARS_HOSTS = 'https://raw.githubusercontent.com/jdlingyu/ad-wars/master/hosts'

# Maintainer's own list, kept in-repo (not gitignored) so CI and every local build pick it
# up. Resolved relative to this script so the build works from any cwd. Add domains here
# after confirming them from a device capture -- see the notes inside the file.
CUSTOM_DOMAINS = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'custom-domains.txt'))
# Second curated list: flux-blocklist-adguard.txt, written from device captures with each
# entry annotated (source, why it is safe, and where an entry must NOT be widened to its
# parent). Kept as its own file so the annotations survive and it can be edited on its own.
# It also carries @@ allow rules -- see the caveat documented next to the allowlist output.
FLUX_DOMAINS = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'flux-blocklist-adguard.txt'))

# anti-AD is the largest CN source (~108k domains) and carries the web/app-ad surface.
# If it silently truncates, folding in Hagezi still leaves a plausible-looking total, so
# it gets its own floor alongside home-dns-adblock's.
ANTIAD_MIN_DOMAINS = 60000

DEFAULT_SOURCES = [
    HAGEZI_DOMAINS,             # Hagezi Light (wildcard = domain + subdomains)
    ANTIAD_DOMAINS,             # anti-AD: CN ads/trackers (web + app)
    ADBLOCKFILTERS_DOMAINS,     # 217heidai lite domain list: Youku/iQiyi/MangoTV ad hosts
    ADWARS_HOSTS,               # jdlingyu/ad-wars: CN app ads (see DEFAULT_PROTECT for its exceptions)
    CUSTOM_DOMAINS,             # data/custom-domains.txt: hand-picked additions
    FLUX_DOMAINS,               # data/flux-blocklist-adguard.txt: capture-verified list
]

# Appended by --with-hda AND always included by the weekly CI release (see DEFAULT_SOURCES
# users). Keep these as *stable raw URLs* so a rebuilt blob picks up upstream changes with
# no edit here.
#
# home-dns-adblock maintains CN-app ad/tracker domains (Douyin/Fanqie/Hongguo/
# Xiaohongshu/Amap) extracted from real device DNS logs. Its own generator writes
# dist/domains.txt; the exporter already special-cases *-reading-ad.qznovelvod.com
# so it does NOT blanket-block the qznovelvod.com parent that carries the real
# video. NEVER add qznovelvod.com itself -- the firmware matches parent domains,
# so that one line would kill Hongguo/Fanqie playback.
HDA_DOMAINS = 'https://raw.githubusercontent.com/abclq/home-dns-adblock/main/dist/domains.txt'
HDA_SOURCES = [HDA_DOMAINS]

# Default guard for --with-hda: how many *usable* domains the HDA list must yield.
# Upstream sits at ~206; a partially-parseable or half-downloaded file still parses
# cleanly as a domain list, so a floor is the only thing that catches that.
HDA_MIN_DOMAINS = 120

# Explicit allowlist, applied AFTER every source and after the @@/-minus filters.
# This is the last line of defence: the firmware blocks a domain and all of its
# subdomains, so one over-broad parent rule in ANY upstream list would take the real
# service down with the ads. Matches exact domains and subdomains.
# Override/disable with --protect-file (see DEFAULT_PROTECT).
DEFAULT_PROTECT = [
    'qznovelvod.com',      # Hongguo / Fanqie real video (*-reading-video)
    'fqnovelpic.com',      # Fanqie image CDN
    'douyincdn.com',       # Douyin video CDN
    'douyinliving.com',    # Douyin live streams
    'ecombdimg.com',       # E-commerce images (order pages)
    'ecombdapi.com',       # E-commerce API
    # Public DNS resolvers: an App's DoH traffic is not itself an ad, but blocking these
    # breaks name resolution for any device/browser/router configured to use them -- i.e.
    # it takes the whole LAN offline. home-dns-adblock ships both; keep them unblocked.
    'dns.alidns.com',      # AliDNS DoH endpoint
    'doh.pub',             # Tencent DoH endpoint (also dot.pub over HTTPS)
    # WeChat's own resolver endpoints. 217heidai's list blocks these deliberately (to stop
    # WeChat side-stepping DNS filtering), but WeChat is too central to risk breaking for an
    # ad-blocking gain. All three spellings appear in that list as separate entries, so
    # protecting only dns.weixin.qq.com would still leave the other two blocked.
    'dns.weixin.qq.com',
    'aedns.weixin.qq.com',
    'dns.weixin.qq.com.cn',
    # ---- ad-wars entries that are NOT ads despite being on that list ----
    # The flux list deliberately @@-allows carrier one-tap-login SDKs (id6.me,
    # auth.wosms.cn, enrichgw.10010.com); ad-wars blocks the Aliyun equivalent, which would
    # reintroduce exactly the breakage those @@ lines exist to prevent.
    'ynuf.aliapp.org',           # Aliyun Yunma phone-number auth (one-tap login)
    'jnn-pa.googleapis.com',     # Google Play services (location/sync, not just ads)
    'resolver.msg.xiaomi.net',   # Xiaomi push / resolver
    'cloudservice22.kingsoft-office-service.com',  # Kingsoft Docs cloud
    'ckjr001.com',               # Caiyun Weather: assets.* / kpstaticbj.wx.* are app resources
    'meipian7.cn',               # Meipian app content
    'nmobi.kuwo.cn',             # Kuwo Music service
    'du.163.com',                # NetEase service
    'hw.zuimeitianqi.com',       # Zuimei Weather service
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False
NO_PRUNE = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # redirect_request returning None makes urllib raise on the 3xx instead of following it.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def write_output(path: str, blob: bytes) -> None:
    # Normalize and validate right at the sink: no .. components, and the resolved
    # location must stay inside the repo tree (CI, maintainer) or the OS temp dir
    # (test harness).
    if '..' in os.path.normpath(path).split(os.sep):
        sys.exit(f'output path may not contain .. components: {path}')
    real = os.path.realpath(path)
    parent = os.path.dirname(real)
    for base in (os.getcwd(), tempfile.gettempdir()):
        base = os.path.realpath(base)
        if parent == base or parent.startswith(base + os.sep):
            pathlib.Path(real).write_bytes(blob)
            return
    sys.exit(f'output path must stay under the working directory or the system '
             f'temp dir, got: {path}')

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    # SSRF guard for the fetch path. This tool runs on the maintainer's machine and in
    # CI and only ever needs public list hosts, so: https with a hostname, nothing that
    # resolves to a non-public address (private, loopback, link-local -- which also
    # covers cloud metadata endpoints), and redirects refused (a 3xx could point
    # anywhere; real list sources never redirect).
    parsed = urllib.parse.urlparse(src)
    if parsed.scheme != 'https' or not parsed.hostname:
        sys.exit(f'remote sources must be https URLs with a hostname, got: {src}')
    try:
        infos = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        sys.exit(f'cannot resolve {parsed.hostname}: {e}')
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            sys.exit(f'{parsed.hostname} resolves to a non-public address ({ip}); refusing')
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.build_opener(_NoRedirect()).open(src, timeout=180).read().decode('utf-8', 'ignore')

# Ad endpoints that legitimately live UNDER a protected playback parent. The parent must
# be un-blocked (it carries the real stream) while these stay blocked by their own hash.
#
# This is a *marker*, not a version list: home-dns-adblock marks every ad endpoint under
# qznovelvod.com with `...reading-ad.` and the real stream with `...reading-video.`, and it
# ships only the ad ones. Hardcoding v5/v6/v26/... would silently start dropping the
# parent's protection as upstream adds vNNN generations -- and as of the 2026-10 listing
# upstream already had 33 reading-ad entries across v5,v6,v7,v9,v11,v13,v26,v95,v99,v100.
#
# Matching is deliberately strict: the label immediately before the protected parent must
# END with one of these markers, so 'not-a-reading-ad.qznovelvod.com' does not qualify and
# a real-video host can never match. The bare 'reading-ad.qznovelvod.com' form (no vNNN
# prefix) is allowed too: strip the leading '-' and compare as a whole label.
AD_ENDPOINT_MARKERS = ('-reading-ad',)

def is_protected(domain: str, protect) -> bool:
    return any(domain == p or domain.endswith('.' + p) for p in protect)

def is_ad_endpoint(domain: str, protect) -> bool:
    """True for a subdomain of a protected parent that is explicitly an ad endpoint."""
    for parent in protect:
        if domain.endswith('.' + parent):
            label = domain[:-(len(parent) + 1)].rsplit('.', 1)[-1]
            if any(label.endswith(m) or label == m.lstrip('-') for m in AD_ENDPOINT_MARKERS):
                return True
    return False

def strip_protected(domains: set, protect) -> list:
    """Return the subset of `domains` to REMOVE because it would break playback.

    Covers a protected parent and its subdomains, minus ad endpoints (which keep their
    own hash and stay blocked). Only domains under a protected parent are ever returned.
    """
    return sorted(d for d in domains
                  if is_protected(d, protect) and not is_ad_endpoint(d, protect))

def prune_parent_redundant(domains: set) -> set:
    """Drop subdomains that a blocked parent already covers.

    The firmware blocks a domain and all of its subdomains and walks up the labels on
    every query, so a query for `a.b.example.com` whose `example.com` is in the blob is
    already answered by that parent entry -- the child's own hash is unreachable, i.e.
    dead weight in flash. On the current source set this is ~9.5% of entries.

    Only exact-parent ancestry counts; a lookalike like `notexample.com` never covers
    `example.com`.
    """
    keep = set()
    for d in domains:
        p = d
        covered = False
        while '.' in p:
            p = p.split('.', 1)[1]
            if '.' not in p:
                break                     # reached a TLD; nothing above can be a rule
            if p in domains:
                covered = True
                break
        if not covered:
            keep.add(d)
    return keep

def check_required_source(src: str, found: int) -> bool:
    """True if a source yielded enough to be publishable. A list that downloads but
    parses to almost nothing (moved file, HTML error page) is the silent-shrink mode.

    Only the CN sources are floored. Hagezi legitimately grows/shrinks between releases,
    but anti-AD and home-dns-adblock are the whole point of this build -- if either
    silently truncates, the published list quietly loses its CN coverage while the total
    size still looks plausible (Hagezi alone is 57k), so a floor is the only catch.
    """
    for required, floor in ((HDA_DOMAINS, HDA_MIN_DOMAINS), (ANTIAD_DOMAINS, ANTIAD_MIN_DOMAINS)):
        if required in src:
            return found >= floor
    return True

def main():
    global ALLOW_MISSING, NO_PRUNE
    raw = sys.argv[1:]
    flags = [a for a in raw if a.startswith('--')]
    ALLOW_MISSING = '--allow-missing' in flags
    NO_PRUNE = '--no-prune' in flags
    if '--no-protect' in flags:
        protect = []
    elif '--protect-file' in flags:
        idx = raw.index('--protect-file') + 1
        if idx >= len(raw):
            sys.exit('--protect-file needs a path or URL argument')
        pf = raw[idx]
        if not os.path.exists(pf) and '://' not in pf:
            sys.exit(f'--protect-file: no such file: {pf}')
        protect = [norm(l) for l in read_source(pf).splitlines()
                   if l.strip() and not l.lstrip().startswith('#')]
        if not protect:
            sys.exit(f'--protect-file: {pf} listed no domains (refusing to disable protection)')
    else:
        protect = [norm(p) for p in DEFAULT_PROTECT]

    # Positional args, minus the value consumed by --protect-file.
    pf_val = [raw[raw.index('--protect-file') + 1]] if '--protect-file' in flags else []
    args = [a for a in raw if not a.startswith('--') and a not in pf_val]
    out = args[0] if args else 'blocklist.bin'
    # The blob is only ever written to the repo tree (CI, maintainer) or the OS temp dir
    # (the test harness); refuse any path that would land anywhere else.
    out_dir = os.path.dirname(os.path.abspath(out))
    allowed = (os.getcwd(), tempfile.gettempdir())
    if not any(os.path.commonpath([out_dir, base]) == base for base in allowed):
        sys.exit(f'output path must stay under the working directory or the system '
                 f'temp dir, got: {out}')

    if args[1:]:
        sources = args[1:]
        if '--with-hda' in flags:
            sources = sources + [s for s in HDA_SOURCES if s not in sources]
    elif '--with-hda' in flags:
        sources = DEFAULT_SOURCES + HDA_SOURCES
    else:
        sources = DEFAULT_SOURCES

    domains, allow = set(), set()
    skipped = 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            # Fail loudly: silently dropping a source shrinks the list without anyone noticing
            # (happened when Hagezi retired domains/light.txt). Pass --allow-missing to continue.
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not ALLOW_MISSING: sys.exit(1)
            continue
        found = set()      # every domain this source LISTED, not just the new ones:
                           # a source that repeats another's entries must not look empty
        for line in data.splitlines():
            # Cosmetic / scriptlet rules must be rejected BEFORE the '#' comment strip
            # below, which would otherwise trim 'bilibili.com##.ad' down to a valid-looking
            # 'bilibili.com' -- turning a CSS selector rule into a block rule for the whole
            # site. A line carrying a cosmetic marker is never a plain-domain entry.
            if any(marker in line for marker in ('##', '#@#', '#?#', '#%#', '$#')):
                skipped += 1; continue
            line = line.split('#', 1)[0].strip() if not line.lstrip().startswith(('||', '@@')) else line.strip()
            if not line or line[0] in '!/[':
                continue
            # AdGuard / ABP basic rules: ||example.com^  and allow rules @@||example.com^
            m = ADG.match(line)
            if m:
                if m.group(3):            # has $modifiers (client/dnstype/etc.) -> can't express, skip
                    skipped += 1; continue
                if m.group(1):
                    allow.add(norm(m.group(2)))
                else:
                    domains.add(norm(m.group(2)))
                    found.add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1; continue    # other adblock syntax (regex, wildcards) -> skip
            parts = line.split()
            if parts[0] in ('0.0.0.0','127.0.0.1','::1','::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
                    found.add(d)
        # A source that downloads fine but parses to almost nothing is the silent-shrink
        # failure mode CI has to catch (dead redirect, HTML error page, moved file).
        print(f'  {src}\n    -> {len(found):,} domains', file=sys.stderr)
        if not check_required_source(src, len(found)):
            print(f'  !! {src} yielded only {len(found):,} domains '
                  f'(expected >= {HDA_MIN_DOMAINS:,}) -- refusing to publish a shrunk list',
                  file=sys.stderr)
            sys.exit(1)
    if allow:
        before = len(domains); domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed ({len(allow):,} @@ rules)', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (adblock syntax that a DNS hash list cannot express)', file=sys.stderr)

    removed_protect = strip_protected(domains, protect)
    if removed_protect:
        domains -= set(removed_protect)
        shown = ', '.join(removed_protect[:6]) + (' ...' if len(removed_protect) > 6 else '')
        print(f'playback protect : {len(removed_protect)} domain(s) removed -> {shown}', file=sys.stderr)

    # Parent-redundant pruning runs AFTER protection, never before: if a parent were
    # removed later (by the protect list), any child pruned in its favour would be left
    # unblocked. Protecting first means each parent kept below really is still blocked,
    # so dropping the child is a genuine no-op for the firmware's parent-matching lookup.
    if not NO_PRUNE:
        before = len(domains)
        domains = prune_parent_redundant(domains)
        if before - len(domains):
            print(f'parent-redundant : {before - len(domains):,} domain(s) dropped '
                  f'(already covered by a blocked parent)', file=sys.stderr)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    blob = b''.join(h.to_bytes(HASH_BYTES, 'little') for h in uniq)
    write_output(out, blob)

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'sources          : {len(sources)}')
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')
    # partitions.csv gives LittleFS 0x150000 = 1,376,256 bytes. CI caps the blob at 1.3 MB
    # to leave headroom, so warn here too rather than only failing in the release job. The
    # firmware itself only rejects a blob whose size is not a multiple of 5.
    if size > 1300000:
        print(f'WARNING: blob exceeds the 1.3 MB CI limit (LittleFS partition is 1,376,256 B)',
              file=sys.stderr)

if __name__ == '__main__':
    main()
