#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [src ...] [flags]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Light) ~= 100k entries: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

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
  --no-protect        skip playback-protect filtering entirely (not recommended).
  --allow-missing     continue when a source cannot be downloaded (default: fail).

Playback protect (DEFAULT_PROTECT) removes domains that must never be blocked because
the firmware also blocks every subdomain — a wildcard parent for a CN video app would
take the real stream down with the ads. See the DEFAULT_PROTECT comment.
"""
import re
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget):
# ads + trackers + malware, WhatsApp/social keep working. ~100k entries / 0.5 MB
# (Hagezi's wildcard lists drop subdomains the firmware's parent-matching already covers).
# Want more? swap light-onlydomains.txt -> pro-onlydomains.txt is 370k and ONLY fits the
# single-app (no-OTA) partition table.
DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',            # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt',  # Hagezi Light (wildcard = domain + subdomains)
]

# Sources appended by --with-hda (and by the weekly CI release), on top of any
# explicit src arguments. Keep these as *stable raw URLs* so a rebuilt blob picks
# up upstream changes with no edit here.
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
# This is the last line of defence for playback: the firmware blocks a domain and
# all of its subdomains, so one over-broad parent rule in ANY upstream list would
# take the real video down with the ads. Matches exact domains and subdomains.
# Override/disable with --protect-file (see DEFAULT_PROTECT).
DEFAULT_PROTECT = [
    'qznovelvod.com',      # Hongguo / Fanqie real video (*-reading-video)
    'fqnovelpic.com',      # Fanqie image CDN
    'douyincdn.com',       # Douyin video CDN
    'douyinliving.com',    # Douyin live streams
    'ecombdimg.com',       # E-commerce images (order pages)
    'ecombdapi.com',       # E-commerce API
]

# ||domain^  or  @@||domain^  optionally followed by $modifiers
ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)

ALLOW_MISSING = False

def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    return urllib.request.urlopen(src, timeout=180).read().decode('utf-8', 'ignore')

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
# a real-video host can never match.
AD_ENDPOINT_MARKERS = ('-reading-ad',)

def is_protected(domain: str, protect) -> bool:
    return any(domain == p or domain.endswith('.' + p) for p in protect)

def is_ad_endpoint(domain: str, protect) -> bool:
    """True for a subdomain of a protected parent that is explicitly an ad endpoint."""
    for parent in protect:
        if domain.endswith('.' + parent):
            label = domain[:-(len(parent) + 1)].rsplit('.', 1)[-1]
            if any(label.endswith(marker) for marker in AD_ENDPOINT_MARKERS):
                return True
    return False

def strip_protected(domains: set, protect) -> list:
    """Return the subset of `domains` to REMOVE because it would break playback.

    Covers a protected parent and its subdomains, minus ad endpoints (which keep their
    own hash and stay blocked). Only domains under a protected parent are ever returned.
    """
    return sorted(d for d in domains
                  if is_protected(d, protect) and not is_ad_endpoint(d, protect))

def check_required_source(src: str, found: int) -> bool:
    """True if a source yielded enough to be publishable. A list that downloads but
    parses to almost nothing (moved file, HTML error page) is the silent-shrink mode."""
    if HDA_DOMAINS not in src:
        return True
    return found >= HDA_MIN_DOMAINS

def main():
    global ALLOW_MISSING
    raw = sys.argv[1:]
    flags = [a for a in raw if a.startswith('--')]
    ALLOW_MISSING = '--allow-missing' in flags
    if '--no-protect' in flags:
        protect = []
    elif '--protect-file' in flags:
        protect = [norm(l) for l in read_source(raw[raw.index('--protect-file') + 1]).splitlines()
                   if l.strip() and not l.lstrip().startswith('#')]
    else:
        protect = [norm(p) for p in DEFAULT_PROTECT]

    # Positional args, minus the value consumed by --protect-file.
    pf_val = [raw[raw.index('--protect-file') + 1]] if '--protect-file' in flags else []
    args = [a for a in raw if not a.startswith('--') and a not in pf_val]
    out = args[0] if args else 'blocklist.bin'

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
                skipped += 1; continue    # other adblock syntax (regex, wildcards, cosmetic) -> skip
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

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash
    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'sources          : {len(sources)}')
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')
    # Dual-OTA layout gives LittleFS 1.3125 MB; the firmware rejects anything that is not a
    # 5-byte multiple, and CI additionally caps the size at 1.3 MB. Warn early so an
    # over-large source set is obvious here instead of only in the release job.
    if size > 1300000:
        print(f'WARNING: blob exceeds the 1.3 MB CI limit (dual-OTA LittleFS is 1.3125 MB)',
              file=sys.stderr)

if __name__ == '__main__':
    main()
