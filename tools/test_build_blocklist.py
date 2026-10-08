"""Unit tests for build_blocklist.py.

These run in CI on every push, so they must stay hermetic: every source here is a
local temp file. Nothing in this module may touch the network.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

from build_blocklist import (ANTIAD_DOMAINS, ANTIAD_MIN_DOMAINS, DEFAULT_PROTECT, HAGEZI_DOMAINS,
                             HASH_BYTES, HDA_DOMAINS, HDA_MIN_DOMAINS, check_required_source,
                             fnv, is_ad_endpoint, is_protected, prune_parent_redundant,
                             strip_protected)

SCRIPT = pathlib.Path(__file__).with_name('build_blocklist.py')


def build(out, *sources, flags=()):
    """Run the tool over local files only and assert it succeeded."""
    proc = subprocess.run([sys.executable, str(SCRIPT), str(out), *map(str, sources), *flags],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(f'tool failed ({proc.returncode})\n{proc.stderr}')
    return proc


def hashes_of(path):
    data = pathlib.Path(path).read_bytes()
    assert len(data) % HASH_BYTES == 0, 'blob must be whole 5-byte entries'
    return {int.from_bytes(data[i:i + HASH_BYTES], 'little')
            for i in range(0, len(data), HASH_BYTES)}


class BuildBlocklistTests(unittest.TestCase):
    def test_hosts_line_includes_every_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'hosts'
            output = root / 'blocklist.bin'
            source.write_text('0.0.0.0 ads.example.com tracker.example.com # comment\n'
                              '127.0.0.1 metrics.example.com\n', encoding='utf-8')

            build(output, source)

            self.assertEqual(hashes_of(output),
                             {fnv(domain.encode()) for domain in
                              ('ads.example.com', 'tracker.example.com', 'metrics.example.com')})

    def test_hda_plain_domain_list_is_parsed(self):
        """home-dns-adblock's dist/domains.txt is a comment header + plain domains."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('# Home DNS Adblock -- plain domain list\n'
                              '# 规则指纹: deadbeef\n'
                              'ads0-normal-lq.zijieapi.com\n'
                              'ad.toutiao.com\n'
                              '\n'
                              'p3-ad-sign.byteimg.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            build(output, source)

            self.assertEqual(hashes_of(output),
                             {fnv(d.encode()) for d in ('ads0-normal-lq.zijieapi.com',
                                                        'ad.toutiao.com',
                                                        'p3-ad-sign.byteimg.com')})

    def test_protect_list_strips_playback_parents(self):
        """The playback parent goes; a whitelisted ad subdomain stays."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('qznovelvod.com\n'
                              'v5-reading-ad.qznovelvod.com\n'
                              'ads.example.com\n'
                              'cdn.qznovelvod.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            build(output, source)

            self.assertEqual(hashes_of(output),
                             {fnv(b'v5-reading-ad.qznovelvod.com'), fnv(b'ads.example.com')})

    def test_protect_keeps_ad_subdomains_but_drops_video_and_parent(self):
        """Mirrors home-dns-adblock's own whitelist: qznovelvod.com carries the real
        video so the parent must go, *-reading-ad subdomains are ad endpoints that stay
        blocked, and a *-reading-video subdomain is real playback and must go too."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('qznovelvod.com\n'
                              'v5-reading-ad.qznovelvod.com\n'
                              'v100-se-sjy-daily-reading-ad.qznovelvod.com\n'
                              'v5-reading-video.qznovelvod.com\n'
                              'ads.example.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            build(output, source)

            kept = hashes_of(output)
            self.assertIn(fnv(b'v5-reading-ad.qznovelvod.com'), kept,
                          'ad endpoint subdomain must stay blocked')
            self.assertIn(fnv(b'v100-se-sjy-daily-reading-ad.qznovelvod.com'), kept,
                          'marker must cover every vNNN generation, not a fixed list')
            self.assertIn(fnv(b'ads.example.com'), kept)
            self.assertNotIn(fnv(b'qznovelvod.com'), kept,
                             'the playback parent itself must never be blocked')
            self.assertNotIn(fnv(b'v5-reading-video.qznovelvod.com'), kept,
                             'a real video subdomain must not be blocked')

    def test_no_protect_flag_keeps_everything(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('qznovelvod.com\nads.example.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            build(output, source, flags=('--no-protect',))

            self.assertEqual(hashes_of(output),
                             {fnv(b'qznovelvod.com'), fnv(b'ads.example.com')})

    def test_protect_file_replaces_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('qznovelvod.com\nkeepme.example.com\n', encoding='utf-8')
            protect = root / 'protect.txt'
            protect.write_text('# custom protect list\nkeepme.example.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            build(output, source, flags=('--protect-file', str(protect)))

            self.assertEqual(hashes_of(output), {fnv(b'qznovelvod.com')})

    def test_protect_file_misuse_fails_cleanly(self):
        """Misuse must exit with a message, not a traceback -- and an empty protect file
        must not silently behave like --no-protect."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('ads.example.com\n', encoding='utf-8')
            out = root / 'blocklist.bin'
            empty = root / 'empty.txt'
            empty.write_text('# only a comment\n', encoding='utf-8')

            cases = {
                'missing value': ('--protect-file',),
                'nonexistent file': ('--protect-file', str(root / 'nope.txt')),
                'empty file': ('--protect-file', str(empty)),
            }
            for label, flags in cases.items():
                with self.subTest(label):
                    proc = subprocess.run([sys.executable, str(SCRIPT), str(out), str(source), *flags],
                                          capture_output=True, text=True)
                    self.assertNotEqual(proc.returncode, 0, f'{label} must fail')
                    self.assertNotIn('Traceback', proc.stderr, f'{label} must not traceback')
                    self.assertIn('--protect-file', proc.stderr)

    def test_marker_only_subdomain_of_protected_parent(self):
        """A subdomain whose label IS the marker (no version prefix) is still an ad
        endpoint; the check must not depend on a vNNN prefix existing."""
        self.assertTrue(is_ad_endpoint('reading-ad.qznovelvod.com', ['qznovelvod.com']))
        self.assertTrue(is_ad_endpoint('x-reading-ad.qznovelvod.com', ['qznovelvod.com']))
        self.assertFalse(is_ad_endpoint('qznovelvod.com', ['qznovelvod.com']))

    def test_repeated_source_reports_its_own_size_not_net_new(self):
        """A source listing only domains already seen must NOT look empty: the shrink
        guard counts what a source lists, not what it newly contributes."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            a = root / 'a.txt'
            a.write_text('one.example.com\ntwo.example.com\n', encoding='utf-8')
            b = root / 'b.txt'
            b.write_text('one.example.com\ntwo.example.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            proc = build(output, a, b)

            self.assertIn('-> 2 domains', proc.stderr)
            self.assertEqual(hashes_of(output),
                             {fnv(b'one.example.com'), fnv(b'two.example.com')})

    def test_cosmetic_rules_are_not_ingested_as_domains(self):
        """A CSS/cosmetic rule must never become a domain. 'bilibili.com##.ad' would
        otherwise be trimmed at the '#' into a valid-looking 'bilibili.com' and block the
        whole site; 'a.com,b.com##x' would be stored as one bogus comma-joined entry."""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'mixed.txt'
            source.write_text(
                '163.com,bilibili.com##a[href*=".admaster."]\n'
                'bilibili.com##.ad\n'
                'example.com#@#.ads\n'
                'example.com#?#div:has(.ad)\n'
                '||ads.example.com^\n'
                'plain.example.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            build(output, source)

            got = hashes_of(output)
            self.assertEqual(got, {fnv(b'ads.example.com'), fnv(b'plain.example.com')})
            for leaked in (b'bilibili.com', b'163.com', b'example.com',
                           b'163.com,bilibili.com'):
                self.assertNotIn(fnv(leaked), got, f'cosmetic rule leaked: {leaked!r}')

    def test_blob_is_sorted_deduped_five_byte_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('b.example.com\na.example.com\nb.example.com\n', encoding='utf-8')
            output = root / 'blocklist.bin'

            build(output, source)

            data = output.read_bytes()
            self.assertEqual(len(data), HASH_BYTES * 2)
            values = [int.from_bytes(data[i:i + HASH_BYTES], 'little')
                      for i in range(0, len(data), HASH_BYTES)]
            self.assertEqual(values, sorted(values), 'firmware binary-searches this blob')


class PruneTests(unittest.TestCase):
    """Parent-redundant pruning must be a no-op for the firmware's lookup."""

    def test_subdomain_covered_by_blocked_parent_is_dropped(self):
        self.assertEqual(prune_parent_redundant({'example.com', 'a.example.com'}),
                         {'example.com'})
        self.assertEqual(prune_parent_redundant({'a.b.example.com', 'b.example.com', 'example.com'}),
                         {'example.com'})

    def test_lookalike_parent_does_not_cover(self):
        """`notexample.com` must never be treated as covering `example.com`."""
        pool = {'example.com', 'notexample.com'}
        self.assertEqual(prune_parent_redundant(pool), pool)
        pool2 = {'example.com', 'example.com.evil.net'}
        self.assertEqual(prune_parent_redundant(pool2), pool2)

    def test_entries_without_a_blocked_parent_survive(self):
        pool = {'ads.example.com', 'other.org', 'com'}
        self.assertEqual(prune_parent_redundant(pool), pool)

    def test_protected_ad_endpoint_survives_parent_pruning(self):
        """The ordering guarantee: protection runs first, so an ad endpoint under a
        playlist parent keeps its own hash instead of being pruned away."""
        pool = {'qznovelvod.com', 'v5-reading-ad.qznovelvod.com', 'cdn.qznovelvod.com'}
        kept = set(pool) - set(strip_protected(pool, DEFAULT_PROTECT))
        self.assertEqual(kept, {'v5-reading-ad.qznovelvod.com'})
        self.assertEqual(prune_parent_redundant(kept), {'v5-reading-ad.qznovelvod.com'})

    def test_no_prune_flag_keeps_subdomains(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'domains.txt'
            source.write_text('example.com\na.example.com\n', encoding='utf-8')
            pruned = root / 'pruned.bin'
            kept = root / 'kept.bin'

            build(pruned, source)
            build(kept, source, flags=('--no-prune',))

            self.assertEqual(len(hashes_of(pruned)), 1)
            self.assertEqual(len(hashes_of(kept)), 2)


class GuardTests(unittest.TestCase):
    """The pure helpers behind the CI guards, tested without any network I/O."""

    def test_shrunk_cn_sources_are_rejected(self):
        """A CN source that parses to almost nothing must fail the build: Hagezi alone
        still yields ~57k, so a truncated anti-AD/HDA would look plausible in the total."""
        self.assertTrue(HDA_DOMAINS.startswith('https://'),
                        'the HDA source must stay a stable URL, not a vendored copy')
        self.assertTrue(ANTIAD_DOMAINS.startswith('https://'),
                        'the anti-AD source must stay a stable URL, not a vendored copy')
        for src, floor in ((HDA_DOMAINS, HDA_MIN_DOMAINS), (ANTIAD_DOMAINS, ANTIAD_MIN_DOMAINS)):
            self.assertFalse(check_required_source(src, floor - 1), f'{src} floor not enforced')
            self.assertTrue(check_required_source(src, floor))

    def test_hagezi_is_not_held_to_a_floor(self):
        """Hagezi legitimately shrinks between releases; only the CN sources are floored.
        check_required_source means 'publishable', so an unfloored source always passes."""
        self.assertTrue(check_required_source(HAGEZI_DOMAINS, 0))
        self.assertTrue(check_required_source(HAGEZI_DOMAINS, 999_999))

    def test_unrelated_source_is_not_held_to_a_floor(self):
        self.assertTrue(check_required_source('https://example.com/hosts', 0))

    def test_public_doh_resolvers_are_protected(self):
        """Blocking a DoH resolver takes the LAN offline -- an App's DoH lookup is not an ad."""
        for resolver in ('doh.pub', 'dns.alidns.com'):
            self.assertTrue(is_protected(resolver, DEFAULT_PROTECT),
                            f'{resolver} must never be blocked (whole LAN loses DNS)')

    def test_protect_matches_exact_and_subdomains_only(self):
        protect = ['qznovelvod.com']
        self.assertTrue(is_protected('qznovelvod.com', protect))
        self.assertTrue(is_protected('v5.qznovelvod.com', protect))
        self.assertFalse(is_protected('notqznovelvod.com', protect),
                         'suffix matching must not leak to lookalike domains')
        self.assertFalse(is_protected('qznovelvod.com.evil.net', protect))
        self.assertFalse(is_protected('other.com', protect))

    def test_default_protect_covers_cn_playback_parents(self):
        for parent in ('qznovelvod.com', 'fqnovelpic.com', 'douyincdn.com', 'douyinliving.com'):
            self.assertIn(parent, DEFAULT_PROTECT)

    def test_strip_protected_keeps_only_ad_endpoints(self):
        """The parent goes, marker-matched ad subdomains stay, other subdomains go."""
        domains = {'qznovelvod.com', 'v5-reading-ad.qznovelvod.com',
                   'cdn.qznovelvod.com', 'ads.example.com'}
        self.assertEqual(strip_protected(domains, ['qznovelvod.com']),
                         ['cdn.qznovelvod.com', 'qznovelvod.com'])

    def test_ad_endpoint_marker_is_not_a_loose_substring(self):
        """A lookalike label must not sneak past the marker test."""
        protect = ['qznovelvod.com']
        self.assertTrue(is_ad_endpoint('v5-reading-ad.qznovelvod.com', protect))
        self.assertFalse(is_ad_endpoint('not-reading-ad-really.qznovelvod.com', protect),
                         'the label must END with the marker')
        self.assertFalse(is_ad_endpoint('reading-ad.qznovelvod.com.evil.net', protect),
                         'must genuinely be under the protected parent')
        self.assertFalse(is_ad_endpoint('v5-reading-video.qznovelvod.com', protect))
        self.assertFalse(is_ad_endpoint('qznovelvod.com', protect),
                         'the parent itself is not an ad endpoint')


if __name__ == '__main__':
    unittest.main()
