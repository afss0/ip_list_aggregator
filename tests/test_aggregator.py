"""Offline test suite: parsers, guards, exit codes and whitelist semantics.

Everything runs against local ``file://`` fixtures, so the suite needs no network
and no privileges. Run with::

    python3 -m unittest discover -s tests -v
"""

import ipaddress
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT = ROOT / "ip_list_aggregator.py"
sys.path.insert(0, str(ROOT))

import ip_list_aggregator as agg  # noqa: E402


def run_script(*args, cwd):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=120,
    )


def write_sources(path: Path, entries):
    path.write_text(json.dumps(entries), encoding="utf-8")


def file_url(path: Path) -> str:
    return path.resolve().as_uri()


def addresses_of(networks):
    covered = set()
    for net in networks:
        covered.update(int(address) for address in net)
    return covered


class ParserTests(unittest.TestCase):
    def test_ip_parser_rejects_invalid_and_normalises(self):
        got = agg.IPParser().parse("198.51.100.9\t7\n999.1.1.1\n")
        self.assertEqual([str(n) for n in got], ["198.51.100.9/32"])

    def test_cidr_parser_normalises_and_skips_invalid(self):
        got = agg.CIDRParser().parse("203.0.113.7/24 300.1.1.1/24\n")
        self.assertEqual([str(n) for n in got], ["203.0.113.0/24"])

    def test_ipv6_is_counted_but_not_parsed(self):
        text = "2606:4700::1111\n2001:db8::/32\nLast update: Thu, 29 Oct 2026 03:02:06 +0100\n198.51.100.9\n"
        self.assertEqual(agg.count_ipv6_addresses(text), 2)
        self.assertEqual([str(n) for n in agg.CIDRParser().parse(text)], [])


class WhitelistFilterTests(unittest.TestCase):
    def make(self, blacklist, whitelist):
        processor = agg.IPProcessor(Path("/tmp/unused"), Path("/tmp/unused.json"))
        processor.blacklist = {ipaddress.IPv4Network(n) for n in blacklist}
        processor.whitelist = {ipaddress.IPv4Network(n) for n in whitelist}
        return processor

    def test_whitelist_subnet_inside_blacklist_is_carved_out(self):
        result = self.make(["10.0.0.0/8"], ["10.1.2.0/24"]).filter_ips()
        strings = {str(n) for n in result}
        self.assertNotIn("10.0.0.0/8", strings)
        self.assertNotIn("10.1.2.0/24", strings)
        self.assertTrue(
            addresses_of(result).isdisjoint(addresses_of([ipaddress.ip_network("10.1.2.0/24")]))
        )
        self.assertEqual(len(addresses_of(result)), 2**24 - 2**8)

    def test_whitelist_half_split_is_carved_out(self):
        result = self.make(["10.1.0.0/16"], ["10.1.128.0/17"]).filter_ips()
        self.assertEqual({str(n) for n in result}, {"10.1.0.0/17"})

    def test_never_whitelisted_addresses_stay_blocked(self):
        result = self.make(["10.1.128.0/17"], ["10.1.128.0/24"]).filter_ips()
        self.assertEqual(len(addresses_of(result)), 2**15 - 2**8)
        self.assertNotIn("10.1.128.0/24", {str(n) for n in result})

    def test_empty_whitelist_is_a_no_op(self):
        blacklist = ["203.0.113.0/24", "192.0.2.7/32"]
        result = self.make(blacklist, []).filter_ips()
        self.assertEqual({str(n) for n in result}, set(blacklist))

    def test_property_matches_brute_force(self):
        random.seed(11)
        base = int(ipaddress.IPv4Address("10.0.0.0"))
        universe = [ipaddress.IPv4Address(base + i) for i in range(256)]

        def to_networks(spans):
            found = set()
            for low, high in spans:
                low, high = sorted((low, high))
                found.update(
                    ipaddress.summarize_address_range(universe[low], universe[high])
                )
            return {ipaddress.IPv4Network(str(net)) for net in found}

        for _ in range(200):
            black_spans = [
                (random.randint(0, 255), random.randint(0, 255))
                for _ in range(random.randint(0, 4))
            ]
            white_spans = [
                (random.randint(0, 255), random.randint(0, 255))
                for _ in range(random.randint(0, 3))
            ]

            expected = set()
            for low, high in black_spans:
                low, high = sorted((low, high))
                expected.update(range(low, high + 1))
            for low, high in white_spans:
                low, high = sorted((low, high))
                expected.difference_update(range(low, high + 1))

            processor = agg.IPProcessor(Path("/tmp/unused"), Path("/tmp/unused.json"))
            processor.blacklist = to_networks(black_spans)
            processor.whitelist = to_networks(white_spans)
            got = {
                int(address) - base for address in addresses_of(processor.filter_ips())
            }
            self.assertEqual(got, expected)


class ExitCodeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.feed = self.dir / "feed.txt"
        self.feed.write_text("203.0.113.0/24\n192.0.2.7/32\n", encoding="utf-8")
        self.out = self.dir / "out.txt"

    def tearDown(self):
        self.tmp.cleanup()

    def sources(self, *entries):
        path = self.dir / "sources.json"
        write_sources(path, list(entries))
        return path

    def blacklist(self, name, url, parser="parse_generic_cidrs"):
        return {
            "name": name,
            "url": url,
            "parser_type": parser,
            "type": "blacklist",
        }

    def test_happy_path(self):
        sources = self.sources(self.blacklist("feed", file_url(self.feed)))
        result = run_script("--sources", str(sources), "-o", str(self.out), cwd=self.dir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.read_text().split(), ["192.0.2.7/32", "203.0.113.0/24"])

    def test_missing_sources_is_config_error_and_writes_nothing(self):
        result = run_script(
            "--sources", str(self.dir / "absent.json"), "-o", str(self.out), cwd=self.dir
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("cannot read sources file", result.stderr)
        self.assertFalse(self.out.exists())

    def test_unknown_parser_is_config_error(self):
        sources = self.sources(
            self.blacklist("feed", file_url(self.feed), parser="parse_magic")
        )
        result = run_script("--sources", str(sources), "-o", str(self.out), cwd=self.dir)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown parser_type", result.stderr)

    def test_partial_failure_still_writes_and_reports(self):
        sources = self.sources(
            self.blacklist("good", file_url(self.feed)),
            self.blacklist("dead", (self.dir / "missing.txt").as_uri(), parser="parse_generic_ips"),
        )
        result = run_script(
            "--sources", str(sources), "-o", str(self.out), "--attempts", "1", cwd=self.dir
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertTrue(self.out.exists())
        self.assertIn("Partial update", result.stderr)

    def test_all_sources_failing_leaves_output_alone(self):
        self.out.write_text("1.1.1.1/32\n", encoding="utf-8")
        sources = self.sources(
            self.blacklist("dead", (self.dir / "missing.txt").as_uri(), parser="parse_generic_ips")
        )
        result = run_script(
            "--sources", str(sources), "-o", str(self.out), "--attempts", "1", cwd=self.dir
        )
        self.assertEqual(result.returncode, 3)
        self.assertEqual(self.out.read_text(), "1.1.1.1/32\n")

    def test_empty_feed_is_a_source_error(self):
        empty = self.dir / "empty.txt"
        empty.write_text("\n\n", encoding="utf-8")
        sources = self.sources(
            self.blacklist("empty", file_url(empty), parser="parse_generic_ips")
        )
        result = run_script("--sources", str(sources), "-o", str(self.out), cwd=self.dir)
        self.assertEqual(result.returncode, 3)
        self.assertFalse(self.out.exists())

    def test_wide_prefix_guard_blocks_feed_poisoning(self):
        poisoned = self.dir / "poisoned.txt"
        poisoned.write_text("0.0.0.0/0\n203.0.113.0/24\n", encoding="utf-8")
        sources = self.sources(self.blacklist("poisoned", file_url(poisoned)))
        result = run_script("--sources", str(sources), "-o", str(self.out), cwd=self.dir)
        self.assertEqual(result.returncode, 4)
        self.assertIn("implausible", result.stderr)
        self.assertFalse(self.out.exists())

    def test_coverage_spike_guard_and_force(self):
        self.out.write_text("1.1.1.1/32\n", encoding="utf-8")
        sources = self.sources(self.blacklist("feed", file_url(self.feed)))

        blocked = run_script("--sources", str(sources), "-o", str(self.out), cwd=self.dir)
        self.assertEqual(blocked.returncode, 4)
        self.assertIn("Coverage jump", blocked.stderr)
        self.assertEqual(self.out.read_text(), "1.1.1.1/32\n")

        forced = run_script(
            "--sources", str(sources), "-o", str(self.out), "--force", cwd=self.dir
        )
        self.assertEqual(forced.returncode, 0, forced.stderr)

    def test_sources_path_resolves_next_to_the_script_not_the_cwd(self):
        # Hermetic copy: script + sources.json in one dir, executed from another.
        packaged = self.dir / "packaged"
        packaged.mkdir()
        shutil.copy(SCRIPT, packaged / "ip_list_aggregator.py")
        feed = packaged / "feed.txt"
        feed.write_text("203.0.113.0/24\n", encoding="utf-8")
        write_sources(
            packaged / "sources.json",
            [self.blacklist("feed", file_url(feed))],
        )
        elsewhere = self.dir / "elsewhere"
        elsewhere.mkdir()
        result = subprocess.run(
            [sys.executable, str(packaged / "ip_list_aggregator.py"), "-o", str(self.out)],
            cwd=str(elsewhere),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.read_text().split(), ["203.0.113.0/24"])

    def test_unwritable_output_is_exit_5(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses directory permissions")
        readonly = self.dir / "readonly"
        readonly.mkdir()
        readonly.chmod(0o500)
        sources = self.sources(self.blacklist("feed", file_url(self.feed)))
        try:
            result = run_script(
                "--sources", str(sources), "-o", str(readonly / "out.txt"), cwd=self.dir
            )
        finally:
            readonly.chmod(0o700)
        self.assertEqual(result.returncode, 5)
        self.assertIn("File save failed", result.stderr)

    def test_output_is_sorted_and_deduplicated(self):
        sources = self.sources(self.blacklist("feed", file_url(self.feed)))
        run_script("--sources", str(sources), "-o", str(self.out), cwd=self.dir)
        lines = self.out.read_text().split()
        self.assertEqual(
            lines, sorted(lines, key=lambda line: ipaddress.ip_network(line))
        )
        self.assertEqual(len(lines), len(set(lines)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
