#!/usr/bin/env python3
"""Download, filter and collapse IPv4 blocklists into a single CIDR list.

Exit codes (documented in README, consumed by cron/systemd):
    0  success
    2  configuration error (sources file missing/invalid, unknown parser)
    3  partial: at least one source failed (list still written) or no source produced data
    4  sanity guard tripped (implausible prefix, coverage spike, empty blacklist)
    5  output could not be written
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import sys
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
CIDR_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
USER_AGENT = "ip_list_aggregator/2.0"

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_PARTIAL = 3
EXIT_GUARD = 4
EXIT_SAVE = 5

DEFAULT_TIMEOUT = 30.0
DEFAULT_ATTEMPTS = 3
DEFAULT_MIN_PREFIX = 8
DEFAULT_COVERAGE_RATIO = 10.0


class ConfigError(RuntimeError):
    """Unusable configuration: missing sources file, bad JSON, unknown parser."""


class FetchError(RuntimeError):
    """A source could not be downloaded after every retry."""


class SourceError(RuntimeError):
    """A source returned data we cannot trust (empty, or nothing parsed)."""


class SourceType(Enum):
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"


@dataclass(frozen=True)
class SourceConfig:
    name: str
    url: str
    parser_type: str
    source_type: SourceType


class CIDRParser:
    def parse(self, text: str) -> Set[ipaddress.IPv4Network]:
        entries = set()
        for match in CIDR_PATTERN.findall(text):
            try:
                entries.add(ipaddress.ip_network(match, strict=False))
            except ValueError:
                logging.warning(f"Skipping invalid CIDR: {match}")
        return entries


class IPParser:
    def parse(self, text: str) -> Set[ipaddress.IPv4Network]:
        entries = set()
        for match in IP_PATTERN.findall(text):
            try:
                entries.add(ipaddress.ip_network(f"{match}/32", strict=False))
            except ValueError:
                logging.warning(f"Skipping invalid IP: {match}")
        return entries


def subtract_ranges(
    spans: Sequence[Tuple[int, int]], cuts: Sequence[Tuple[int, int]]
) -> List[Tuple[int, int]]:
    """Return ``spans`` minus ``cuts`` as a list of inclusive integer intervals."""
    ordered_cuts = sorted(cuts)
    result: List[Tuple[int, int]] = []
    for start, end in spans:
        cursor = start
        for cut_start, cut_end in ordered_cuts:
            if cut_end < cursor:
                continue
            if cut_start > end:
                break
            if cut_start > cursor:
                result.append((cursor, cut_start - 1))
            cursor = max(cursor, cut_end + 1)
            if cursor > end:
                break
        if cursor <= end:
            result.append((cursor, end))
    return result


def summarize(intervals: Sequence[Tuple[int, int]]) -> Set[ipaddress.IPv4Network]:
    networks: Set[ipaddress.IPv4Network] = set()
    for start, end in intervals:
        networks.update(
            ipaddress.summarize_address_range(
                ipaddress.IPv4Address(start), ipaddress.IPv4Address(end)
            )
        )
    return networks


def coverage(networks: Set[ipaddress.IPv4Network]) -> int:
    if not networks:
        return 0
    return sum(network.num_addresses for network in ipaddress.collapse_addresses(networks))


def file_coverage(path: Path) -> int:
    """Covered address count of an existing output file, 0 if absent/unreadable."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    networks = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            networks.add(ipaddress.ip_network(line, strict=False))
        except ValueError:
            continue
    return coverage(networks)


def count_ipv6_addresses(text: str) -> int:
    """Count tokens that are IPv6 literals or CIDRs (the tool itself is IPv4-only)."""
    found = 0
    for token in re.split(r"[\s;,|]+", text):
        candidate = token.strip("[]()\"'")
        if candidate.count(":") < 2:
            continue
        address = candidate.split("/", 1)[0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 6:
            found += 1
    return found


class IPProcessor:
    PARSERS = {
        "parse_generic_cidrs": CIDRParser(),
        "parse_generic_ips": IPParser(),
    }

    def __init__(
        self,
        output_path: Path,
        sources_path: Path,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        attempts: int = DEFAULT_ATTEMPTS,
        min_prefix: int = DEFAULT_MIN_PREFIX,
        coverage_ratio: float = DEFAULT_COVERAGE_RATIO,
    ):
        self.output_path = output_path
        self.sources_path = sources_path
        self.timeout = timeout
        self.attempts = attempts
        self.min_prefix = min_prefix
        self.coverage_ratio = coverage_ratio
        self.blacklist: Set[ipaddress.IPv4Network] = set()
        self.whitelist: Set[ipaddress.IPv4Network] = set()

    def load_sources(self) -> List[SourceConfig]:
        path = self.sources_path
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read sources file {path}: {exc}") from exc
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"sources file {path} is not valid JSON: {exc}") from exc
        if not isinstance(payload, list) or not payload:
            raise ConfigError(f"sources file {path} must contain a non-empty JSON list")

        sources = []
        for index, item in enumerate(payload):
            try:
                source = SourceConfig(
                    name=item["name"],
                    url=item["url"],
                    parser_type=item["parser_type"],
                    source_type=SourceType(item["type"]),
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ConfigError(
                    f"sources file {path}: entry #{index} is invalid ({exc})"
                ) from exc
            if source.parser_type not in self.PARSERS:
                raise ConfigError(
                    f"sources file {path}: entry #{index} uses unknown parser_type "
                    f"{source.parser_type!r} (known: {', '.join(sorted(self.PARSERS))})"
                )
            sources.append(source)
        return sources

    def fetch(self, url: str) -> str:
        last_error: Optional[Exception] = None
        for attempt in range(1, self.attempts + 1):
            try:
                request = Request(url, headers={"User-Agent": USER_AGENT})
                with urlopen(request, timeout=self.timeout) as response:
                    return response.read().decode("utf-8", errors="replace")
            except (URLError, OSError, ValueError) as exc:
                last_error = exc
                if attempt < self.attempts:
                    time.sleep(2 ** (attempt - 1))
        raise FetchError(f"{url}: {last_error}")

    def process_source(self, source: SourceConfig) -> int:
        content = self.fetch(source.url)
        if not content.strip():
            raise SourceError("empty response")

        ipv6 = count_ipv6_addresses(content)
        if ipv6:
            logging.warning(
                f"{source.name}: ignored {ipv6} IPv6 address(es) - this tool is IPv4-only"
            )

        parser = self.PARSERS.get(source.parser_type)
        if parser is None:
            raise ConfigError(
                f"{source.name}: unknown parser_type {source.parser_type!r}"
            )

        entries = parser.parse(content)
        if not entries:
            raise SourceError("no entries parsed (feed format changed?)")

        target = (
            self.blacklist
            if source.source_type == SourceType.BLACKLIST
            else self.whitelist
        )
        target.update(entries)
        return len(entries)

    def filter_ips(self) -> Set[ipaddress.IPv4Network]:
        """Blacklist minus whitelist, as exact set difference (partial ranges split)."""
        cuts = sorted(
            (int(net.network_address), int(net.broadcast_address))
            for net in ipaddress.collapse_addresses(self.whitelist)
        )
        result: Set[ipaddress.IPv4Network] = set()
        for net in self.blacklist:
            span = (int(net.network_address), int(net.broadcast_address))
            result.update(summarize(subtract_ranges([span], cuts)))
        return result

    def save_results(self, entries: Set[ipaddress.IPv4Network]) -> bool:
        try:
            temp_path = self.output_path.with_suffix(".tmp")
            with temp_path.open("w", encoding="utf-8") as handle:
                for net in sorted(entries, key=lambda n: (n.network_address, n.prefixlen)):
                    handle.write(f"{net.with_prefixlen}\n")
                handle.flush()
            temp_path.replace(self.output_path)
            return True
        except OSError as exc:
            logging.error(f"File save failed: {exc}")
            return False

    def run(self) -> int:
        sources = self.load_sources()

        failures: List[str] = []
        succeeded = 0
        for source in sources:
            try:
                count = self.process_source(source)
            except (FetchError, SourceError, ConfigError) as exc:
                failures.append(f"{source.name}: {exc}")
                logging.error(f"Source failed: {source.name}: {exc}")
                continue
            succeeded += 1
            logging.info(f"Processed {source.name}: {count} entries")

        if succeeded == 0:
            logging.error("No source produced data; previous list left untouched")
            return EXIT_PARTIAL

        if not self.blacklist:
            logging.error("No blacklist entries found")
            return EXIT_GUARD

        filtered = self.filter_ips()

        implausible = sorted(
            (net for net in filtered if net.prefixlen < self.min_prefix),
            key=lambda n: n.prefixlen,
        )
        if implausible:
            sample = ", ".join(str(n) for n in implausible[:5])
            logging.error(
                f"Refusing {len(implausible)} implausible network(s) wider than "
                f"/{self.min_prefix} (feed poisoning?): {sample}"
            )
            return EXIT_GUARD

        summarized = set(ipaddress.collapse_addresses(filtered))
        removed = len(filtered) - len(summarized)
        if removed:
            logging.info(f"Summarized {removed} redundant networks")

        previous = file_coverage(self.output_path)
        current = coverage(summarized)
        if previous and current > previous * self.coverage_ratio:
            logging.error(
                f"Coverage jump {previous} -> {current} addresses exceeds "
                f"x{self.coverage_ratio:g}; refusing to write (override with --force)"
            )
            return EXIT_GUARD

        if not self.save_results(summarized):
            return EXIT_SAVE

        logging.info(
            f"Saved {len(summarized)} entries ({current} addresses) to {self.output_path}"
        )
        if failures:
            logging.error(
                f"Partial update: {len(failures)} of {len(sources)} source(s) failed "
                f"({'; '.join(failures)})"
            )
            return EXIT_PARTIAL
        return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="IP list processor")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("merged-ip-list.txt"),
        help="output file (default: ./merged-ip-list.txt)",
    )
    parser.add_argument(
        "--sources",
        type=Path,
        default=None,
        help="sources file (default: sources.json next to this script)",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--min-prefix", type=int, default=DEFAULT_MIN_PREFIX)
    parser.add_argument("--coverage-ratio", type=float, default=DEFAULT_COVERAGE_RATIO)
    parser.add_argument(
        "--force",
        action="store_true",
        help="disable the coverage-spike guard",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sources_path = args.sources or Path(__file__).resolve().with_name("sources.json")
    processor = IPProcessor(
        args.output,
        sources_path,
        timeout=args.timeout,
        attempts=args.attempts,
        min_prefix=args.min_prefix,
        coverage_ratio=float("inf") if args.force else args.coverage_ratio,
    )
    try:
        return processor.run()
    except ConfigError as exc:
        logging.error(str(exc))
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
