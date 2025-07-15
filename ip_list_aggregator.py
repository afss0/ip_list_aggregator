import argparse
import ipaddress
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

import requests

# Constants and Types
IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
CIDR_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b")


class SourceType(Enum):
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"


@dataclass
class SourceConfig:
    name: str
    url: str
    parser_type: str
    source_type: SourceType


class Parser(ABC):
    @abstractmethod
    def parse(self, text: str) -> Set[ipaddress.IPv4Network]:
        pass


class CIDRParser(Parser):
    def parse(self, text: str) -> Set[ipaddress.IPv4Network]:
        entries = set()
        for match in CIDR_PATTERN.findall(text):
            try:
                entries.add(ipaddress.ip_network(match, strict=False))
            except ValueError:
                logging.warning(f"Skipping invalid CIDR notation: {match}")
        return entries


class IPParser(Parser):
    def parse(self, text: str) -> Set[ipaddress.IPv4Network]:
        entries = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for match in IP_PATTERN.findall(line):
                try:
                    network = ipaddress.ip_network(f"{match}/32")
                    entries.add(network)
                except ValueError:
                    logging.warning(f"Skipping invalid IP address: {match}")
        return entries


class IntervalNode:
    def __init__(self, start: int, end: int):
        self.start = start
        self.end = end
        self.max_end = end
        self.left: Optional["IntervalNode"] = None
        self.right: Optional["IntervalNode"] = None


def insert_interval(root: Optional[IntervalNode], start: int, end: int) -> IntervalNode:
    if not root:
        return IntervalNode(start, end)
    if start <= root.start:
        root.left = insert_interval(root.left, start, end)
    else:
        root.right = insert_interval(root.right, start, end)
    root.max_end = max(root.max_end, end)
    return root


def build_interval_tree(intervals: List[Tuple[int, int]]) -> Optional[IntervalNode]:
    root = None
    for start, end in intervals:
        root = insert_interval(root, start, end)
    return root


def overlaps(node: Optional[IntervalNode], point: int) -> bool:
    if not node:
        return False
    if node.start <= point <= node.end:
        return True
    if point < node.start:
        return overlaps(node.left, point)
    elif point > node.max_end:
        return False
    return overlaps(node.left, point) or overlaps(node.right, point)


def ip_to_int(ip: Union[str, ipaddress.IPv4Address]) -> int:
    """Convert IPv4 address to integer for comparison"""
    # Convert to string if it's an IPv4Address object
    ip_str = str(ip)
    return sum(
        int(octet) << (8 * i) for i, octet in enumerate(reversed(ip_str.split(".")))
    )


class IPLoader:
    def __init__(self, parser_map: Dict[str, Parser]):
        self.parser_map = parser_map

    def load_sources(self) -> List[SourceConfig]:
        """Load sources configuration from sources.json file"""
        try:
            with open("sources.json", "r") as f:
                sources_data = json.load(f)

            # Create SourceConfig instances with all required fields
            return [
                SourceConfig(
                    name=source["name"],
                    url=source["url"],
                    parser_type=source["parser_type"],
                    source_type=SourceType(source["type"]),
                )
                for source in sources_data
            ]
        except Exception as e:
            logging.error(f"Failed to load sources.json: {e}")
            raise


class IPFilter:
    def __init__(self):
        self.blacklist_entries: Set[ipaddress.IPv4Network] = set()
        self.whitelist_entries: Set[ipaddress.IPv4Network] = set()

    def filter_whitelisted_ips(
        self,
        blacklist: Set[ipaddress.IPv4Network],
        whitelist: Set[ipaddress.IPv4Network],
    ) -> Set[ipaddress.IPv4Network]:
        """Remove whitelisted IPs from the blacklist using an interval tree."""
        intervals = []
        for net in whitelist:
            start = ip_to_int(net.network_address)
            end = ip_to_int(net.broadcast_address)
            intervals.append((start, end))

        root = build_interval_tree(intervals)
        filtered_blacklist = set()

        for black_net in blacklist:
            point = ip_to_int(black_net.network_address)
            if not overlaps(root, point):
                filtered_blacklist.add(black_net)

        return filtered_blacklist


class IPProcessor:
    def __init__(self, loader: IPLoader, filter_: IPFilter, output_path: Path):
        self.loader = loader
        self.filter_ = filter_
        self.output_path = output_path
        self.blacklist_entries: Set[ipaddress.IPv4Network] = set()
        self.whitelist_entries: Set[ipaddress.IPv4Network] = set()

    def fetch_content(self, session: requests.Session, url: str) -> Optional[str]:
        """Fetch text content from a URL using a requests session."""
        try:
            response = session.get(url, timeout=30)
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            logging.error(f"Request timed out for URL: {url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred while fetching {url}: {e}")
        return None

    def save_to_file(self, entries: Set[ipaddress.IPv4Network], filepath: Path) -> bool:
        """Saves a set of unique IP/CIDR entries to a file using an atomic write."""
        temp_path = filepath.with_suffix(filepath.suffix + ".tmp")

        try:
            with temp_path.open("w", encoding="utf-8") as f:
                sorted_entries = sorted(entries, key=lambda ip: ip.network_address)
                for entry in sorted_entries:
                    f.write(f"{entry.with_prefixlen}\n")

            temp_path.replace(filepath)
            return True

        except OSError as e:
            logging.error(f"Failed to write to file {filepath}: {e}")
            if temp_path.exists():
                temp_path.unlink()
            return False

    def process(self) -> None:
        """Process IP addresses from configured sources."""
        parser_map = {
            "parse_generic_cidrs": CIDRParser(),
            "parse_generic_ips": IPParser(),
        }
        self.loader.parser_map = parser_map

        try:
            sources = self.loader.load_sources()
        except Exception:
            return

        with requests.Session() as session:
            for source in sources:
                logging.info(f"Processing source: {source.name}")

                content = self.fetch_content(session, source.url)
                if not content:
                    logging.error(
                        f"Failed to fetch content from {source.name}, skipping."
                    )
                    continue

                parser = parser_map.get(source.parser_type)
                if not parser:
                    logging.error(f"Unknown parser type: {source.parser_type}")
                    continue

                source_entries = parser.parse(content)
                logging.info(
                    f"Found {len(source_entries)} unique entries from {source.name}."
                )

                if source.source_type == SourceType.BLACKLIST:
                    self.blacklist_entries.update(source_entries)
                elif source.source_type == SourceType.WHITELIST:
                    self.whitelist_entries.update(source_entries)

        if not self.blacklist_entries:
            logging.warning("No blacklist entries were collected.")
            return

        logging.info(
            f"Total unique blacklist entries collected: {len(self.blacklist_entries)}"
        )
        logging.info(
            f"Total unique whitelist entries collected: {len(self.whitelist_entries)}"
        )

        # Filter out whitelisted IPs from the blacklist
        filtered_entries = self.filter_.filter_whitelisted_ips(
            self.blacklist_entries, self.whitelist_entries
        )

        logging.info(
            f"Total unique blacklist entries after filtering: {len(filtered_entries)}"
        )

        # Summarize network list to remove redundant subnets
        summarized_entries = set(ipaddress.collapse_addresses(filtered_entries))
        num_removed = len(filtered_entries) - len(summarized_entries)

        if num_removed > 0:
            logging.info(
                f"Removed {num_removed} subsumed networks. "
                f"Final count: {len(summarized_entries)}"
            )
        else:
            logging.info("No redundant networks found to summarize")

        if self.save_to_file(summarized_entries, self.output_path):
            logging.info(f"Successfully saved all entries to {self.output_path}")
        else:
            logging.error(f"Failed to save the final list to {self.output_path}")


def main():
    """Main function to download, process, summarize, and save IP lists."""
    parser = argparse.ArgumentParser(
        description="Download, validate, merge, summarize, and save IP blocklists."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file path",
        default=Path("merged-ip-list.txt"),
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    processor = IPProcessor(IPLoader({}), IPFilter(), args.output)
    processor.process()


if __name__ == "__main__":
    main()
