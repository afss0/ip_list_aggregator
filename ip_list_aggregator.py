import argparse
import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set

IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
CIDR_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")


class SourceType(Enum):
    BLACKLIST = "blacklist"
    WHITELIST = "whitelist"


@dataclass
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


class IntervalTreeNode:
    def __init__(self, start: int, end: int):
        self.start = start
        self.end = end
        self.max_end = end
        self.left: Optional["IntervalTreeNode"] = None
        self.right: Optional["IntervalTreeNode"] = None


class IntervalTree:
    def __init__(self):
        self.root = None

    def insert(self, start: int, end: int) -> None:
        if not self.root:
            self.root = IntervalTreeNode(start, end)
            return

        node = self.root
        while True:
            node.max_end = max(node.max_end, end)
            if start <= node.start:
                if node.left:
                    node = node.left
                else:
                    node.left = IntervalTreeNode(start, end)
                    break
            else:
                if node.right:
                    node = node.right
                else:
                    node.right = IntervalTreeNode(start, end)
                    break

    def contains(self, point: int) -> bool:
        stack = [self.root]
        while stack:
            node = stack.pop()
            if not node:
                continue
            if node.start <= point <= node.end:
                return True
            if node.left and point <= node.max_end:
                stack.append(node.left)
            if node.right and point >= node.start:
                stack.append(node.right)
        return False


class IPProcessor:
    PARSERS = {
        "parse_generic_cidrs": CIDRParser(),
        "parse_generic_ips": IPParser(),
    }

    def __init__(self, output_path: Path):
        self.output_path = output_path
        self.blacklist = set()
        self.whitelist = set()

    def load_sources(self) -> List[SourceConfig]:
        try:
            with open("sources.json") as f:
                return [
                    SourceConfig(
                        name=s["name"],
                        url=s["url"],
                        parser_type=s["parser_type"],
                        source_type=SourceType(s["type"]),
                    )
                    for s in json.load(f)
                ]
        except Exception as e:
            logging.error(f"Failed to load sources: {e}")
            raise

    def fetch(self, url):
        from urllib.request import urlopen

        try:
            with urlopen(url) as response:
                return response.read().decode("utf-8")
        except Exception as e:
            raise Exception(f"Failed to fetch URL: {str(e)}")

    def process_source(self, source: SourceConfig) -> None:
        content = self.fetch(source.url)
        if not content:
            return

        parser = self.PARSERS.get(source.parser_type)
        if not parser:
            logging.error(f"Invalid parser: {source.parser_type}")
            return

        entries = parser.parse(content)
        target = (
            self.blacklist
            if source.source_type == SourceType.BLACKLIST
            else self.whitelist
        )
        target.update(entries)
        logging.info(f"Processed {source.name}: {len(entries)} entries")

    def filter_ips(self) -> Set[ipaddress.IPv4Network]:
        tree = IntervalTree()
        for net in self.whitelist:
            start = int(net.network_address)
            end = int(net.broadcast_address)
            tree.insert(start, end)

        return {
            net for net in self.blacklist if not tree.contains(int(net.network_address))
        }

    def save_results(self, entries: Set[ipaddress.IPv4Network]) -> bool:
        try:
            temp_path = self.output_path.with_suffix(".tmp")
            with temp_path.open("w") as f:
                for net in sorted(entries, key=lambda n: n.network_address):
                    f.write(f"{net.with_prefixlen}\n")
            temp_path.replace(self.output_path)
            return True
        except OSError as e:
            logging.error(f"File save failed: {e}")
            return False

    def run(self) -> None:
        try:
            sources = self.load_sources()
        except Exception:
            return

        for source in sources:
            self.process_source(source)

        if not self.blacklist:
            logging.warning("No blacklist entries found")
            return

        filtered = self.filter_ips()
        summarized = set(ipaddress.collapse_addresses(filtered))
        removed_count = len(filtered) - len(summarized)

        if removed_count:
            logging.info(f"Summarized {removed_count} redundant networks")

        if self.save_results(summarized):
            logging.info(f"Saved {len(summarized)} entries to {self.output_path}")
        else:
            logging.error("Failed to save results")


def main():
    parser = argparse.ArgumentParser(description="IP list processor")
    parser.add_argument("-o", "--output", type=Path, default="merged-ip-list.txt")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    processor = IPProcessor(args.output)
    processor.run()


if __name__ == "__main__":
    main()
