import argparse
import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Set

import requests

# --- Configuration ---

IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
CIDR_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

IPAddressObject = ipaddress.IPv4Network


# --- Parsing Functions ---


def parse_generic_cidrs(text: str) -> Set[IPAddressObject]:
    """Parses and validates CIDR notations from a block of text."""
    entries = set()
    for match in CIDR_PATTERN.findall(text):
        try:
            entries.add(ipaddress.ip_network(match, strict=False))
        except ValueError:
            logging.warning(f"Skipping invalid CIDR notation: {match}")
    return entries


def parse_generic_ips(text: str) -> Set[IPAddressObject]:
    """
    Parses and validates IPs from a block of text, ignoring comments and empty lines.
    Converts single IPs to /32 networks.
    """
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


# --- Core Logic ---

def load_sources() -> List[Dict[str, Any]]:
    """Load sources configuration from sources.json file"""
    try:
        with open('sources.json', 'r') as f:
            sources = json.load(f)
            # Map parser strings to actual functions
            parser_map = {
                'parse_generic_cidrs': parse_generic_cidrs,
                'parse_generic_ips': parse_generic_ips
            }
            for source in sources:
                source['parser'] = parser_map[source['parser']]
            return sources
    except Exception as e:
        logging.error(f"Failed to load sources.json: {e}")
        raise


def fetch_content(session: requests.Session, url: str) -> str | None:
    """Fetch text content from a URL using a requests session."""
    try:
        response = session.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except requests.exceptions.Timeout:
        logging.error(f"Request timed out for URL: {url}")
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP Error for URL {url}: {e}")
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while fetching {url}: {e}")
    return None


def save_to_file(entries: Set[IPAddressObject], filepath: Path) -> bool:
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


def filter_whitelisted_ips(blacklist: Set[IPAddressObject], whitelist: Set[IPAddressObject]) -> Set[IPAddressObject]:
    """Remove whitelisted IPs from the blacklist."""
    filtered_blacklist = set()
    for black_entry in blacklist:
        if not any(black_entry.subnet_of(white_entry) for white_entry in whitelist):
            filtered_blacklist.add(black_entry)
    return filtered_blacklist


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

    blacklist_entries: Set[IPAddressObject] = set()
    whitelist_entries: Set[IPAddressObject] = set()

    try:
        SOURCES = load_sources()
    except Exception:
        return

    with requests.Session() as session:
        for source in SOURCES:
            name, url, parser_func, source_type = source["name"], source["url"], source["parser"], source["type"]
            logging.info(f"Processing source: {name}")

            content = fetch_content(session, url)
            if not content:
                logging.error(f"Failed to fetch content from {name}, skipping.")
                continue

            source_entries = parser_func(content)
            logging.info(f"Found {len(source_entries)} unique entries from {name}.")

            if source_type == "blacklist":
                blacklist_entries.update(source_entries)
            elif source_type == "whitelist":
                whitelist_entries.update(source_entries)

    if not blacklist_entries:
        logging.warning(
            "No blacklist entries were collected. The output file will not be created."
        )
        return

    logging.info(f"Total unique blacklist entries collected: {len(blacklist_entries)}")

    # Save blacklist to a buffer file
    buffer_file = Path("buffer-blacklist.txt")
    if not save_to_file(blacklist_entries, buffer_file):
        logging.error(f"Failed to save the buffer blacklist to {buffer_file}")
        return

    logging.info(f"Buffer blacklist saved to {buffer_file}")

    # Filter out whitelisted IPs from the blacklist
    filtered_blacklist_entries = filter_whitelisted_ips(blacklist_entries, whitelist_entries)

    logging.info(f"Total unique blacklist entries after filtering: {len(filtered_blacklist_entries)}")

    logging.info("Summarizing network list to remove redundant subnets...")
    summarized_entries = set(ipaddress.collapse_addresses(filtered_blacklist_entries))

    num_removed = len(filtered_blacklist_entries) - len(summarized_entries)
    if num_removed > 0:
        logging.info(
            f"Removed {num_removed} subsumed networks. Final count: {len(summarized_entries)}"
        )
    else:
        logging.info("No redundant networks found to summarize")

    if save_to_file(summarized_entries, args.output):
        logging.info(f"Successfully saved all entries to {args.output}")
    else:
        logging.error(f"Failed to save the final list to {args.output}")


if __name__ == "__main__":
    main()
