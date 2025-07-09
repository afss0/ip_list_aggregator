import argparse
import ipaddress
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

# AI: Load SOURCES from the sources.json file
SOURCES: List[Dict[str, Any]] = [
    {
        "name": "avastel",
        "url": "https://raw.githubusercontent.com/antoinevastel/avastel-bot-ips-lists/refs/heads/master/avastel-proxy-bot-ips-blocklist-8days.txt",
        "parser": parse_generic_cidrs,
    },
    {
        "name": "ipsum",
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt",
        "parser": parse_generic_ips,
    },
]


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


def main():
    """Main function to download, process, summarize, and save IP lists."""
    parser = argparse.ArgumentParser(
        description="Download, validate, merge, and summarize multiple IP blocklists."
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file path",
        default=Path("merged-ip-list.txt"),
    )
    args = parser.parse_args()

    merged_entries: Set[IPAddressObject] = set()

    with requests.Session() as session:
        for source in SOURCES:
            name, url, parser_func = source["name"], source["url"], source["parser"]
            logging.info(f"Processing source: {name}")

            content = fetch_content(session, url)
            if not content:
                logging.error(f"Failed to fetch content from {name}, skipping.")
                continue

            source_entries = parser_func(content)
            logging.info(f"Found {len(source_entries)} unique entries from {name}.")

            merged_entries.update(source_entries)

    if not merged_entries:
        logging.warning(
            "No entries were collected. The output file will not be created."
        )
        return

    logging.info(f"Total unique entries collected: {len(merged_entries)}")

    # --- NEW: Summarize the networks ---
    logging.info("Summarizing network list to remove redundant subnets...")
    # `collapse_addresses` creates the minimal set of networks covering all inputs.
    # For example, if the list contains 1.1.1.1/32 and 1.1.1.0/24, it will only keep 1.1.1.0/24.
    summarized_entries = set(ipaddress.collapse_addresses(merged_entries))

    num_removed = len(merged_entries) - len(summarized_entries)
    if num_removed > 0:
        logging.info(
            f"Removed {num_removed} subsumed networks. Final count: {len(summarized_entries)}"
        )
    else:
        logging.info("No redundant networks found to summarize.")
    # --- End of new section ---

    if save_to_file(summarized_entries, args.output):
        logging.info(f"Successfully saved all entries to {args.output}")
    else:
        logging.error(f"Failed to save the final list to {args.output}")


if __name__ == "__main__":
    main()
