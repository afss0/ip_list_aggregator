# IP List Aggregator

Download, validate, de-duplicate and collapse IPv4 blocklists from several sources into a single
CIDR file, then apply that file to the kernel firewall as an `ipset` with two dedicated
`iptables` chains.

Two components:

1. **`ip_list_aggregator.py`** — fetches the configured feeds, validates every entry, subtracts the
   whitelist, collapses the result and writes the list atomically.
2. **`update_firewall_blocklist.sh`** — applies the list as a kernel block set, refuses anything it
   cannot trust, and verifies what the kernel actually accepted.

> **NOTE:** the default lists are aggressive and intended for **servers**. Applying them on a
> router or a desktop **WILL** break connectivity to many services.

## What it actually does with the addresses

Feeds are parsed into networks, deduplicated, and collapsed with `ipaddress.collapse_addresses`.
Collapsing only merges sibling networks whose union is exactly a larger network:

- `1.1.1.0/25` + `1.1.1.128/25` → `1.1.1.0/24`
- all 256 addresses of `1.1.1.0/24` present as `/32` → `1.1.1.0/24`
- `1.1.1.1/32` + `1.1.1.2/32` → **still two `/32`** (the tool never widens a block to cover
  addresses the feeds did not list)

## Requirements

- Python 3.9+ (standard library only — no `pip install` needed)
- For the applier: Linux with `ipset`, `iptables`, and a way to persist rules
  (`iptables-persistent`/`netfilter-persistent` on Debian/Ubuntu; `iptables-services` +
  `ipset-service` on the RHEL family)

## Install

The aggregator resolves `sources.json` **next to the script**, so the packaged layout keeps working
from any working directory (including cron and systemd).

```bash
sudo install -d -m 0755 /usr/local/lib/ip_list_aggregator
sudo install -m 0755 ip_list_aggregator.py /usr/local/lib/ip_list_aggregator/
sudo install -m 0644 sources.json /usr/local/lib/ip_list_aggregator/
sudo install -m 0755 update_firewall_blocklist.sh /usr/local/sbin/update_firewall_blocklist.sh
sudo install -d -m 0700 /var/lib/ip-list-aggregator
```

## Run with systemd (recommended)

One timer drives both steps, so the list never passes through an unprivileged account.

`/etc/systemd/system/ip-list-aggregator.service`

```ini
[Unit]
Description=Refresh and apply the aggregated IP blocklist
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/ip_list_aggregator/ip_list_aggregator.py --output /var/lib/ip-list-aggregator/merged-ip-list.txt
ExecStart=/usr/local/sbin/update_firewall_blocklist.sh /var/lib/ip-list-aggregator/merged-ip-list.txt
StateDirectory=ip-list-aggregator
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/ip-list-aggregator.timer`

```ini
[Unit]
Description=Daily IP blocklist refresh

[Timer]
OnCalendar=*-*-* 23:30:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ip-list-aggregator.timer
```

`Persistent=true` runs the job after boot if the machine was down at the scheduled time.

## Configuration

### `sources.json`

```json
[
  {
    "name": "antoinevastel/avastel-bot-ips-lists",
    "url": "https://raw.githubusercontent.com/antoinevastel/avastel-bot-ips-lists/refs/heads/master/avastel-proxy-bot-ips-blocklist-8days.txt",
    "parser_type": "parse_generic_cidrs",
    "type": "blacklist"
  }
]
```

| Field | Values | Meaning |
|---|---|---|
| `parser_type` | `parse_generic_cidrs` | extracts `a.b.c.d/prefix` tokens (CIDR feeds) |
| | `parse_generic_ips` | extracts bare `a.b.c.d` tokens as `/32` (IP feeds) |
| `type` | `blacklist` | addresses to block |
| | `whitelist` | addresses removed from the blacklist (exact range subtraction) |

A `parser_type` that does not match the feed silently narrows coverage (a `/8` feed read with
`parse_generic_ips` becomes a single `/32`), so the tool fails the run when a source yields zero
entries and refuses networks wider than `/8`.

Default sources:

- [Antoine Vastel's IP Lists](https://github.com/antoinevastel/avastel-bot-ips-lists)
- [Stamparm's Ipsum](https://github.com/stamparm/ipsum)
- [Borestad's AbuseIPDB blocklist](https://github.com/borestad/blocklist-abuseipdb) (`s100-3d`,
  ~57k addresses reported at ~100% confidence in the last 3 days)

> If you want to protect your web applications against bots, you may also want to check out
> [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis/tree/main).

### Allow-list (management addresses)

`/etc/ip-list-allow.txt`, one CIDR or IP per line (`#` comments allowed):

```
# never block the tailnet, the LAN, or the admin jump host
100.64.0.0/10
192.168.1.0/24
203.0.113.10
```

These addresses are loaded into `ip_allow_set` and matched with a `RETURN` **before** the block-set
`DROP` in both chains, so a feed that lists your own address cannot lock you out.

## Exit codes

| Code | Meaning | What happens to the previous list |
|---|---|---|
| `0` | success | replaced |
| `2` | configuration error (missing/invalid `sources.json`, unknown `parser_type`) | untouched |
| `3` | every source failed, or a partial update (some sources failed) | untouched / written with the surviving sources |
| `4` | sanity guard: network wider than `/8`, coverage jump above the ratio, empty blacklist | untouched |
| `5` | output could not be written | untouched |

The applier exits `1` on any refusal or verification failure and leaves the live set in place.

## Running by hand

```bash
# build the list
python3 ip_list_aggregator.py --output /var/lib/ip-list-aggregator/merged-ip-list.txt

# apply it
sudo update_firewall_blocklist.sh /var/lib/ip-list-aggregator/merged-ip-list.txt

# inspect
sudo ipset list bad_ips_set | head
sudo iptables -S IPBLOCK_IN
sudo iptables -S IPBLOCK_OUT
```

Useful flags: `--sources PATH`, `--timeout SECONDS` (default 30), `--attempts N` (default 3),
`--min-prefix N` (default 8), `--coverage-ratio N` (default 10), `--force` (disable the coverage
guard for an intentional big change).

## Publishing the list as a release asset

A clone does not need the generated file: `.github/workflows/publish-blocklist.yml` builds it from
`main` and refreshes a rolling `latest` release every day at 00:15 UTC (also on `workflow_dispatch`
and on pushes that touch the aggregator or `sources.json`). No commit is made — the release asset
is the artifact.

Stable download URL, no token needed:

```bash
curl -fsSL https://github.com/afss0/ip_list_aggregator/releases/latest/download/merged-ip-list.txt -o merged-ip-list.txt
curl -fsSL https://github.com/afss0/ip_list_aggregator/releases/latest/download/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS
```

The job stops before publishing when the aggregator exits non-zero (configuration error, dead feed,
sanity guard), so a partial or refused build never reaches consumers. Scheduled runs can be delayed
by GitHub under load; the asset always carries its generation timestamp in the release notes.

## How the applier protects itself

1. Refuses a list that is missing, empty, a symlink, or not owned by `root`.
2. Refuses malformed lines and any network wider than `/8` **before** the kernel sees them.
3. Builds `bad_ips_set_temp`, compares `Number of entries` with the file, and only then swaps it
   into place atomically (`ipset swap`), verifying the count again afterwards.
4. Holds a `flock`, so two concurrent runs cannot corrupt each other's temp set.
5. Rebuilds `IPBLOCK_IN`/`IPBLOCK_OUT` (allow `RETURN` first, block `DROP` second) and inserts the
   jump into `INPUT`/`OUTPUT` at most once.
6. Reports persistence honestly: if `netfilter-persistent` is missing, it says so instead of
   pretending the rules will survive a reboot.

## Persistence

After a successful run, save the rules:

```bash
# Debian/Ubuntu
sudo netfilter-persistent save

# RHEL family
sudo service iptables save && sudo service ipset save
```

`ipset swap` also replaces the set contents on the next run, so the saved state is refreshed by the
daily job.

## Tests

```bash
# unit tests (offline, file:// fixtures, no privileges)
python3 -m unittest discover -s tests -v

# applier scenarios against stubbed ipset/iptables
bash tests/scenarios.sh

# real kernel test, isolated in a container's network namespace
docker build -t ip_list_aggregator:test -f tests/Dockerfile .
docker run --rm --privileged -v "$PWD:/repo:ro" ip_list_aggregator:test \
    bash /repo/tests/integration.sh
```

The integration suite applies a list containing `127.0.0.1/32`, verifies the connection to a local
listener is dropped, adds the peer to the allow-list, and verifies the connection succeeds again.

## Limitations

- **IPv4 only.** IPv6 literals in a feed are ignored, with a warning that reports how many were
  skipped. IPv6 support needs a separate `family inet6` set and `ip6tables` chains.
- The block set is capped at `MAX_ELEMS` (default 500000) entries.
- The applier assumes `iptables`/`ipset` are present and functional; on an nftables-only host use
  `iptables-nft`/`iptables-legacy` explicitly.

## Recovery from a lockout

If a feed ever blocks your management path, you need console access (provider console, IPMI,
serial). Then:

```bash
sudo ipset del bad_ips_set <your-ip> -exist   # unblock yourself now
echo "<your-ip>" | sudo tee -a /etc/ip-list-allow.txt
```

Adding it to the allow-list file is what makes the fix survive the next run.

## License

Apache-2.0 — see [LICENSE](LICENSE).
