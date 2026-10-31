# IP List Aggregator

Download, validate, de-duplicate and collapse IPv4 blocklists from several sources into a single
CIDR file, then apply that file to the kernel firewall as an `ipset` with two dedicated `iptables`
chains.

Two components:

1. `ip_list_aggregator.py` fetches the configured feeds, validates every entry, subtracts the
   whitelist, collapses the result and writes the list atomically.
2. `update_firewall_blocklist.sh` applies the list as a kernel block set, refuses lists it cannot
   fully validate, and checks what the kernel actually accepted.

> **NOTE:** the default lists are aggressive and meant for servers. On a router or a desktop they
> **WILL** break connectivity to many services.

## How collapsing works

Feeds are parsed into networks and deduplicated, then collapsed with
`ipaddress.collapse_addresses`. Collapsing only merges sibling networks whose union is exactly a
larger network:

- `1.1.1.0/25` + `1.1.1.128/25` → `1.1.1.0/24`
- all 256 addresses of `1.1.1.0/24` present as `/32` → `1.1.1.0/24`

## Requirements

- Python 3.9 or newer. The aggregator imports only the standard library, so there is nothing to
  install.
- For the applier: Linux with `ipset`, `iptables`, and a way to persist rules
  (`iptables-persistent`/`netfilter-persistent` on Debian/Ubuntu; `iptables-services` +
  `ipset-service` on the RHEL family).

## Install

The aggregator looks for `sources.json` next to the script rather than in the working directory, so
the packaged layout keeps working under cron and systemd.

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

A `parser_type` that does not match the feed narrows coverage without raising an error: read a `/8`
feed with `parse_generic_ips` and you get a single `/32`. Two guards catch the worst cases: a source
that yields zero entries fails the run, and no network wider than `/8` is accepted.

Default sources:

- [Antoine Vastel's IP Lists](https://github.com/antoinevastel/avastel-bot-ips-lists)
- [Stamparm's Ipsum](https://github.com/stamparm/ipsum)
- [Borestad's AbuseIPDB blocklist](https://github.com/borestad/blocklist-abuseipdb) (`s100-3d`,
  ~57k addresses reported at ~100% confidence in the last 3 days)

> For bot filtering at the application layer rather than the network layer, see
> [TecharoHQ/anubis](https://github.com/TecharoHQ/anubis/tree/main).

### Allow-list (management addresses)

`/etc/ip-list-allow.txt`, one CIDR or IP per line (`#` comments allowed):

```
# never block the tailnet, the LAN, or the admin jump host
100.64.0.0/10
192.168.1.0/24
203.0.113.10
```

These addresses are loaded into `ip_allow_set` and matched with a `RETURN` before the block-set
`DROP` in both chains, so a feed that lists your own address cannot lock you out.

## Exit codes

| Code | Meaning | What happens to the previous list |
|---|---|---|
| `0` | success | replaced |
| `2` | configuration error (missing/invalid `sources.json`, unknown `parser_type`) | untouched |
| `3` | every source failed, or a partial update (some sources failed) | kept if every source failed; otherwise overwritten with the surviving sources |
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

## Pre-made list

`.github/workflows/publish-blocklist.yml` builds the list from `main`
and refreshes a rolling `latest` release every day at 00:15 UTC. It also runs on `workflow_dispatch`
and on pushes that touch the aggregator or `sources.json`.

The download URL is stable and needs no token:

```bash
curl -fsSL https://github.com/afss0/ip_list_aggregator/releases/latest/download/merged-ip-list.txt -o merged-ip-list.txt
curl -fsSL https://github.com/afss0/ip_list_aggregator/releases/latest/download/SHA256SUMS -o SHA256SUMS
sha256sum -c SHA256SUMS
```

The job stops before publishing when the aggregator exits non-zero (configuration error, dead feed,
sanity guard), so a partial or refused build is never published. Scheduled runs can be delayed by
GitHub under load; the release notes always carry the generation timestamp.

## What the applier checks

1. It refuses a list that is missing, empty, a symlink, or not owned by `root`.
2. It refuses malformed lines and any network wider than `/8` before the kernel sees them.
3. It builds `bad_ips_set_temp`, compares its `Number of entries` against the file, and only then
   swaps it into place with `ipset swap`. The count is verified once more after the swap.
4. It holds a `flock`, so two concurrent runs cannot corrupt each other's temp set.
5. It rebuilds `IPBLOCK_IN`/`IPBLOCK_OUT` with the allow `RETURN` first and the block `DROP` second,
   and inserts the jump into `INPUT`/`OUTPUT` at most once.
6. It warns when `netfilter-persistent` is missing rather than implying the rules will survive a
   reboot.

## Persistence

When `netfilter-persistent` is installed, the applier saves the rules at the end of every run, so on
Debian and Ubuntu there is nothing to do by hand. Without it, the script says so and the rules are
gone after a reboot.

The RHEL family is not covered by that call. Save after each refresh, or add the command to the
unit:

```bash
sudo service iptables save && sudo service ipset save
```

`ipset swap` gives every run a fresh live set, and the save at the end carries the rules across a
reboot.

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

- IPv4 only. IPv6 literals in a feed are ignored, and the warning says how many were skipped.
  Supporting IPv6 needs a separate `family inet6` set and `ip6tables` chains.
- The block set is capped at `MAX_ELEMS` entries (default 500000).
- The applier assumes `iptables`/`ipset` are present and functional. On an nftables-only host, call
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

Apache-2.0. See [LICENSE](LICENSE).
