# IP List Aggregator

This project provides a Python script with a set of tools to automatically download, merge, de-duplicate, and summarize IP lists from multiple sources.

There are two main components:

1. **`ip_list_aggregator.py`**: A Python script that fetches, validates, and processes IP lists.
2. **`update_firewall_blocklist.sh`**: A complementary shell script that uses the generated list to update the system's firewall rules for blocking purposes with zero downtime (optional).

## Features

- **Multi-Source Fetching**: Downloads blocklists from a configurable list of URLs.
- **IP/CIDR Validation**: Ensures that only valid IPv4 addresses and networks are processed.
- **Deduplication & Summarization**: Removes duplicate entries and collapses smaller networks into larger, more efficient CIDR blocks (e.g., `1.1.1.1/32` and `1.1.1.2/32` might become part of `1.1.1.0/24`).

Currently, the following sources are used:

- [Antoine Vastel's IP Lists](https://github.com/antoinevastel/avastel-bot-ips-lists)
- [Stamparm's Ipsum](https://github.com/stamparm/ipsum)

```markdown
> If you want to protect your web applications against bots, you may also want to check out:

[TecharoHQ/anubis](https://github.com/TecharoHQ/anubis/tree/main)
```

**NOTE:** The default lists included are aggressive and intended to block bad agents **ON SERVERS**. Applying them on a router or desktop **WILL** break connectivity to many services.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- Python 3.x
- `pip`
- `git`

**(Optional, for the complementary shell script that applies the list as a blocklist)**

- `iptables`
- `ipset`
- For Debian/Ubuntu: `iptables-persistent` and `ipset-persistent`
- For RHEL family (CentOS, RHEL, Fedora, Rocky Linux, AlmaLinux): `iptables-services` and `ipset-service`

## Installation & Setup

Follow these steps to set up the project on your Linux server.

### 1. Clone the Repository

```bash
git clone https://github.com/afss0/ip_list_aggregator/ ~/git-repos/ip_list_aggregator
cd ~/git-repos/ip_list_aggregator
```

### 2. Install System Dependencies

You need ipset and some packages to make your firewall rules persistent across reboots.

- For Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install ipset iptables-persistent ipset-persistent
```

- For CentOS/RHEL:

```bash
# For RHEL/CentOS 7
# sudo yum install ipset iptables-services ipset-service

# For RHEL 8+, Fedora, and modern derivatives, use dnf
sudo dnf install ipset iptables-services ipset-service

sudo systemctl enable iptables
sudo systemctl enable ipset
```

### 3. Make the Update Script Executable

```bash
mkdir -p ~/git-repos/ip_list_aggregator/logs
sudo chmod +x update_firewall_blocklist.sh
```

### 4. Generate the IP List

Run the Python script. This will create the merged-ip-list.txt file in the current directory.

```bash
python3 ip_list_aggregator.py --output "/tmp/merged-ip-list.txt" >> /tmp/ip_list_aggregator.log 2>&1
```

### 5. Update the Firewall

Run the shell script with sudo. This will create the ipset and apply the iptables rules.

```bash
sudo ./update_firewall_blocklist.sh
```

### 6. Verify the Results

Check that the ipset was created and populated:

#### This should show a list of IPs and networks

```bash
sudo ipset list bad_ips_set
```

#### Check that the iptables rules are in place (they should be at the top of the INPUT and OUTPUT chains):

```bash
sudo iptables -L INPUT -n -v
sudo iptables -L OUTPUT -n -v
```

## Automation with Cron

To keep the blocklist updated automatically, set up two cron jobs.

### 1. User Cron Job (to run the Python script)

First, copy the script to the /usr/local/bin folder:

```bash
sudo cp ~/git-repos/ip_list_aggregator /usr/local/bin/ip_list_aggregator/
```

```bash
crontab -e
```

Add the following line to run the script every day at `23:30` and log its output:

```crontab
# At 23:30 every day, run the IP list aggregator script
30 23 * * * /usr/bin/python3 /usr/local/bin/ip_list_aggregator/ip_list_aggregator.py --output "/tmp/merged-ip-list.txt" >> /tmp/ip_list_aggregator.log 2>&1
```

### 2. Root Cron Job (to update the firewall)

First, copy the script to the /usr/local/sbin folder and mark it as executable:

```bash
sudo cp ./update_firewall_blocklist.sh /usr/local/sbin/update_firewall_blocklist.sh
sudo chmod +x /usr/local/sbin/update_firewall_blocklist.sh
```

Open the root user's crontab:

```bash
sudo crontab -e
```

Add the following line to run the update script a few minutes later (e.g., at `23:35`):

```crontab
# At 23:35 every day, update the iptables rules from the generated blocklist
35 23 * * * /usr/local/sbin/update_firewall_blocklist.sh >> /var/log/iptables_update.log 2>&1
```

## Making Firewall Rules Persistent

iptables and ipset rules are lost on reboot. After you have successfully run the update_firewall_blocklist.sh script once, save the current rules so they are restored automatically on startup.

For Debian/Ubuntu:

```bash
sudo netfilter-persistent save
```

For CentOS/RHEL:

```bash
sudo service iptables save
sudo service ipset save
```

Your daily cron job will handle the updates, and the persistence packages will handle restoring the last saved state on reboot.
